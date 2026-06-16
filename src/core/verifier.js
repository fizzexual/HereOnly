'use strict';

/**
 * HereOnly verification engine.
 *
 * Produces an allow/deny verdict for a client, combining (in order):
 *   deny-list -> loopback -> host-self -> allow-list -> rate-limit
 *   -> session-token fast path -> live checks (subnet, ARP/NDP adjacency,
 *   network approval).
 *
 * ARP/NDP adjacency is the PRIMARY gate. When `requireArp` is true (default) a
 * verified unicast neighbor grants access and the subnet check is advisory (a
 * passed ARP implies on-segment even if subnet enumeration missed an
 * interface, so subnet never causes a false-deny). Fails closed. Every verdict
 * can be recorded to the physical-access audit log.
 */

const os = require('node:os');
const { isLoopback, ipInAnyCidr, normalizeIp, extractClientIp } = require('./ip.js');
const { getLocalSubnets } = require('../os/netinfo.js');
const { getOwnIps } = require('../os/self.js');
const { createNeighborCache } = require('./arpcache.js');
const { createRateLimiter } = require('./ratelimit.js');
const { createPolicyResolver } = require('./policy.js');
const { createAudit } = require('./audit.js');
const fp = require('./fingerprint.js');
const tokens = require('./tokens.js');
const { createLogger, noopLogger } = require('./logger.js');

const DEFAULTS = {
  allowLoopback: true,
  allowSelf: true,
  requireSubnet: true,
  requireArp: true,
  failClosed: true,
  tokenTtlSeconds: 1800,
  renewWithinSeconds: 300,
  revalidateArpWithToken: true,
  arpTtlMs: 2000,
  netIdentTtlMs: 15000,
  includeWifi: true,
  fingerprintOpts: undefined,
  network: {},
  extraAllowCidrs: [],
  denyCidrs: [],
  rateLimit: null, // true | {capacity, refillPerSec} | a limiter instance
  policies: [],
  audit: null, // true | {file, sign, secret, ...} | an audit instance
};

function resolveAudit(a, fallbackSecret) {
  if (!a) return null;
  if (typeof a.record === 'function') return a;
  return createAudit(a === true ? {} : { secret: fallbackSecret, ...a });
}

function resolveLimiter(rl, now) {
  if (!rl) return null;
  if (typeof rl.take === 'function') return rl;
  return createRateLimiter({ ...(rl === true ? {} : rl), now });
}

function createVerifier(userOptions = {}) {
  const opts = { ...DEFAULTS, ...userOptions };
  const logger =
    userOptions.logger || (userOptions.silent ? noopLogger : createLogger({ level: userOptions.logLevel || 'warn' }));
  const secret = tokens.normalizeSecret(opts.secret || tokens.generateSecret());
  const { run, platform } = opts;
  const nowMs = opts.now || (() => Date.now());

  const arpCache = createNeighborCache({ ttlMs: opts.arpTtlMs, run, platform, now: nowMs });
  const limiter = resolveLimiter(opts.rateLimit, nowMs);
  const audit = resolveAudit(opts.audit, secret);
  const resolvePolicy = createPolicyResolver(opts.policies);

  // network-identity cache (rarely changes; longer TTL). staticIdentity pins it.
  const staticIdentity = opts.staticIdentity || null;
  let netCache = { at: 0, identity: null, fp: null };
  let netInflight = null;
  async function getNetwork() {
    if (staticIdentity) {
      if (!netCache.identity) netCache = { at: nowMs(), identity: staticIdentity, fp: fp.fingerprint(staticIdentity, opts.fingerprintOpts) };
      return netCache;
    }
    if (netCache.at && nowMs() - netCache.at < opts.netIdentTtlMs) return netCache;
    if (netInflight) return netInflight;
    netInflight = fp
      .computeIdentity({ run, platform, includeWifi: opts.includeWifi })
      .then((identity) => {
        netCache = { at: nowMs(), identity, fp: fp.fingerprint(identity, opts.fingerprintOpts) };
        netInflight = null;
        return netCache;
      })
      .catch((err) => {
        netInflight = null;
        logger.warn('network identity probe failed:', err && err.message);
        return { at: nowMs(), identity: null, fp: null };
      });
    return netInflight;
  }

  // host own-IP set (refreshed lazily; interface IPs rarely change).
  // `opts.ownIps` pins the set (fixed deployments / deterministic tests).
  const ownOverride = opts.ownIps ? new Set([...opts.ownIps].map((x) => normalizeIp(x)).filter(Boolean)) : null;
  let ownCache = { at: 0, set: new Set() };
  function ownIps() {
    if (ownOverride) return ownOverride;
    if (!ownCache.at || nowMs() - ownCache.at > 5000) ownCache = { at: nowMs(), set: getOwnIps() };
    return ownCache.set;
  }

  const issue = (ip, mac, net) =>
    tokens.issueToken({ ip, mac, net }, secret, { ttlSeconds: opts.tokenTtlSeconds, now: nowMs });

  const netInfo = (net) =>
    net && net.identity ? { fingerprint: net.fp ? net.fp.hash : null, label: fp.networkLabel(net.identity) } : null;

  function presentFor(allow, reason, via) {
    if (!allow) return false;
    return reason === 'arp-verified' || reason === 'loopback' || reason === 'self' || via === 'token';
  }

  function build(allow, reason, detail, extra = {}) {
    return {
      allow,
      reason,
      detail,
      ip: extra.ip != null ? extra.ip : null,
      mac: extra.mac != null ? extra.mac : null,
      via: extra.via || 'none',
      token: extra.token != null ? extra.token : null,
      network: extra.network != null ? extra.network : null,
      checks: extra.checks || {},
      present: presentFor(allow, reason, extra.via),
      retryAfterMs: extra.retryAfterMs || 0,
    };
  }

  function eff(overrides, key) {
    return overrides && overrides[key] !== undefined ? overrides[key] : opts[key];
  }

  async function verify(input = {}, overrides = {}) {
    const clientIp = normalizeIp(input.ip);
    const token = input.token || null;
    const resource = input.resource || null;

    const finish = (v) => {
      if (audit) {
        audit.record({
          ip: v.ip,
          mac: v.mac,
          allow: v.allow,
          reason: v.reason,
          via: v.via,
          resource,
          net: v.network ? v.network.fingerprint : null,
          present: v.present,
        });
      }
      return v;
    };

    if (!clientIp) return finish(build(false, 'no-client-ip', 'could not determine client IP'));

    const denyCidrs = eff(overrides, 'denyCidrs') || [];
    if (denyCidrs.length && ipInAnyCidr(clientIp, denyCidrs)) {
      return finish(build(false, 'denied-cidr', 'client IP is in the deny list', { ip: clientIp, via: 'deny' }));
    }

    if (eff(overrides, 'allowLoopback') && isLoopback(clientIp)) {
      return finish(build(true, 'loopback', 'request from host loopback', { ip: clientIp, via: 'loopback' }));
    }

    if (opts.allowSelf && ownIps().has(clientIp)) {
      return finish(build(true, 'self', 'request from one of the host’s own addresses', { ip: clientIp, via: 'self' }));
    }

    const extraAllow = eff(overrides, 'extraAllowCidrs') || [];
    if (extraAllow.length && ipInAnyCidr(clientIp, extraAllow)) {
      const net = await getNetwork().catch(() => null);
      const tok = issue(clientIp, null, net && net.fp ? net.fp.hash : null);
      return finish(
        build(true, 'allowlisted-cidr', 'client IP is in the allow list', {
          ip: clientIp,
          via: 'allowlist',
          token: tok,
          network: netInfo(net),
        }),
      );
    }

    if (limiter) {
      const rl = limiter.take(clientIp);
      if (!rl.allowed) {
        return finish(
          build(false, 'rate-limited', 'too many requests from this client', {
            ip: clientIp,
            via: 'ratelimit',
            retryAfterMs: rl.retryAfterMs,
          }),
        );
      }
    }

    const net = await getNetwork().catch(() => null);
    const currentFp = net && net.fp ? net.fp.hash : null;
    const networkPolicy = eff(overrides, 'network') || {};

    // token fast path
    if (token) {
      const tv = tokens.verifyToken(token, secret, { now: nowMs });
      if (tv.valid && tv.payload && tv.payload.ip === clientIp) {
        const netMatches = !tv.payload.net || !currentFp || tv.payload.net === currentFp;
        if (netMatches) {
          let macOk = true;
          let mac = tv.payload.mac;
          if (opts.revalidateArpWithToken) {
            const look = await arpCache.lookup(clientIp);
            if (!look.ok && opts.failClosed) macOk = false;
            else {
              const n = look.neighbor;
              macOk = !!(n && n.unicast && (!tv.payload.mac || n.mac === tv.payload.mac));
              if (n && n.mac) mac = n.mac;
            }
          }
          if (macOk) {
            const nowSec = Math.floor(nowMs() / 1000);
            const renewed = tv.payload.exp - nowSec < opts.renewWithinSeconds ? issue(clientIp, mac, currentFp || tv.payload.net) : null;
            return finish(
              build(true, 'token', 'valid bound session token', {
                ip: clientIp,
                mac,
                via: 'token',
                token: renewed,
                network: netInfo(net),
                checks: { token: true },
              }),
            );
          }
        }
      }
    }

    // live checks
    const subnets = (net && net.identity && net.identity.subnets) || getLocalSubnets();
    const inSubnet = ipInAnyCidr(clientIp, subnets);
    const look = await arpCache.lookup(clientIp);
    const probeOk = look.ok;
    const neighbor = look.neighbor;
    const arpVerified = !!(neighbor && neighbor.unicast);
    const mac = neighbor && neighbor.mac ? neighbor.mac : null;
    const checks = { subnet: inSubnet, arp: arpVerified, probeOk };
    const requireArp = eff(overrides, 'requireArp');

    if (requireArp) {
      if (!probeOk && opts.failClosed) {
        return finish(
          build(false, 'probe-failed', 'could not read the neighbor table (failing closed)', {
            ip: clientIp,
            mac,
            via: 'full-check',
            network: netInfo(net),
            checks,
          }),
        );
      }
      if (!arpVerified) {
        const reason = neighbor && !neighbor.unicast ? 'incomplete-arp' : 'no-arp-entry';
        return finish(
          build(false, reason, 'no resolved on-segment neighbor for the client IP', {
            ip: clientIp,
            mac,
            via: 'full-check',
            network: netInfo(net),
            checks,
          }),
        );
      }
    } else if (eff(overrides, 'requireSubnet') && !inSubnet) {
      return finish(
        build(false, 'off-subnet', 'client IP is not within any local subnet', {
          ip: clientIp,
          mac,
          via: 'full-check',
          network: netInfo(net),
          checks,
        }),
      );
    }

    if (fp.hasAllowlist(networkPolicy)) {
      if (!net || !net.identity) {
        if (opts.failClosed) {
          return finish(
            build(false, 'network-unknown', 'could not fingerprint the host network (failing closed)', {
              ip: clientIp,
              mac,
              via: 'full-check',
              checks,
            }),
          );
        }
      } else {
        const appr = fp.approveNetwork(net.identity, net.fp, networkPolicy);
        checks.network = appr.approved;
        if (!appr.approved) {
          return finish(
            build(false, 'network-not-approved', 'the host network is not in the approved list', {
              ip: clientIp,
              mac,
              via: 'full-check',
              network: netInfo(net),
              checks,
            }),
          );
        }
      }
    }

    const tok = issue(clientIp, mac, currentFp);
    return finish(
      build(true, arpVerified ? 'arp-verified' : 'subnet-verified', 'client is on the same network segment', {
        ip: clientIp,
        mac,
        via: 'full-check',
        token: tok,
        network: netInfo(net),
        checks,
      }),
    );
  }

  function readToken(req, cookieName, headerName) {
    const h = (req && req.headers) || {};
    if (headerName && h[headerName]) return String(h[headerName]);
    const auth = h['authorization'];
    if (auth && /^Bearer\s+(.+)/i.test(auth)) return auth.replace(/^Bearer\s+/i, '').trim();
    const cookie = h['cookie'];
    if (cookie && cookieName) {
      const safe = cookieName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      const m = cookie.match(new RegExp('(?:^|;\\s*)' + safe + '=([^;]+)'));
      if (m) {
        try {
          return decodeURIComponent(m[1]);
        } catch {
          return m[1];
        }
      }
    }
    return null;
  }

  function requestResource(req) {
    const host = (req && req.headers && req.headers.host) || '';
    return `${(req && req.method) || 'GET'} ${host}${(req && req.url) || ''}`.trim();
  }

  async function verifyRequest(req, reqOpts = {}) {
    const ip = extractClientIp(req, { trustForwardedHeader: !!reqOpts.trustForwardedHeader });
    const token = readToken(req, reqOpts.cookieName || 'hereonly', reqOpts.headerName || 'x-hereonly-token');
    const resource = reqOpts.resource || requestResource(req);
    const overrides = resolvePolicy({
      path: (req && req.url) || '/',
      host: (req && req.headers && req.headers.host) || '',
      method: (req && req.method) || 'GET',
    });
    return verify({ ip, token, resource }, overrides);
  }

  return {
    verify,
    verifyRequest,
    getNetwork,
    readToken,
    issueToken: issue,
    audit,
    limiter,
    options: opts,
    host: os.hostname(),
    _arpCache: arpCache,
    _secret: secret,
  };
}

module.exports = { createVerifier, DEFAULTS };
