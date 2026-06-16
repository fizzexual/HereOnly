'use strict';

/**
 * HereOnly verification engine.
 *
 * Produces an allow/deny verdict for a client, combining:
 *   loopback fast-path -> deny-list -> allow-list -> session token fast-path
 *   -> live checks (subnet, ARP/NDP adjacency, network approval).
 *
 * Design notes:
 *  - ARP/NDP adjacency is the PRIMARY gate. When `requireArp` is true (default),
 *    a verified unicast neighbor is what grants access; the subnet check is then
 *    advisory only (a passed ARP implies on-segment even if our subnet
 *    enumeration missed an interface, so subnet must never cause a false-deny).
 *    When `requireArp` is false, the subnet check becomes the gate (a weaker
 *    mode for hosts where the neighbor table can't be read).
 *  - Fail closed: if the neighbor table can't be read, deny (configurable).
 *  - Every successful verdict carries a freshly issued/renewed session token.
 */

const os = require('node:os');
const { isLoopback, ipInAnyCidr, normalizeIp, extractClientIp } = require('./ip.js');
const { getLocalSubnets } = require('../os/netinfo.js');
const { createNeighborCache } = require('./arpcache.js');
const netid = require('./netident.js');
const tokenMod = require('./token.js');
const { createLogger, noopLogger } = require('./logger.js');

const DEFAULTS = {
  allowLoopback: true,
  requireSubnet: true,
  requireArp: true,
  failClosed: true,
  tokenTtlSeconds: 1800,
  renewWithinSeconds: 300,
  revalidateArpWithToken: true,
  arpTtlMs: 2000,
  netIdentTtlMs: 15000,
  includeWifi: true,
  fingerprintOpts: undefined, // -> netident.DEFAULT_FP_OPTS
  network: {}, // { allowedFingerprints, allowedSsids, allowedGatewayMacs }
  extraAllowCidrs: [],
  denyCidrs: [],
};

function createVerifier(userOptions = {}) {
  const opts = { ...DEFAULTS, ...userOptions };
  const logger =
    userOptions.logger || (userOptions.silent ? noopLogger : createLogger({ level: userOptions.logLevel || 'warn' }));
  const secret = tokenMod.normalizeSecret(opts.secret || tokenMod.generateSecret());
  const run = opts.run;
  const platform = opts.platform;
  const nowMs = opts.now || (() => Date.now());

  const arpCache = createNeighborCache({ ttlMs: opts.arpTtlMs, run, platform, now: nowMs });

  // --- network-identity cache (changes rarely; longer TTL) ---------------
  // `staticIdentity` pins the network identity (skips live gateway/Wi-Fi
  // probing) — useful for fixed deployments and for deterministic testing.
  const staticIdentity = opts.staticIdentity || null;
  let netCache = { at: 0, identity: null, fp: null };
  let netInflight = null;
  async function getNetwork(force = false) {
    if (staticIdentity) {
      if (!netCache.identity) {
        netCache = { at: nowMs(), identity: staticIdentity, fp: netid.fingerprint(staticIdentity, opts.fingerprintOpts) };
      }
      return netCache;
    }
    if (!force && netCache.at && nowMs() - netCache.at < opts.netIdentTtlMs) return netCache;
    if (netInflight) return netInflight;
    netInflight = netid
      .computeNetIdentity({ run, platform, includeWifi: opts.includeWifi })
      .then((identity) => {
        const fp = netid.fingerprint(identity, opts.fingerprintOpts);
        netCache = { at: nowMs(), identity, fp };
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

  function issue(ip, mac, net) {
    return tokenMod.issueToken({ ip, mac, net }, secret, { ttlSeconds: opts.tokenTtlSeconds, now: nowMs });
  }

  function netInfo(net) {
    if (!net || !net.identity) return null;
    return { fingerprint: net.fp ? net.fp.hash : null, label: netid.networkLabel(net.identity) };
  }

  function verdict(allow, reason, detail, extra = {}) {
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
    };
  }

  async function verify(input = {}) {
    const clientIp = normalizeIp(input.ip);
    const token = input.token || null;

    if (!clientIp) {
      return verdict(false, 'no-client-ip', 'could not determine client IP');
    }

    // 1. explicit deny list
    if (opts.denyCidrs.length && ipInAnyCidr(clientIp, opts.denyCidrs)) {
      return verdict(false, 'denied-cidr', 'client IP is in the deny list', { ip: clientIp, via: 'deny' });
    }

    // 2. loopback (the host itself)
    if (opts.allowLoopback && isLoopback(clientIp)) {
      return verdict(true, 'loopback', 'request originated from host loopback', { ip: clientIp, via: 'loopback' });
    }

    // 3. explicit allow list (administrative bypass of ARP)
    if (opts.extraAllowCidrs.length && ipInAnyCidr(clientIp, opts.extraAllowCidrs)) {
      const net = await getNetwork().catch(() => null);
      const tok = issue(clientIp, null, net && net.fp ? net.fp.hash : null);
      return verdict(true, 'allowlisted-cidr', 'client IP is in the allow list', {
        ip: clientIp,
        via: 'allowlist',
        token: tok,
        network: netInfo(net),
      });
    }

    // network identity (cached) — needed for token-net compare and approval
    const net = await getNetwork().catch(() => null);
    const currentFp = net && net.fp ? net.fp.hash : null;

    // 4. session-token fast path
    if (token) {
      const tv = tokenMod.verifyToken(token, secret, { now: nowMs });
      if (tv.valid && tv.payload && tv.payload.ip === clientIp) {
        const netMatches = !tv.payload.net || !currentFp || tv.payload.net === currentFp;
        if (netMatches) {
          let macOk = true;
          let mac = tv.payload.mac;
          if (opts.revalidateArpWithToken) {
            const look = await arpCache.lookup(clientIp);
            if (!look.ok && opts.failClosed) {
              macOk = false;
            } else {
              const n = look.neighbor;
              macOk = !!(n && n.unicast && (!tv.payload.mac || n.mac === tv.payload.mac));
              if (n && n.mac) mac = n.mac;
            }
          }
          if (macOk) {
            const nowSec = Math.floor(nowMs() / 1000);
            const renewed =
              tv.payload.exp - nowSec < opts.renewWithinSeconds ? issue(clientIp, mac, currentFp || tv.payload.net) : null;
            return verdict(true, 'token', 'valid bound session token', {
              ip: clientIp,
              mac,
              via: 'token',
              token: renewed,
              network: netInfo(net),
              checks: { token: true },
            });
          }
        }
      }
      // otherwise fall through to live checks (and re-issue on success)
    }

    // 5. live checks
    const subnets = (net && net.identity && net.identity.subnets) || getLocalSubnets();
    const inSubnet = ipInAnyCidr(clientIp, subnets);

    const look = await arpCache.lookup(clientIp);
    const probeOk = look.ok;
    const neighbor = look.neighbor;
    const arpVerified = !!(neighbor && neighbor.unicast);
    const arpReason = arpVerified
      ? 'arp-verified'
      : neighbor && !neighbor.unicast
        ? 'incomplete-arp'
        : 'no-arp-entry';
    const mac = neighbor && neighbor.mac ? neighbor.mac : null;

    const checks = { subnet: inSubnet, arp: arpVerified, probeOk };

    if (opts.requireArp) {
      if (!probeOk && opts.failClosed) {
        return verdict(false, 'probe-failed', 'could not read the neighbor table (failing closed)', {
          ip: clientIp,
          mac,
          via: 'full-check',
          network: netInfo(net),
          checks,
        });
      }
      if (!arpVerified) {
        const detail =
          arpReason === 'incomplete-arp'
            ? 'client IP has only an unresolved/incomplete neighbor entry'
            : 'no resolved on-segment neighbor exists for the client IP';
        return verdict(false, arpReason, detail, {
          ip: clientIp,
          mac,
          via: 'full-check',
          network: netInfo(net),
          checks,
        });
      }
    } else if (opts.requireSubnet && !inSubnet) {
      return verdict(false, 'off-subnet', 'client IP is not within any local subnet', {
        ip: clientIp,
        mac,
        via: 'full-check',
        network: netInfo(net),
        checks,
      });
    }

    // 6. network approval (allow-list of approved networks)
    if (netid.hasAllowlist(opts.network)) {
      if (!net || !net.identity) {
        if (opts.failClosed) {
          return verdict(false, 'network-unknown', 'could not fingerprint the host network (failing closed)', {
            ip: clientIp,
            mac,
            via: 'full-check',
            checks,
          });
        }
      } else {
        const appr = netid.approveNetwork(net.identity, net.fp, opts.network);
        checks.network = appr.approved;
        if (!appr.approved) {
          return verdict(false, 'network-not-approved', 'the host network is not in the approved list', {
            ip: clientIp,
            mac,
            via: 'full-check',
            network: netInfo(net),
            checks,
          });
        }
      }
    }

    // 7. success
    const tok = issue(clientIp, mac, currentFp);
    return verdict(true, arpVerified ? 'arp-verified' : 'subnet-verified', 'client is on the same network segment', {
      ip: clientIp,
      mac,
      via: 'full-check',
      token: tok,
      network: netInfo(net),
      checks,
    });
  }

  // --- request helpers ----------------------------------------------------

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

  async function verifyRequest(req, reqOpts = {}) {
    const ip = extractClientIp(req, { trustForwardedHeader: !!reqOpts.trustForwardedHeader });
    const token = readToken(req, reqOpts.cookieName || 'hereonly', reqOpts.headerName || 'x-hereonly-token');
    return verify({ ip, token });
  }

  return {
    verify,
    verifyRequest,
    getNetwork,
    readToken,
    issueToken: issue,
    options: opts,
    host: os.hostname(),
    _arpCache: arpCache,
    _secret: secret,
  };
}

module.exports = { createVerifier, DEFAULTS };
