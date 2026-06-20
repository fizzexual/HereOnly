#!/usr/bin/env node
'use strict';

/**
 * HereOnly CLI.
 *
 *   hereonly proxy  --target http://127.0.0.1:3000 --port 7000
 *   hereonly auth   --port 7001                 # forward-auth for nginx/Caddy/Traefik
 *   hereonly doctor                             # network identity + sample checks
 *   hereonly status                             # dashboard + audit summary
 *   hereonly check  192.168.1.42                # verify one IP (exit 0/1)
 *   hereonly audit  --tail 20 --denies          # query the physical-access log
 */

const path = require('node:path');
const { createVerifier } = require('../src/core/verifier.js');
const { createProxyServer } = require('../src/server/proxy.js');
const { createAuthServer } = require('../src/server/authserver.js');
const { createHub } = require('../src/hub');
const { createAudit, loadAuditFile } = require('../src/core/audit.js');
const fp = require('../src/core/fingerprint.js');
const { getOwnIps } = require('../src/os/self.js');
const { loadOrCreateSecret, readConfigFile, fromEnv, toArray } = require('../src/config.js');
const pkg = require('../package.json');

const DEFAULT_SECRET_FILE = '.hereonly/secret';
const DEFAULT_AUDIT_FILE = '.hereonly/audit.log';

function parseArgs(argv) {
  const args = { _: [] };
  const short = { t: 'target', p: 'port', h: 'help', v: 'version', c: 'config' };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a.startsWith('--')) {
      const key = a.slice(2);
      if (key.startsWith('no-')) {
        args[key.slice(3)] = false;
        continue;
      }
      const next = argv[i + 1];
      if (next === undefined || next.startsWith('-')) args[key] = true;
      else {
        if (args[key] === undefined) args[key] = next;
        else if (Array.isArray(args[key])) args[key].push(next);
        else args[key] = [args[key], next];
        i++;
      }
    } else if (a.startsWith('-') && a.length === 2) {
      const key = short[a[1]] || a[1];
      const next = argv[i + 1];
      if (next === undefined || next.startsWith('-')) args[key] = true;
      else {
        args[key] = next;
        i++;
      }
    } else args._.push(a);
  }
  return args;
}

function resolveSecret(args, fileCfg) {
  if (process.env.HEREONLY_SECRET) return process.env.HEREONLY_SECRET;
  if (fileCfg.secret) return fileCfg.secret;
  const file =
    args['secret-file'] || fileCfg.secretFile || fromEnv().secretFile || (args.persist === false ? null : DEFAULT_SECRET_FILE);
  return loadOrCreateSecret(file);
}

function buildOptions(args, fileCfg) {
  const network = {};
  const ssids = toArray(args['allow-ssid']);
  const gwMacs = toArray(args['allow-gw-mac']);
  const fps = toArray(args['allow-fingerprint']);
  if (ssids.length) network.allowedSsids = ssids;
  if (gwMacs.length) network.allowedGatewayMacs = gwMacs;
  if (fps.length) network.allowedFingerprints = fps;

  const secret = resolveSecret(args, fileCfg);

  const auditFile = args['audit-file'] || fileCfg.auditFile || fromEnv().auditFile || (args.audit ? DEFAULT_AUDIT_FILE : null);
  const signAudit = !!(args['sign-audit'] || fileCfg.signAudit);
  const audit = auditFile || signAudit || args.audit ? { file: auditFile, sign: signAudit } : null;

  let rateLimit = fileCfg.rateLimit || null;
  if (args['rate-limit']) {
    rateLimit = { capacity: Number(args['rate-capacity']) || 60, refillPerSec: Number(args['rate-refill']) || 30 };
  }

  return {
    secret,
    requireArp: args['require-arp'] === false ? false : fileCfg.requireArp !== false,
    includeWifi: args.wifi === false ? false : fileCfg.includeWifi !== false,
    failClosed: args['fail-open'] ? false : fileCfg.failClosed !== false,
    tokenTtlSeconds: args.ttl ? Number(args.ttl) : fileCfg.tokenTtlSeconds || 1800,
    extraAllowCidrs: toArray(args['allow-cidr']).concat(fileCfg.extraAllowCidrs || []),
    denyCidrs: toArray(args['deny-cidr']).concat(fileCfg.denyCidrs || []),
    network: Object.keys(network).length ? network : fileCfg.network || {},
    policies: fileCfg.policies || [],
    rateLimit,
    audit,
    logLevel: args['log-level'] || fileCfg.logLevel || 'info',
  };
}

function fmtVerdict(r) {
  let line = `${r.allow ? 'ALLOW' : 'DENY '}  ${(r.ip || '?').padEnd(22)} ${r.reason}`;
  if (r.mac) line += `  mac=${r.mac}`;
  if (r.present) line += '  [present]';
  if (r.network && r.network.label) line += `  net=${r.network.label}`;
  return line;
}

async function cmdProxy(args, fileCfg) {
  const target = args.target || fileCfg.target || fromEnv().target;
  if (!target) {
    console.error('error: --target is required (e.g. --target http://127.0.0.1:3000)');
    process.exit(2);
  }
  const port = Number(args.port || fileCfg.port || fromEnv().port || 7000);
  const host = args.host || fileCfg.host || fromEnv().host || '0.0.0.0';
  const opts = buildOptions(args, fileCfg);
  const verifier = createVerifier(opts);
  const server = createProxyServer({ target, verifier, logLevel: opts.logLevel, trustForwardedHeader: !!args['trust-forwarded'] });
  const net = await verifier.getNetwork().catch(() => null);
  server.listen(port, host, () => {
    console.log(`\n  HereOnly v${pkg.version}  -  subnet-locked reverse proxy`);
    console.log('  ' + '-'.repeat(48));
    console.log(`  listening : http://${host}:${port}`);
    console.log(`  forwarding: ${target}`);
    if (net && net.identity) console.log(`  network   : ${fp.networkLabel(net.identity)}  (fp ${net.fp.hash})`);
    console.log(
      `  policy    : requireArp=${opts.requireArp} failClosed=${opts.failClosed}` +
        (opts.rateLimit ? ' rateLimit=on' : '') +
        (opts.audit ? ` audit=${opts.audit.file || 'memory'}${opts.audit.sign ? '(signed)' : ''}` : ''),
    );
    console.log('  Only devices on this physical network segment can reach the target.\n');
  });
  server.on('error', (err) => {
    console.error(`error: ${err.message}`);
    process.exit(1);
  });
}

async function cmdAuth(args, fileCfg) {
  const port = Number(args.port || fileCfg.port || 7001);
  const host = args.host || fileCfg.host || '127.0.0.1';
  const opts = buildOptions(args, fileCfg);
  const verifier = createVerifier(opts);
  const trustedProxies = toArray(args['trusted-proxy']).concat(fileCfg.trustedProxies || []);
  const server = createAuthServer({ verifier, logLevel: opts.logLevel, trustedProxies });
  server.listen(port, host, () => {
    console.log(`\n  HereOnly v${pkg.version}  -  forward-auth server`);
    console.log('  ' + '-'.repeat(48));
    console.log(`  listening : http://${host}:${port}   (point auth_request / forward_auth here)`);
    console.log(`  trusts    : loopback${trustedProxies.length ? ', ' + trustedProxies.join(', ') : ''} for X-Real-IP`);
    console.log(`  returns   : 204 allow / 403 deny  + X-HereOnly-* headers`);
    console.log('  See integrations/ for nginx, Caddy, and Traefik snippets.\n');
  });
  server.on('error', (err) => {
    console.error(`error: ${err.message}`);
    process.exit(1);
  });
}

async function cmdDoctor(args, fileCfg) {
  const verifier = createVerifier({ ...buildOptions(args, fileCfg), silent: true });
  const net = await verifier.getNetwork();
  console.log(`\nHereOnly doctor v${pkg.version}  (host ${verifier.host})`);
  console.log('-'.repeat(52));
  if (net.identity) {
    console.log('subnets    :', net.identity.subnets.join(', ') || '(none)');
    console.log('gateway    :', net.identity.gateway.ip || '(none)', net.identity.gateway.mac ? `(${net.identity.gateway.mac})` : '');
    console.log('wifi       :', net.identity.wifi.ssid || '(no wifi / wired)', net.identity.wifi.bssid || '');
    console.log('fingerprint:', net.fp.hash);
  }
  console.log('\nsample verifications:');
  const samples = ['127.0.0.1'];
  if (net.identity && net.identity.gateway.ip) samples.push(net.identity.gateway.ip);
  samples.push('8.8.8.8');
  for (const ip of samples) console.log('  ' + fmtVerdict(await verifier.verify({ ip })));
  console.log('');
}

async function cmdStatus(args, fileCfg) {
  const opts = buildOptions(args, fileCfg);
  const verifier = createVerifier({ ...opts, silent: true });
  const net = await verifier.getNetwork();
  const own = [...getOwnIps()];
  console.log(`\nHereOnly status v${pkg.version}  (host ${verifier.host})`);
  console.log('-'.repeat(52));
  if (net.identity) {
    console.log('network    :', fp.networkLabel(net.identity), `(fp ${net.fp.hash})`);
    console.log('subnets    :', net.identity.subnets.join(', ') || '(none)');
    console.log('gateway    :', net.identity.gateway.ip || '(none)', net.identity.gateway.mac || '');
  }
  console.log('own IPs    :', own.length, 'addresses');
  console.log('policy     :', `requireArp=${opts.requireArp} failClosed=${opts.failClosed}`, opts.rateLimit ? 'rateLimit=on' : '');
  const allow = fp.hasAllowlist(opts.network) ? JSON.stringify(opts.network) : '(any local network)';
  console.log('allow-list :', allow);

  const auditFile = args['audit-file'] || fileCfg.auditFile || DEFAULT_AUDIT_FILE;
  const entries = loadAuditFile(auditFile);
  if (entries.length) {
    const denies = entries.filter((e) => e.verdict === 'deny').length;
    console.log(`\naudit (${path.resolve(auditFile)}): ${entries.length} entries, ${denies} denies`);
    for (const e of entries.slice(-5)) {
      console.log(`  ${new Date(e.ts).toISOString()}  ${e.verdict.toUpperCase().padEnd(5)} ${(e.ip || '?').padEnd(18)} ${e.mac || ''} ${e.reason}`);
    }
  } else {
    console.log('\naudit      : no log file at', auditFile, '(enable with --audit / --audit-file)');
  }
  console.log('');
}

async function cmdCheck(args, fileCfg) {
  const ip = args._[1];
  if (!ip) {
    console.error('error: usage: hereonly check <ip>');
    process.exit(2);
  }
  const verifier = createVerifier({ ...buildOptions(args, fileCfg), silent: true });
  const r = await verifier.verify({ ip });
  console.log(fmtVerdict(r));
  process.exit(r.allow ? 0 : 1);
}

function cmdAudit(args, fileCfg) {
  const file = args.file || args['audit-file'] || fileCfg.auditFile || DEFAULT_AUDIT_FILE;
  const entries = loadAuditFile(file);
  if (!entries.length) {
    console.error(`no audit entries at ${path.resolve(file)}`);
    process.exit(1);
  }
  if (args.verify) {
    if (entries[0].hash === undefined) {
      console.log('log is not signed (no hash chain to verify)');
      return;
    }
    const secret = resolveSecret(args, fileCfg);
    const a = createAudit({ sign: true, secret });
    const res = a.verifyChain(entries);
    console.log(res.ok ? `chain OK: ${entries.length} entries intact` : `CHAIN BROKEN at seq ${res.brokenAt} (${res.reason})`);
    process.exit(res.ok ? 0 : 1);
  }
  let rows = entries;
  if (args.denies) rows = rows.filter((e) => e.verdict === 'deny');
  if (args.mac) rows = rows.filter((e) => (e.mac || '').toLowerCase() === String(args.mac).toLowerCase());
  const n = Number(args.tail) || 50;
  for (const e of rows.slice(-n)) {
    console.log(
      `${new Date(e.ts).toISOString()}  ${e.verdict.toUpperCase().padEnd(5)} ${(e.ip || '?').padEnd(18)} ${(e.mac || '-').padEnd(17)} ${e.present ? 'present' : '       '} ${e.reason}  ${e.resource || ''}`,
    );
  }
}

async function cmdHub(args, fileCfg) {
  const port = Number(args.port || fileCfg.port || 7080);
  const host = args.host || fileCfg.host || '0.0.0.0';
  const opts = buildOptions(args, fileCfg);
  const verifier = createVerifier(opts);
  const hub = createHub({
    verifier,
    name: args.name || fileCfg.name,
    port,
    scan: args.scan === false ? false : fileCfg.scan !== false,
    services: toArray(args.service).concat(fileCfg.services || []),
    hubSecret: args['hub-secret'] || fileCfg.hubSecret || process.env.HEREONLY_HUB_SECRET || null,
    addrRange: args['addr-range'] || fileCfg.addrRange,
    group: args.group || fileCfg.group,
    mcastPort: args['mcast-port'] ? Number(args['mcast-port']) : fileCfg.mcastPort,
    logLevel: opts.logLevel,
    trustForwardedHeader: !!args['trust-forwarded'],
  });
  await hub.start(port, host);
  const svc = hub.self.services();
  console.log(`\n  HereOnly v${pkg.version}  -  segment hub`);
  console.log('  ' + '-'.repeat(48));
  console.log(`  dashboard : http://${host}:${port}   (open from any on-segment device)`);
  console.log(`  identity  : ${hub.identity.name}  ->  ${hub.identity.addr}   (stable, in ${hub.identity.range})`);
  console.log(`  this host : ${hub.self.host}  ${hub.ownAddrs().join(', ')}`);
  console.log(`  services  : ${svc.length ? svc.map((s) => s.name + ':' + s.port).join(', ') : '(none detected; advertise with --service name=port)'}`);
  console.log(`  discovery : multicast, segment-scoped (TTL 1)${args['hub-secret'] || process.env.HEREONLY_HUB_SECRET ? ', signed' : ''}`);
  console.log('  Peers running `hereonly hub` on this segment appear automatically.\n');
}

function printHelp() {
  console.log(`HereOnly v${pkg.version} - make your LAN a vault

USAGE
  hereonly <command> [options]

COMMANDS
  proxy        Reverse proxy that gates a local server to this segment
  auth         Forward-auth server for nginx / Caddy / Traefik
  hub          Zero-config directory: auto-discover every device + service on
               this segment and show them to every on-segment device
  doctor       Print network identity + sample verifications
  status       Dashboard: identity, policy, and audit summary
  check <ip>   Verify a single IP (exit 0=allow, 1=deny)
  audit        Query the physical-access audit log (--tail, --denies, --verify)

COMMON OPTIONS
  -t, --target <url>        proxy: local server to protect
  -p, --port <n>            listen port (proxy 7000, auth 7001)
      --host <addr>         bind address (proxy 0.0.0.0, auth 127.0.0.1)
      --allow-ssid <ssid>   pin to an approved Wi-Fi SSID (repeatable)
      --allow-gw-mac <mac>  pin to an approved gateway MAC (repeatable)
      --allow-cidr <cidr>   always allow / --deny-cidr always deny (repeatable)
      --rate-limit          throttle abusive clients (token bucket)
      --audit [--audit-file <path>] [--sign-audit]   physical-access log
      --secret-file <path>  persist token secret (default .hereonly/secret)
      --no-require-arp      subnet-only mode (weaker)
      --trusted-proxy <cidr>  auth: extra proxies allowed to set X-Real-IP
      --trust-forwarded     proxy: trust X-Forwarded-For (only behind a proxy)
      --log-level <lvl>     silent|error|warn|info|debug
  -c, --config <path>       load options from a JSON config file

HUB OPTIONS
      --service <name=port> advertise a service (repeatable)
      --no-scan             don't auto-detect this host's listening HTTP ports
      --hub-secret <s>      only machines sharing this secret form the hub
      --name <label>        display name for this machine
      --addr-range <r>      device address space: class-e (default, 240.0.0.0/8),
                            cgnat (100.64.0.0/10), ula (secret-derived fd..::/48),
                            or a custom CIDR. ula needs --hub-secret to stay private

EXAMPLES
  hereonly hub                                  # open http://<this-host>:7080
  hereonly hub --service grafana=3000 --service nas=5000
  hereonly proxy -t http://127.0.0.1:3000 -p 7000 --audit --sign-audit
  hereonly auth -p 7001 --allow-ssid HomeNet
`);
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.version || args._[0] === 'version') {
    console.log(pkg.version);
    return;
  }
  const fileCfg = readConfigFile(args.config);
  const cmd = args._[0];
  if (!cmd || args.help || cmd === 'help') return printHelp();
  switch (cmd) {
    case 'proxy':
      return cmdProxy(args, fileCfg);
    case 'auth':
      return cmdAuth(args, fileCfg);
    case 'hub':
      return cmdHub(args, fileCfg);
    case 'doctor':
      return cmdDoctor(args, fileCfg);
    case 'status':
      return cmdStatus(args, fileCfg);
    case 'check':
      return cmdCheck(args, fileCfg);
    case 'audit':
      return cmdAudit(args, fileCfg);
    default:
      console.error(`error: unknown command '${cmd}'\n`);
      printHelp();
      process.exit(2);
  }
}

main().catch((err) => {
  console.error('fatal:', err && err.stack ? err.stack : err);
  process.exit(1);
});
