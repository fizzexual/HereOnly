#!/usr/bin/env node
'use strict';

/**
 * HereOnly CLI.
 *
 *   hereonly proxy --target http://127.0.0.1:3000 --port 7000
 *   hereonly doctor
 *   hereonly check 192.168.1.42
 */

const { createVerifier } = require('../src/core/verifier.js');
const { createProxyServer } = require('../src/proxy/server.js');
const { loadOrCreateSecret, readConfigFile, fromEnv, toArray } = require('../src/config.js');
const netid = require('../src/core/netident.js');
const pkg = require('../package.json');

// ---- tiny arg parser ------------------------------------------------------
function parseArgs(argv) {
  const args = { _: [] };
  const short = { t: 'target', p: 'port', h: 'help', v: 'version', c: 'config' };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a.startsWith('--')) {
      let key = a.slice(2);
      if (key.startsWith('no-')) {
        args[key.slice(3)] = false;
        continue;
      }
      const next = argv[i + 1];
      if (next === undefined || next.startsWith('-')) {
        args[key] = true;
      } else {
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
    } else {
      args._.push(a);
    }
  }
  return args;
}

function buildVerifierOptions(args, fileCfg) {
  const network = {};
  const allowedSsids = toArray(args['allow-ssid']);
  const allowedGatewayMacs = toArray(args['allow-gw-mac']);
  const allowedFingerprints = toArray(args['allow-fingerprint']);
  if (allowedSsids.length) network.allowedSsids = allowedSsids;
  if (allowedGatewayMacs.length) network.allowedGatewayMacs = allowedGatewayMacs;
  if (allowedFingerprints.length) network.allowedFingerprints = allowedFingerprints;

  const opts = {
    requireArp: args['require-arp'] === false ? false : fileCfg.requireArp !== false,
    includeWifi: args.wifi === false ? false : fileCfg.includeWifi !== false,
    failClosed: args['fail-open'] ? false : fileCfg.failClosed !== false,
    tokenTtlSeconds: args.ttl ? Number(args.ttl) : fileCfg.tokenTtlSeconds || 1800,
    extraAllowCidrs: toArray(args['allow-cidr']).concat(fileCfg.extraAllowCidrs || []),
    denyCidrs: toArray(args['deny-cidr']).concat(fileCfg.denyCidrs || []),
    network: Object.keys(network).length ? network : fileCfg.network || {},
    logLevel: args['log-level'] || fileCfg.logLevel || 'info',
  };
  const secretFile = args['secret-file'] || fileCfg.secretFile || (fromEnv().secretFile);
  opts.secret = process.env.HEREONLY_SECRET || fileCfg.secret || loadOrCreateSecret(secretFile);
  return opts;
}

function fmtVerdict(r) {
  const tag = r.allow ? 'ALLOW' : 'DENY ';
  let line = `${tag}  ${(r.ip || '?').padEnd(20)} ${r.reason}`;
  if (r.mac) line += `  mac=${r.mac}`;
  if (r.network && r.network.label) line += `  net=${r.network.label}`;
  return line;
}

// ---- commands -------------------------------------------------------------

async function cmdProxy(args, fileCfg) {
  const target = args.target || fileCfg.target || fromEnv().target;
  if (!target) {
    console.error('error: --target is required (e.g. --target http://127.0.0.1:3000)');
    process.exit(2);
  }
  const port = Number(args.port || fileCfg.port || fromEnv().port || 7000);
  const host = args.host || fileCfg.host || fromEnv().host || '0.0.0.0';
  const opts = buildVerifierOptions(args, fileCfg);
  const verifier = createVerifier(opts);
  const server = createProxyServer({
    target,
    verifier,
    logLevel: opts.logLevel,
    trustForwardedHeader: !!args['trust-forwarded'],
  });

  const net = await verifier.getNetwork().catch(() => null);
  server.listen(port, host, () => {
    console.log(`\n  HereOnly v${pkg.version}  ·  subnet-locked reverse proxy`);
    console.log(`  ───────────────────────────────────────────────`);
    console.log(`  listening : http://${host}:${port}`);
    console.log(`  forwarding: ${target}`);
    if (net && net.identity) {
      console.log(`  network   : ${netid.networkLabel(net.identity)}  (fingerprint ${net.fp.hash})`);
      console.log(`  subnets   : ${net.identity.subnets.join(', ') || '(none)'}`);
    }
    console.log(`  policy    : requireArp=${opts.requireArp} failClosed=${opts.failClosed}` +
      (opts.network && Object.keys(opts.network).length ? ` network-allowlist=on` : ''));
    console.log(`  Only devices on this physical network segment can reach the target.\n`);
  });
  server.on('error', (err) => {
    console.error(`error: ${err.message}`);
    process.exit(1);
  });
}

async function cmdDoctor(args, fileCfg) {
  const opts = buildVerifierOptions(args, fileCfg);
  const verifier = createVerifier({ ...opts, silent: true });
  const net = await verifier.getNetwork();
  console.log(`\nHereOnly doctor · v${pkg.version}  (host ${verifier.host})`);
  console.log('─'.repeat(52));
  if (net.identity) {
    console.log('subnets    :', net.identity.subnets.join(', ') || '(none)');
    console.log('gateway    :', net.identity.gateway.ip || '(none)', net.identity.gateway.mac ? `(${net.identity.gateway.mac})` : '');
    console.log('wifi       :', net.identity.wifi.ssid || '(no wifi / wired)', net.identity.wifi.bssid || '');
    console.log('fingerprint:', net.fp.hash);
  } else {
    console.log('could not determine network identity');
  }
  console.log('\nsample verifications:');
  const samples = ['127.0.0.1'];
  if (net.identity && net.identity.gateway.ip) samples.push(net.identity.gateway.ip);
  samples.push('8.8.8.8');
  for (const ip of samples) {
    console.log('  ' + fmtVerdict(await verifier.verify({ ip })));
  }
  console.log('');
}

async function cmdCheck(args, fileCfg) {
  const ip = args._[1];
  if (!ip) {
    console.error('error: usage: hereonly check <ip>');
    process.exit(2);
  }
  const opts = buildVerifierOptions(args, fileCfg);
  const verifier = createVerifier({ ...opts, silent: true });
  const r = await verifier.verify({ ip });
  console.log(fmtVerdict(r));
  process.exit(r.allow ? 0 : 1);
}

function printHelp() {
  console.log(`HereOnly v${pkg.version} — subnet-locked access control for local web servers

USAGE
  hereonly <command> [options]

COMMANDS
  proxy        Run a reverse proxy that gates a local server to this segment
  doctor       Print network identity + sample verifications
  check <ip>   Verify a single IP and print the verdict (exit 0=allow, 1=deny)
  help         Show this help
  version      Print version

PROXY OPTIONS
  -t, --target <url>        Local server to protect  (e.g. http://127.0.0.1:3000)
  -p, --port <n>            Port to listen on         (default 7000)
      --host <addr>         Address to bind           (default 0.0.0.0)
      --no-require-arp      Use subnet-only mode (weaker; for no-ARP hosts)
      --no-wifi             Skip Wi-Fi SSID fingerprinting
      --fail-open           Allow when the neighbor table can't be read (unsafe)
      --ttl <seconds>       Session token lifetime    (default 1800)
      --allow-cidr <cidr>   Always allow a CIDR (repeatable)
      --deny-cidr <cidr>    Always deny a CIDR (repeatable)
      --allow-ssid <ssid>   Pin to approved Wi-Fi SSID (repeatable)
      --allow-gw-mac <mac>  Pin to approved gateway MAC (repeatable)
      --secret-file <path>  Persist the token secret across restarts
      --trust-forwarded     Trust X-Forwarded-For (ONLY behind a trusted proxy)
      --log-level <lvl>     silent|error|warn|info|debug   (default info)
  -c, --config <path>       Load options from a JSON config file

EXAMPLES
  hereonly proxy -t http://127.0.0.1:3000 -p 7000
  hereonly proxy -t http://127.0.0.1:8080 --allow-ssid HomeNet --secret-file ./.hereonly/secret
  hereonly doctor
  hereonly check 192.168.1.42
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
    case 'doctor':
      return cmdDoctor(args, fileCfg);
    case 'check':
      return cmdCheck(args, fileCfg);
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
