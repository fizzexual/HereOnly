'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');

const { createVerifier } = require('../../src/core/verifier.js');

const IDENTITY = {
  subnets: ['192.168.100.0/24'],
  gateway: { ip: '192.168.100.1', mac: '58:72:c9:41:36:94' },
  wifi: { ssid: null, bssid: null },
};

const ARP_ONSEG = `Interface: 192.168.100.2 --- 0x12
  192.168.100.1     58-72-c9-41-36-94   dynamic
  192.168.100.5     84-47-09-75-92-32   dynamic
  192.168.100.255   ff-ff-ff-ff-ff-ff   static`;

function makeEnv(initial = ARP_ONSEG) {
  const state = { arp: initial, arpOk: true };
  const run = async (file) => {
    if (file === 'arp') return { ok: state.arpOk, code: 0, stdout: state.arp, stderr: '', error: null };
    return { ok: true, code: 0, stdout: '', stderr: '', error: null }; // netsh ipv6 -> empty
  };
  return { state, run };
}

const SECRET = Buffer.from('test-secret-test-secret-test-sec', 'utf8');

function makeVerifier(extra = {}, env = makeEnv()) {
  let t = 1_700_000_000_000;
  const v = createVerifier({
    secret: SECRET,
    platform: 'win32',
    run: env.run,
    staticIdentity: IDENTITY,
    now: () => t,
    silent: true,
    arpTtlMs: 0,
    ownIps: ['10.9.9.9'], // pin a fake "own" address for deterministic self tests
    ...extra,
  });
  return { v, env, advance: (ms) => (t += ms) };
}

test('loopback and host-self are always allowed', async () => {
  const { v } = makeVerifier();
  assert.equal((await v.verify({ ip: '127.0.0.1' })).reason, 'loopback');
  const self = await v.verify({ ip: '10.9.9.9' }); // pinned own IP
  assert.equal(self.allow, true);
  assert.equal(self.reason, 'self');
  assert.equal(self.present, true);
});

test('CORE: on-segment client allowed + token; off-segment denied', async () => {
  const { v } = makeVerifier();
  const ok = await v.verify({ ip: '192.168.100.5' });
  assert.equal(ok.allow, true);
  assert.equal(ok.reason, 'arp-verified');
  assert.equal(ok.mac, '84:47:09:75:92:32');
  assert.equal(ok.present, true);
  assert.ok(ok.token);

  const off = await v.verify({ ip: '203.0.113.50' });
  assert.equal(off.allow, false);
  assert.equal(off.reason, 'no-arp-entry');
  assert.equal(off.present, false);
});

test('CORE: in-subnet without ARP still denied; broadcast denied', async () => {
  const { v } = makeVerifier();
  assert.equal((await v.verify({ ip: '192.168.100.77' })).reason, 'no-arp-entry');
  assert.equal((await v.verify({ ip: '192.168.100.255' })).reason, 'incomplete-arp');
});

test('token fast path, then stolen-token and device-left rejection', async () => {
  const { v, env, advance } = makeVerifier();
  const first = await v.verify({ ip: '192.168.100.5' });
  assert.equal((await v.verify({ ip: '192.168.100.5', token: first.token })).via, 'token');
  assert.equal((await v.verify({ ip: '192.168.100.6', token: first.token })).reason, 'no-arp-entry'); // stolen
  env.state.arp = `Interface: 192.168.100.2 --- 0x12\n  192.168.100.1  58-72-c9-41-36-94  dynamic`;
  advance(1000);
  assert.equal((await v.verify({ ip: '192.168.100.5', token: first.token })).reason, 'no-arp-entry'); // left
});

test('deny-list, allow-list, fail-closed', async () => {
  assert.equal((await makeVerifier({ denyCidrs: ['192.168.100.0/24'] }).v.verify({ ip: '192.168.100.5' })).reason, 'denied-cidr');
  const allow = await makeVerifier({ extraAllowCidrs: ['203.0.113.0/24'] }).v.verify({ ip: '203.0.113.9' });
  assert.equal(allow.reason, 'allowlisted-cidr');
  assert.equal(allow.present, false); // administrative bypass, not physically verified
  const env = makeEnv();
  env.state.arpOk = false;
  assert.equal((await makeVerifier({}, env).v.verify({ ip: '192.168.100.5' })).reason, 'probe-failed');
});

test('NEW: rate limiting throttles a flood from one client', async () => {
  const { v } = makeVerifier({ rateLimit: { capacity: 1, refillPerSec: 0 } });
  assert.equal((await v.verify({ ip: '192.168.100.5' })).allow, true); // 1st consumes the token
  const second = await v.verify({ ip: '192.168.100.5' });
  assert.equal(second.allow, false);
  assert.equal(second.reason, 'rate-limited');
  assert.ok(second.retryAfterMs >= 0);
});

test('NEW: every verdict is written to the audit log with presence', async () => {
  const { v } = makeVerifier({ audit: true });
  await v.verify({ ip: '192.168.100.5' }); // allow, present
  await v.verify({ ip: '203.0.113.50' }); // deny
  const entries = v.audit.tail();
  assert.equal(entries.length, 2);
  assert.equal(entries[0].verdict, 'allow');
  assert.equal(entries[0].present, true);
  assert.equal(entries[0].mac, '84:47:09:75:92:32');
  assert.equal(entries[1].verdict, 'deny');
  assert.equal(entries[1].present, false);
});

test('NEW: per-resource policy tightens /admin to an approved network', async () => {
  const wifiId = { ...IDENTITY, wifi: { ssid: 'HomeNet', bssid: null } };
  const { v } = makeVerifier({
    staticIdentity: wifiId,
    policies: [{ match: { path: '/admin' }, overrides: { network: { allowedSsids: ['OpsOnly'] } } }],
  });
  const base = { socket: { remoteAddress: '192.168.100.5' }, headers: { host: 'x' }, method: 'GET' };
  const open = await v.verifyRequest({ ...base, url: '/' });
  assert.equal(open.allow, true); // no policy on '/'
  const admin = await v.verifyRequest({ ...base, url: '/admin/panel' });
  assert.equal(admin.allow, false);
  assert.equal(admin.reason, 'network-not-approved'); // policy required OpsOnly SSID
});

test('network allow-list (global) denies a non-approved network even on-segment', async () => {
  const wifiId = { ...IDENTITY, wifi: { ssid: 'HomeNet', bssid: null } };
  const { v } = makeVerifier({ staticIdentity: wifiId, network: { allowedSsids: ['OfficeNet'] } });
  assert.equal((await v.verify({ ip: '192.168.100.5' })).reason, 'network-not-approved');
});
