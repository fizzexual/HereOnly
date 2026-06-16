'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');

const { createVerifier } = require('../../src/core/verifier.js');

// Fixed network identity so tests are independent of the host running them.
const IDENTITY = {
  subnets: ['192.168.100.0/24'],
  gateway: { ip: '192.168.100.1', mac: '58:72:c9:41:36:94' },
  wifi: { ssid: null, bssid: null },
};

// On-segment neighbors: .1 (gateway) and .5 (a client). .255 is broadcast.
const ARP_ONSEG = `Interface: 192.168.100.2 --- 0x12
  192.168.100.1     58-72-c9-41-36-94   dynamic
  192.168.100.5     84-47-09-75-92-32   dynamic
  192.168.100.255   ff-ff-ff-ff-ff-ff   static`;

// A mutable fake runner: arp output and ok-ness can be changed per test.
function makeEnv(initial = ARP_ONSEG) {
  const state = { arp: initial, arpOk: true };
  const run = async (file) => {
    if (file === 'arp') return { ok: state.arpOk, code: 0, stdout: state.arp, stderr: '', error: null };
    return { ok: false, code: 1, stdout: '', stderr: '', error: null };
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
    arpTtlMs: 0, // always re-read in tests (no stale cache between mutations)
    ...extra,
  });
  return { v, env, advance: (ms) => (t += ms), clock: () => t };
}

test('loopback is always allowed', async () => {
  const { v } = makeVerifier();
  assert.equal((await v.verify({ ip: '127.0.0.1' })).allow, true);
  assert.equal((await v.verify({ ip: '::1' })).allow, true);
});

test('CORE: on-segment client with a unicast ARP entry is allowed and gets a token', async () => {
  const { v } = makeVerifier();
  const res = await v.verify({ ip: '192.168.100.5' });
  assert.equal(res.allow, true);
  assert.equal(res.reason, 'arp-verified');
  assert.equal(res.mac, '84:47:09:75:92:32');
  assert.ok(res.token, 'a session token should be issued');
  assert.equal(res.checks.arp, true);
});

test('CORE: off-segment client (no neighbor entry) is denied — the key property', async () => {
  const { v } = makeVerifier();
  // A routable, public IP that reached the host from "outside": not a neighbor.
  const res = await v.verify({ ip: '203.0.113.50' });
  assert.equal(res.allow, false);
  assert.equal(res.reason, 'no-arp-entry');
  assert.equal(res.token, null);
});

test('CORE: in-subnet IP without an ARP entry is still denied (subnet ≠ proof)', async () => {
  const { v } = makeVerifier();
  const res = await v.verify({ ip: '192.168.100.77' }); // in 192.168.100.0/24 but not a neighbor
  assert.equal(res.allow, false);
  assert.equal(res.reason, 'no-arp-entry');
  assert.equal(res.checks.subnet, true); // subnet passed, but ARP is the gate
});

test('broadcast/incomplete neighbor (non-unicast) is denied', async () => {
  const { v } = makeVerifier();
  const res = await v.verify({ ip: '192.168.100.255' });
  assert.equal(res.allow, false);
  assert.equal(res.reason, 'incomplete-arp');
});

test('valid bound token takes the fast path', async () => {
  const { v } = makeVerifier();
  const first = await v.verify({ ip: '192.168.100.5' });
  const second = await v.verify({ ip: '192.168.100.5', token: first.token });
  assert.equal(second.allow, true);
  assert.equal(second.via, 'token');
});

test('stolen token presented from a different device is rejected', async () => {
  const { v } = makeVerifier();
  const issued = await v.verify({ ip: '192.168.100.5' });
  // .6 is NOT a neighbor; replaying .5's token from .6 must fail.
  const stolen = await v.verify({ ip: '192.168.100.6', token: issued.token });
  assert.equal(stolen.allow, false);
  assert.equal(stolen.reason, 'no-arp-entry');
});

test('token is useless once the device leaves the segment', async () => {
  const { v, env, advance } = makeVerifier();
  const issued = await v.verify({ ip: '192.168.100.5' });
  assert.equal(issued.allow, true);
  // Device .5 disconnects: it disappears from the neighbor table.
  env.state.arp = `Interface: 192.168.100.2 --- 0x12
  192.168.100.1   58-72-c9-41-36-94   dynamic`;
  advance(1000);
  const after = await v.verify({ ip: '192.168.100.5', token: issued.token });
  assert.equal(after.allow, false);
  assert.equal(after.reason, 'no-arp-entry');
});

test('deny-list wins over everything, including loopback ordering', async () => {
  const { v } = makeVerifier({ denyCidrs: ['192.168.100.0/24'] });
  const res = await v.verify({ ip: '192.168.100.5' });
  assert.equal(res.allow, false);
  assert.equal(res.reason, 'denied-cidr');
});

test('allow-list CIDR bypasses ARP (administrative escape hatch)', async () => {
  const { v } = makeVerifier({ extraAllowCidrs: ['203.0.113.0/24'] });
  const res = await v.verify({ ip: '203.0.113.9' });
  assert.equal(res.allow, true);
  assert.equal(res.reason, 'allowlisted-cidr');
  assert.ok(res.token);
});

test('fail-closed: when the neighbor table cannot be read, deny', async () => {
  const env = makeEnv();
  env.state.arpOk = false;
  const { v } = makeVerifier({}, env);
  const res = await v.verify({ ip: '192.168.100.5' });
  assert.equal(res.allow, false);
  assert.equal(res.reason, 'probe-failed');
});

test('network allow-list: approved SSID allows, other SSID denies even on-segment', async () => {
  const wifiIdentity = { ...IDENTITY, wifi: { ssid: 'HomeNet', bssid: null } };
  const okEnv = makeEnv();
  const allowed = createVerifier({
    secret: SECRET, platform: 'win32', run: okEnv.run, staticIdentity: wifiIdentity,
    now: () => 1_700_000_000_000, silent: true, arpTtlMs: 0,
    network: { allowedSsids: ['HomeNet'] },
  });
  assert.equal((await allowed.verify({ ip: '192.168.100.5' })).allow, true);

  const denied = createVerifier({
    secret: SECRET, platform: 'win32', run: okEnv.run, staticIdentity: wifiIdentity,
    now: () => 1_700_000_000_000, silent: true, arpTtlMs: 0,
    network: { allowedSsids: ['OfficeNet'] },
  });
  const res = await denied.verify({ ip: '192.168.100.5' });
  assert.equal(res.allow, false);
  assert.equal(res.reason, 'network-not-approved');
});

test('verifyRequest extracts client IP from the socket, not X-Forwarded-For', async () => {
  const { v } = makeVerifier();
  const req = {
    socket: { remoteAddress: '::ffff:192.168.100.5' },
    headers: { 'x-forwarded-for': '203.0.113.1' },
  };
  const res = await v.verifyRequest(req);
  assert.equal(res.allow, true);
  assert.equal(res.ip, '192.168.100.5');
});

test('verifyRequest reads a token from the cookie', async () => {
  const { v } = makeVerifier();
  const issued = await v.verify({ ip: '192.168.100.5' });
  const req = {
    socket: { remoteAddress: '192.168.100.5' },
    headers: { cookie: `foo=bar; hereonly=${encodeURIComponent(issued.token)}; baz=qux` },
  };
  const res = await v.verifyRequest(req);
  assert.equal(res.allow, true);
  assert.equal(res.via, 'token');
});

test('no client IP -> deny', async () => {
  const { v } = makeVerifier();
  const res = await v.verify({ ip: undefined });
  assert.equal(res.allow, false);
  assert.equal(res.reason, 'no-client-ip');
});
