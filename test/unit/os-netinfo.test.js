'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');

const {
  getInterfaces,
  getLocalSubnets,
  getDefaultGateway,
  getGateway,
  canonicalizeCidr,
  isLinkLocalAddr,
  parseWindowsGateway,
  parseLinuxGateway,
  parseMacGateway,
} = require('../../src/os/netinfo.js');

// Real-shaped `route print -4` Active Routes, with two defaults (pick min metric).
const WIN_ROUTE = `===========================================================================
Active Routes:
Network Destination        Netmask          Gateway       Interface  Metric
          0.0.0.0          0.0.0.0    192.168.100.1    192.168.100.2     25
          0.0.0.0          0.0.0.0  192.168.100.254    192.168.100.2     55
        224.0.0.0        240.0.0.0         On-link         127.0.0.1    331
===========================================================================`;

const LINUX_ROUTE = `default via 192.168.1.1 dev eth0 proto dhcp src 192.168.1.50 metric 100`;

const MAC_ROUTE = `   route to: default
destination: default
       mask: default
    gateway: 192.168.1.1
  interface: en0
      flags: <UP,GATEWAY,DONE,STATIC>`;

const WIN_ARP_GW = `
Interface: 192.168.100.2 --- 0x12
  Internet Address      Physical Address      Type
  192.168.100.1         58-72-c9-41-36-94     dynamic
`;

function fakeRun(map) {
  return async (file, args = []) => {
    const key = [file, ...args].join(' ');
    const r = map[key] !== undefined ? map[key] : map['*'];
    if (!r) return { ok: false, code: 1, stdout: '', stderr: 'no mock', error: new Error('no mock') };
    return { ok: r.ok !== false, code: r.code || 0, stdout: r.stdout || '', stderr: r.stderr || '', error: null };
  };
}

test('parseWindowsGateway: picks lowest-metric default, skips On-link', () => {
  assert.equal(parseWindowsGateway(WIN_ROUTE), '192.168.100.1');
});

test('parseLinuxGateway / parseMacGateway', () => {
  assert.equal(parseLinuxGateway(LINUX_ROUTE), '192.168.1.1');
  assert.equal(parseMacGateway(MAC_ROUTE), '192.168.1.1');
  assert.equal(parseLinuxGateway('no default here'), null);
});

test('getDefaultGateway: dispatch', async () => {
  assert.equal(
    await getDefaultGateway({ platform: 'win32', run: fakeRun({ 'route print -4': { stdout: WIN_ROUTE } }) }),
    '192.168.100.1',
  );
  assert.equal(
    await getDefaultGateway({ platform: 'linux', run: fakeRun({ 'ip route show default': { stdout: LINUX_ROUTE } }) }),
    '192.168.1.1',
  );
  assert.equal(
    await getDefaultGateway({ platform: 'darwin', run: fakeRun({ 'route -n get default': { stdout: MAC_ROUTE } }) }),
    '192.168.1.1',
  );
});

test('getGateway: resolves gateway IP and its MAC from the neighbor table', async () => {
  const run = fakeRun({
    'route print -4': { stdout: WIN_ROUTE },
    'arp -a': { stdout: WIN_ARP_GW },
  });
  const gw = await getGateway({ platform: 'win32', run });
  assert.equal(gw.ip, '192.168.100.1');
  assert.equal(gw.mac, '58:72:c9:41:36:94');
});

test('getGateway: null gateway yields null mac', async () => {
  const run = fakeRun({ 'route print -4': { stdout: 'no routes' } });
  const gw = await getGateway({ platform: 'win32', run });
  assert.deepEqual(gw, { ip: null, mac: null });
});

test('canonicalizeCidr: zeroes host bits (v4 and v6)', () => {
  assert.equal(canonicalizeCidr('192.168.100.2/24'), '192.168.100.0/24');
  assert.equal(canonicalizeCidr('10.1.2.3/8'), '10.0.0.0/8');
  assert.equal(canonicalizeCidr('172.26.192.1/20'), '172.26.192.0/20');
  assert.equal(canonicalizeCidr('2a00:4804:b000:6ce0:ccb5:1dda:3e91:4e99/64'), '2a00:4804:b000:6ce0::/64');
  assert.equal(canonicalizeCidr('fe80::abcd/10'), 'fe80::/10');
});

test('isLinkLocalAddr', () => {
  assert.equal(isLinkLocalAddr('169.254.1.1'), true);
  assert.equal(isLinkLocalAddr('fe80::1'), true);
  assert.equal(isLinkLocalAddr('192.168.1.1'), false);
});

// Real-environment sanity (host-agnostic): these must not throw and must
// return well-formed data on whatever machine runs the suite.
test('getInterfaces (real): returns normalized entries', () => {
  const ifaces = getInterfaces();
  assert.ok(Array.isArray(ifaces));
  for (const i of ifaces) {
    assert.ok(typeof i.name === 'string');
    assert.ok(i.family === 4 || i.family === 6 || i.family === 0);
  }
});

test('getLocalSubnets (real): excludes host routes and link-local by default', () => {
  const subnets = getLocalSubnets();
  assert.ok(Array.isArray(subnets));
  for (const s of subnets) {
    assert.ok(!s.endsWith('/32'), `unexpected host route ${s}`);
    assert.ok(!s.endsWith('/128'), `unexpected host route ${s}`);
    assert.ok(!s.startsWith('169.254.'), `unexpected link-local ${s}`);
  }
});
