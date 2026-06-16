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

const WIN_ROUTE = `Active Routes:
Network Destination        Netmask          Gateway       Interface  Metric
          0.0.0.0          0.0.0.0    192.168.100.1    192.168.100.2     25
          0.0.0.0          0.0.0.0  192.168.100.254    192.168.100.2     55
        224.0.0.0        240.0.0.0         On-link         127.0.0.1    331`;

const WIN_ARP_GW = `Interface: 192.168.100.2 --- 0x12
  192.168.100.1   58-72-c9-41-36-94   dynamic`;

function fakeRun(map) {
  return async (file, args = []) => {
    const key = [file, ...args].join(' ');
    const r = map[key] !== undefined ? map[key] : map['*'];
    if (!r) return { ok: false, code: 1, stdout: '', stderr: '', error: null };
    return { ok: r.ok !== false, code: 0, stdout: r.stdout || '', stderr: '', error: null };
  };
}

test('gateway parsers (win lowest-metric/skip On-link, linux, mac)', () => {
  assert.equal(parseWindowsGateway(WIN_ROUTE), '192.168.100.1');
  assert.equal(parseLinuxGateway('default via 192.168.1.1 dev eth0 metric 100'), '192.168.1.1');
  assert.equal(parseMacGateway('   gateway: 192.168.1.1\n  interface: en0'), '192.168.1.1');
});

test('getGateway resolves IP + MAC from the neighbor table (win32)', async () => {
  const run = fakeRun({
    'route print -4': { stdout: WIN_ROUTE },
    'arp -a': { stdout: WIN_ARP_GW },
    'netsh interface ipv6 show neighbors': { stdout: '' },
  });
  const gw = await getGateway({ platform: 'win32', run });
  assert.equal(gw.ip, '192.168.100.1');
  assert.equal(gw.mac, '58:72:c9:41:36:94');
});

test('getDefaultGateway dispatch (linux/mac)', async () => {
  assert.equal(
    await getDefaultGateway({ platform: 'linux', run: fakeRun({ 'ip route show default': { stdout: 'default via 10.0.0.1 dev eth0' } }) }),
    '10.0.0.1',
  );
  assert.equal(
    await getDefaultGateway({ platform: 'darwin', run: fakeRun({ 'route -n get default': { stdout: 'gateway: 10.0.0.1' } }) }),
    '10.0.0.1',
  );
});

test('canonicalizeCidr zeroes host bits (v4 + v6)', () => {
  assert.equal(canonicalizeCidr('192.168.100.2/24'), '192.168.100.0/24');
  assert.equal(canonicalizeCidr('172.26.192.1/20'), '172.26.192.0/20');
  assert.equal(canonicalizeCidr('2a00:4804:b000:6ce0:ccb5:1dda:3e91:4e99/64'), '2a00:4804:b000:6ce0::/64');
  assert.equal(canonicalizeCidr('fe80::abcd/10'), 'fe80::/10');
});

test('isLinkLocalAddr', () => {
  assert.equal(isLinkLocalAddr('169.254.1.1'), true);
  assert.equal(isLinkLocalAddr('fe80::1'), true);
  assert.equal(isLinkLocalAddr('192.168.1.1'), false);
});

test('real host: getInterfaces/getLocalSubnets are well-formed', () => {
  assert.ok(Array.isArray(getInterfaces()));
  for (const s of getLocalSubnets()) {
    assert.ok(!s.endsWith('/32') && !s.endsWith('/128'), `host route leaked: ${s}`);
    assert.ok(!s.startsWith('169.254.'), `link-local leaked: ${s}`);
  }
});
