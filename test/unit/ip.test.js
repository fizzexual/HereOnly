'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');

const {
  normalizeIp,
  ipFamily,
  ipToBigInt,
  cidrContains,
  ipInAnyCidr,
  isLoopback,
  isPrivateIp,
  normalizeMac,
  isUnicastMac,
  extractClientIp,
} = require('../../src/core/ip.js');

test('normalizeIp: trims, lowercases, strips brackets and zone id', () => {
  assert.equal(normalizeIp('  192.168.1.5 '), '192.168.1.5');
  assert.equal(normalizeIp('[::1]'), '::1');
  assert.equal(normalizeIp('FE80::1%eth0'), 'fe80::1');
  assert.equal(normalizeIp('2001:DB8::AB'), '2001:db8::ab');
});

test('normalizeIp: unwraps IPv4-mapped IPv6 (dotted and hex forms)', () => {
  assert.equal(normalizeIp('::ffff:192.168.1.5'), '192.168.1.5');
  assert.equal(normalizeIp('::ffff:127.0.0.1'), '127.0.0.1');
  assert.equal(normalizeIp('::ffff:c0a8:0105'), '192.168.1.5');
});

test('normalizeIp: rejects non-string / empty', () => {
  assert.equal(normalizeIp(null), null);
  assert.equal(normalizeIp(undefined), null);
  assert.equal(normalizeIp(123), null);
  assert.equal(normalizeIp('   '), null);
});

test('ipFamily classifies correctly', () => {
  assert.equal(ipFamily('192.168.1.1'), 4);
  assert.equal(ipFamily('::ffff:192.168.1.1'), 4); // unwrapped
  assert.equal(ipFamily('fe80::1'), 6);
  assert.equal(ipFamily('::1'), 6);
  assert.equal(ipFamily('not-an-ip'), 0);
  assert.equal(ipFamily('999.1.1.1'), 0);
});

test('ipToBigInt: IPv4 boundaries', () => {
  assert.equal(ipToBigInt('0.0.0.0'), 0n);
  assert.equal(ipToBigInt('255.255.255.255'), 4294967295n);
  assert.equal(ipToBigInt('192.168.1.1'), 3232235777n);
  assert.equal(ipToBigInt('1.2.3.999'), null);
});

test('ipToBigInt: IPv6 including :: compression and embedded v4', () => {
  assert.equal(ipToBigInt('::'), 0n);
  assert.equal(ipToBigInt('::1'), 1n);
  assert.equal(ipToBigInt('fe80::1'), 0xfe80n << 112n | 1n);
  // 2001:db8:: -> top 32 bits set
  assert.equal(ipToBigInt('2001:db8::'), 0x20010db8n << 96n);
  // embedded v4 maps to low 32 bits: 64:ff9b::192.0.2.33
  // -> 0064:ff9b:0000:0000:0000:0000:c000:0221
  assert.equal(ipToBigInt('64:ff9b::192.0.2.33'),
    0x0064ff9b0000000000000000c0000221n);
  assert.equal(ipToBigInt('garbage'), null);
});

test('cidrContains: IPv4 membership', () => {
  assert.equal(cidrContains('192.168.100.0/24', '192.168.100.2'), true);
  assert.equal(cidrContains('192.168.100.0/24', '192.168.100.255'), true);
  assert.equal(cidrContains('192.168.100.0/24', '192.168.101.2'), false);
  assert.equal(cidrContains('10.0.0.0/8', '10.255.255.254'), true);
  assert.equal(cidrContains('10.0.0.0/8', '11.0.0.1'), false);
  assert.equal(cidrContains('192.168.1.50/32', '192.168.1.50'), true);
  assert.equal(cidrContains('192.168.1.50/32', '192.168.1.51'), false);
  assert.equal(cidrContains('0.0.0.0/0', '8.8.8.8'), true);
});

test('cidrContains: handles IPv4-mapped client form against v4 cidr', () => {
  assert.equal(cidrContains('192.168.100.0/24', '::ffff:192.168.100.7'), true);
});

test('cidrContains: IPv6 membership', () => {
  assert.equal(cidrContains('fe80::/10', 'fe80::abcd'), true);
  assert.equal(cidrContains('fe80::/10', 'fec0::1'), false);
  assert.equal(cidrContains('2001:db8::/32', '2001:db8:1234::1'), true);
  assert.equal(cidrContains('2001:db8::/32', '2001:db9::1'), false);
  assert.equal(cidrContains('::/0', '2001:db8::1'), true);
});

test('cidrContains: family mismatch is false, never throws', () => {
  assert.equal(cidrContains('192.168.1.0/24', 'fe80::1'), false);
  assert.equal(cidrContains('fe80::/10', '192.168.1.1'), false);
  assert.equal(cidrContains('bogus', '192.168.1.1'), false);
  assert.equal(cidrContains('192.168.1.0/33', '192.168.1.1'), false);
});

test('ipInAnyCidr', () => {
  const subnets = ['192.168.100.0/24', '10.0.0.0/8'];
  assert.equal(ipInAnyCidr('10.1.2.3', subnets), true);
  assert.equal(ipInAnyCidr('192.168.100.9', subnets), true);
  assert.equal(ipInAnyCidr('172.16.0.1', subnets), false);
  assert.equal(ipInAnyCidr('1.1.1.1', 'not-array'), false);
});

test('isLoopback', () => {
  assert.equal(isLoopback('127.0.0.1'), true);
  assert.equal(isLoopback('127.5.6.7'), true);
  assert.equal(isLoopback('::1'), true);
  assert.equal(isLoopback('::ffff:127.0.0.1'), true);
  assert.equal(isLoopback('192.168.1.1'), false);
});

test('isPrivateIp', () => {
  assert.equal(isPrivateIp('192.168.1.1'), true);
  assert.equal(isPrivateIp('10.9.9.9'), true);
  assert.equal(isPrivateIp('172.16.0.1'), true);
  assert.equal(isPrivateIp('172.32.0.1'), false);
  assert.equal(isPrivateIp('169.254.1.1'), true);
  assert.equal(isPrivateIp('8.8.8.8'), false);
  assert.equal(isPrivateIp('fe80::1'), true);
  assert.equal(isPrivateIp('fc00::1'), true);
  assert.equal(isPrivateIp('2001:db8::1'), false);
});

test('normalizeMac: accepts dash/colon/dot/bare forms', () => {
  assert.equal(normalizeMac('58-72-c9-41-36-94'), '58:72:c9:41:36:94');
  assert.equal(normalizeMac('58:72:C9:41:36:94'), '58:72:c9:41:36:94');
  assert.equal(normalizeMac('5872.c941.3694'), '58:72:c9:41:36:94');
  assert.equal(normalizeMac('5872c9413694'), '58:72:c9:41:36:94');
  assert.equal(normalizeMac('58-72-c9-41-36'), null); // too short
  assert.equal(normalizeMac(''), null);
  assert.equal(normalizeMac(42), null);
});

test('isUnicastMac: rejects multicast, broadcast, all-zero', () => {
  assert.equal(isUnicastMac('58:72:c9:41:36:94'), true);
  assert.equal(isUnicastMac('84-47-09-75-92-32'), true);
  assert.equal(isUnicastMac('00:00:00:00:00:00'), false); // incomplete entry
  assert.equal(isUnicastMac('ff:ff:ff:ff:ff:ff'), false); // broadcast
  assert.equal(isUnicastMac('01:00:5e:00:00:16'), false); // IPv4 multicast
  assert.equal(isUnicastMac('33:33:00:00:00:fb'), false); // IPv6 multicast
  assert.equal(isUnicastMac('garbage'), false);
});

test('extractClientIp: uses TCP peer by default, ignores XFF', () => {
  const req = {
    socket: { remoteAddress: '::ffff:192.168.100.7' },
    headers: { 'x-forwarded-for': '1.2.3.4' },
  };
  assert.equal(extractClientIp(req), '192.168.100.7');
});

test('extractClientIp: honors XFF only when explicitly trusted', () => {
  const req = {
    socket: { remoteAddress: '192.168.100.1' },
    headers: { 'x-forwarded-for': '10.0.0.9, 192.168.100.1' },
  };
  assert.equal(extractClientIp(req, { trustForwardedHeader: true }), '10.0.0.9');
});

test('extractClientIp: tolerates missing socket', () => {
  assert.equal(extractClientIp({}), null);
  assert.equal(extractClientIp(null), null);
});
