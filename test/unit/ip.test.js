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

test('normalizeIp: trims, lowercases, strips brackets/zone, unwraps v4-mapped', () => {
  assert.equal(normalizeIp('  192.168.1.5 '), '192.168.1.5');
  assert.equal(normalizeIp('[::1]'), '::1');
  assert.equal(normalizeIp('FE80::1%eth0'), 'fe80::1');
  assert.equal(normalizeIp('::ffff:192.168.1.5'), '192.168.1.5');
  assert.equal(normalizeIp('::ffff:c0a8:0105'), '192.168.1.5');
  assert.equal(normalizeIp(null), null);
  assert.equal(normalizeIp('   '), null);
});

test('ipFamily', () => {
  assert.equal(ipFamily('192.168.1.1'), 4);
  assert.equal(ipFamily('::ffff:192.168.1.1'), 4);
  assert.equal(ipFamily('fe80::1'), 6);
  assert.equal(ipFamily('nope'), 0);
});

test('ipToBigInt: v4 + v6 incl :: and embedded v4', () => {
  assert.equal(ipToBigInt('0.0.0.0'), 0n);
  assert.equal(ipToBigInt('255.255.255.255'), 4294967295n);
  assert.equal(ipToBigInt('::'), 0n);
  assert.equal(ipToBigInt('::1'), 1n);
  assert.equal(ipToBigInt('2001:db8::'), 0x20010db8n << 96n);
  assert.equal(ipToBigInt('64:ff9b::192.0.2.33'), 0x0064ff9b0000000000000000c0000221n);
  assert.equal(ipToBigInt('garbage'), null);
});

test('cidrContains v4/v6 + v4-mapped + never throws on junk', () => {
  assert.equal(cidrContains('192.168.100.0/24', '192.168.100.2'), true);
  assert.equal(cidrContains('192.168.100.0/24', '192.168.101.2'), false);
  assert.equal(cidrContains('192.168.100.0/24', '::ffff:192.168.100.7'), true);
  assert.equal(cidrContains('10.0.0.0/8', '10.255.255.254'), true);
  assert.equal(cidrContains('fe80::/10', 'fe80::abcd'), true);
  assert.equal(cidrContains('2001:db8::/32', '2001:db9::1'), false);
  assert.equal(cidrContains('192.168.1.0/24', 'fe80::1'), false);
  assert.equal(cidrContains('bogus', '1.2.3.4'), false);
  assert.equal(cidrContains('1.2.3.0/33', '1.2.3.4'), false);
});

test('ipInAnyCidr', () => {
  assert.equal(ipInAnyCidr('10.1.2.3', ['192.168.0.0/16', '10.0.0.0/8']), true);
  assert.equal(ipInAnyCidr('8.8.8.8', ['10.0.0.0/8']), false);
  assert.equal(ipInAnyCidr('1.1.1.1', 'nope'), false);
});

test('isLoopback / isPrivateIp', () => {
  assert.equal(isLoopback('127.0.0.1'), true);
  assert.equal(isLoopback('::1'), true);
  assert.equal(isLoopback('192.168.1.1'), false);
  assert.equal(isPrivateIp('192.168.1.1'), true);
  assert.equal(isPrivateIp('172.16.0.1'), true);
  assert.equal(isPrivateIp('172.32.0.1'), false);
  assert.equal(isPrivateIp('8.8.8.8'), false);
  assert.equal(isPrivateIp('fe80::1'), true);
});

test('normalizeMac / isUnicastMac', () => {
  assert.equal(normalizeMac('58-72-c9-41-36-94'), '58:72:c9:41:36:94');
  assert.equal(normalizeMac('5872.c941.3694'), '58:72:c9:41:36:94');
  assert.equal(normalizeMac('short'), null);
  assert.equal(isUnicastMac('58:72:c9:41:36:94'), true);
  assert.equal(isUnicastMac('00:00:00:00:00:00'), false);
  assert.equal(isUnicastMac('ff:ff:ff:ff:ff:ff'), false);
  assert.equal(isUnicastMac('01:00:5e:00:00:16'), false);
  assert.equal(isUnicastMac('33:33:00:00:00:fb'), false);
});

test('extractClientIp: TCP peer by default; XFF/X-Real-IP only when trusted', () => {
  const req = {
    socket: { remoteAddress: '::ffff:192.168.100.7' },
    headers: { 'x-forwarded-for': '1.2.3.4', 'x-real-ip': '5.6.7.8' },
  };
  assert.equal(extractClientIp(req), '192.168.100.7');
  assert.equal(extractClientIp(req, { trustForwardedHeader: true }), '5.6.7.8'); // X-Real-IP wins
  const req2 = { socket: { remoteAddress: '9.9.9.9' }, headers: { 'x-forwarded-for': '5.6.7.8, 9.9.9.9' } };
  assert.equal(extractClientIp(req2, { trustForwardedHeader: true }), '5.6.7.8');
  assert.equal(extractClientIp({}), null);
});
