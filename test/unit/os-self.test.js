'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');

const { getOwnIps, isOwnIp } = require('../../src/os/self.js');

test('getOwnIps includes loopback and returns a Set of normalized strings', () => {
  const own = getOwnIps();
  assert.ok(own instanceof Set);
  assert.ok(own.has('127.0.0.1') || own.has('::1'), 'loopback should be present');
});

test('isOwnIp matches against an injected set and normalizes the input', () => {
  const own = new Set(['192.168.100.2', '::1']);
  assert.equal(isOwnIp('192.168.100.2', own), true);
  assert.equal(isOwnIp('::ffff:192.168.100.2', own), true); // normalized to v4
  assert.equal(isOwnIp('192.168.100.3', own), false);
  assert.equal(isOwnIp(null, own), false);
});

test('isOwnIp without an explicit set uses the live host set (loopback is own)', () => {
  assert.equal(isOwnIp('127.0.0.1'), true);
});
