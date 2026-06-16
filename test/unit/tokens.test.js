'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');

const { issueToken, verifyToken, generateSecret } = require('../../src/core/tokens.js');

const SECRET = Buffer.from('0123456789abcdef0123456789abcdef', 'utf8');
const T0 = 1_700_000_000_000;
const at = (ms) => () => ms;

test('issue + verify round-trips and preserves bound claims', () => {
  const tok = issueToken({ ip: '192.168.100.5', mac: '84:47:09:75:92:32', net: 'abc' }, SECRET, { now: at(T0) });
  const res = verifyToken(tok, SECRET, { now: at(T0) });
  assert.equal(res.valid, true);
  assert.equal(res.payload.ip, '192.168.100.5');
  assert.equal(res.payload.mac, '84:47:09:75:92:32');
  assert.equal(res.payload.net, 'abc');
  assert.ok(tok.startsWith('HO2.'));
});

test('wrong secret / tampered payload -> bad signature', () => {
  const tok = issueToken({ ip: '10.0.0.1' }, SECRET, { now: at(T0) });
  assert.equal(verifyToken(tok, generateSecret(), { now: at(T0) }).reason, 'bad-signature');
  const parts = tok.split('.');
  const forged = Buffer.from(JSON.stringify({ v: 2, ip: '10.0.0.99', exp: 9e9 })).toString('base64url');
  assert.equal(verifyToken(`${parts[0]}.${forged}.${parts[2]}`, SECRET, { now: at(T0) }).reason, 'bad-signature');
});

test('expiry + clock skew', () => {
  const tok = issueToken({ ip: '10.0.0.1' }, SECRET, { ttlSeconds: 60, now: at(T0) });
  assert.equal(verifyToken(tok, SECRET, { now: at(T0 + 60_000 + 20_000) }).valid, true); // within 30s skew
  assert.equal(verifyToken(tok, SECRET, { now: at(T0 + 60_000 + 31_000) }).reason, 'expired');
});

test('malformed inputs', () => {
  assert.equal(verifyToken('', SECRET).reason, 'missing');
  assert.equal(verifyToken('nope', SECRET).reason, 'malformed');
  assert.equal(verifyToken('HO1.a.b', SECRET).reason, 'malformed'); // wrong header version
  assert.equal(verifyToken(null, SECRET).reason, 'missing');
});
