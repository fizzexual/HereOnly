'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');

const { issueToken, verifyToken, generateSecret } = require('../../src/core/token.js');

const SECRET = Buffer.from('0123456789abcdef0123456789abcdef', 'utf8');
// Fixed clock for determinism.
const T0 = 1_700_000_000_000;
const at = (ms) => () => ms;

test('issue + verify round-trips and preserves bound claims', () => {
  const tok = issueToken(
    { ip: '192.168.100.5', mac: '84:47:09:75:92:32', net: 'abc123' },
    SECRET,
    { ttlSeconds: 1800, now: at(T0) },
  );
  const res = verifyToken(tok, SECRET, { now: at(T0) });
  assert.equal(res.valid, true);
  assert.equal(res.payload.ip, '192.168.100.5');
  assert.equal(res.payload.mac, '84:47:09:75:92:32');
  assert.equal(res.payload.net, 'abc123');
  assert.equal(res.payload.exp - res.payload.iat, 1800);
});

test('wrong secret -> bad signature', () => {
  const tok = issueToken({ ip: '10.0.0.1' }, SECRET, { now: at(T0) });
  const res = verifyToken(tok, generateSecret(), { now: at(T0) });
  assert.equal(res.valid, false);
  assert.equal(res.reason, 'bad-signature');
});

test('tampered payload -> bad signature', () => {
  const tok = issueToken({ ip: '10.0.0.1' }, SECRET, { now: at(T0) });
  const parts = tok.split('.');
  const forged = Buffer.from(JSON.stringify({ v: 1, ip: '10.0.0.99', exp: 9_999_999_999 })).toString('base64url');
  const tampered = `${parts[0]}.${forged}.${parts[2]}`;
  const res = verifyToken(tampered, SECRET, { now: at(T0) });
  assert.equal(res.valid, false);
  assert.equal(res.reason, 'bad-signature');
});

test('expired token -> expired', () => {
  const tok = issueToken({ ip: '10.0.0.1' }, SECRET, { ttlSeconds: 60, now: at(T0) });
  const later = at(T0 + 61_000 + 31_000); // past exp + skew
  const res = verifyToken(tok, SECRET, { now: later });
  assert.equal(res.valid, false);
  assert.equal(res.reason, 'expired');
});

test('within clock skew is still valid', () => {
  const tok = issueToken({ ip: '10.0.0.1' }, SECRET, { ttlSeconds: 60, now: at(T0) });
  const res = verifyToken(tok, SECRET, { now: at(T0 + 60_000 + 20_000) }); // 20s past exp, within 30s skew
  assert.equal(res.valid, true);
});

test('malformed inputs', () => {
  assert.equal(verifyToken('', SECRET).reason, 'missing');
  assert.equal(verifyToken('not-a-token', SECRET).reason, 'malformed');
  assert.equal(verifyToken('HO1.only-two', SECRET).reason, 'malformed');
  assert.equal(verifyToken('XX1.a.b', SECRET).reason, 'malformed');
  assert.equal(verifyToken(null, SECRET).reason, 'missing');
});

test('two tokens for same claims differ (random jti)', () => {
  const a = issueToken({ ip: '10.0.0.1' }, SECRET, { now: at(T0) });
  const b = issueToken({ ip: '10.0.0.1' }, SECRET, { now: at(T0) });
  assert.notEqual(a, b);
});

test('string secret is accepted', () => {
  const tok = issueToken({ ip: '10.0.0.1' }, 'a-string-secret', { now: at(T0) });
  assert.equal(verifyToken(tok, 'a-string-secret', { now: at(T0) }).valid, true);
  assert.equal(verifyToken(tok, 'different', { now: at(T0) }).valid, false);
});
