'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');

const { encodeMessage, decodeMessage, createPeerTable } = require('../../src/hub/discovery.js');

test('encode/decode round-trips (unsigned)', () => {
  const msg = { t: 'announce', v: 1, id: 'abc', host: 'box', services: [{ port: 3000 }] };
  const wire = encodeMessage(msg);
  assert.ok(wire.startsWith('HOH1.'));
  assert.deepEqual(decodeMessage(wire), msg);
});

test('signed messages: right secret ok, wrong/tampered rejected', () => {
  const msg = { t: 'announce', id: 'abc' };
  const wire = encodeMessage(msg, 'shared');
  assert.deepEqual(decodeMessage(wire, 'shared'), msg);
  assert.equal(decodeMessage(wire, 'other'), null);
  // tamper the payload, keep the signature
  const parts = wire.split('.');
  const forged = Buffer.from(JSON.stringify({ t: 'announce', id: 'evil' })).toString('base64url');
  assert.equal(decodeMessage(`${parts[0]}.${forged}.${parts[2]}`, 'shared'), null);
});

test('decode rejects junk', () => {
  assert.equal(decodeMessage('not-a-message'), null);
  assert.equal(decodeMessage('HOH1.@@@.'), null);
  assert.equal(decodeMessage(123), null);
});

test('peer table upserts, sorts by host, and prunes on TTL', () => {
  let t = 1000;
  const table = createPeerTable({ now: () => t, defaultTtlMs: 5000 });
  table.upsert({ id: 'b', host: 'beta', addrs: ['192.168.1.3'], services: [], ttlMs: 5000 }, '192.168.1.3');
  table.upsert({ id: 'a', host: 'alpha', addrs: ['192.168.1.2'], services: [], ttlMs: 5000 }, '192.168.1.2');
  const list = table.list();
  assert.deepEqual(list.map((p) => p.host), ['alpha', 'beta']); // sorted

  t += 6000; // both expire
  assert.equal(table.list().length, 0);
});

test('peer table falls back to source address when none advertised', () => {
  let t = 1000;
  const table = createPeerTable({ now: () => t });
  table.upsert({ id: 'x' }, '192.168.1.9');
  assert.deepEqual(table.list()[0].addrs, ['192.168.1.9']);
});
