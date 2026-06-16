'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');

const { createAudit } = require('../../src/core/audit.js');

let clock = 1000;
const now = () => clock;

test('records allow/deny entries with normalized fields and present flag', () => {
  const a = createAudit({ now });
  a.record({ ip: '::ffff:192.168.1.5', mac: '58-72-C9-41-36-94', allow: true, reason: 'arp-verified', present: true });
  a.record({ ip: '8.8.8.8', allow: false, reason: 'no-arp-entry', present: false });
  const all = a.tail();
  assert.equal(all.length, 2);
  assert.equal(all[0].ip, '192.168.1.5');
  assert.equal(all[0].mac, '58:72:c9:41:36:94');
  assert.equal(all[0].verdict, 'allow');
  assert.equal(all[0].present, true);
  assert.equal(all[1].verdict, 'deny');
});

test('query filters by verdict / mac / since', () => {
  const a = createAudit({ now });
  clock = 1000;
  a.record({ ip: '1.1.1.1', mac: 'aa:bb:cc:dd:ee:ff', allow: true, reason: 'x' });
  clock = 2000;
  a.record({ ip: '2.2.2.2', allow: false, reason: 'y' });
  clock = 3000;
  a.record({ ip: '3.3.3.3', mac: 'aa:bb:cc:dd:ee:ff', allow: false, reason: 'z' });
  assert.equal(a.query({ deniesOnly: true }).length, 2);
  assert.equal(a.query({ mac: 'AA-BB-CC-DD-EE-FF' }).length, 2);
  assert.equal(a.query({ since: 2500 }).length, 1);
});

test('ring buffer caps retained entries', () => {
  const a = createAudit({ now, ringSize: 5 });
  for (let i = 0; i < 20; i++) a.record({ ip: '1.1.1.' + i, allow: true, reason: 'x' });
  assert.equal(a.tail(100).length, 5);
  assert.equal(a._ring[0].seq, 16); // oldest retained
});

test('signed hash-chain is tamper-evident', () => {
  const a = createAudit({ now, sign: true, secret: 'audit-key' });
  a.record({ ip: '1.1.1.1', allow: true, reason: 'a' });
  a.record({ ip: '2.2.2.2', allow: false, reason: 'b' });
  a.record({ ip: '3.3.3.3', allow: true, reason: 'c' });
  assert.equal(a.verifyChain().ok, true);

  // Tamper with a recorded entry's verdict — the chain must break.
  const entries = a.tail();
  entries[1].verdict = 'allow';
  assert.equal(a.verifyChain(entries).ok, false);
  assert.equal(a.verifyChain(entries).brokenAt, 2);
});

test('chain detects a deleted entry', () => {
  const a = createAudit({ now, sign: true });
  a.record({ ip: '1.1.1.1', allow: true, reason: 'a' });
  a.record({ ip: '2.2.2.2', allow: true, reason: 'b' });
  a.record({ ip: '3.3.3.3', allow: true, reason: 'c' });
  const entries = a.tail();
  entries.splice(1, 1); // drop the middle entry
  assert.equal(a.verifyChain(entries).ok, false);
});
