'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const os = require('node:os');
const fs = require('node:fs');
const path = require('node:path');

const { addrFromId, loadOrCreateIdentity, resolveRange, ulaPrefix } = require('../../src/hub/identity.js');
const { cidrContains } = require('../../src/core/ip.js');

test('default range is reserved Class E (240.0.0.0/8), not 100.x', () => {
  for (const id of ['a', 'b', 'deadbeef', 'hello-world', 'ffffffffffffffff']) {
    const addr = addrFromId(id);
    assert.ok(cidrContains('240.0.0.0/8', addr), `${addr} should be in 240.0.0.0/8`);
    assert.ok(!cidrContains('100.64.0.0/10', addr));
    assert.ok(!/\.(0|255)$/.test(addr), `${addr} should avoid .0/.255 last octet`);
  }
  assert.equal(addrFromId('x'), addrFromId('x')); // deterministic
});

test('range presets: cgnat, custom CIDR, and ULA', () => {
  assert.ok(cidrContains('100.64.0.0/10', addrFromId('node1', { range: 'cgnat' })));
  assert.ok(cidrContains('10.77.0.0/16', addrFromId('node1', { range: '10.77.0.0/16' })));

  // ULA: address sits inside the secret-derived /48, which lives in fd00::/8.
  const a = addrFromId('node1', { range: 'ula', secret: 'team-secret' });
  assert.ok(cidrContains('fd00::/8', a), `${a} should be a ULA address`);
  assert.ok(cidrContains(ulaPrefix('team-secret'), a));
});

test('ULA prefix is unguessable: different secrets -> different /48', () => {
  assert.notEqual(ulaPrefix('secretA'), ulaPrefix('secretB'));
  assert.equal(ulaPrefix('secretA'), ulaPrefix('secretA')); // stable
  assert.match(ulaPrefix('x'), /^fd[0-9a-f]{2}:[0-9a-f]{1,4}:[0-9a-f]{1,4}::\/48$/);
});

test('resolveRange maps names and passes through CIDRs', () => {
  assert.equal(resolveRange('cgnat'), '100.64.0.0/10');
  assert.equal(resolveRange('class-e'), '240.0.0.0/8');
  assert.equal(resolveRange(undefined), '240.0.0.0/8');
  assert.equal(resolveRange('10.0.0.0/24'), '10.0.0.0/24');
});

test('loadOrCreateIdentity persists a stable id + reloads same addr', () => {
  const file = path.join(os.tmpdir(), `ho-id-${process.pid}.json`);
  try {
    fs.rmSync(file, { force: true });
  } catch {
    /* ignore */
  }
  const a = loadOrCreateIdentity(file, 'myhost', null, { range: 'cgnat' });
  assert.ok(/^[0-9a-f]{16}$/.test(a.id));
  assert.equal(a.range, '100.64.0.0/10');
  assert.ok(cidrContains('100.64.0.0/10', a.addr));

  const b = loadOrCreateIdentity(file, 'myhost', null, { range: 'cgnat' });
  assert.equal(b.id, a.id);
  assert.equal(b.addr, a.addr); // stable across reloads

  fs.rmSync(file, { force: true });
});
