'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const os = require('node:os');
const fs = require('node:fs');
const path = require('node:path');

const { addrFromId, loadOrCreateIdentity } = require('../../src/hub/identity.js');
const { cidrContains } = require('../../src/core/ip.js');

test('addrFromId is deterministic and inside 100.64.0.0/10', () => {
  assert.equal(addrFromId('abc123'), addrFromId('abc123'));
  assert.notEqual(addrFromId('abc123'), addrFromId('abc124'));
  for (const id of ['a', 'b', 'deadbeefdeadbeef', '00', 'ffffffffffffffff', 'hello-world']) {
    const addr = addrFromId(id);
    assert.ok(cidrContains('100.64.0.0/10', addr), `${addr} should be in 100.64.0.0/10`);
    assert.ok(/^100\.\d+\.\d+\.\d+$/.test(addr));
  }
});

test('loadOrCreateIdentity creates, persists, and reloads a stable identity', () => {
  const file = path.join(os.tmpdir(), `ho-id-${process.pid}.json`);
  try {
    fs.rmSync(file, { force: true });
  } catch {
    /* ignore */
  }
  const a = loadOrCreateIdentity(file, 'myhost');
  assert.ok(/^[0-9a-f]{16}$/.test(a.id));
  assert.equal(a.name, 'myhost');
  assert.equal(a.addr, addrFromId(a.id));

  const b = loadOrCreateIdentity(file, 'myhost'); // reload -> same id + addr
  assert.equal(b.id, a.id);
  assert.equal(b.addr, a.addr);

  const c = loadOrCreateIdentity(file, 'myhost', 'NicerName'); // name override
  assert.equal(c.id, a.id);
  assert.equal(c.name, 'NicerName');

  fs.rmSync(file, { force: true });
});
