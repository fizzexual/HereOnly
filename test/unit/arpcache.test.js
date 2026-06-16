'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');

const { createNeighborCache } = require('../../src/core/arpcache.js');

const ARP_BASE = `Interface: 192.168.100.2 --- 0x12
  192.168.100.1   58-72-c9-41-36-94   dynamic
  192.168.100.5   84-47-09-75-92-32   dynamic`;

const ARP_PLUS_7 = `${ARP_BASE}
  192.168.100.7   aa-bb-cc-dd-ee-ff   dynamic`;

// A controllable Windows `arp -a` runner that counts calls and can change
// its output over time (to simulate a new device appearing).
function makeRun(stateRef) {
  return async (file, args = []) => {
    if (file === 'arp') {
      stateRef.calls++;
      return { ok: stateRef.ok, code: 0, stdout: stateRef.text, stderr: '', error: null };
    }
    return { ok: false, code: 1, stdout: '', stderr: 'no mock', error: null };
  };
}

test('lookup returns a cached unicast neighbor', async () => {
  const state = { text: ARP_BASE, ok: true, calls: 0 };
  let t = 1000;
  const cache = createNeighborCache({ run: makeRun(state), platform: 'win32', now: () => t, ttlMs: 2000 });
  const r = await cache.lookup('192.168.100.5');
  assert.equal(r.neighbor.mac, '84:47:09:75:92:32');
  assert.equal(r.neighbor.unicast, true);
  assert.equal(state.calls, 1);
});

test('within TTL, repeated lookups do not re-read the table', async () => {
  const state = { text: ARP_BASE, ok: true, calls: 0 };
  let t = 1000;
  const cache = createNeighborCache({ run: makeRun(state), platform: 'win32', now: () => t, ttlMs: 2000 });
  await cache.lookup('192.168.100.1');
  t += 500; // still within TTL
  await cache.lookup('192.168.100.5');
  assert.equal(state.calls, 1);
});

test('after TTL expiry the table is re-read', async () => {
  const state = { text: ARP_BASE, ok: true, calls: 0 };
  let t = 1000;
  const cache = createNeighborCache({ run: makeRun(state), platform: 'win32', now: () => t, ttlMs: 2000 });
  await cache.lookup('192.168.100.1');
  t += 2500; // past TTL
  await cache.lookup('192.168.100.1');
  assert.equal(state.calls, 2);
});

test('concurrent lookups coalesce into a single read', async () => {
  const state = { text: ARP_BASE, ok: true, calls: 0 };
  let t = 1000;
  const cache = createNeighborCache({ run: makeRun(state), platform: 'win32', now: () => t, ttlMs: 2000 });
  await Promise.all([cache.lookup('192.168.100.1'), cache.lookup('192.168.100.5'), cache.lookup('192.168.100.1')]);
  assert.equal(state.calls, 1);
});

test('refresh-on-miss catches a device that just appeared', async () => {
  const state = { text: ARP_BASE, ok: true, calls: 0 };
  let t = 1000;
  const cache = createNeighborCache({
    run: makeRun(state),
    platform: 'win32',
    now: () => t,
    ttlMs: 2000,
    minRefreshMs: 250,
  });
  // Prime the cache (does not contain .7 yet).
  await cache.lookup('192.168.100.1');
  assert.equal(state.calls, 1);

  // Device .7 connects; OS table now includes it. Advance time past minRefreshMs
  // but still within TTL so ensureFresh won't refresh on its own.
  state.text = ARP_PLUS_7;
  t += 300;
  const r = await cache.lookup('192.168.100.7');
  assert.equal(r.neighbor.mac, 'aa:bb:cc:dd:ee:ff'); // found via miss-refresh
  assert.equal(state.calls, 2);
});

test('miss-refresh does not fire when cache was just refreshed', async () => {
  const state = { text: ARP_BASE, ok: true, calls: 0 };
  let t = 1000;
  const cache = createNeighborCache({
    run: makeRun(state),
    platform: 'win32',
    now: () => t,
    ttlMs: 2000,
    minRefreshMs: 250,
  });
  // First lookup of an absent IP: ensureFresh refreshes (calls=1); age is 0 so
  // no second refresh fires.
  const r = await cache.lookup('192.168.100.250');
  assert.equal(r.neighbor, null);
  assert.equal(state.calls, 1);
});

test('failed probe is reported as not-ok with no neighbor (fail closed)', async () => {
  const state = { text: '', ok: false, calls: 0 };
  let t = 1000;
  const cache = createNeighborCache({ run: makeRun(state), platform: 'win32', now: () => t, ttlMs: 2000 });
  const r = await cache.lookup('192.168.100.5');
  assert.equal(r.ok, false);
  assert.equal(r.neighbor, null);
});
