'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');

const { createRateLimiter } = require('../../src/core/ratelimit.js');

test('allows up to capacity, then denies with a retry hint', () => {
  let t = 1000;
  const rl = createRateLimiter({ capacity: 3, refillPerSec: 1, now: () => t });
  assert.equal(rl.take('a').allowed, true);
  assert.equal(rl.take('a').allowed, true);
  assert.equal(rl.take('a').allowed, true);
  const denied = rl.take('a');
  assert.equal(denied.allowed, false);
  assert.ok(denied.retryAfterMs > 0 && denied.retryAfterMs <= 1000);
});

test('refills over time', () => {
  let t = 1000;
  const rl = createRateLimiter({ capacity: 2, refillPerSec: 2, now: () => t });
  rl.take('a');
  rl.take('a');
  assert.equal(rl.take('a').allowed, false);
  t += 500; // 0.5s * 2/s = 1 token
  assert.equal(rl.take('a').allowed, true);
  assert.equal(rl.take('a').allowed, false);
});

test('keys are independent', () => {
  let t = 1000;
  const rl = createRateLimiter({ capacity: 1, refillPerSec: 1, now: () => t });
  assert.equal(rl.take('a').allowed, true);
  assert.equal(rl.take('a').allowed, false);
  assert.equal(rl.take('b').allowed, true); // separate bucket
});

test('reset clears a key (or all)', () => {
  let t = 1000;
  const rl = createRateLimiter({ capacity: 1, refillPerSec: 1, now: () => t });
  rl.take('a');
  assert.equal(rl.take('a').allowed, false);
  rl.reset('a');
  assert.equal(rl.take('a').allowed, true);
  rl.reset();
  assert.equal(rl.size(), 0);
});

test('bucket count is capped', () => {
  let t = 1000;
  const rl = createRateLimiter({ capacity: 1, refillPerSec: 1, maxKeys: 100, now: () => (t += 1) });
  for (let i = 0; i < 500; i++) rl.take('k' + i);
  assert.ok(rl.size() <= 100, `size ${rl.size()} should be <= 100`);
});
