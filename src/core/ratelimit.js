'use strict';

/**
 * In-memory token-bucket rate limiter, keyed by client (usually IP).
 *
 * Used to throttle abusive probing — e.g. an off-segment host hammering the
 * gate, or brute-force attempts against a token. Each key gets a bucket that
 * refills at `refillPerSec` up to `capacity`; a request costs one token.
 *
 * Zero deps; `now` is injectable for testing. Bucket count is capped so the
 * map can't grow unbounded under a spray of distinct keys.
 */

function createRateLimiter(opts = {}) {
  const capacity = opts.capacity != null ? opts.capacity : 30;
  const refillPerSec = opts.refillPerSec != null ? opts.refillPerSec : 10;
  const maxKeys = opts.maxKeys != null ? opts.maxKeys : 50000;
  const now = opts.now || (() => Date.now());
  const buckets = new Map();

  function refill(b, t) {
    const elapsedSec = (t - b.last) / 1000;
    if (elapsedSec > 0) {
      b.tokens = Math.min(capacity, b.tokens + elapsedSec * refillPerSec);
      b.last = t;
    }
  }

  function evictOldest() {
    // Drop the ~10% least-recently-used buckets.
    const entries = [...buckets.entries()].sort((a, b) => a[1].last - b[1].last);
    const drop = Math.max(1, Math.floor(buckets.size - maxKeys * 0.9));
    for (let i = 0; i < drop && i < entries.length; i++) buckets.delete(entries[i][0]);
  }

  function take(key, cost = 1) {
    const t = now();
    let b = buckets.get(key);
    if (!b) {
      b = { tokens: capacity, last: t };
      buckets.set(key, b);
      if (buckets.size > maxKeys) evictOldest();
    } else {
      refill(b, t);
    }
    if (b.tokens >= cost) {
      b.tokens -= cost;
      return { allowed: true, remaining: Math.floor(b.tokens), retryAfterMs: 0 };
    }
    const deficit = cost - b.tokens;
    return {
      allowed: false,
      remaining: Math.floor(b.tokens),
      retryAfterMs: Math.ceil((deficit / refillPerSec) * 1000),
    };
  }

  function reset(key) {
    if (key === undefined) buckets.clear();
    else buckets.delete(key);
  }

  return { take, reset, size: () => buckets.size, capacity, refillPerSec };
}

module.exports = { createRateLimiter };
