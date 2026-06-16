'use strict';

/**
 * TTL cache over the neighbor table.
 *
 * Reading the ARP/NDP table on every request would be slow, so we cache the
 * parsed table briefly. Concurrent refreshes coalesce into a single read; and
 * on a cache *miss* for a not-just-refreshed table we refresh once and retry,
 * because a client that connected microseconds ago is already in the OS table
 * (the kernel resolved it to complete the TCP handshake) but may not yet be in
 * our snapshot — closing a brief false-deny window without re-reading every
 * lookup. Fails closed: a failed read yields an empty, not-ok snapshot.
 */

const { readNeighbors } = require('../os/neighbors.js');
const { normalizeIp } = require('./ip.js');

function createNeighborCache(opts = {}) {
  const ttlMs = opts.ttlMs != null ? opts.ttlMs : 2000;
  const minRefreshMs = opts.minRefreshMs != null ? opts.minRefreshMs : 250;
  const refreshOnMiss = opts.refreshOnMiss !== false;
  const now = opts.now || (() => Date.now());
  const { run, platform } = opts;

  let cache = { at: 0, neighbors: [], source: null, ok: false };
  let inflight = null;
  const stats = { reads: 0, hits: 0, refreshes: 0, missRefreshes: 0 };

  function refresh() {
    if (inflight) return inflight;
    stats.refreshes++;
    inflight = readNeighbors({ run, platform })
      .then((res) => {
        cache = { at: now(), neighbors: res.neighbors, source: res.source, ok: res.ok };
        inflight = null;
        return cache;
      })
      .catch((err) => {
        inflight = null;
        cache = { at: now(), neighbors: [], source: 'error', ok: false, error: err };
        return cache;
      });
    return inflight;
  }

  async function ensureFresh() {
    if (cache.at === 0 || now() - cache.at > ttlMs) return refresh();
    return cache;
  }

  const find = (neighbors, target) => (target ? neighbors.find((n) => n.ip === target) || null : null);

  async function lookup(ip) {
    stats.reads++;
    const target = normalizeIp(ip);
    if (!target) return { neighbor: null, source: cache.source, ok: cache.ok, cachedAt: cache.at };
    let c = await ensureFresh();
    let neighbor = find(c.neighbors, target);
    if (neighbor) stats.hits++;
    if (!neighbor && refreshOnMiss && c.ok && now() - c.at >= minRefreshMs) {
      stats.missRefreshes++;
      c = await refresh();
      neighbor = find(c.neighbors, target);
    }
    return { neighbor, source: c.source, ok: c.ok, cachedAt: c.at };
  }

  return { lookup, refresh, ensureFresh, snapshot: () => ({ ...cache }), stats };
}

module.exports = { createNeighborCache };
