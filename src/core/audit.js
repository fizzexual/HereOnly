'use strict';

/**
 * Physical-access audit log.
 *
 * Records every access decision with the physical evidence behind it: client
 * IP, MAC, verdict, reason, the network fingerprint, and whether the device was
 * provably present on the segment. This is an audit trail no VPN can produce —
 * "who tried to reach this resource, from what hardware, and were they actually
 * here" — which is exactly what regulated environments need.
 *
 * Entries are kept in an in-memory ring (for fast `hereonly audit` queries) and
 * optionally appended to a JSONL file. With `sign: true` each entry is chained
 * to the previous via a hash (optionally HMAC-keyed), making the log
 * tamper-evident: you cannot alter or delete an entry without breaking the
 * chain, and without the key you cannot forge a valid continuation.
 */

const crypto = require('node:crypto');
const fs = require('node:fs');
const { normalizeMac, normalizeIp } = require('./ip.js');

const GENESIS = '0'.repeat(64);

function canonical(e) {
  return JSON.stringify([e.seq, e.ts, e.ip, e.mac, e.verdict, e.reason, e.via, e.resource, e.net, e.present]);
}

function chainHash(prev, e, secret) {
  const data = prev + canonical(e);
  return secret
    ? crypto.createHmac('sha256', secret).update(data).digest('hex')
    : crypto.createHash('sha256').update(data).digest('hex');
}

function createAudit(opts = {}) {
  const ringSize = opts.ringSize != null ? opts.ringSize : 1000;
  const file = opts.file || null;
  const sign = !!opts.sign;
  const secret = opts.secret ? (Buffer.isBuffer(opts.secret) ? opts.secret : Buffer.from(String(opts.secret))) : null;
  const now = opts.now || (() => Date.now());
  const ring = [];
  let seq = 0;
  let prevHash = opts.genesis || GENESIS;

  // Continue an existing on-disk log so the chain (and seq) stays unbroken
  // across restarts — otherwise each process would start a fresh chain and a
  // concatenated file would fail verification.
  if (file) {
    const existing = loadAuditFile(file);
    if (existing.length) {
      const last = existing[existing.length - 1];
      if (typeof last.seq === 'number') seq = last.seq;
      if (sign && last.hash) prevHash = last.hash;
    }
  }

  function record(input = {}) {
    seq += 1;
    const e = {
      seq,
      ts: input.ts != null ? input.ts : now(),
      ip: input.ip != null ? normalizeIp(input.ip) : null,
      mac: input.mac != null ? normalizeMac(input.mac) || input.mac : null,
      verdict: input.allow ? 'allow' : 'deny',
      reason: input.reason != null ? input.reason : null,
      via: input.via != null ? input.via : null,
      resource: input.resource != null ? input.resource : null,
      net: input.net != null ? input.net : null,
      present: !!input.present,
    };
    if (sign) {
      e.prev = prevHash;
      e.hash = chainHash(prevHash, e, secret);
      prevHash = e.hash;
    }
    ring.push(e);
    if (ring.length > ringSize) ring.shift();
    if (file) {
      try {
        fs.appendFileSync(file, JSON.stringify(e) + '\n');
      } catch {
        /* never let auditing break a request */
      }
    }
    return e;
  }

  function query(filter = {}) {
    const { limit = 100, deniesOnly = false, allowsOnly = false, mac = null, ip = null, since = null } = filter;
    let items = ring;
    if (deniesOnly) items = items.filter((e) => e.verdict === 'deny');
    if (allowsOnly) items = items.filter((e) => e.verdict === 'allow');
    if (mac) {
      const m = normalizeMac(mac) || mac;
      items = items.filter((e) => e.mac === m);
    }
    if (ip) {
      const n = normalizeIp(ip);
      items = items.filter((e) => e.ip === n);
    }
    if (since != null) items = items.filter((e) => e.ts >= since);
    return items.slice(-limit);
  }

  const tail = (n = 20) => ring.slice(-n);

  /** Verify a signed chain (defaults to this instance's ring). */
  function verifyChain(entries = ring) {
    let prev = opts.genesis || GENESIS;
    for (const e of entries) {
      if (e.hash === undefined) return { ok: false, reason: 'unsigned', brokenAt: e.seq };
      const expected = chainHash(prev, e, secret);
      if (e.prev !== prev || e.hash !== expected) return { ok: false, reason: 'tampered', brokenAt: e.seq };
      prev = e.hash;
    }
    return { ok: true, length: entries.length };
  }

  return {
    record,
    query,
    tail,
    verifyChain,
    stats: () => ({ count: seq, ring: ring.length, ringSize, file, signed: sign }),
    _ring: ring,
  };
}

/** Parse a persisted JSONL audit file into entries (for the CLI). */
function loadAuditFile(file) {
  const out = [];
  let text = '';
  try {
    text = fs.readFileSync(file, 'utf8');
  } catch {
    return out;
  }
  for (const line of text.split(/\r?\n/)) {
    if (!line.trim()) continue;
    try {
      out.push(JSON.parse(line));
    } catch {
      /* skip corrupt line */
    }
  }
  return out;
}

module.exports = { createAudit, loadAuditFile, GENESIS, canonical, chainHash };
