'use strict';

/**
 * Control-plane-free peer discovery on the local segment.
 *
 * Every HereOnly hub announces itself over UDP multicast and listens for the
 * announcements of its peers. There is no coordination server: discovery rides
 * the segment itself. Multicast TTL is 1, so announcements never cross the
 * gateway — discovery is inherently confined to the same broadcast domain,
 * which is exactly HereOnly's trust boundary.
 *
 * Announcements may be HMAC-signed with a shared `secret` so only machines that
 * share it form a hub (others on the segment are ignored).
 */

const dgram = require('node:dgram');
const crypto = require('node:crypto');
const { noopLogger } = require('../core/logger.js');

const HEADER = 'HOH1';
const DEFAULT_GROUP = '239.255.71.79';
const DEFAULT_PORT = 47471;

const b64url = (buf) => Buffer.from(buf).toString('base64url');
const fromB64url = (s) => Buffer.from(s, 'base64url');

function sign(b64, secret) {
  return crypto.createHmac('sha256', secret).update(b64).digest();
}

/** Encode a message: HOH1.<payload>.<sig?> */
function encodeMessage(obj, secret) {
  const body = b64url(JSON.stringify(obj));
  if (secret) return `${HEADER}.${body}.${b64url(sign(body, secret))}`;
  return `${HEADER}.${body}.`;
}

/** Decode + (if secret) verify a message. Returns the object or null. */
function decodeMessage(str, secret) {
  if (typeof str !== 'string') return null;
  const parts = str.split('.');
  if (parts.length !== 3 || parts[0] !== HEADER) return null;
  if (secret) {
    let provided;
    try {
      provided = fromB64url(parts[2]);
    } catch {
      return null;
    }
    const expected = sign(parts[1], secret);
    if (provided.length !== expected.length || !crypto.timingSafeEqual(provided, expected)) return null;
  }
  try {
    return JSON.parse(fromB64url(parts[1]).toString('utf8'));
  } catch {
    return null;
  }
}

function newId() {
  return crypto.randomBytes(8).toString('hex');
}

function createPeerTable(opts = {}) {
  const now = opts.now || (() => Date.now());
  const defaultTtlMs = opts.defaultTtlMs != null ? opts.defaultTtlMs : 15000;
  const peers = new Map();

  function upsert(announce, fromAddr) {
    if (!announce || !announce.id) return;
    const ttl = Number(announce.ttlMs) || defaultTtlMs;
    peers.set(announce.id, {
      id: announce.id,
      host: announce.host || fromAddr || announce.id,
      name: announce.name || announce.host || announce.id,
      addr: announce.addr || null,
      addrs: Array.isArray(announce.addrs) && announce.addrs.length ? announce.addrs : fromAddr ? [fromAddr] : [],
      services: Array.isArray(announce.services) ? announce.services : [],
      from: fromAddr || null,
      lastSeen: now(),
      expiresAt: now() + ttl,
    });
  }

  function prune() {
    const t = now();
    for (const [id, p] of peers) if (p.expiresAt <= t) peers.delete(id);
  }

  function list() {
    prune();
    return [...peers.values()].sort((a, b) => String(a.host).localeCompare(String(b.host)));
  }

  return { upsert, prune, list, size: () => peers.size, _peers: peers };
}

function createDiscovery(opts = {}) {
  const self = opts.self || {};
  const group = opts.group || DEFAULT_GROUP;
  const port = opts.port || DEFAULT_PORT;
  const intervalMs = opts.intervalMs != null ? opts.intervalMs : 5000;
  const ttlMs = opts.ttlMs != null ? opts.ttlMs : 15000;
  const secret = opts.secret ? (Buffer.isBuffer(opts.secret) ? opts.secret : Buffer.from(String(opts.secret))) : null;
  const logger = opts.logger || noopLogger;
  const now = opts.now || (() => Date.now());

  const table = createPeerTable({ now, defaultTtlMs: ttlMs });
  const listeners = new Set();
  let socket = null;
  let timer = null;

  const servicesNow = () => (typeof self.services === 'function' ? self.services() : self.services || []);
  const emit = () => {
    for (const l of listeners) {
      try {
        l(table.list());
      } catch {
        /* ignore */
      }
    }
  };

  function send(obj) {
    if (!socket) return;
    const msg = Buffer.from(encodeMessage(obj, secret));
    socket.send(msg, port, group, (err) => {
      if (err) logger.debug('discovery send error:', err.message);
    });
  }

  const announce = () =>
    send({
      t: 'announce',
      v: 1,
      id: self.id,
      host: self.host,
      name: self.name || self.host,
      addr: self.addr || null,
      addrs: self.addrs || [],
      services: servicesNow(),
      ttlMs,
    });
  const query = () => send({ t: 'query', v: 1, id: self.id });

  function onMessage(buf, rinfo) {
    const obj = decodeMessage(buf.toString('utf8'), secret);
    if (!obj || obj.id === self.id) return; // ignore junk and our own packets
    if (obj.t === 'query') {
      announce();
      return;
    }
    if (obj.t === 'announce') {
      table.upsert(obj, rinfo && rinfo.address);
      emit();
    }
  }

  function start() {
    socket = dgram.createSocket({ type: 'udp4', reuseAddr: true });
    socket.on('message', onMessage);
    socket.on('error', (e) => logger.warn('discovery socket error:', e.message));
    socket.bind(port, () => {
      try {
        socket.addMembership(group);
      } catch (e) {
        logger.warn('discovery addMembership failed:', e.message);
      }
      try {
        socket.setMulticastTTL(1);
        socket.setMulticastLoopback(true);
        socket.setBroadcast(true);
      } catch {
        /* ignore */
      }
      announce();
      query();
      timer = setInterval(() => {
        announce();
        emit();
      }, intervalMs);
      if (timer.unref) timer.unref();
    });
    return api;
  }

  function stop() {
    if (timer) clearInterval(timer);
    timer = null;
    if (socket) {
      try {
        socket.close();
      } catch {
        /* ignore */
      }
      socket = null;
    }
  }

  const api = {
    start,
    stop,
    announce,
    query,
    peers: () => table.list(),
    table,
    onChange: (fn) => {
      listeners.add(fn);
      return () => listeners.delete(fn);
    },
  };
  return api;
}

module.exports = {
  encodeMessage,
  decodeMessage,
  createPeerTable,
  createDiscovery,
  newId,
  HEADER,
  DEFAULT_GROUP,
  DEFAULT_PORT,
};
