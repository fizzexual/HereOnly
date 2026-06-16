'use strict';

/**
 * IP and MAC address utilities.
 *
 * Zero dependencies. Handles IPv4, IPv6, and the IPv4-mapped-IPv6 form
 * (`::ffff:a.b.c.d`) that Node hands back for dual-stack sockets. CIDR math
 * uses BigInt so one code path covers v4 (/0../32) and v6 (/0../128).
 */

const net = require('node:net');

// --- normalization ---------------------------------------------------------

/**
 * Clean an address string: trim, drop surrounding brackets, strip an IPv6
 * zone id, lowercase, and unwrap IPv4-mapped IPv6 to plain IPv4.
 * Returns the cleaned string, or null for non-string/empty input.
 */
function normalizeIp(ip) {
  if (typeof ip !== 'string') return null;
  let s = ip.trim();
  if (s === '') return null;

  const pct = s.indexOf('%');
  if (pct !== -1) s = s.slice(0, pct);
  if (s.startsWith('[') && s.endsWith(']')) s = s.slice(1, -1);
  s = s.toLowerCase();

  const mapped = s.match(/^::ffff:(.+)$/);
  if (mapped) {
    const inner = mapped[1];
    if (net.isIP(inner) === 4) return inner;
    const hx = inner.match(/^([0-9a-f]{1,4}):([0-9a-f]{1,4})$/);
    if (hx) {
      const hi = parseInt(hx[1], 16);
      const lo = parseInt(hx[2], 16);
      return `${(hi >> 8) & 0xff}.${hi & 0xff}.${(lo >> 8) & 0xff}.${lo & 0xff}`;
    }
  }
  return s;
}

/** 4, 6, or 0 (invalid). */
function ipFamily(ip) {
  return net.isIP(normalizeIp(ip) || '');
}

// --- IP <-> BigInt ----------------------------------------------------------

function ipv4ToInt(s) {
  const parts = s.split('.');
  if (parts.length !== 4) return null;
  let v = 0;
  for (const p of parts) {
    if (!/^\d{1,3}$/.test(p)) return null;
    const n = Number(p);
    if (n > 255) return null;
    v = v * 256 + n;
  }
  return v >>> 0;
}

function ipv6ToBigInt(input) {
  let s = input;
  const lastColon = s.lastIndexOf(':');
  const tail = s.slice(lastColon + 1);
  if (tail.includes('.')) {
    const v4 = ipv4ToInt(tail);
    if (v4 === null) return null;
    const hi = (v4 >>> 16) & 0xffff;
    const lo = v4 & 0xffff;
    s = s.slice(0, lastColon + 1) + hi.toString(16) + ':' + lo.toString(16);
  }
  const halves = s.split('::');
  if (halves.length > 2) return null;
  const head = halves[0] ? halves[0].split(':') : [];
  const back = halves.length === 2 ? (halves[1] ? halves[1].split(':') : []) : [];
  let groups;
  if (halves.length === 1) {
    if (head.length !== 8) return null;
    groups = head;
  } else {
    const missing = 8 - (head.length + back.length);
    if (missing < 0) return null;
    groups = [...head, ...Array(missing).fill('0'), ...back];
  }
  if (groups.length !== 8) return null;
  let result = 0n;
  for (const g of groups) {
    if (!/^[0-9a-f]{1,4}$/.test(g)) return null;
    result = (result << 16n) | BigInt(parseInt(g, 16));
  }
  return result;
}

function ipToBigInt(ip) {
  const norm = normalizeIp(ip);
  const fam = net.isIP(norm || '');
  if (fam === 4) {
    const v = ipv4ToInt(norm);
    return v === null ? null : BigInt(v);
  }
  if (fam === 6) return ipv6ToBigInt(norm);
  return null;
}

// --- CIDR -------------------------------------------------------------------

function parseCidr(cidr) {
  if (typeof cidr !== 'string') return null;
  const slash = cidr.indexOf('/');
  const ipPart = slash === -1 ? cidr : cidr.slice(0, slash);
  const norm = normalizeIp(ipPart);
  const fam = net.isIP(norm || '');
  if (fam === 0) return null;
  const bits = fam === 4 ? 32 : 128;
  const prefix = slash === -1 ? bits : Number(cidr.slice(slash + 1));
  if (!Number.isInteger(prefix) || prefix < 0 || prefix > bits) return null;
  const base = ipToBigInt(norm);
  if (base === null) return null;
  return { base, prefix, bits, family: fam };
}

function cidrContains(cidr, ip) {
  const c = parseCidr(cidr);
  if (!c) return false;
  const fam = ipFamily(ip);
  if (fam === 0 || (fam === 4 ? 32 : 128) !== c.bits) return false;
  const v = ipToBigInt(ip);
  if (v === null) return false;
  const hostBits = BigInt(c.bits - c.prefix);
  return v >> hostBits === c.base >> hostBits;
}

function ipInAnyCidr(ip, cidrs) {
  return Array.isArray(cidrs) && cidrs.some((c) => cidrContains(c, ip));
}

// --- classification ---------------------------------------------------------

function isLoopback(ip) {
  const norm = normalizeIp(ip);
  if (!norm) return false;
  if (norm === '::1') return true;
  return cidrContains('127.0.0.0/8', norm);
}

const PRIVATE_V4 = ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '169.254.0.0/16'];
const PRIVATE_V6 = ['fc00::/7', 'fe80::/10'];

function isPrivateIp(ip) {
  const fam = ipFamily(ip);
  if (fam === 4) return isLoopback(ip) || ipInAnyCidr(ip, PRIVATE_V4);
  if (fam === 6) return isLoopback(ip) || ipInAnyCidr(ip, PRIVATE_V6);
  return false;
}

// --- MAC --------------------------------------------------------------------

/** Normalize a MAC to lowercase colon form, or null unless 48 bits present. */
function normalizeMac(mac) {
  if (typeof mac !== 'string') return null;
  const hex = mac.replace(/[^0-9a-fA-F]/g, '').toLowerCase();
  if (hex.length !== 12) return null;
  return hex.match(/.{2}/g).join(':');
}

/**
 * True only for a real, resolved *unicast* neighbor MAC. Rejects the all-zero
 * (incomplete) entry, broadcast, and any multicast (I/G bit set) — the noise
 * that fills a neighbor table and is never a genuine on-segment device.
 */
function isUnicastMac(mac) {
  const m = normalizeMac(mac);
  if (!m) return false;
  if (m === '00:00:00:00:00:00') return false;
  const firstOctet = parseInt(m.slice(0, 2), 16);
  if (firstOctet & 0x01) return false;
  return true;
}

// --- request client IP ------------------------------------------------------

/**
 * Extract the client IP from an http(s) request.
 *
 * SECURITY: defaults to the real TCP peer (`req.socket.remoteAddress`). Only
 * honor `X-Forwarded-For` / `X-Real-IP` when `trustForwardedHeader` is set AND
 * a proxy you control sits in front — otherwise the segment check applies to
 * the spoofer, not the client.
 */
function extractClientIp(req, opts = {}) {
  const sock = (req && (req.socket || req.connection)) || {};
  let ip = sock.remoteAddress;
  if (opts.trustForwardedHeader && req && req.headers) {
    const xri = req.headers['x-real-ip'];
    const xff = req.headers['x-forwarded-for'];
    if (xri) ip = String(xri).trim();
    else if (xff) ip = String(xff).split(',')[0].trim();
  }
  return normalizeIp(ip);
}

module.exports = {
  normalizeIp,
  ipFamily,
  ipToBigInt,
  parseCidr,
  cidrContains,
  ipInAnyCidr,
  isLoopback,
  isPrivateIp,
  normalizeMac,
  isUnicastMac,
  extractClientIp,
};
