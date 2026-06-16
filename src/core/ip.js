'use strict';

/**
 * IP and MAC address utilities for HereOnly.
 *
 * Zero dependencies. Handles IPv4, IPv6, and the IPv4-mapped-IPv6 form
 * (`::ffff:a.b.c.d`) that Node hands back for dual-stack sockets. CIDR math is
 * done with BigInt so the same code path covers v4 (/0../32) and v6 (/0../128).
 */

const net = require('node:net');

// ---------------------------------------------------------------------------
// Normalization
// ---------------------------------------------------------------------------

/**
 * Best-effort normalize an address string:
 *  - trims whitespace and surrounding brackets (`[::1]` -> `::1`)
 *  - strips an IPv6 zone/scope id (`fe80::1%eth0` -> `fe80::1`)
 *  - lowercases
 *  - unwraps IPv4-mapped IPv6 (`::ffff:192.168.1.5` -> `192.168.1.5`,
 *    including the hex form `::ffff:c0a8:0105`)
 *
 * Returns the cleaned string, or `null` for non-string / empty input.
 * Does NOT guarantee validity — use {@link ipFamily} to validate.
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

/** Returns 4, 6, or 0 (invalid). Normalizes first. */
function ipFamily(ip) {
  return net.isIP(normalizeIp(ip) || '');
}

// ---------------------------------------------------------------------------
// IP <-> BigInt
// ---------------------------------------------------------------------------

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

  // Embedded IPv4 tail, e.g. "::ffff:1.2.3.4" or "64:ff9b::192.0.2.1"
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

/** Convert a v4/v6 address to a BigInt, or `null` if invalid. */
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

// ---------------------------------------------------------------------------
// CIDR
// ---------------------------------------------------------------------------

/**
 * Parse `"192.168.1.0/24"` (or a bare address -> host route) into
 * `{ base, prefix, bits, family }`, or `null` if malformed.
 */
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

/** True if `ip` is inside `cidr`. Family must match. */
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

/** True if `ip` is inside any CIDR in the list. */
function ipInAnyCidr(ip, cidrs) {
  if (!Array.isArray(cidrs)) return false;
  return cidrs.some((c) => cidrContains(c, ip));
}

// ---------------------------------------------------------------------------
// Classification
// ---------------------------------------------------------------------------

/** True for 127.0.0.0/8 and ::1. */
function isLoopback(ip) {
  const norm = normalizeIp(ip);
  if (!norm) return false;
  if (norm === '::1') return true;
  return cidrContains('127.0.0.0/8', norm);
}

const PRIVATE_V4 = ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '169.254.0.0/16'];
const PRIVATE_V6 = ['fc00::/7', 'fe80::/10'];

/** True for RFC1918 / link-local / ULA / loopback ranges. */
function isPrivateIp(ip) {
  const fam = ipFamily(ip);
  if (fam === 4) return isLoopback(ip) || ipInAnyCidr(ip, PRIVATE_V4);
  if (fam === 6) return isLoopback(ip) || ipInAnyCidr(ip, PRIVATE_V6);
  return false;
}

// ---------------------------------------------------------------------------
// MAC
// ---------------------------------------------------------------------------

/**
 * Normalize a MAC to lowercase colon form `aa:bb:cc:dd:ee:ff`.
 * Accepts dash, colon, dot (Cisco `aabb.ccdd.eeff`), or bare-hex separators.
 * Returns `null` unless exactly 48 bits (12 hex digits) are present.
 */
function normalizeMac(mac) {
  if (typeof mac !== 'string') return null;
  const hex = mac.replace(/[^0-9a-fA-F]/g, '').toLowerCase();
  if (hex.length !== 12) return null;
  return hex.match(/.{2}/g).join(':');
}

/**
 * True only for a *real, resolved* unicast neighbor MAC. Rejects:
 *  - the all-zero address (an incomplete / unresolved ARP entry)
 *  - broadcast `ff:ff:ff:ff:ff:ff`
 *  - any multicast address (I/G low bit of the first octet set:
 *    `01:00:5e:*` IPv4 multicast, `33:33:*` IPv6 multicast, etc.)
 *
 * This is the predicate that distinguishes a genuine on-segment device from
 * the multicast/broadcast/incomplete noise in a neighbor table.
 */
function isUnicastMac(mac) {
  const m = normalizeMac(mac);
  if (!m) return false;
  if (m === '00:00:00:00:00:00') return false;
  const firstOctet = parseInt(m.slice(0, 2), 16);
  if (firstOctet & 0x01) return false; // multicast/broadcast (I/G bit)
  return true;
}

// ---------------------------------------------------------------------------
// Request client IP
// ---------------------------------------------------------------------------

/**
 * Extract the client IP from an http(s) request.
 *
 * SECURITY: by default this returns the real TCP peer address
 * (`req.socket.remoteAddress`). HereOnly's entire model depends on the source
 * address being the *actual* packet source — which `X-Forwarded-For` is not, as
 * any client can set it. Only enable `trustForwardedHeader` when a trusted
 * proxy you control sits in front AND you understand that the segment check then
 * applies to that proxy, not the end client.
 *
 * @param {import('http').IncomingMessage} req
 * @param {{ trustForwardedHeader?: boolean }} [opts]
 * @returns {string|null} normalized IP, or null
 */
function extractClientIp(req, opts = {}) {
  const sock = (req && (req.socket || req.connection)) || {};
  let ip = sock.remoteAddress;
  if (opts.trustForwardedHeader && req && req.headers) {
    const xff = req.headers['x-forwarded-for'];
    if (xff) ip = String(xff).split(',')[0].trim();
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
