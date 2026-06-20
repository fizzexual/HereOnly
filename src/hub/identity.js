'use strict';

/**
 * Stable per-device hub identity.
 *
 * Each machine gets a persistent id, a friendly name, and a stable address
 * derived deterministically from the id — so it never changes even as DHCP
 * reshuffles the machine's real LAN IP. The hub routes by this name/address, so
 * you get a stable handle for every device without any overlay or network
 * reconfig.
 *
 * The address space is configurable (`range`), defaulting to a reserved,
 * never-publicly-routed block so it stays a private world of its own:
 *   - 'class-e'  -> 240.0.0.0/8   (reserved; default; won't collide with LANs,
 *                                  CGNAT, or Tailscale)
 *   - 'cgnat'    -> 100.64.0.0/10 (RFC 6598, Tailscale-style)
 *   - 'ula'      -> fdXX:XXXX:XXXX::/48  (IPv6 Unique Local; the /48 prefix is
 *                                  derived from the shared hub secret, so the
 *                                  address space is unguessable without it)
 *   - any explicit CIDR, e.g. '10.77.0.0/16'
 *
 * The address is decentralized-by-construction (a hash of the id), keeping the
 * "no control plane" promise.
 */

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { parseCidr } = require('../core/ip.js');
const { bigIntToIPv6 } = require('../os/netinfo.js');

const DEFAULT_ID_FILE = '.hereonly/hub-id.json';
const DEFAULT_RANGE = 'class-e';

function sha(s) {
  return crypto.createHash('sha256').update(String(s)).digest();
}

/** A ULA /48 prefix derived from the shared secret (unguessable without it). */
function ulaPrefix(secret) {
  const key = secret ? (Buffer.isBuffer(secret) ? secret.toString('hex') : String(secret)) : 'default';
  const g = sha('hereonly-ula:' + key).slice(0, 5).toString('hex'); // 40-bit global id
  return `fd${g.slice(0, 2)}:${g.slice(2, 6)}:${g.slice(6, 10)}::/48`;
}

/** Resolve a preset name or CIDR to a concrete CIDR string. */
function resolveRange(spec, secret) {
  const s = spec || DEFAULT_RANGE;
  if (typeof s === 'string' && s.includes('/')) return s; // explicit CIDR
  switch (String(s).toLowerCase()) {
    case 'cgnat':
    case 'tailscale':
    case '100':
      return '100.64.0.0/10';
    case 'class-e':
    case 'classe':
    case 'e':
    case '240':
      return '240.0.0.0/8';
    case 'ula':
    case 'v6':
    case 'ipv6':
      return ulaPrefix(secret);
    default:
      return '240.0.0.0/8';
  }
}

function bigToV4(v) {
  const o = [];
  for (let i = 3; i >= 0; i--) o.push(Number((v >> BigInt(i * 8)) & 0xffn));
  return o.join('.');
}

/** Deterministic stable address for `id` within the configured range. */
function addrFromId(id, opts = {}) {
  const cidr = resolveRange(opts.range, opts.secret);
  const c = parseCidr(cidr) || parseCidr('240.0.0.0/8');
  const hostBits = BigInt(c.bits - c.prefix);
  let host = BigInt('0x' + sha('hereonly-addr:' + String(id)).toString('hex'));
  if (hostBits < 256n) host %= 1n << hostBits;
  const net = (c.base >> hostBits) << hostBits;
  let value = net | host;
  if (c.family === 4) {
    const last = value & 0xffn;
    if (last === 0n) value |= 1n; // avoid x.x.x.0
    else if (last === 0xffn) value = (value & ~0xffn) | 0xfen; // avoid x.x.x.255
    return bigToV4(value);
  }
  return bigIntToIPv6(value);
}

/**
 * Load (or create + persist) this host's stable identity.
 * @param {{range?:string, secret?:any}} [addrOpts]
 * @returns {{ id, name, addr, range }}
 */
function loadOrCreateIdentity(file, hostname, nameOverride, addrOpts = {}) {
  const target = file || DEFAULT_ID_FILE;
  let id = null;
  let name = null;
  try {
    const j = JSON.parse(fs.readFileSync(target, 'utf8'));
    if (j && typeof j.id === 'string') {
      id = j.id;
      name = j.name || null;
    }
  } catch {
    /* not created yet */
  }
  if (!id) {
    id = crypto.randomBytes(8).toString('hex');
    name = nameOverride || hostname;
    try {
      fs.mkdirSync(path.dirname(path.resolve(target)), { recursive: true });
      fs.writeFileSync(target, JSON.stringify({ id, name }, null, 2));
    } catch {
      /* ephemeral identity if the path isn't writable */
    }
  }
  return {
    id,
    name: nameOverride || name || hostname,
    addr: addrFromId(id, addrOpts),
    range: resolveRange(addrOpts.range, addrOpts.secret),
  };
}

module.exports = { addrFromId, loadOrCreateIdentity, resolveRange, ulaPrefix, DEFAULT_ID_FILE, DEFAULT_RANGE };
