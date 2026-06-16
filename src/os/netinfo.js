'use strict';

/**
 * Host network information: interfaces, local subnets, and the default gateway.
 *
 * Interface/subnet data comes from `os.networkInterfaces()` — pure Node, no
 * shelling, always available. The default gateway is parsed per-platform; the
 * gateway's MAC (looked up in the neighbor table) is HereOnly's strongest
 * always-available network-identity signal, since it is present even on wired
 * networks with no Wi-Fi SSID.
 */

const os = require('node:os');
const { run: defaultRun } = require('./exec.js');
const { normalizeIp, normalizeMac, parseCidr } = require('../core/ip.js');
const { lookupNeighbor } = require('./arp.js');

/** Normalize Node's family field ('IPv4'/'IPv6' or 4/6) to 4/6. */
function famNum(family) {
  if (family === 4 || family === 6) return family;
  if (family === 'IPv4') return 4;
  if (family === 'IPv6') return 6;
  return 0;
}

/** All interface addresses, normalized. */
function getInterfaces() {
  const out = [];
  const ifaces = os.networkInterfaces();
  for (const [name, addrs] of Object.entries(ifaces)) {
    for (const a of addrs || []) {
      out.push({
        name,
        address: normalizeIp(a.address),
        netmask: a.netmask,
        family: famNum(a.family),
        mac: normalizeMac(a.mac),
        internal: !!a.internal,
        cidr: a.cidr || null,
      });
    }
  }
  return out;
}

/** True for 169.254.0.0/16 (APIPA) or fe80::/10 link-local. */
function isLinkLocalAddr(address) {
  if (!address) return false;
  if (address.startsWith('169.254.')) return true;
  if (address.toLowerCase().startsWith('fe80:')) return true;
  return false;
}

/** Format a 128-bit BigInt as a compressed IPv6 string. */
function bigIntToIPv6(value) {
  const groups = [];
  for (let i = 7; i >= 0; i--) groups.push(Number((value >> BigInt(i * 16)) & 0xffffn).toString(16));
  // Compress the longest run (length >= 2) of zero groups into "::".
  let bestStart = -1;
  let bestLen = 0;
  let curStart = -1;
  let curLen = 0;
  for (let i = 0; i < 8; i++) {
    if (groups[i] === '0') {
      if (curStart < 0) curStart = i;
      curLen++;
      if (curLen > bestLen) {
        bestLen = curLen;
        bestStart = curStart;
      }
    } else {
      curStart = -1;
      curLen = 0;
    }
  }
  if (bestLen > 1) {
    const head = groups.slice(0, bestStart).join(':');
    const tail = groups.slice(bestStart + bestLen).join(':');
    return `${head}::${tail}`;
  }
  return groups.join(':');
}

/**
 * Zero the host bits of a CIDR for a stable canonical form. Critical for IPv6:
 * SLAAC privacy extensions rotate the host portion, so the network fingerprint
 * must key on the network prefix only, not the full (changing) address.
 */
function canonicalizeCidr(cidr) {
  const c = parseCidr(cidr);
  if (!c) return cidr;
  const hostBits = BigInt(c.bits - c.prefix);
  const net = (c.base >> hostBits) << hostBits;
  if (c.family === 4) {
    const b = [];
    for (let i = 3; i >= 0; i--) b.push(Number((net >> BigInt(i * 8)) & 0xffn));
    return `${b.join('.')}/${c.prefix}`;
  }
  return `${bigIntToIPv6(net)}/${c.prefix}`;
}

/**
 * Local subnets as CIDR strings, suitable for membership testing.
 *
 * Single-host routes (/32 v4, /128 v6) are excluded by default: they have no
 * on-segment peers, so they can't define a "same subnet" relationship. This
 * also naturally drops mesh-VPN addresses like Tailscale's 100.x/32, which is
 * correct — HereOnly gates the *physical* segment, not an overlay.
 *
 * @param {{ includeInternal?: boolean, includeLinkLocal?: boolean, includeHostRoutes?: boolean }} [opts]
 */
function getLocalSubnets(opts = {}) {
  const { includeInternal = false, includeLinkLocal = false, includeHostRoutes = false } = opts;
  const seen = new Set();
  const out = [];
  for (const i of getInterfaces()) {
    if (!i.cidr) continue;
    if (i.internal && !includeInternal) continue;
    if (isLinkLocalAddr(i.address) && !includeLinkLocal) continue;
    const c = parseCidr(i.cidr);
    if (!c) continue;
    if (c.prefix === c.bits && !includeHostRoutes) continue; // skip /32, /128
    const canon = canonicalizeCidr(i.cidr);
    if (seen.has(canon)) continue;
    seen.add(canon);
    out.push(canon);
  }
  return out;
}

// ---------------------------------------------------------------------------
// Default gateway
// ---------------------------------------------------------------------------

// Windows: `route print -4` -> Active Routes; the default route has
// destination 0.0.0.0 and netmask 0.0.0.0. Choose the lowest metric.
function parseWindowsGateway(text) {
  let best = null;
  for (const line of String(text).split(/\r?\n/)) {
    const m = line.match(
      /^\s*0\.0\.0\.0\s+0\.0\.0\.0\s+([\d.]+)\s+([\d.]+)\s+(\d+)/,
    );
    if (!m) continue;
    const gateway = m[1];
    const metric = Number(m[3]);
    if (!/^\d+\.\d+\.\d+\.\d+$/.test(gateway)) continue; // skip "On-link"
    if (!best || metric < best.metric) best = { gateway, ifaceAddr: m[2], metric };
  }
  return best ? best.gateway : null;
}

// Linux: `ip route show default` -> "default via 192.168.1.1 dev eth0 ..."
function parseLinuxGateway(text) {
  const m = String(text).match(/default\s+via\s+([\da-fA-F:.]+)/);
  return m ? normalizeIp(m[1]) : null;
}

// macOS: `route -n get default` -> a line "    gateway: 192.168.1.1"
function parseMacGateway(text) {
  const m = String(text).match(/gateway:\s*([\da-fA-F:.]+)/);
  return m ? normalizeIp(m[1]) : null;
}

/**
 * Determine the default-gateway IP.
 * @returns {Promise<string|null>}
 */
async function getDefaultGateway({ run = defaultRun, platform = process.platform } = {}) {
  if (platform === 'win32') {
    const r = await run('route', ['print', '-4']);
    return r.ok ? parseWindowsGateway(r.stdout) : null;
  }
  if (platform === 'linux') {
    const r = await run('ip', ['route', 'show', 'default']);
    return r.ok ? parseLinuxGateway(r.stdout) : null;
  }
  if (platform === 'darwin') {
    const r = await run('route', ['-n', 'get', 'default']);
    return r.ok ? parseMacGateway(r.stdout) : null;
  }
  return null;
}

/**
 * Resolve the default gateway and its MAC.
 * @returns {Promise<{ ip: string|null, mac: string|null }>}
 */
async function getGateway(opts = {}) {
  const ip = await getDefaultGateway(opts);
  if (!ip) return { ip: null, mac: null };
  const { neighbor } = await lookupNeighbor(ip, opts);
  return { ip, mac: neighbor ? neighbor.mac : null };
}

module.exports = {
  getInterfaces,
  getLocalSubnets,
  getDefaultGateway,
  getGateway,
  canonicalizeCidr,
  isLinkLocalAddr,
  famNum,
  // parsers for tests
  parseWindowsGateway,
  parseLinuxGateway,
  parseMacGateway,
};
