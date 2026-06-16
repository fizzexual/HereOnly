'use strict';

/**
 * Host network info: interfaces, local subnets, default gateway (+ its MAC).
 *
 * Interface/subnet data comes from os.networkInterfaces() — pure Node, always
 * available. The gateway MAC (resolved from the neighbor table) is HereOnly's
 * strongest always-available network-identity signal, present even on wired
 * networks with no Wi-Fi SSID.
 */

const os = require('node:os');
const { run: defaultRun } = require('./exec.js');
const { normalizeIp, normalizeMac, parseCidr } = require('../core/ip.js');
const { lookupNeighbor } = require('./neighbors.js');

function famNum(family) {
  if (family === 4 || family === 6) return family;
  if (family === 'IPv4') return 4;
  if (family === 'IPv6') return 6;
  return 0;
}

function getInterfaces() {
  const out = [];
  for (const [name, addrs] of Object.entries(os.networkInterfaces())) {
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

function isLinkLocalAddr(address) {
  if (!address) return false;
  return address.startsWith('169.254.') || address.toLowerCase().startsWith('fe80:');
}

function bigIntToIPv6(value) {
  const groups = [];
  for (let i = 7; i >= 0; i--) groups.push(Number((value >> BigInt(i * 16)) & 0xffffn).toString(16));
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
    return `${groups.slice(0, bestStart).join(':')}::${groups.slice(bestStart + bestLen).join(':')}`;
  }
  return groups.join(':');
}

/** Zero host bits for a stable canonical CIDR (critical for IPv6 SLAAC churn). */
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
    if (c.prefix === c.bits && !includeHostRoutes) continue; // skip /32, /128 (incl. mesh VPNs)
    const canon = canonicalizeCidr(i.cidr);
    if (seen.has(canon)) continue;
    seen.add(canon);
    out.push(canon);
  }
  return out;
}

function parseWindowsGateway(text) {
  let best = null;
  for (const line of String(text).split(/\r?\n/)) {
    const m = line.match(/^\s*0\.0\.0\.0\s+0\.0\.0\.0\s+([\d.]+)\s+([\d.]+)\s+(\d+)/);
    if (!m) continue;
    if (!/^\d+\.\d+\.\d+\.\d+$/.test(m[1])) continue; // skip "On-link"
    const metric = Number(m[3]);
    if (!best || metric < best.metric) best = { gateway: m[1], metric };
  }
  return best ? best.gateway : null;
}

function parseLinuxGateway(text) {
  const m = String(text).match(/default\s+via\s+([\da-fA-F:.]+)/);
  return m ? normalizeIp(m[1]) : null;
}

function parseMacGateway(text) {
  const m = String(text).match(/gateway:\s*([\da-fA-F:.]+)/);
  return m ? normalizeIp(m[1]) : null;
}

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
  bigIntToIPv6,
  parseWindowsGateway,
  parseLinuxGateway,
  parseMacGateway,
};
