'use strict';

/**
 * Neighbor-table (ARP / NDP) reading and parsing — dual-stack.
 *
 * The presence of a *unicast* neighbor entry for a client IP is HereOnly's
 * core proof of Layer-2 adjacency: a neighbor entry exists only for a device
 * the host resolved on-link. Off-segment clients reach the host via the
 * gateway, so the host has a neighbor entry for the gateway — never for them.
 *
 * IPv4 (ARP) and IPv6 (NDP) are both read on every platform:
 *   Windows : `arp -a`            + `netsh interface ipv6 show neighbors`
 *   Linux   : `ip neigh`          (both families; /proc/net/arp v4 fallback)
 *   macOS   : `arp -an`           + `ndp -an`
 */

const { run: defaultRun } = require('./exec.js');
const { normalizeIp, normalizeMac, isUnicastMac } = require('../core/ip.js');

function normState(raw, hasMac) {
  const s = String(raw || '').toLowerCase();
  if (s.includes('incomplete') || s.includes('failed') || s.includes('unreachable')) return 'incomplete';
  if (s.includes('reachable')) return 'reachable';
  if (s.includes('stale')) return 'stale';
  if (s.includes('permanent') || s.includes('static') || s.includes('noarp')) return 'permanent';
  if (s.includes('dynamic')) return 'reachable';
  if (s.includes('delay') || s.includes('probe')) return 'stale';
  return hasMac ? 'reachable' : 'incomplete';
}

function makeNeighbor(ip, rawMac, rawState, iface) {
  const mac = normalizeMac(rawMac);
  return {
    ip: normalizeIp(ip),
    mac,
    state: normState(rawState, !!mac),
    unicast: mac ? isUnicastMac(mac) : false,
    iface: iface || null,
    rawState: rawState || null,
  };
}

// BSD `arp`/`ndp` print MAC octets without leading zeros (e.g. 84:47:9:..).
function padBsdMac(raw) {
  if (typeof raw !== 'string' || !raw.includes(':')) return raw;
  const parts = raw.split(':');
  if (parts.length !== 6) return raw;
  return parts.map((p) => p.padStart(2, '0')).join(':');
}

// --- Windows ----------------------------------------------------------------

function parseWindowsArp(text) {
  const out = [];
  let iface = null;
  for (const line of String(text).split(/\r?\n/)) {
    const ifMatch = line.match(/^Interface:\s*([\d.]+)/i);
    if (ifMatch) {
      iface = ifMatch[1];
      continue;
    }
    const m = line.match(/^\s*(\d{1,3}(?:\.\d{1,3}){3})\s+([0-9a-fA-F-]{17})\s+(\w+)/);
    if (m) out.push(makeNeighbor(m[1], m[2], m[3], iface));
  }
  return out;
}

// `netsh interface ipv6 show neighbors`
//   Interface 12: Ethernet
//   Internet Address      Physical Address   Type
//   fe80::1               58-72-c9-41-36-94  Reachable (Router)
function parseWindowsNdp(text) {
  const out = [];
  let iface = null;
  for (const line of String(text).split(/\r?\n/)) {
    const ifMatch = line.match(/^Interface\s+\d+:\s*(.+?)\s*$/i);
    if (ifMatch) {
      iface = ifMatch[1];
      continue;
    }
    const m = line.match(/^\s*([0-9a-fA-F:]+(?:%\w+)?)\s+([0-9a-fA-F-]{17})\s+(.+?)\s*$/);
    if (m && m[1].includes(':')) out.push(makeNeighbor(m[1], m[2], m[3], iface));
  }
  return out;
}

// --- Linux ------------------------------------------------------------------

function parseIpNeigh(text) {
  const out = [];
  for (const line of String(text).split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    const tokens = trimmed.split(/\s+/);
    const ip = tokens[0];
    let mac = null;
    let iface = null;
    const devIdx = tokens.indexOf('dev');
    if (devIdx !== -1 && tokens[devIdx + 1]) iface = tokens[devIdx + 1];
    const llIdx = tokens.indexOf('lladdr');
    if (llIdx !== -1 && tokens[llIdx + 1]) mac = tokens[llIdx + 1];
    out.push(makeNeighbor(ip, mac, tokens[tokens.length - 1], iface));
  }
  return out;
}

function parseProcNetArp(text) {
  const out = [];
  const lines = String(text).split(/\r?\n/).slice(1);
  for (const line of lines) {
    const cols = line.trim().split(/\s+/);
    if (cols.length < 6) continue;
    const [ip, , flags, mac, , device] = cols;
    out.push(makeNeighbor(ip, mac, flags === '0x0' ? 'incomplete' : 'reachable', device));
  }
  return out;
}

// --- macOS / BSD ------------------------------------------------------------

function parseMacArp(text) {
  const out = [];
  for (const line of String(text).split(/\r?\n/)) {
    const m = line.match(/\(([\d.]+)\)\s+at\s+(\S+)\s+on\s+(\w+)/i);
    if (!m) continue;
    if (/incomplete/i.test(m[2])) out.push(makeNeighbor(m[1], null, 'incomplete', m[3]));
    else out.push(makeNeighbor(m[1], padBsdMac(m[2]), 'reachable', m[3]));
  }
  return out;
}

// `ndp -an`: Neighbor  Linklayer Address  Netif  Expire  St  Flgs  Prbs
function parseMacNdp(text) {
  const out = [];
  for (const line of String(text).split(/\r?\n/)) {
    if (/^\s*Neighbor\b/i.test(line)) continue;
    const tokens = line.trim().split(/\s+/);
    if (tokens.length < 2 || !tokens[0].includes(':')) continue;
    const ip = tokens[0].split('%')[0];
    const iface = tokens[0].includes('%') ? tokens[0].split('%')[1] : tokens[2] || null;
    const ll = tokens[1];
    if (/incomplete/i.test(ll)) out.push(makeNeighbor(ip, null, 'incomplete', iface));
    else if (ll.includes(':')) out.push(makeNeighbor(ip, padBsdMac(ll), 'reachable', iface));
  }
  return out;
}

// --- dispatch ---------------------------------------------------------------

async function readNeighbors({ run = defaultRun, platform = process.platform } = {}) {
  if (platform === 'win32') {
    const [v4, v6] = await Promise.all([
      run('arp', ['-a']),
      run('netsh', ['interface', 'ipv6', 'show', 'neighbors']),
    ]);
    const neighbors = [];
    if (v4.ok) neighbors.push(...parseWindowsArp(v4.stdout));
    if (v6.ok) neighbors.push(...parseWindowsNdp(v6.stdout));
    return { ok: v4.ok, source: 'windows:arp+ndp', neighbors };
  }
  if (platform === 'linux') {
    const r = await run('ip', ['neigh']);
    if (r.ok && r.stdout.trim()) return { ok: true, source: 'linux:ip-neigh', neighbors: parseIpNeigh(r.stdout) };
    const r2 = await run('cat', ['/proc/net/arp']);
    return { ok: r2.ok, source: 'linux:proc-net-arp', neighbors: r2.ok ? parseProcNetArp(r2.stdout) : [] };
  }
  if (platform === 'darwin') {
    const [v4, v6] = await Promise.all([run('arp', ['-an']), run('ndp', ['-an'])]);
    const neighbors = [];
    if (v4.ok) neighbors.push(...parseMacArp(v4.stdout));
    if (v6.ok) neighbors.push(...parseMacNdp(v6.stdout));
    return { ok: v4.ok, source: 'darwin:arp+ndp', neighbors };
  }
  const r = await run('arp', ['-an']);
  return { ok: r.ok, source: 'unknown:arp', neighbors: r.ok ? parseMacArp(r.stdout) : [] };
}

async function lookupNeighbor(ip, opts = {}) {
  const target = normalizeIp(ip);
  const { ok, source, neighbors } = await readNeighbors(opts);
  const neighbor = target ? neighbors.find((n) => n.ip === target) || null : null;
  return { ok, source, neighbor };
}

module.exports = {
  readNeighbors,
  lookupNeighbor,
  parseWindowsArp,
  parseWindowsNdp,
  parseIpNeigh,
  parseProcNetArp,
  parseMacArp,
  parseMacNdp,
  padBsdMac,
  normState,
};
