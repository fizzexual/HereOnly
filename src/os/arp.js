'use strict';

/**
 * Neighbor-table (ARP / NDP) reading and parsing.
 *
 * The presence of a *unicast* neighbor entry for a client IP is HereOnly's
 * core proof of Layer-2 adjacency: a neighbor entry only exists for a device
 * the host resolved on-link. Off-segment clients reach the host via the
 * gateway, so the host has a neighbor entry for the gateway — never for them.
 *
 * Each platform parser returns an array of normalized neighbors:
 *   { ip, mac, state, unicast, iface, rawState }
 * where `mac` is normalized (or null) and `unicast` marks a real device
 * (rejecting multicast / broadcast / incomplete rows).
 */

const { run: defaultRun } = require('./exec.js');
const { normalizeIp, normalizeMac, isUnicastMac } = require('../core/ip.js');

/** Map a platform-specific state string to a normalized enum. */
function normState(raw, hasMac) {
  const s = String(raw || '').toLowerCase();
  if (s.includes('incomplete') || s.includes('failed')) return 'incomplete';
  if (s.includes('reachable')) return 'reachable';
  if (s.includes('stale')) return 'stale';
  if (s.includes('permanent') || s.includes('static') || s.includes('noarp')) return 'permanent';
  if (s.includes('dynamic')) return 'reachable';
  if (s.includes('delay') || s.includes('probe')) return 'stale';
  return hasMac ? 'reachable' : 'incomplete';
}

function makeNeighbor(ip, rawMac, rawState, iface) {
  const nIp = normalizeIp(ip);
  const mac = normalizeMac(rawMac);
  return {
    ip: nIp,
    mac,
    state: normState(rawState, !!mac),
    unicast: mac ? isUnicastMac(mac) : false,
    iface: iface || null,
    rawState: rawState || null,
  };
}

// ---------------------------------------------------------------------------
// Windows: `arp -a`
// ---------------------------------------------------------------------------
//   Interface: 192.168.100.2 --- 0x12
//     Internet Address      Physical Address      Type
//     192.168.100.1         58-72-c9-41-36-94     dynamic
function parseWindowsArp(text) {
  const out = [];
  let iface = null;
  for (const line of String(text).split(/\r?\n/)) {
    const ifMatch = line.match(/^Interface:\s*([\d.]+)/i);
    if (ifMatch) {
      iface = ifMatch[1];
      continue;
    }
    const m = line.match(/^\s*([\d]{1,3}(?:\.[\d]{1,3}){3})\s+([0-9a-fA-F-]{17})\s+(\w+)/);
    if (m) out.push(makeNeighbor(m[1], m[2], m[3], iface));
  }
  return out;
}

// ---------------------------------------------------------------------------
// Linux: `ip neigh`
// ---------------------------------------------------------------------------
//   192.168.1.1 dev eth0 lladdr 58:72:c9:41:36:94 REACHABLE
//   192.168.1.9 dev eth0  INCOMPLETE
//   fe80::1 dev eth0 lladdr 58:72:c9:41:36:94 router REACHABLE
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
    const state = tokens[tokens.length - 1];
    out.push(makeNeighbor(ip, mac, state, iface));
  }
  return out;
}

// ---------------------------------------------------------------------------
// Linux fallback: /proc/net/arp
// ---------------------------------------------------------------------------
//   IP address       HW type   Flags  HW address          Mask  Device
//   192.168.1.1      0x1       0x2    58:72:c9:41:36:94    *     eth0
function parseProcNetArp(text) {
  const out = [];
  const lines = String(text).split(/\r?\n/).slice(1); // drop header
  for (const line of lines) {
    const cols = line.trim().split(/\s+/);
    if (cols.length < 6) continue;
    const [ip, , flags, mac, , device] = cols;
    // Flags 0x0 == incomplete; treat 00:00:00:00:00:00 as unresolved.
    const state = flags === '0x0' ? 'incomplete' : 'reachable';
    out.push(makeNeighbor(ip, mac, state, device));
  }
  return out;
}

// ---------------------------------------------------------------------------
// macOS / BSD: `arp -an`
// ---------------------------------------------------------------------------
//   ? (192.168.1.1) at 58:72:c9:41:36:94 on en0 ifscope [ethernet]
//   ? (192.168.1.5) at 84:47:9:75:92:32 on en0 ifscope [ethernet]   <- octets unpadded!
//   ? (192.168.1.9) at (incomplete) on en0 ifscope [ethernet]
function padBsdMac(raw) {
  if (typeof raw !== 'string' || !raw.includes(':')) return raw;
  const parts = raw.split(':');
  if (parts.length !== 6) return raw;
  return parts.map((p) => p.padStart(2, '0')).join(':');
}

function parseMacArp(text) {
  const out = [];
  for (const line of String(text).split(/\r?\n/)) {
    const m = line.match(/\(([\d.]+)\)\s+at\s+(\S+)\s+on\s+(\w+)/i);
    if (!m) continue;
    const ip = m[1];
    const macField = m[2];
    const iface = m[3];
    if (/incomplete/i.test(macField)) {
      out.push(makeNeighbor(ip, null, 'incomplete', iface));
    } else {
      out.push(makeNeighbor(ip, padBsdMac(macField), 'reachable', iface));
    }
  }
  return out;
}

// ---------------------------------------------------------------------------
// Dispatch
// ---------------------------------------------------------------------------

/**
 * Read and normalize the host's neighbor table.
 * @param {{ run?: Function, platform?: string }} [opts]
 * @returns {Promise<{ ok: boolean, source: string, neighbors: object[] }>}
 */
async function readNeighbors({ run = defaultRun, platform = process.platform } = {}) {
  if (platform === 'win32') {
    const r = await run('arp', ['-a']);
    return { ok: r.ok, source: 'windows:arp', neighbors: r.ok ? parseWindowsArp(r.stdout) : [] };
  }
  if (platform === 'linux') {
    const r = await run('ip', ['neigh']);
    if (r.ok && r.stdout.trim()) {
      return { ok: true, source: 'linux:ip-neigh', neighbors: parseIpNeigh(r.stdout) };
    }
    const r2 = await run('cat', ['/proc/net/arp']);
    return { ok: r2.ok, source: 'linux:proc-net-arp', neighbors: r2.ok ? parseProcNetArp(r2.stdout) : [] };
  }
  if (platform === 'darwin') {
    const r = await run('arp', ['-an']);
    return { ok: r.ok, source: 'darwin:arp', neighbors: r.ok ? parseMacArp(r.stdout) : [] };
  }
  // Unknown platform: best-effort BSD-style arp.
  const r = await run('arp', ['-an']);
  return { ok: r.ok, source: 'unknown:arp', neighbors: r.ok ? parseMacArp(r.stdout) : [] };
}

/**
 * Look up a single IP in the neighbor table.
 * @returns {Promise<{ ok, source, neighbor: object|null }>}
 */
async function lookupNeighbor(ip, opts = {}) {
  const target = normalizeIp(ip);
  const { ok, source, neighbors } = await readNeighbors(opts);
  const neighbor = target ? neighbors.find((n) => n.ip === target) || null : null;
  return { ok, source, neighbor };
}

module.exports = {
  readNeighbors,
  lookupNeighbor,
  // parsers exported for unit testing
  parseWindowsArp,
  parseIpNeigh,
  parseProcNetArp,
  parseMacArp,
  padBsdMac,
  normState,
};
