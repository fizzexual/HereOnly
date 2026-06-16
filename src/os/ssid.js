'use strict';

/**
 * Wi-Fi SSID / BSSID fingerprinting.
 *
 * This is the *optional* network-identity signal. It is inherently
 * platform-flaky (no Wi-Fi hardware, Wi-Fi service stopped, OS privacy
 * restrictions on reading BSSID) so every path degrades gracefully to `null`.
 * HereOnly never depends on Wi-Fi alone — the default gateway MAC and local
 * subnets cover wired networks.
 *
 * getWifi() returns { ssid, bssid } where either field may be null, or
 * { ssid: null, bssid: null } when no Wi-Fi could be determined.
 */

const { run: defaultRun } = require('./exec.js');
const { normalizeMac } = require('../core/ip.js');

const EMPTY = { ssid: null, bssid: null };

function cleanSsid(s) {
  if (s == null) return null;
  const t = String(s).trim();
  if (!t) return null;
  if (/^(disconnected|not associated)$/i.test(t)) return null;
  return t;
}

// ---------------------------------------------------------------------------
// Windows: `netsh wlan show interfaces`
// ---------------------------------------------------------------------------
//     SSID                   : MyNetwork
//     BSSID                  : 58:72:c9:41:36:94
function parseWindowsWlan(text) {
  const s = String(text);
  // No wireless interface / service stopped -> no Wi-Fi.
  if (/is not running|no wireless interface|no such service/i.test(s)) return { ...EMPTY };
  let ssid = null;
  let bssid = null;
  for (const line of s.split(/\r?\n/)) {
    const sm = line.match(/^\s*SSID\s*:\s*(.+?)\s*$/i);
    if (sm) {
      ssid = cleanSsid(sm[1]);
      continue;
    }
    const bm = line.match(/^\s*BSSID\s*:\s*([0-9a-fA-F:.-]+)\s*$/i);
    if (bm) bssid = normalizeMac(bm[1]);
  }
  return { ssid, bssid };
}

// ---------------------------------------------------------------------------
// Linux: `nmcli -t -f active,ssid,bssid dev wifi`
// ---------------------------------------------------------------------------
//   yes:MyNetwork:58\:72\:C9\:41\:36\:94
//   no:OtherNet:AA\:BB\:CC\:DD\:EE\:FF
function parseNmcli(text) {
  for (const line of String(text).split(/\r?\n/)) {
    if (!line.trim()) continue;
    // nmcli escapes the ':' inside the BSSID as '\:' — unescape first.
    const unescaped = line.replace(/\\:/g, '%%C%%');
    const fields = unescaped.split(':').map((f) => f.replace(/%%C%%/g, ':'));
    if (fields[0] === 'yes') {
      return { ssid: cleanSsid(fields[1]), bssid: normalizeMac(fields[2] || '') };
    }
  }
  return { ...EMPTY };
}

// Linux fallback: `iwgetid -r` (SSID) and `iwgetid -a` (BSSID).
function parseIwgetidSsid(text) {
  return cleanSsid(text);
}
function parseIwgetidApMac(text) {
  // "wlan0     Access Point/Cell: 58:72:C9:41:36:94"
  const m = String(text).match(/([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})/);
  return m ? normalizeMac(m[1]) : null;
}

// ---------------------------------------------------------------------------
// macOS: `networksetup -getairportnetwork en0`
// ---------------------------------------------------------------------------
//   Current Wi-Fi Network: MyNetwork
//   (or) You are not associated with an AirPort network.
function parseNetworksetup(text) {
  const s = String(text);
  const m = s.match(/Current Wi-?Fi Network:\s*(.+?)\s*$/im);
  if (m) return { ssid: cleanSsid(m[1]), bssid: null };
  return { ...EMPTY };
}

// macOS legacy airport -I: "         SSID: MyNetwork" / "        BSSID: 58:72:c9:..."
function parseAirport(text) {
  const s = String(text);
  let ssid = null;
  let bssid = null;
  const sm = s.match(/^\s*SSID:\s*(.+?)\s*$/im);
  if (sm) ssid = cleanSsid(sm[1]);
  const bm = s.match(/^\s*BSSID:\s*([0-9a-fA-F:.-]+)\s*$/im);
  if (bm) bssid = normalizeMac(bm[1]);
  return { ssid, bssid };
}

const AIRPORT_BIN =
  '/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport';

/**
 * Determine current Wi-Fi SSID/BSSID, best-effort.
 * @returns {Promise<{ ssid: string|null, bssid: string|null }>}
 */
async function getWifi({ run = defaultRun, platform = process.platform } = {}) {
  try {
    if (platform === 'win32') {
      const r = await run('netsh', ['wlan', 'show', 'interfaces']);
      // netsh returns non-zero when the service is stopped; still parse stdout.
      return parseWindowsWlan((r.stdout || '') + (r.stderr || ''));
    }
    if (platform === 'linux') {
      const r = await run('nmcli', ['-t', '-f', 'active,ssid,bssid', 'dev', 'wifi']);
      if (r.ok && r.stdout.trim()) {
        const res = parseNmcli(r.stdout);
        if (res.ssid || res.bssid) return res;
      }
      const s = await run('iwgetid', ['-r']);
      const a = await run('iwgetid', ['-a']);
      const ssid = s.ok ? parseIwgetidSsid(s.stdout) : null;
      const bssid = a.ok ? parseIwgetidApMac(a.stdout) : null;
      return { ssid, bssid };
    }
    if (platform === 'darwin') {
      const air = await run(AIRPORT_BIN, ['-I']);
      if (air.ok && /SSID/i.test(air.stdout)) {
        const res = parseAirport(air.stdout);
        if (res.ssid || res.bssid) return res;
      }
      const ns = await run('networksetup', ['-getairportnetwork', 'en0']);
      return ns.ok ? parseNetworksetup(ns.stdout) : { ...EMPTY };
    }
    return { ...EMPTY };
  } catch {
    return { ...EMPTY };
  }
}

module.exports = {
  getWifi,
  parseWindowsWlan,
  parseNmcli,
  parseIwgetidSsid,
  parseIwgetidApMac,
  parseNetworksetup,
  parseAirport,
  cleanSsid,
};
