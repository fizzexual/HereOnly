'use strict';

/**
 * Wi-Fi SSID / BSSID fingerprinting — the *optional* network-identity signal.
 * Inherently platform-flaky (no Wi-Fi hardware, service stopped, OS privacy
 * limits on BSSID), so every path degrades gracefully to null. HereOnly never
 * depends on Wi-Fi alone — gateway MAC + subnets cover wired networks.
 */

const { run: defaultRun } = require('./exec.js');
const { normalizeMac } = require('../core/ip.js');

const EMPTY = { ssid: null, bssid: null };

function cleanSsid(s) {
  if (s == null) return null;
  const t = String(s).trim();
  if (!t || /^(disconnected|not associated)$/i.test(t)) return null;
  return t;
}

function parseWindowsWlan(text) {
  const s = String(text);
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

function parseNmcli(text) {
  for (const line of String(text).split(/\r?\n/)) {
    if (!line.trim()) continue;
    const unescaped = line.replace(/\\:/g, '%%C%%');
    const fields = unescaped.split(':').map((f) => f.replace(/%%C%%/g, ':'));
    if (fields[0] === 'yes') return { ssid: cleanSsid(fields[1]), bssid: normalizeMac(fields[2] || '') };
  }
  return { ...EMPTY };
}

function parseIwgetidSsid(text) {
  return cleanSsid(text);
}
function parseIwgetidApMac(text) {
  const m = String(text).match(/([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})/);
  return m ? normalizeMac(m[1]) : null;
}

function parseNetworksetup(text) {
  const m = String(text).match(/Current Wi-?Fi Network:\s*(.+?)\s*$/im);
  return m ? { ssid: cleanSsid(m[1]), bssid: null } : { ...EMPTY };
}

function parseAirport(text) {
  const s = String(text);
  const sm = s.match(/^\s*SSID:\s*(.+?)\s*$/im);
  const bm = s.match(/^\s*BSSID:\s*([0-9a-fA-F:.-]+)\s*$/im);
  return { ssid: sm ? cleanSsid(sm[1]) : null, bssid: bm ? normalizeMac(bm[1]) : null };
}

const AIRPORT_BIN =
  '/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport';

async function getWifi({ run = defaultRun, platform = process.platform } = {}) {
  try {
    if (platform === 'win32') {
      const r = await run('netsh', ['wlan', 'show', 'interfaces']);
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
      return { ssid: s.ok ? parseIwgetidSsid(s.stdout) : null, bssid: a.ok ? parseIwgetidApMac(a.stdout) : null };
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
