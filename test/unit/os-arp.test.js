'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');

const {
  parseWindowsArp,
  parseIpNeigh,
  parseProcNetArp,
  parseMacArp,
  padBsdMac,
  readNeighbors,
  lookupNeighbor,
} = require('../../src/os/arp.js');

// Real captured `arp -a` output from a Windows host (wired, no Wi-Fi).
const WIN_ARP = `
Interface: 192.168.100.2 --- 0x12
  Internet Address      Physical Address      Type
  192.168.100.1         58-72-c9-41-36-94     dynamic
  192.168.100.5         84-47-09-75-92-32     dynamic
  192.168.100.255       ff-ff-ff-ff-ff-ff     static
  224.0.0.22            01-00-5e-00-00-16     static
  239.255.255.250       01-00-5e-7f-ff-fa     static
  255.255.255.255       ff-ff-ff-ff-ff-ff     static
`;

const LINUX_NEIGH = `192.168.1.1 dev eth0 lladdr 58:72:c9:41:36:94 REACHABLE
192.168.1.5 dev eth0 lladdr 84:47:09:75:92:32 STALE
192.168.1.9 dev eth0  INCOMPLETE
fe80::1 dev eth0 lladdr 58:72:c9:41:36:94 router REACHABLE
`;

const PROC_ARP = `IP address       HW type     Flags       HW address            Mask     Device
192.168.1.1      0x1         0x2         58:72:c9:41:36:94     *        eth0
192.168.1.9      0x1         0x0         00:00:00:00:00:00     *        eth0
`;

const MAC_ARP = `? (192.168.1.1) at 58:72:c9:41:36:94 on en0 ifscope [ethernet]
? (192.168.1.5) at 84:47:9:75:92:32 on en0 ifscope [ethernet]
? (192.168.1.9) at (incomplete) on en0 ifscope [ethernet]
`;

function byIp(neighbors, ip) {
  return neighbors.find((n) => n.ip === ip);
}

// Build a fake runner from a map of "file arg1 arg2" -> { stdout, ok }.
function fakeRun(map) {
  return async (file, args = []) => {
    const key = [file, ...args].join(' ');
    const r = map[key] !== undefined ? map[key] : map['*'];
    if (!r) return { ok: false, code: 1, stdout: '', stderr: 'no mock', error: new Error('no mock') };
    return {
      ok: r.ok !== false,
      code: r.code || 0,
      stdout: r.stdout || '',
      stderr: r.stderr || '',
      error: r.error || null,
    };
  };
}

test('parseWindowsArp: real fixture, unicast vs multicast/broadcast', () => {
  const n = parseWindowsArp(WIN_ARP);
  assert.equal(n.length, 6);
  const gw = byIp(n, '192.168.100.1');
  assert.equal(gw.mac, '58:72:c9:41:36:94');
  assert.equal(gw.unicast, true);
  assert.equal(gw.state, 'reachable'); // "dynamic"
  assert.equal(byIp(n, '192.168.100.5').unicast, true);
  assert.equal(byIp(n, '192.168.100.255').unicast, false); // broadcast
  assert.equal(byIp(n, '224.0.0.22').unicast, false); // multicast
  assert.equal(byIp(n, '255.255.255.255').unicast, false);
});

test('parseIpNeigh: reachable, stale, incomplete, IPv6 router', () => {
  const n = parseIpNeigh(LINUX_NEIGH);
  assert.equal(n.length, 4);
  assert.equal(byIp(n, '192.168.1.1').mac, '58:72:c9:41:36:94');
  assert.equal(byIp(n, '192.168.1.1').state, 'reachable');
  assert.equal(byIp(n, '192.168.1.1').unicast, true);
  assert.equal(byIp(n, '192.168.1.5').state, 'stale');
  const incomplete = byIp(n, '192.168.1.9');
  assert.equal(incomplete.mac, null);
  assert.equal(incomplete.state, 'incomplete');
  assert.equal(incomplete.unicast, false);
  const v6 = byIp(n, 'fe80::1');
  assert.equal(v6.mac, '58:72:c9:41:36:94');
  assert.equal(v6.unicast, true);
});

test('parseProcNetArp: flags 0x0 means incomplete', () => {
  const n = parseProcNetArp(PROC_ARP);
  assert.equal(n.length, 2);
  assert.equal(byIp(n, '192.168.1.1').unicast, true);
  assert.equal(byIp(n, '192.168.1.9').state, 'incomplete');
  assert.equal(byIp(n, '192.168.1.9').unicast, false);
});

test('padBsdMac pads octets stripped of leading zeros', () => {
  assert.equal(padBsdMac('84:47:9:75:92:32'), '84:47:09:75:92:32');
  assert.equal(padBsdMac('0:1e:c2:0:0:5'), '00:1e:c2:00:00:05');
  assert.equal(padBsdMac('not:a:mac'), 'not:a:mac'); // wrong group count, passthrough
});

test('parseMacArp: BSD format, unpadded MAC, incomplete', () => {
  const n = parseMacArp(MAC_ARP);
  assert.equal(n.length, 3);
  assert.equal(byIp(n, '192.168.1.5').mac, '84:47:09:75:92:32'); // padded
  assert.equal(byIp(n, '192.168.1.5').unicast, true);
  assert.equal(byIp(n, '192.168.1.9').mac, null); // incomplete
  assert.equal(byIp(n, '192.168.1.9').unicast, false);
});

test('readNeighbors: dispatch per platform', async () => {
  const win = await readNeighbors({ platform: 'win32', run: fakeRun({ 'arp -a': { stdout: WIN_ARP } }) });
  assert.equal(win.source, 'windows:arp');
  assert.equal(win.ok, true);
  assert.equal(win.neighbors.length, 6);

  const lin = await readNeighbors({ platform: 'linux', run: fakeRun({ 'ip neigh': { stdout: LINUX_NEIGH } }) });
  assert.equal(lin.source, 'linux:ip-neigh');
  assert.equal(lin.neighbors.length, 4);

  const mac = await readNeighbors({ platform: 'darwin', run: fakeRun({ 'arp -an': { stdout: MAC_ARP } }) });
  assert.equal(mac.source, 'darwin:arp');
  assert.equal(mac.neighbors.length, 3);
});

test('readNeighbors: linux falls back to /proc/net/arp when ip neigh fails', async () => {
  const run = fakeRun({
    'ip neigh': { ok: false, stdout: '' },
    'cat /proc/net/arp': { stdout: PROC_ARP },
  });
  const res = await readNeighbors({ platform: 'linux', run });
  assert.equal(res.source, 'linux:proc-net-arp');
  assert.equal(res.neighbors.length, 2);
});

test('lookupNeighbor: finds by normalized IP, including IPv4-mapped input', async () => {
  const run = fakeRun({ 'arp -a': { stdout: WIN_ARP } });
  const hit = await lookupNeighbor('::ffff:192.168.100.5', { platform: 'win32', run });
  assert.equal(hit.neighbor.mac, '84:47:09:75:92:32');

  const miss = await lookupNeighbor('10.10.10.10', { platform: 'win32', run });
  assert.equal(miss.neighbor, null);
});
