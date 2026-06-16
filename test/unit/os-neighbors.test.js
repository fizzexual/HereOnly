'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');

const {
  parseWindowsArp,
  parseWindowsNdp,
  parseIpNeigh,
  parseProcNetArp,
  parseMacArp,
  parseMacNdp,
  padBsdMac,
  readNeighbors,
  lookupNeighbor,
} = require('../../src/os/neighbors.js');

const WIN_ARP = `
Interface: 192.168.100.2 --- 0x12
  Internet Address      Physical Address      Type
  192.168.100.1         58-72-c9-41-36-94     dynamic
  192.168.100.5         84-47-09-75-92-32     dynamic
  192.168.100.255       ff-ff-ff-ff-ff-ff     static
  224.0.0.22            01-00-5e-00-00-16     static
`;

// Real-shaped `netsh interface ipv6 show neighbors`.
const WIN_NDP = `
Interface 12: Ethernet

Internet Address                              Physical Address   Type
--------------------------------------------  -----------------  -----------
fe80::1                                       58-72-c9-41-36-94  Reachable (Router)
2a00:4804:b000:6ce0::5                        84-47-09-75-92-32  Stale
ff02::1                                       33-33-00-00-00-01  Permanent
fe80::dead                                                       Incomplete
`;

const LINUX_NEIGH = `192.168.1.1 dev eth0 lladdr 58:72:c9:41:36:94 REACHABLE
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

const MAC_NDP = `Neighbor                             Linklayer Address  Netif Expire    St Flgs Prbs
fe80::1%en0                          58:72:c9:41:36:94  en0   23h59m58s R  R
2001:db8::5%en0                      84:47:9:75:92:32   en0   permanent  R
fe80::dead%en0                       (incomplete)       en0   expired    I
`;

const byIp = (ns, ip) => ns.find((n) => n.ip === ip);

function fakeRun(map) {
  return async (file, args = []) => {
    const key = [file, ...args].join(' ');
    const r = map[key] !== undefined ? map[key] : map['*'];
    if (!r) return { ok: false, code: 1, stdout: '', stderr: 'no mock', error: new Error('no mock') };
    return { ok: r.ok !== false, code: r.code || 0, stdout: r.stdout || '', stderr: r.stderr || '', error: null };
  };
}

test('parseWindowsArp: unicast vs multicast/broadcast', () => {
  const n = parseWindowsArp(WIN_ARP);
  assert.equal(byIp(n, '192.168.100.1').mac, '58:72:c9:41:36:94');
  assert.equal(byIp(n, '192.168.100.1').unicast, true);
  assert.equal(byIp(n, '192.168.100.255').unicast, false);
  assert.equal(byIp(n, '224.0.0.22').unicast, false);
});

test('parseWindowsNdp: resolved IPv6 neighbors, router flag, multicast filtered', () => {
  const n = parseWindowsNdp(WIN_NDP);
  const gw = byIp(n, 'fe80::1');
  assert.equal(gw.mac, '58:72:c9:41:36:94');
  assert.equal(gw.unicast, true);
  assert.equal(gw.state, 'reachable'); // "Reachable (Router)"
  assert.equal(byIp(n, '2a00:4804:b000:6ce0::5').state, 'stale');
  assert.equal(byIp(n, 'ff02::1').unicast, false); // 33:33 multicast
  assert.equal(byIp(n, 'fe80::dead'), undefined); // no MAC -> not parsed
});

test('parseIpNeigh / parseProcNetArp', () => {
  const n = parseIpNeigh(LINUX_NEIGH);
  assert.equal(byIp(n, '192.168.1.1').unicast, true);
  assert.equal(byIp(n, '192.168.1.9').state, 'incomplete');
  assert.equal(byIp(n, 'fe80::1').unicast, true);
  const p = parseProcNetArp(PROC_ARP);
  assert.equal(byIp(p, '192.168.1.9').unicast, false);
});

test('padBsdMac + parseMacArp + parseMacNdp', () => {
  assert.equal(padBsdMac('84:47:9:75:92:32'), '84:47:09:75:92:32');
  const a = parseMacArp(MAC_ARP);
  assert.equal(byIp(a, '192.168.1.5').mac, '84:47:09:75:92:32');
  assert.equal(byIp(a, '192.168.1.9').mac, null);
  const d = parseMacNdp(MAC_NDP);
  assert.equal(byIp(d, 'fe80::1').mac, '58:72:c9:41:36:94');
  assert.equal(byIp(d, '2001:db8::5').mac, '84:47:09:75:92:32'); // padded
  assert.equal(byIp(d, 'fe80::dead').mac, null); // incomplete -> present but
  assert.equal(byIp(d, 'fe80::dead').unicast, false); // not a usable neighbor
});

test('readNeighbors win32: merges ARP (v4) + NDP (v6)', async () => {
  const run = fakeRun({
    'arp -a': { stdout: WIN_ARP },
    'netsh interface ipv6 show neighbors': { stdout: WIN_NDP },
  });
  const res = await readNeighbors({ platform: 'win32', run });
  assert.equal(res.source, 'windows:arp+ndp');
  assert.ok(byIp(res.neighbors, '192.168.100.5')); // v4
  assert.ok(byIp(res.neighbors, 'fe80::1')); // v6
});

test('readNeighbors linux falls back to /proc/net/arp', async () => {
  const run = fakeRun({ 'ip neigh': { ok: false }, 'cat /proc/net/arp': { stdout: PROC_ARP } });
  const res = await readNeighbors({ platform: 'linux', run });
  assert.equal(res.source, 'linux:proc-net-arp');
});

test('lookupNeighbor finds an IPv6 neighbor by normalized IP (win32)', async () => {
  const run = fakeRun({
    'arp -a': { stdout: WIN_ARP },
    'netsh interface ipv6 show neighbors': { stdout: WIN_NDP },
  });
  const hit = await lookupNeighbor('FE80::1', { platform: 'win32', run });
  assert.equal(hit.neighbor.mac, '58:72:c9:41:36:94');
  const miss = await lookupNeighbor('10.10.10.10', { platform: 'win32', run });
  assert.equal(miss.neighbor, null);
});
