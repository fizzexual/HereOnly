'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');

const {
  getWifi,
  parseWindowsWlan,
  parseNmcli,
  parseIwgetidSsid,
  parseIwgetidApMac,
  parseNetworksetup,
  parseAirport,
} = require('../../src/os/ssid.js');

const WIN_WLAN_CONNECTED = `
There is 1 interface on the system:

    Name                   : Wi-Fi
    Description            : Intel(R) Wi-Fi 6 AX201
    State                  : connected
    SSID                   : MyHomeNet
    BSSID                  : 58:72:c9:41:36:94
    Signal                 : 87%
    Radio type             : 802.11ax
`;

// Real captured output when the WLAN service is stopped (wired-only host).
const WIN_WLAN_OFF = `The Wireless AutoConfig Service (wlansvc) is not running.`;

function fakeRun(map) {
  return async (file, args = []) => {
    const key = [file, ...args].join(' ');
    const r = map[key] !== undefined ? map[key] : map['*'];
    if (!r) return { ok: false, code: 1, stdout: '', stderr: 'no mock', error: new Error('no mock') };
    return { ok: r.ok !== false, code: r.code || 0, stdout: r.stdout || '', stderr: r.stderr || '', error: null };
  };
}

test('parseWindowsWlan: connected -> ssid + bssid', () => {
  const r = parseWindowsWlan(WIN_WLAN_CONNECTED);
  assert.equal(r.ssid, 'MyHomeNet');
  assert.equal(r.bssid, '58:72:c9:41:36:94');
});

test('parseWindowsWlan: does not confuse BSSID line for SSID', () => {
  const r = parseWindowsWlan(WIN_WLAN_CONNECTED);
  assert.notEqual(r.ssid, '58:72:c9:41:36:94');
});

test('parseWindowsWlan: service stopped -> empty', () => {
  assert.deepEqual(parseWindowsWlan(WIN_WLAN_OFF), { ssid: null, bssid: null });
});

test('parseNmcli: active row, unescapes \\: in BSSID', () => {
  const out = parseNmcli('no:OtherNet:AA\\:BB\\:CC\\:DD\\:EE\\:FF\nyes:MyHomeNet:58\\:72\\:C9\\:41\\:36\\:94\n');
  assert.equal(out.ssid, 'MyHomeNet');
  assert.equal(out.bssid, '58:72:c9:41:36:94');
});

test('parseNmcli: no active row -> empty', () => {
  assert.deepEqual(parseNmcli('no:A:AA\\:BB\\:CC\\:DD\\:EE\\:FF\n'), { ssid: null, bssid: null });
});

test('parseIwgetid helpers', () => {
  assert.equal(parseIwgetidSsid('MyHomeNet\n'), 'MyHomeNet');
  assert.equal(parseIwgetidApMac('wlan0     Access Point/Cell: 58:72:C9:41:36:94'), '58:72:c9:41:36:94');
  assert.equal(parseIwgetidApMac('no mac here'), null);
});

test('parseNetworksetup', () => {
  assert.deepEqual(parseNetworksetup('Current Wi-Fi Network: CoffeeShop\n'), { ssid: 'CoffeeShop', bssid: null });
  assert.deepEqual(
    parseNetworksetup('You are not associated with an AirPort network.'),
    { ssid: null, bssid: null },
  );
});

test('parseAirport', () => {
  const txt = `     agrCtlRSSI: -50
     SSID: MyHomeNet
    BSSID: 58:72:c9:41:36:94
    channel: 36`;
  assert.deepEqual(parseAirport(txt), { ssid: 'MyHomeNet', bssid: '58:72:c9:41:36:94' });
});

test('getWifi: windows connected', async () => {
  const r = await getWifi({
    platform: 'win32',
    run: fakeRun({ 'netsh wlan show interfaces': { stdout: WIN_WLAN_CONNECTED } }),
  });
  assert.equal(r.ssid, 'MyHomeNet');
  assert.equal(r.bssid, '58:72:c9:41:36:94');
});

test('getWifi: windows service stopped -> graceful null', async () => {
  const r = await getWifi({
    platform: 'win32',
    run: fakeRun({ 'netsh wlan show interfaces': { ok: false, stdout: WIN_WLAN_OFF } }),
  });
  assert.deepEqual(r, { ssid: null, bssid: null });
});

test('getWifi: linux via nmcli', async () => {
  const r = await getWifi({
    platform: 'linux',
    run: fakeRun({
      'nmcli -t -f active,ssid,bssid dev wifi': { stdout: 'yes:MyHomeNet:58\\:72\\:C9\\:41\\:36\\:94\n' },
    }),
  });
  assert.equal(r.ssid, 'MyHomeNet');
  assert.equal(r.bssid, '58:72:c9:41:36:94');
});

test('getWifi: darwin falls back to networksetup when airport unavailable', async () => {
  const r = await getWifi({
    platform: 'darwin',
    run: fakeRun({
      '*': { ok: false }, // airport bin fails
      'networksetup -getairportnetwork en0': { stdout: 'Current Wi-Fi Network: CoffeeShop\n' },
    }),
  });
  assert.equal(r.ssid, 'CoffeeShop');
});
