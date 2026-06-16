'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');

const {
  getWifi,
  parseWindowsWlan,
  parseNmcli,
  parseNetworksetup,
  parseAirport,
  parseIwgetidApMac,
} = require('../../src/os/wifi.js');

const WIN_CONNECTED = `
    Name                   : Wi-Fi
    State                  : connected
    SSID                   : MyHomeNet
    BSSID                  : 58:72:c9:41:36:94
    Signal                 : 87%
`;
const WIN_OFF = `The Wireless AutoConfig Service (wlansvc) is not running.`;

function fakeRun(map) {
  return async (file, args = []) => {
    const key = [file, ...args].join(' ');
    const r = map[key] !== undefined ? map[key] : map['*'];
    if (!r) return { ok: false, code: 1, stdout: '', stderr: '', error: null };
    return { ok: r.ok !== false, code: 0, stdout: r.stdout || '', stderr: '', error: null };
  };
}

test('parseWindowsWlan: connected vs service-off; BSSID not mistaken for SSID', () => {
  const r = parseWindowsWlan(WIN_CONNECTED);
  assert.equal(r.ssid, 'MyHomeNet');
  assert.equal(r.bssid, '58:72:c9:41:36:94');
  assert.deepEqual(parseWindowsWlan(WIN_OFF), { ssid: null, bssid: null });
});

test('parseNmcli unescapes \\: in BSSID; parseNetworksetup; parseAirport; iwgetid', () => {
  const r = parseNmcli('no:Other:AA\\:BB\\:CC\\:DD\\:EE\\:FF\nyes:MyHomeNet:58\\:72\\:C9\\:41\\:36\\:94\n');
  assert.equal(r.ssid, 'MyHomeNet');
  assert.equal(r.bssid, '58:72:c9:41:36:94');
  assert.deepEqual(parseNetworksetup('Current Wi-Fi Network: CoffeeShop'), { ssid: 'CoffeeShop', bssid: null });
  assert.deepEqual(parseAirport('     SSID: Home\n    BSSID: 58:72:c9:41:36:94'), {
    ssid: 'Home',
    bssid: '58:72:c9:41:36:94',
  });
  assert.equal(parseIwgetidApMac('wlan0  Access Point/Cell: 58:72:C9:41:36:94'), '58:72:c9:41:36:94');
});

test('getWifi dispatch: windows connected / off / linux nmcli', async () => {
  assert.equal(
    (await getWifi({ platform: 'win32', run: fakeRun({ 'netsh wlan show interfaces': { stdout: WIN_CONNECTED } }) })).ssid,
    'MyHomeNet',
  );
  assert.deepEqual(
    await getWifi({ platform: 'win32', run: fakeRun({ 'netsh wlan show interfaces': { ok: false, stdout: WIN_OFF } }) }),
    { ssid: null, bssid: null },
  );
  assert.equal(
    (await getWifi({
      platform: 'linux',
      run: fakeRun({ 'nmcli -t -f active,ssid,bssid dev wifi': { stdout: 'yes:Net:58\\:72\\:C9\\:41\\:36\\:94' } }),
    })).ssid,
    'Net',
  );
});
