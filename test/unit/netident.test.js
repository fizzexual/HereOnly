'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');

const { fingerprint, networkLabel, approveNetwork, computeNetIdentity } = require('../../src/core/netident.js');

const IDENTITY = {
  subnets: ['192.168.100.0/24'],
  gateway: { ip: '192.168.100.1', mac: '58:72:c9:41:36:94' },
  wifi: { ssid: 'HomeNet', bssid: 'aa:bb:cc:dd:ee:ff' },
};

test('fingerprint is deterministic for the same identity', () => {
  assert.equal(fingerprint(IDENTITY).hash, fingerprint(IDENTITY).hash);
});

test('fingerprint omits BSSID by default but includes SSID', () => {
  const fp = fingerprint(IDENTITY);
  assert.ok(fp.canon.includes('ssid=HomeNet'));
  assert.ok(!fp.canon.includes('bssid='));
  assert.ok(fp.canon.includes('gwmac=58:72:c9:41:36:94'));
});

test('fingerprint changes when a keyed signal changes', () => {
  const moved = { ...IDENTITY, gateway: { ip: '192.168.100.1', mac: '00:11:22:33:44:55' } };
  assert.notEqual(fingerprint(IDENTITY).hash, fingerprint(moved).hash);
});

test('BSSID roaming does not change the default fingerprint', () => {
  const roamed = { ...IDENTITY, wifi: { ssid: 'HomeNet', bssid: '11:22:33:44:55:66' } };
  assert.equal(fingerprint(IDENTITY).hash, fingerprint(roamed).hash);
});

test('networkLabel prefers SSID, then gateway, then subnet', () => {
  assert.equal(networkLabel(IDENTITY), 'HomeNet');
  assert.equal(networkLabel({ ...IDENTITY, wifi: { ssid: null, bssid: null } }), 'gw:192.168.100.1');
  assert.equal(
    networkLabel({ subnets: ['10.0.0.0/8'], gateway: { ip: null, mac: null }, wifi: { ssid: null, bssid: null } }),
    '10.0.0.0/8',
  );
});

test('approveNetwork: no allowlist approves any network', () => {
  assert.equal(approveNetwork(IDENTITY, fingerprint(IDENTITY), {}).approved, true);
});

test('approveNetwork: SSID allowlist', () => {
  assert.equal(approveNetwork(IDENTITY, fingerprint(IDENTITY), { allowedSsids: ['HomeNet'] }).approved, true);
  assert.equal(approveNetwork(IDENTITY, fingerprint(IDENTITY), { allowedSsids: ['Office'] }).approved, false);
});

test('approveNetwork: gateway-MAC allowlist (normalized)', () => {
  assert.equal(
    approveNetwork(IDENTITY, fingerprint(IDENTITY), { allowedGatewayMacs: ['58-72-C9-41-36-94'] }).approved,
    true,
  );
  assert.equal(
    approveNetwork(IDENTITY, fingerprint(IDENTITY), { allowedGatewayMacs: ['de:ad:be:ef:00:00'] }).approved,
    false,
  );
});

test('approveNetwork: fingerprint allowlist', () => {
  const fp = fingerprint(IDENTITY);
  assert.equal(approveNetwork(IDENTITY, fp, { allowedFingerprints: [fp.hash] }).approved, true);
  assert.equal(approveNetwork(IDENTITY, fp, { allowedFingerprints: ['deadbeef'] }).approved, false);
});

test('computeNetIdentity uses injected gateway + wifi', async () => {
  const run = async (file, args = []) => {
    const key = [file, ...args].join(' ');
    const map = {
      'route print -4': `  0.0.0.0          0.0.0.0    192.168.100.1    192.168.100.2     25`,
      'arp -a': `Interface: 192.168.100.2 --- 0x12\n  192.168.100.1  58-72-c9-41-36-94  dynamic`,
      'netsh wlan show interfaces': 'The Wireless AutoConfig Service (wlansvc) is not running.',
    };
    return { ok: true, code: 0, stdout: map[key] || '', stderr: '', error: null };
  };
  const id = await computeNetIdentity({ run, platform: 'win32' });
  assert.equal(id.gateway.ip, '192.168.100.1');
  assert.equal(id.gateway.mac, '58:72:c9:41:36:94');
  assert.deepEqual(id.wifi, { ssid: null, bssid: null }); // service stopped
  assert.ok(Array.isArray(id.subnets));
});
