'use strict';

/**
 * Network identity & segment fingerprinting.
 *
 * Collapses several host-network signals into a stable fingerprint used to
 * bind session tokens and to (optionally) pin access to specific approved
 * networks. The default keys on the most stable, always-available signals —
 * local subnets, the default-gateway MAC, and the Wi-Fi SSID (when present) —
 * and omits the BSSID, which changes as you roam between APs on one network.
 *
 * Segment binding is HereOnly's topology-aware twist: even a cloned MAC on a
 * different broadcast domain produces a different fingerprint.
 */

const crypto = require('node:crypto');
const { getLocalSubnets, getGateway } = require('../os/netinfo.js');
const { getWifi } = require('../os/wifi.js');
const { normalizeMac } = require('./ip.js');

async function computeIdentity(opts = {}) {
  const { run, platform, includeWifi = true } = opts;
  const subnets = getLocalSubnets().slice().sort();
  let gateway = { ip: null, mac: null };
  try {
    gateway = await getGateway({ run, platform });
  } catch {
    gateway = { ip: null, mac: null };
  }
  let wifi = { ssid: null, bssid: null };
  if (includeWifi) {
    try {
      wifi = await getWifi({ run, platform });
    } catch {
      wifi = { ssid: null, bssid: null };
    }
  }
  return { subnets, gateway, wifi };
}

const DEFAULT_FP_OPTS = {
  useSubnets: true,
  useGatewayMac: true,
  useGatewayIp: false,
  useSsid: true,
  useBssid: false,
};

function fingerprint(identity, fpOpts = {}) {
  const o = { ...DEFAULT_FP_OPTS, ...fpOpts };
  const parts = [];
  if (o.useSubnets && identity.subnets && identity.subnets.length) parts.push('net=' + identity.subnets.join(','));
  if (o.useGatewayMac && identity.gateway && identity.gateway.mac) parts.push('gwmac=' + identity.gateway.mac);
  else if (o.useGatewayIp && identity.gateway && identity.gateway.ip) parts.push('gwip=' + identity.gateway.ip);
  if (o.useSsid && identity.wifi && identity.wifi.ssid) parts.push('ssid=' + identity.wifi.ssid);
  if (o.useBssid && identity.wifi && identity.wifi.bssid) parts.push('bssid=' + identity.wifi.bssid);
  const canon = parts.join('|');
  const hash = crypto.createHash('sha256').update(canon).digest('hex').slice(0, 32);
  return { hash, canon, parts };
}

function networkLabel(identity) {
  if (identity.wifi && identity.wifi.ssid) return identity.wifi.ssid;
  if (identity.gateway && identity.gateway.ip) return `gw:${identity.gateway.ip}`;
  if (identity.subnets && identity.subnets.length) return identity.subnets[0];
  return 'local';
}

function hasAllowlist(policy = {}) {
  return !!(
    (policy.allowedFingerprints && policy.allowedFingerprints.length) ||
    (policy.allowedSsids && policy.allowedSsids.length) ||
    (policy.allowedGatewayMacs && policy.allowedGatewayMacs.length)
  );
}

function approveNetwork(identity, fp, policy = {}) {
  if (!hasAllowlist(policy)) return { approved: true, reason: 'no-allowlist' };
  if (policy.allowedFingerprints && policy.allowedFingerprints.includes(fp.hash)) {
    return { approved: true, reason: 'fingerprint-match' };
  }
  if (policy.allowedSsids && identity.wifi && identity.wifi.ssid && policy.allowedSsids.includes(identity.wifi.ssid)) {
    return { approved: true, reason: 'ssid-match' };
  }
  if (policy.allowedGatewayMacs && identity.gateway && identity.gateway.mac) {
    const allowed = policy.allowedGatewayMacs.map(normalizeMac).filter(Boolean);
    if (allowed.includes(identity.gateway.mac)) return { approved: true, reason: 'gateway-mac-match' };
  }
  return { approved: false, reason: 'not-in-allowlist' };
}

module.exports = { computeIdentity, fingerprint, networkLabel, approveNetwork, hasAllowlist, DEFAULT_FP_OPTS };
