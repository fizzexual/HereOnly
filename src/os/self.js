'use strict';

/**
 * Host self-identity: the set of IP addresses that belong to this machine's
 * own interfaces (including loopback).
 *
 * Why this matters: a request that arrives at the host *from one of the host's
 * own addresses* is the host itself — e.g. you open `http://192.168.1.50:7000`
 * (your own LAN IP) in a browser on the same box. That traffic loops back
 * internally and is never resolved via ARP, so without this check it would be
 * (confusingly) denied as "no neighbor entry". Treating own IPs as self fixes
 * that: you are maximally "here".
 */

const os = require('node:os');
const { normalizeIp } = require('../core/ip.js');

/** Snapshot the set of this host's own interface IPs (normalized strings). */
function getOwnIps() {
  const set = new Set();
  for (const addrs of Object.values(os.networkInterfaces())) {
    for (const a of addrs || []) {
      const ip = normalizeIp(a.address);
      if (ip) set.add(ip);
    }
  }
  return set;
}

/** True if `ip` is one of this host's own interface addresses. */
function isOwnIp(ip, ownSet) {
  const n = normalizeIp(ip);
  if (!n) return false;
  const set = ownSet || getOwnIps();
  return set.has(n);
}

module.exports = { getOwnIps, isOwnIp };
