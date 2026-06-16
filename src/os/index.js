'use strict';

/**
 * OS introspection layer — the bridge between HereOnly's policy engine and the
 * host operating system. Every function accepts an optional `{ run, platform }`
 * so it can be driven with a fake runner / forced platform in tests.
 */

const { run, makeRunner } = require('./exec.js');
const arp = require('./arp.js');
const netinfo = require('./netinfo.js');
const ssid = require('./ssid.js');

module.exports = {
  run,
  makeRunner,

  // neighbor table
  readNeighbors: arp.readNeighbors,
  lookupNeighbor: arp.lookupNeighbor,

  // interfaces / subnets / gateway
  getInterfaces: netinfo.getInterfaces,
  getLocalSubnets: netinfo.getLocalSubnets,
  getDefaultGateway: netinfo.getDefaultGateway,
  getGateway: netinfo.getGateway,

  // wifi
  getWifi: ssid.getWifi,

  // submodules (parsers, helpers) for advanced use / testing
  arp,
  netinfo,
  ssid,
};
