'use strict';

/**
 * OS introspection layer — the bridge between HereOnly's policy engine and the
 * host OS. Every function accepts an optional `{ run, platform }` so it can be
 * driven with a fake runner / forced platform in tests.
 */

const { run, makeRunner } = require('./exec.js');
const neighbors = require('./neighbors.js');
const netinfo = require('./netinfo.js');
const wifi = require('./wifi.js');
const self = require('./self.js');

module.exports = {
  run,
  makeRunner,

  readNeighbors: neighbors.readNeighbors,
  lookupNeighbor: neighbors.lookupNeighbor,

  getInterfaces: netinfo.getInterfaces,
  getLocalSubnets: netinfo.getLocalSubnets,
  getDefaultGateway: netinfo.getDefaultGateway,
  getGateway: netinfo.getGateway,

  getWifi: wifi.getWifi,

  getOwnIps: self.getOwnIps,
  isOwnIp: self.isOwnIp,

  neighbors,
  netinfo,
  wifi,
  self,
};
