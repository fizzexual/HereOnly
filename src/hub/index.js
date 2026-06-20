'use strict';

/**
 * The segment hub: discovery + local service detection + gated dashboard, wired
 * into one thing you can `start()`.
 *
 *   const { createHub } = require('hereonly/hub');
 *   createHub({ scan: true }).start(7080);
 */

const os = require('node:os');
const { createDiscovery } = require('./discovery.js');
const { loadOrCreateIdentity, addrFromId } = require('./identity.js');
const { createHubServer } = require('./server.js');
const services = require('./services.js');
const { createVerifier } = require('../core/verifier.js');
const { networkLabel } = require('../core/fingerprint.js');
const { getInterfaces } = require('../os/netinfo.js');
const { createLogger, noopLogger } = require('../core/logger.js');

/** This host's reachable LAN IPv4 addresses (what peers use to reach us). */
function ownLanAddrs() {
  return getInterfaces()
    .filter((i) => i.family === 4 && !i.internal && i.address && !i.address.startsWith('169.254.'))
    .map((i) => i.address);
}

function createHub(options = {}) {
  const verifier = options.verifier || createVerifier(options);
  const logger = options.logger || (options.silent ? noopLogger : createLogger({ level: options.logLevel || 'info' }));
  const hostname = os.hostname();
  const ident = options.id
    ? { id: options.id, name: options.name || hostname, addr: addrFromId(options.id) }
    : loadOrCreateIdentity(options.idFile, hostname, options.name);
  const id = ident.id;
  const host = hostname;
  const hubPort = options.port || 7080;
  const mcastPort = options.mcastPort || undefined;
  const scan = options.scan !== false;
  const configured = services.parseConfiguredServices(options.services);
  const { run, platform } = options;

  let serviceCache = configured.slice();
  let addrsCache = ownLanAddrs();
  let netLabel = '';

  async function refreshServices() {
    addrsCache = ownLanAddrs();
    let detected = [];
    if (scan) {
      try {
        detected = await services.detectServices({ run, platform, excludePorts: [hubPort, mcastPort || 47471] });
      } catch {
        detected = [];
      }
    }
    serviceCache = services.mergeServices(configured, detected);
    return serviceCache;
  }

  const self = {
    id,
    host,
    name: ident.name,
    addr: ident.addr,
    get addrs() {
      return addrsCache;
    },
    services: () => serviceCache,
  };

  const discovery = createDiscovery({
    self,
    group: options.group,
    port: mcastPort,
    secret: options.hubSecret,
    intervalMs: options.intervalMs,
    ttlMs: options.ttlMs,
    logger,
  });

  function entries() {
    const selfEntry = { id, host, name: ident.name, addr: ident.addr, addrs: addrsCache, services: serviceCache, self: true, lastSeen: Date.now() };
    return [selfEntry, ...discovery.peers().map((p) => ({ ...p, self: false }))];
  }

  const server = createHubServer({
    verifier,
    logger,
    getEntries: entries,
    networkLabel: () => netLabel,
    cookieName: options.cookieName,
    headerName: options.headerName,
    trustForwardedHeader: options.trustForwardedHeader,
    denyStatus: options.denyStatus,
  });

  let svcTimer = null;

  async function start(port = hubPort, bindHost = '0.0.0.0') {
    await refreshServices();
    try {
      const net = await verifier.getNetwork();
      if (net && net.identity) netLabel = networkLabel(net.identity);
    } catch {
      /* ignore */
    }
    discovery.start();
    svcTimer = setInterval(() => refreshServices().catch(() => {}), options.serviceRefreshMs || 30000);
    if (svcTimer.unref) svcTimer.unref();
    await new Promise((resolve) => server.listen(port, bindHost, resolve));
    return { port, host: bindHost, id };
  }

  function stop() {
    if (svcTimer) clearInterval(svcTimer);
    svcTimer = null;
    discovery.stop();
    try {
      server.close();
    } catch {
      /* ignore */
    }
  }

  return { start, stop, server, discovery, entries, refreshServices, id, self, identity: ident, ownAddrs: () => addrsCache };
}

module.exports = { createHub, ownLanAddrs };
