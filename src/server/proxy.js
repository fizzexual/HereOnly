'use strict';

/**
 * Standalone reverse proxy.
 *
 * Put HereOnly in front of ANY local server, in any language: it verifies every
 * request (and WebSocket upgrade) for on-segment adjacency and forwards allowed
 * traffic to the target, denying everything else.
 *
 *   const { createProxyServer } = require('hereonly/proxy');
 *   createProxyServer({ target: 'http://127.0.0.1:3000' }).listen(7000);
 */

const http = require('node:http');
const https = require('node:https');
const net = require('node:net');
const { createVerifier } = require('../core/verifier.js');
const respond = require('./respond.js');
const { createLogger, noopLogger } = require('../core/logger.js');

const targetPort = (url) => (url.port ? Number(url.port) : url.protocol === 'https:' ? 443 : 80);

function createProxyServer(options = {}) {
  if (!options.target) throw new Error('HereOnly proxy requires a `target` (e.g. http://127.0.0.1:3000)');
  const targetUrl = new URL(options.target);
  const verifier = options.verifier || createVerifier(options);
  const logger = options.logger || (options.silent ? noopLogger : createLogger({ level: options.logLevel || 'info' }));

  const cookieName = options.cookieName || 'hereonly';
  const headerName = options.headerName || 'x-hereonly-token';
  const setCookie = options.setCookie !== false;
  const cookieOptions = options.cookieOptions || {};
  const trustForwardedHeader = !!options.trustForwardedHeader;
  const denyStatus = options.denyStatus || 403;
  const addForwardHeaders = options.addForwardHeaders !== false;
  const ttlSeconds = verifier.options.tokenTtlSeconds;
  const reqOpts = { cookieName, headerName, trustForwardedHeader };
  const bridges = new Set();

  async function verify(req) {
    try {
      return await verifier.verifyRequest(req, reqOpts);
    } catch (err) {
      return { allow: false, reason: 'error', detail: (err && err.message) || 'verification error', ip: null };
    }
  }

  async function onRequest(req, res) {
    const verdict = await verify(req);
    req.hereonly = verdict;
    logger.debug(`${req.method} ${req.url} from ${verdict.ip || '?'} -> ${verdict.allow ? 'ALLOW' : 'DENY'} (${verdict.reason})`);
    if (!verdict.allow) {
      logger.info(`deny ${verdict.ip || '?'} ${req.method} ${req.url} (${verdict.reason})`);
      return respond.sendDeny(req, res, denyStatus, verdict);
    }
    forward(req, res, verdict);
  }

  function forward(req, res, verdict) {
    const headers = { ...req.headers, host: targetUrl.host };
    if (addForwardHeaders) {
      const prior = req.headers['x-forwarded-for'];
      const peer = verdict.ip || (req.socket && req.socket.remoteAddress) || '';
      headers['x-forwarded-for'] = prior ? `${prior}, ${peer}` : peer;
      headers['x-forwarded-host'] = req.headers.host || '';
      headers['x-forwarded-proto'] = 'http';
      headers['x-hereonly-verified'] = verdict.reason;
      headers['x-hereonly-present'] = verdict.present ? '1' : '0';
      if (verdict.mac) headers['x-hereonly-mac'] = verdict.mac;
      if (verdict.network && verdict.network.fingerprint) headers['x-hereonly-network'] = verdict.network.fingerprint;
    }
    const mod = targetUrl.protocol === 'https:' ? https : http;
    const upstream = mod.request(
      { protocol: targetUrl.protocol, hostname: targetUrl.hostname, port: targetPort(targetUrl), method: req.method, path: req.url, headers },
      (up) => {
        res.statusCode = up.statusCode || 502;
        for (const [k, v] of Object.entries(up.headers)) if (v !== undefined) res.setHeader(k, v);
        if (setCookie && verdict.token) {
          respond.appendSetCookie(res, respond.buildSessionCookie(cookieName, verdict.token, { ttlSeconds, ...cookieOptions }));
        }
        up.pipe(res);
      },
    );
    upstream.on('error', (err) => {
      logger.warn(`upstream error: ${err.message}`);
      if (!res.headersSent) {
        res.statusCode = 502;
        res.setHeader('Content-Type', 'text/plain; charset=utf-8');
      }
      try {
        res.end('HereOnly: upstream server unavailable\n');
      } catch {
        /* ignore */
      }
    });
    req.pipe(upstream);
  }

  function rebuildHead(req) {
    const lines = [`${req.method} ${req.url} HTTP/1.1`];
    const raw = req.rawHeaders;
    for (let i = 0; i < raw.length; i += 2) {
      const k = raw[i];
      const isHost = k.toLowerCase() === 'host';
      lines.push(`${isHost ? 'Host' : k}: ${isHost ? targetUrl.host : raw[i + 1]}`);
    }
    return lines.join('\r\n') + '\r\n\r\n';
  }

  async function onUpgrade(req, socket, head) {
    const verdict = await verify(req);
    if (!verdict.allow) {
      logger.info(`deny upgrade ${verdict.ip || '?'} ${req.url} (${verdict.reason})`);
      socket.write('HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n');
      socket.destroy();
      return;
    }
    const upstream = net.connect(targetPort(targetUrl), targetUrl.hostname, () => {
      upstream.write(rebuildHead(req));
      if (head && head.length) upstream.write(head);
      upstream.pipe(socket);
      socket.pipe(upstream);
    });
    const pair = { socket, upstream };
    bridges.add(pair);
    const teardown = () => {
      bridges.delete(pair);
      socket.destroy();
      upstream.destroy();
    };
    upstream.on('error', teardown);
    upstream.on('close', teardown);
    socket.on('error', teardown);
    socket.on('close', teardown);
  }

  function closeBridges() {
    for (const { socket, upstream } of bridges) {
      socket.destroy();
      upstream.destroy();
    }
    bridges.clear();
  }

  const server = options.server || http.createServer();
  server.on('request', onRequest);
  server.on('upgrade', onUpgrade);
  server.on('close', closeBridges);
  server.hereonly = { verifier, target: options.target, logger, closeBridges, bridges };
  return server;
}

module.exports = { createProxyServer };
