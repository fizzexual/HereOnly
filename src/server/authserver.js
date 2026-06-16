'use strict';

/**
 * Forward-auth subrequest server.
 *
 * Lets any reverse proxy delegate access decisions to HereOnly via a sub-auth
 * request:
 *   - nginx   `auth_request /_hereonly;`
 *   - Caddy   `forward_auth 127.0.0.1:7001 { uri /auth }`
 *   - Traefik ForwardAuth middleware -> http://127.0.0.1:7001/auth
 *
 * It returns 204 (allow) or 403 (deny) and stamps `X-HereOnly-*` response
 * headers the proxy can copy onto the backend request.
 *
 * SECURITY: the real client IP arrives in `X-Real-IP` / `X-Forwarded-For`, set
 * by the proxy. Those are only trusted when the subrequest's own TCP peer is a
 * trusted proxy (loopback by default, plus any `trustedProxies` CIDRs) — so a
 * device hitting this server directly can't spoof its IP; it's verified by its
 * own adjacency instead. Bind this server to localhost in normal deployments.
 */

const http = require('node:http');
const { createVerifier } = require('../core/verifier.js');
const { normalizeIp, isLoopback, ipInAnyCidr } = require('../core/ip.js');
const respond = require('./respond.js');
const { createLogger, noopLogger } = require('../core/logger.js');

function createAuthServer(options = {}) {
  const verifier = options.verifier || createVerifier(options);
  const logger = options.logger || (options.silent ? noopLogger : createLogger({ level: options.logLevel || 'info' }));
  const allowStatus = options.allowStatus || 204;
  const denyStatus = options.denyStatus || 403;
  const headerName = options.headerName || 'x-hereonly-token';
  const cookieName = options.cookieName || 'hereonly';
  const trustedProxies = options.trustedProxies || [];

  async function handle(req, res) {
    const peer = normalizeIp(req.socket && req.socket.remoteAddress);
    const trusted = !!peer && (isLoopback(peer) || ipInAnyCidr(peer, trustedProxies));

    // The proxy passes the ORIGINAL request line via well-known headers.
    const h = req.headers;
    const uri = h['x-forwarded-uri'] || h['x-original-uri'] || req.url || '/';
    const method = h['x-forwarded-method'] || h['x-original-method'] || req.method || 'GET';
    const host = h['x-forwarded-host'] || h['host'] || '';

    const synthReq = { socket: req.socket, headers: h, url: uri, method };
    let verdict;
    try {
      verdict = await verifier.verifyRequest(synthReq, { trustForwardedHeader: trusted, headerName, cookieName });
    } catch (err) {
      verdict = { allow: false, reason: 'error', detail: (err && err.message) || 'verification error', ip: peer };
    }

    respond.setVerdictHeaders(res, verdict);
    logger.debug(
      `auth ${verdict.ip || '?'} (peer ${peer}${trusted ? ' trusted' : ''}) ${method} ${host}${uri} -> ${verdict.allow ? 'ALLOW' : 'DENY'} (${verdict.reason})`,
    );

    if (verdict.allow) {
      res.statusCode = allowStatus;
      res.end();
    } else {
      logger.info(`deny ${verdict.ip || '?'} ${method} ${host}${uri} (${verdict.reason})`);
      res.statusCode = denyStatus;
      res.setHeader('Content-Type', 'application/json; charset=utf-8');
      res.setHeader('Cache-Control', 'no-store');
      res.end(JSON.stringify({ error: 'access denied', by: 'hereonly', reason: verdict.reason }));
    }
  }

  const server = options.server || http.createServer();
  server.on('request', handle);
  server.hereonly = { verifier, logger };
  return server;
}

module.exports = { createAuthServer };
