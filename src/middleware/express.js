'use strict';

/**
 * Express / Connect middleware.
 *
 *   const { hereonly } = require('hereonly/middleware');
 *   app.use(hereonly());                 // gate everything
 *   app.use('/admin', hereonly({ ... })); // gate a subtree
 *
 * Uses only the Node core res API, so the same function also works as a
 * `(req, res, next)` handler with a raw http server or Connect.
 *
 * On allow: attaches `req.hereonly` (the verdict), optionally sets the session
 * cookie, and calls next(). On deny: sends a 403 (HTML or JSON by negotiation)
 * or defers to a custom `onDeny(req, res, verdict)` handler.
 */

const { createVerifier } = require('../core/verifier.js');
const respond = require('../http/respond.js');

const ERROR_VERDICT = {
  allow: false,
  reason: 'error',
  detail: 'verification error',
  ip: null,
  mac: null,
  via: 'error',
  token: null,
  network: null,
  checks: {},
};

function hereonly(options = {}) {
  const verifier = options.verifier || createVerifier(options);
  const cookieName = options.cookieName || 'hereonly';
  const headerName = options.headerName || 'x-hereonly-token';
  const setCookie = options.setCookie !== false;
  const cookieOptions = options.cookieOptions || {};
  const trustForwardedHeader = !!options.trustForwardedHeader;
  const denyStatus = options.denyStatus || 403;
  const denyFormat = options.denyFormat; // 'json' | 'html' | undefined (negotiate)
  const onDeny = typeof options.onDeny === 'function' ? options.onDeny : null;
  const exposeVerdict = options.exposeVerdict !== false;
  const ttlSeconds = verifier.options.tokenTtlSeconds;

  async function middleware(req, res, next) {
    let verdict;
    try {
      verdict = await verifier.verifyRequest(req, { cookieName, headerName, trustForwardedHeader });
    } catch (err) {
      verdict = { ...ERROR_VERDICT, detail: (err && err.message) || 'verification error' };
    }
    if (exposeVerdict) req.hereonly = verdict;

    if (verdict.allow) {
      if (setCookie && verdict.token) {
        respond.appendSetCookie(
          res,
          respond.buildSessionCookie(cookieName, verdict.token, { ttlSeconds, ...cookieOptions }),
        );
      }
      return next();
    }

    if (onDeny) return onDeny(req, res, verdict);
    return respond.sendDeny(req, res, denyStatus, verdict, { format: denyFormat });
  }

  middleware.verifier = verifier;
  return middleware;
}

module.exports = { hereonly };
