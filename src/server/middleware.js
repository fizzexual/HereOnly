'use strict';

/**
 * Express / Connect middleware (also works as a raw-http (req,res,next) handler).
 *
 *   const { hereonly } = require('hereonly/middleware');
 *   app.use(hereonly());                  // gate everything
 *   app.use('/admin', hereonly());        // ...or a subtree
 *
 * On allow: attaches `req.hereonly` (the verdict), optionally sets the session
 * cookie, calls next(). On deny: sends a 403 (HTML/JSON by negotiation) or
 * defers to a custom `onDeny(req, res, verdict)`.
 */

const { createVerifier } = require('../core/verifier.js');
const respond = require('./respond.js');

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
  present: false,
  retryAfterMs: 0,
};

function hereonly(options = {}) {
  const verifier = options.verifier || createVerifier(options);
  const cookieName = options.cookieName || 'hereonly';
  const headerName = options.headerName || 'x-hereonly-token';
  const setCookie = options.setCookie !== false;
  const cookieOptions = options.cookieOptions || {};
  const trustForwardedHeader = !!options.trustForwardedHeader;
  const denyStatus = options.denyStatus || 403;
  const denyFormat = options.denyFormat;
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
        respond.appendSetCookie(res, respond.buildSessionCookie(cookieName, verdict.token, { ttlSeconds, ...cookieOptions }));
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
