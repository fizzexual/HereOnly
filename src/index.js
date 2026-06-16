'use strict';

/**
 * HereOnly — make your LAN a vault.
 * Public API surface.
 */

const { createVerifier, DEFAULTS } = require('./core/verifier.js');
const { hereonly } = require('./server/middleware.js');
const { createProxyServer } = require('./server/proxy.js');
const { createAuthServer } = require('./server/authserver.js');
const { createAudit, loadAuditFile } = require('./core/audit.js');
const { createRateLimiter } = require('./core/ratelimit.js');
const { createPolicyResolver } = require('./core/policy.js');
const tokens = require('./core/tokens.js');
const ip = require('./core/ip.js');
const fingerprint = require('./core/fingerprint.js');
const os = require('./os');
const respond = require('./server/respond.js');
const { createLogger, noopLogger } = require('./core/logger.js');

module.exports = {
  createVerifier,
  defaults: DEFAULTS,

  // server fronts
  hereonly,
  middleware: hereonly,
  createProxyServer,
  createAuthServer,

  // audit, rate limiting, policy
  createAudit,
  loadAuditFile,
  createRateLimiter,
  createPolicyResolver,
  respond,

  // tokens
  generateSecret: tokens.generateSecret,
  issueToken: tokens.issueToken,
  verifyToken: tokens.verifyToken,
  tokens,

  // building blocks
  ip,
  fingerprint,
  os,
  createLogger,
  noopLogger,
};
