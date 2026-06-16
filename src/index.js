'use strict';

/**
 * HereOnly — make your LAN a vault.
 * Public API surface.
 */

const { createVerifier, DEFAULTS } = require('./core/verifier.js');
const { createAudit, loadAuditFile } = require('./core/audit.js');
const { createRateLimiter } = require('./core/ratelimit.js');
const { createPolicyResolver } = require('./core/policy.js');
const tokens = require('./core/tokens.js');
const ip = require('./core/ip.js');
const fingerprint = require('./core/fingerprint.js');
const os = require('./os');
const { createLogger, noopLogger } = require('./core/logger.js');

module.exports = {
  createVerifier,
  defaults: DEFAULTS,

  // audit, rate limiting, policy
  createAudit,
  loadAuditFile,
  createRateLimiter,
  createPolicyResolver,

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
