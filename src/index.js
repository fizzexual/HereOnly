'use strict';

/**
 * HereOnly — subnet-locked access control for local web servers.
 * Public API surface.
 */

const { createVerifier, DEFAULTS } = require('./core/verifier.js');
const token = require('./core/token.js');
const ip = require('./core/ip.js');
const netident = require('./core/netident.js');
const os = require('./os');
const { createLogger, noopLogger } = require('./core/logger.js');

module.exports = {
  createVerifier,
  defaults: DEFAULTS,

  // crypto / tokens
  generateSecret: token.generateSecret,
  issueToken: token.issueToken,
  verifyToken: token.verifyToken,
  token,

  // building blocks
  ip,
  netident,
  os,
  createLogger,
  noopLogger,
};
