'use strict';

/**
 * Configuration helpers: secret persistence and config-file / env loading.
 */

const fs = require('node:fs');
const { generateSecret } = require('./core/token.js');

/**
 * Load a 256-bit secret from `file`, creating and persisting one (hex, mode
 * 0600) if it does not exist. Persisting the secret keeps issued session
 * tokens valid across restarts. With no file, returns an ephemeral secret
 * (restart invalidates all tokens — often exactly what you want).
 */
function loadOrCreateSecret(file) {
  if (!file) return generateSecret();
  try {
    if (fs.existsSync(file)) {
      const txt = fs.readFileSync(file, 'utf8').trim();
      if (/^[0-9a-fA-F]+$/.test(txt) && txt.length >= 32) return Buffer.from(txt, 'hex');
      if (txt.length > 0) return Buffer.from(txt, 'utf8');
    }
  } catch {
    /* fall through to create */
  }
  const secret = generateSecret();
  try {
    fs.writeFileSync(file, secret.toString('hex'), { mode: 0o600 });
  } catch {
    /* non-fatal: use ephemeral secret in memory */
  }
  return secret;
}

/** Read a JSON config file, returning {} if missing/unreadable. */
function readConfigFile(file) {
  if (!file) return {};
  try {
    return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch {
    return {};
  }
}

/** Pull HEREONLY_* env vars into a partial options object. */
function fromEnv(env = process.env) {
  const out = {};
  if (env.HEREONLY_TARGET) out.target = env.HEREONLY_TARGET;
  if (env.HEREONLY_PORT) out.port = Number(env.HEREONLY_PORT);
  if (env.HEREONLY_HOST) out.host = env.HEREONLY_HOST;
  if (env.HEREONLY_SECRET) out.secret = env.HEREONLY_SECRET;
  if (env.HEREONLY_SECRET_FILE) out.secretFile = env.HEREONLY_SECRET_FILE;
  if (env.HEREONLY_LOG_LEVEL) out.logLevel = env.HEREONLY_LOG_LEVEL;
  return out;
}

/** Coerce a value (string|array|undefined) to a trimmed string array. */
function toArray(v) {
  if (v == null) return [];
  if (Array.isArray(v)) return v.flatMap(toArray);
  return String(v)
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
}

module.exports = { loadOrCreateSecret, readConfigFile, fromEnv, toArray };
