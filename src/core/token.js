'use strict';

/**
 * HereOnly session tokens.
 *
 * A token is a compact, signed assertion that a client was verified as
 * on-segment, bound to the three things that make a stolen token useless:
 *   - `ip`  : the client's IP at issuance
 *   - `mac` : the client's link-layer address (from the neighbor table)
 *   - `net` : a fingerprint of the host's network at issuance
 *
 * A token carried to another device fails the MAC bind; carried to another
 * network it fails the `net` bind; replayed after `exp` it fails the clock.
 * The signature is HMAC-SHA256 over the payload, compared in constant time.
 *
 * Wire format:  HO1.<base64url(payload)>.<base64url(hmac)>
 */

const crypto = require('node:crypto');

const HEADER = 'HO1';

function b64url(buf) {
  return Buffer.from(buf).toString('base64url');
}

function fromB64url(str) {
  return Buffer.from(str, 'base64url');
}

/** A fresh 256-bit secret. */
function generateSecret(bytes = 32) {
  return crypto.randomBytes(bytes);
}

function normalizeSecret(secret) {
  if (Buffer.isBuffer(secret)) return secret;
  if (typeof secret === 'string') return Buffer.from(secret, 'utf8');
  throw new TypeError('HereOnly token secret must be a Buffer or string');
}

function sign(payloadB64, secret) {
  return crypto.createHmac('sha256', secret).update(payloadB64).digest();
}

/**
 * Issue a token.
 * @param {{ ip?: string|null, mac?: string|null, net?: string|null }} claims
 * @param {Buffer|string} secret
 * @param {{ ttlSeconds?: number, now?: () => number }} [opts]
 */
function issueToken(claims, secret, opts = {}) {
  const sec = normalizeSecret(secret);
  const ttlSeconds = opts.ttlSeconds || 1800;
  const now = opts.now || Date.now;
  const iat = Math.floor(now() / 1000);
  const payload = {
    v: 1,
    ip: claims.ip != null ? claims.ip : null,
    mac: claims.mac != null ? claims.mac : null,
    net: claims.net != null ? claims.net : null,
    iat,
    exp: iat + ttlSeconds,
    jti: crypto.randomBytes(8).toString('hex'),
  };
  const payloadB64 = b64url(JSON.stringify(payload));
  const sig = b64url(sign(payloadB64, sec));
  return `${HEADER}.${payloadB64}.${sig}`;
}

/**
 * Verify a token's structure, signature, and expiry. Does NOT compare the
 * bound claims against the current request — that is the verifier's job.
 * @returns {{ valid: boolean, reason: string, payload?: object }}
 */
function verifyToken(token, secret, opts = {}) {
  if (typeof token !== 'string' || token.length === 0) return { valid: false, reason: 'missing' };
  const parts = token.split('.');
  if (parts.length !== 3 || parts[0] !== HEADER) return { valid: false, reason: 'malformed' };
  const [, payloadB64, sigB64] = parts;

  const sec = normalizeSecret(secret);
  const expected = sign(payloadB64, sec);
  let provided;
  try {
    provided = fromB64url(sigB64);
  } catch {
    return { valid: false, reason: 'malformed-signature' };
  }
  if (provided.length !== expected.length || !crypto.timingSafeEqual(provided, expected)) {
    return { valid: false, reason: 'bad-signature' };
  }

  let payload;
  try {
    payload = JSON.parse(fromB64url(payloadB64).toString('utf8'));
  } catch {
    return { valid: false, reason: 'bad-payload' };
  }

  const now = opts.now || Date.now;
  const skew = opts.clockSkewSeconds != null ? opts.clockSkewSeconds : 30;
  const nowSec = Math.floor(now() / 1000);
  if (typeof payload.exp !== 'number' || nowSec > payload.exp + skew) {
    return { valid: false, reason: 'expired', payload };
  }
  if (typeof payload.iat === 'number' && payload.iat - skew > nowSec) {
    return { valid: false, reason: 'not-yet-valid', payload };
  }
  return { valid: true, reason: 'ok', payload };
}

module.exports = { issueToken, verifyToken, generateSecret, normalizeSecret, HEADER };
