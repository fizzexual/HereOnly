'use strict';

/**
 * Per-resource policy resolution.
 *
 * A policy is a list of rules; the first whose matcher fits a request supplies
 * a set of verifier-option overrides for that request. Lets you, e.g., require
 * a specific approved network for `/admin` while the rest of the site only
 * needs plain on-segment adjacency.
 *
 *   policies: [
 *     { match: { path: '/admin' }, overrides: { network: { allowedSsids: ['Ops'] } } },
 *     { match: { host: 'nas.local' }, overrides: { requireArp: true } },
 *   ]
 */

function matchOne(pattern, value) {
  if (pattern == null) return true;
  if (pattern instanceof RegExp) return pattern.test(value || '');
  return String(value || '').startsWith(String(pattern));
}

function ruleMatches(match, ctx) {
  if (!match) return true;
  if (match.path != null && !matchOne(match.path, ctx.path)) return false;
  if (match.host != null) {
    if (match.host instanceof RegExp) {
      if (!match.host.test(ctx.host || '')) return false;
    } else if (String(ctx.host || '') !== String(match.host)) {
      return false;
    }
  }
  if (match.method != null && String(ctx.method || '').toUpperCase() !== String(match.method).toUpperCase()) {
    return false;
  }
  return true;
}

function createPolicyResolver(rules = []) {
  const list = Array.isArray(rules) ? rules : [];
  return function resolve(ctx = {}) {
    for (const r of list) {
      if (ruleMatches(r.match || null, ctx)) return r.overrides || r.options || {};
    }
    return {};
  };
}

module.exports = { createPolicyResolver, ruleMatches };
