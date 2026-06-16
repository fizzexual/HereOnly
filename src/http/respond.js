'use strict';

/**
 * Shared HTTP response helpers for the middleware and the reverse proxy.
 * Framework-agnostic: only uses the Node core `res` API (setHeader / statusCode
 * / end), so it works with raw http, Connect, and Express alike.
 */

function buildSessionCookie(name, value, opts = {}) {
  const parts = [`${name}=${encodeURIComponent(value)}`];
  parts.push(`Path=${opts.path || '/'}`);
  if (opts.ttlSeconds != null) parts.push(`Max-Age=${Math.max(0, Math.floor(opts.ttlSeconds))}`);
  parts.push(`SameSite=${opts.sameSite || 'Lax'}`);
  if (opts.httpOnly !== false) parts.push('HttpOnly');
  if (opts.secure) parts.push('Secure');
  if (opts.domain) parts.push(`Domain=${opts.domain}`);
  return parts.join('; ');
}

function appendSetCookie(res, cookieStr) {
  const prev = res.getHeader ? res.getHeader('Set-Cookie') : undefined;
  let arr = [];
  if (Array.isArray(prev)) arr = prev.slice();
  else if (prev) arr = [prev];
  arr.push(cookieStr);
  res.setHeader('Set-Cookie', arr);
}

function clearSessionCookie(res, name, opts = {}) {
  appendSetCookie(
    res,
    buildSessionCookie(name, '', { ...opts, ttlSeconds: 0 }),
  );
}

function wantsJson(req) {
  const accept = (req && req.headers && (req.headers['accept'] || '')) || '';
  return /application\/json/i.test(accept) && !/text\/html/i.test(accept);
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c],
  );
}

function denyHtml(verdict) {
  const reason = escapeHtml(verdict.reason || 'denied');
  const detail = escapeHtml(verdict.detail || 'This request is not on the allowed network segment.');
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>HereOnly · Access denied</title>
<style>
  :root { color-scheme: light dark; }
  body { margin:0; min-height:100vh; display:grid; place-items:center;
    font:16px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif;
    background:#0b0e14; color:#e6e6e6; }
  .card { max-width:30rem; padding:2.5rem; border:1px solid #232a36;
    border-radius:16px; background:#11161f; box-shadow:0 10px 40px rgba(0,0,0,.4); }
  h1 { margin:0 0 .25rem; font-size:1.4rem; }
  .lock { font-size:2.5rem; }
  code { background:#1b2230; padding:.15rem .4rem; border-radius:6px; font-size:.85em; }
  .muted { color:#8a93a3; font-size:.9rem; margin-top:1.25rem; }
</style>
</head>
<body>
  <div class="card">
    <div class="lock">🔒</div>
    <h1>Access denied</h1>
    <p>${detail}</p>
    <p class="muted">Blocked by <strong>HereOnly</strong> · reason <code>${reason}</code><br>
    Only devices on the same physical network segment as the host may reach this site.</p>
  </div>
</body>
</html>`;
}

/**
 * Send a denial response. Chooses JSON or HTML by content negotiation
 * (override with opts.format = 'json' | 'html').
 */
function sendDeny(req, res, status, verdict, opts = {}) {
  if (res.headersSent || res.writableEnded) {
    try {
      res.end();
    } catch {
      /* ignore */
    }
    return;
  }
  const json = opts.format === 'json' || (opts.format !== 'html' && wantsJson(req));
  res.statusCode = status || 403;
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('X-HereOnly-Denied', verdict.reason || 'denied');
  if (json) {
    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    res.end(
      JSON.stringify({
        error: 'access denied',
        by: 'hereonly',
        reason: verdict.reason || 'denied',
        detail: verdict.detail || null,
      }),
    );
  } else {
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.end(denyHtml(verdict));
  }
}

module.exports = {
  buildSessionCookie,
  appendSetCookie,
  clearSessionCookie,
  wantsJson,
  sendDeny,
  denyHtml,
  escapeHtml,
};
