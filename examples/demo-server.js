'use strict';

/**
 * A deliberately unprotected "internal" server — the thing you want to keep on
 * your local segment. Run it, then put HereOnly in front of it:
 *
 *   node examples/demo-server.js                 # listens on :3000
 *   node bin/hereonly.js proxy -t http://127.0.0.1:3000 -p 7000
 *
 * Now :7000 is reachable only from on-segment devices; :3000 is the raw app.
 */

const http = require('node:http');

const PORT = Number(process.env.PORT || 3000);

http
  .createServer((req, res) => {
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.end(`<!doctype html><html><head><meta charset="utf-8"><title>Internal Dashboard</title>
<style>body{font:16px system-ui;margin:3rem auto;max-width:40rem;color:#222}</style></head>
<body>
  <h1>🗄️ Internal Dashboard</h1>
  <p>If you can read this <strong>through the HereOnly proxy</strong>, you are on the
  same physical network segment as the host.</p>
  <p>Request path: <code>${req.url}</code></p>
  <p>X-HereOnly-Verified: <code>${req.headers['x-hereonly-verified'] || '(direct, not proxied)'}</code></p>
</body></html>`);
  })
  .listen(PORT, () => {
    console.log(`demo server (unprotected) on http://127.0.0.1:${PORT}`);
  });
