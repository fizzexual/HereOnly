'use strict';

/**
 * A deliberately unprotected "internal" server - the thing you keep on your
 * local segment. Run it, then put HereOnly in front:
 *
 *   node examples/demo-server.js                 # listens on :3000
 *   node bin/hereonly.js proxy -t http://127.0.0.1:3000 -p 7000
 */

const http = require('node:http');
const PORT = Number(process.env.PORT || 3000);

http
  .createServer((req, res) => {
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.end(`<!doctype html><meta charset="utf-8"><title>Internal Dashboard</title>
<body style="font:16px system-ui;max-width:40rem;margin:3rem auto;color:#222">
  <h1>&#128274; Internal Dashboard</h1>
  <p>If you can read this <strong>through the HereOnly proxy</strong>, you are on the
  same physical network segment as the host.</p>
  <p>HereOnly verdict: <code>${req.headers['x-hereonly-verified'] || '(direct, not proxied)'}</code></p>
  <p>Your device MAC (per HereOnly): <code>${req.headers['x-hereonly-mac'] || '(n/a)'}</code></p>
</body>`);
  })
  .listen(PORT, () => console.log(`demo server (unprotected) on http://127.0.0.1:${PORT}`));
