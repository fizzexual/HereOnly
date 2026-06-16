'use strict';

/**
 * Embed HereOnly directly in a raw Node http server (no Express needed).
 * The middleware is a standard (req, res, next) handler.
 *
 *   node examples/protect-with-middleware.js     # listens on :7000
 */

const http = require('node:http');
const { hereonly } = require('../src');

const guard = hereonly({ logLevel: 'debug' });

http
  .createServer((req, res) => {
    guard(req, res, () => {
      // Only reached for on-segment devices.
      res.setHeader('Content-Type', 'text/html; charset=utf-8');
      res.end(
        `<h1>✅ Protected app</h1><p>You are on the segment.</p>` +
          `<pre>${JSON.stringify(req.hereonly, null, 2)}</pre>`,
      );
    });
  })
  .listen(7000, () => {
    console.log('protected app on http://localhost:7000 (loopback always allowed)');
  });
