'use strict';

/**
 * Embed HereOnly directly in a raw Node http server (no framework, no deps).
 * The middleware is a standard (req, res, next) handler.
 *
 *   node examples/protect-with-middleware.js     # listens on :7000
 */

const http = require('node:http');
const { hereonly } = require('../src');

// Gate to the segment; keep a tamper-evident audit log of attempts.
const guard = hereonly({ logLevel: 'debug', audit: { file: '.hereonly/audit.log', sign: true } });

http
  .createServer((req, res) => {
    guard(req, res, () => {
      res.setHeader('Content-Type', 'text/html; charset=utf-8');
      res.end(`<h1>&#9989; Protected app</h1><p>You are on the segment.</p><pre>${JSON.stringify(req.hereonly, null, 2)}</pre>`);
    });
  })
  .listen(7000, () => console.log('protected app on http://localhost:7000 (loopback/self always allowed)'));
