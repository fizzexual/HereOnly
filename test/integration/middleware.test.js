'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');

const { hereonly } = require('../../src/server/middleware.js');
const { createVerifier } = require('../../src/core/verifier.js');
const { listen, close, request } = require('./_client.js');

function appWith(guard) {
  return http.createServer((req, res) => {
    guard(req, res, () => {
      res.statusCode = 200;
      res.setHeader('Content-Type', 'text/plain');
      res.end('APP via ' + (req.hereonly ? req.hereonly.reason : '?'));
    });
  });
}

test('middleware calls next() and exposes req.hereonly for an allowed request', async () => {
  const server = appWith(hereonly({ silent: true }));
  const port = await listen(server);
  try {
    const res = await request(`http://127.0.0.1:${port}/`);
    assert.equal(res.status, 200);
    assert.equal(res.body, 'APP via loopback');
  } finally {
    await close(server);
  }
});

test('middleware denies with HTML or JSON by negotiation', async () => {
  const verifier = createVerifier({ allowLoopback: false, allowSelf: false, silent: true });
  const server = appWith(hereonly({ verifier }));
  const port = await listen(server);
  try {
    const html = await request(`http://127.0.0.1:${port}/`, { headers: { accept: 'text/html' } });
    assert.equal(html.status, 403);
    assert.match(html.headers['content-type'], /text\/html/);
    assert.match(html.body, /Access denied/);
    const json = await request(`http://127.0.0.1:${port}/`, { headers: { accept: 'application/json' } });
    assert.equal(json.status, 403);
    assert.equal(json.json().reason, 'no-arp-entry');
  } finally {
    await close(server);
  }
});

test('middleware supports a custom onDeny handler', async () => {
  const verifier = createVerifier({ allowLoopback: false, allowSelf: false, silent: true });
  const guard = hereonly({
    verifier,
    onDeny: (req, res, verdict) => {
      res.statusCode = 418;
      res.end('custom:' + verdict.reason);
    },
  });
  const server = appWith(guard);
  const port = await listen(server);
  try {
    const res = await request(`http://127.0.0.1:${port}/`);
    assert.equal(res.status, 418);
    assert.equal(res.body, 'custom:no-arp-entry');
  } finally {
    await close(server);
  }
});
