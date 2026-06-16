'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');

const { hereonly } = require('../../src/middleware/express.js');
const { createVerifier } = require('../../src/core/verifier.js');
const { listen, close, request } = require('./_client.js');

// Mount the middleware on a raw http server with a trivial next() handler.
function appWith(guard) {
  return http.createServer((req, res) => {
    guard(req, res, () => {
      res.statusCode = 200;
      res.setHeader('Content-Type', 'text/plain');
      res.end('APP REACHED via ' + (req.hereonly ? req.hereonly.reason : '?'));
    });
  });
}

test('middleware calls next() and exposes req.hereonly for an allowed request', async () => {
  const server = appWith(hereonly({ silent: true }));
  const port = await listen(server);
  try {
    const res = await request(`http://127.0.0.1:${port}/`);
    assert.equal(res.status, 200);
    assert.equal(res.body, 'APP REACHED via loopback');
  } finally {
    await close(server);
  }
});

test('middleware sends a 403 (HTML) when denied', async () => {
  const verifier = createVerifier({ allowLoopback: false, silent: true });
  const server = appWith(hereonly({ verifier }));
  const port = await listen(server);
  try {
    const res = await request(`http://127.0.0.1:${port}/`, { headers: { accept: 'text/html' } });
    assert.equal(res.status, 403);
    assert.match(res.headers['content-type'], /text\/html/);
    assert.match(res.body, /Access denied/);
  } finally {
    await close(server);
  }
});

test('middleware negotiates JSON when the client asks for it', async () => {
  const verifier = createVerifier({ allowLoopback: false, silent: true });
  const server = appWith(hereonly({ verifier }));
  const port = await listen(server);
  try {
    const res = await request(`http://127.0.0.1:${port}/`, { headers: { accept: 'application/json' } });
    assert.equal(res.status, 403);
    assert.match(res.headers['content-type'], /application\/json/);
    const body = res.json();
    assert.equal(body.by, 'hereonly');
    assert.equal(body.reason, 'no-arp-entry');
  } finally {
    await close(server);
  }
});

test('middleware supports a custom onDeny handler', async () => {
  const verifier = createVerifier({ allowLoopback: false, silent: true });
  const guard = hereonly({
    verifier,
    onDeny: (req, res, verdict) => {
      res.statusCode = 418;
      res.setHeader('Content-Type', 'text/plain');
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
