'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const net = require('node:net');

const { createProxyServer } = require('../../src/proxy/server.js');
const { createVerifier } = require('../../src/core/verifier.js');
const { listen, close, request, rawUpgrade, cookieValue } = require('./_client.js');

// A target that echoes back the HereOnly forward header so we can assert what
// the proxy injected, and serves a body. Also handles WebSocket upgrades.
function makeTarget() {
  const server = http.createServer((req, res) => {
    res.setHeader('X-Echo-Verified', req.headers['x-hereonly-verified'] || '(none)');
    res.setHeader('X-Echo-XFF', req.headers['x-forwarded-for'] || '(none)');
    res.end('TARGET OK');
  });
  server.on('upgrade', (req, socket) => {
    socket.write('HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n');
    socket.write('ECHO');
  });
  return server;
}

const SECRET = Buffer.from('integration-secret-integration!!', 'utf8');

// Drive the *full* check over loopback by treating 127.0.0.1 as an on-segment
// neighbor (allowLoopback off, fake ARP table includes 127.0.0.1).
function onSegmentLoopbackVerifier() {
  const run = async (file) =>
    file === 'arp'
      ? { ok: true, code: 0, stdout: 'Interface: 127.0.0.1 --- 0x1\n  127.0.0.1   aa-bb-cc-dd-ee-ff   dynamic', stderr: '' }
      : { ok: false, code: 1, stdout: '', stderr: '' };
  return createVerifier({
    allowLoopback: false,
    platform: 'win32',
    run,
    staticIdentity: { subnets: ['127.0.0.0/8'], gateway: { ip: null, mac: null }, wifi: { ssid: null, bssid: null } },
    secret: SECRET,
    silent: true,
    arpTtlMs: 50,
  });
}

test('proxy forwards an allowed (loopback) request and injects forward headers', async () => {
  const target = makeTarget();
  const tport = await listen(target);
  const proxy = createProxyServer({ target: `http://127.0.0.1:${tport}`, silent: true });
  const pport = await listen(proxy);
  try {
    const res = await request(`http://127.0.0.1:${pport}/dashboard`);
    assert.equal(res.status, 200);
    assert.equal(res.body, 'TARGET OK');
    assert.equal(res.headers['x-echo-verified'], 'loopback'); // proxy told the target why
  } finally {
    await close(proxy);
    await close(target);
  }
});

test('proxy denies an off-segment request with a 403 page', async () => {
  const target = makeTarget();
  const tport = await listen(target);
  // allowLoopback:false + real OS => 127.0.0.1 has no ARP entry => denied.
  const verifier = createVerifier({ allowLoopback: false, silent: true });
  const proxy = createProxyServer({ target: `http://127.0.0.1:${tport}`, verifier, silent: true });
  const pport = await listen(proxy);
  try {
    const res = await request(`http://127.0.0.1:${pport}/`);
    assert.equal(res.status, 403);
    assert.equal(res.headers['x-hereonly-denied'], 'no-arp-entry');
    assert.match(res.body, /Access denied/);
  } finally {
    await close(proxy);
    await close(target);
  }
});

test('proxy issues a session token, then accepts it on the next request', async () => {
  const target = makeTarget();
  const tport = await listen(target);
  const proxy = createProxyServer({
    target: `http://127.0.0.1:${tport}`,
    verifier: onSegmentLoopbackVerifier(),
    silent: true,
  });
  const pport = await listen(proxy);
  try {
    const first = await request(`http://127.0.0.1:${pport}/`);
    assert.equal(first.status, 200);
    assert.equal(first.headers['x-echo-verified'], 'arp-verified'); // full check on first hit
    const token = cookieValue(first.setCookie, 'hereonly');
    assert.ok(token, 'a hereonly cookie should be set');

    const second = await request(`http://127.0.0.1:${pport}/`, {
      headers: { cookie: `hereonly=${encodeURIComponent(token)}` },
    });
    assert.equal(second.status, 200);
    assert.equal(second.headers['x-echo-verified'], 'token'); // fast path on second hit
  } finally {
    await close(proxy);
    await close(target);
  }
});

test('proxy returns 502 when the upstream is down', async () => {
  // Point at a port with nothing listening.
  const dead = await new Promise((resolve) => {
    const s = net.createServer();
    s.listen(0, '127.0.0.1', () => {
      const p = s.address().port;
      s.close(() => resolve(p));
    });
  });
  const proxy = createProxyServer({ target: `http://127.0.0.1:${dead}`, silent: true });
  const pport = await listen(proxy);
  try {
    const res = await request(`http://127.0.0.1:${pport}/`);
    assert.equal(res.status, 502);
  } finally {
    await close(proxy);
  }
});

test('proxy bridges an allowed WebSocket upgrade', async () => {
  const target = makeTarget();
  const tport = await listen(target);
  const proxy = createProxyServer({ target: `http://127.0.0.1:${tport}`, silent: true });
  const pport = await listen(proxy);
  try {
    const reply = await rawUpgrade(pport);
    assert.match(reply, /101 Switching Protocols/);
    assert.match(reply, /ECHO/);
  } finally {
    await close(proxy);
    await close(target);
  }
});

test('proxy refuses a denied WebSocket upgrade with 403', async () => {
  const target = makeTarget();
  const tport = await listen(target);
  const verifier = createVerifier({ allowLoopback: false, silent: true }); // loopback has no ARP entry
  const proxy = createProxyServer({ target: `http://127.0.0.1:${tport}`, verifier, silent: true });
  const pport = await listen(proxy);
  try {
    const reply = await rawUpgrade(pport);
    assert.match(reply, /403 Forbidden/);
  } finally {
    await close(proxy);
    await close(target);
  }
});
