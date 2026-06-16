'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const net = require('node:net');

const { createProxyServer } = require('../../src/server/proxy.js');
const { createVerifier } = require('../../src/core/verifier.js');
const { listen, close, request, rawUpgrade, cookieValue } = require('./_client.js');

function makeTarget() {
  const server = http.createServer((req, res) => {
    res.setHeader('X-Echo-Verified', req.headers['x-hereonly-verified'] || '(none)');
    res.setHeader('X-Echo-Mac', req.headers['x-hereonly-mac'] || '(none)');
    res.end('TARGET OK');
  });
  server.on('upgrade', (req, socket) => {
    socket.write('HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n');
    socket.write('ECHO');
  });
  return server;
}

const SECRET = Buffer.from('integration-secret-integration!!', 'utf8');

// Treat 127.0.0.1 as an on-segment neighbor so the full check runs over loopback.
function onSegmentVerifier(extra = {}) {
  const run = async (file) =>
    file === 'arp'
      ? { ok: true, code: 0, stdout: 'Interface: 127.0.0.1 --- 0x1\n  127.0.0.1   aa-bb-cc-dd-ee-ff   dynamic', stderr: '' }
      : { ok: true, code: 0, stdout: '', stderr: '' };
  return createVerifier({
    allowLoopback: false,
    allowSelf: false,
    ownIps: [],
    platform: 'win32',
    run,
    staticIdentity: { subnets: ['127.0.0.0/8'], gateway: { ip: null, mac: null }, wifi: { ssid: null, bssid: null } },
    secret: SECRET,
    silent: true,
    arpTtlMs: 50,
    ...extra,
  });
}

test('proxy forwards an allowed (loopback) request, injecting forward headers', async () => {
  const target = makeTarget();
  const tport = await listen(target);
  const proxy = createProxyServer({ target: `http://127.0.0.1:${tport}`, silent: true });
  const pport = await listen(proxy);
  try {
    const res = await request(`http://127.0.0.1:${pport}/dashboard`);
    assert.equal(res.status, 200);
    assert.equal(res.body, 'TARGET OK');
    assert.equal(res.headers['x-echo-verified'], 'loopback');
  } finally {
    await close(proxy);
    await close(target);
  }
});

test('proxy denies an off-segment request with a 403 page', async () => {
  const target = makeTarget();
  const tport = await listen(target);
  const verifier = createVerifier({ allowLoopback: false, allowSelf: false, silent: true });
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

test('proxy issues a session token, then accepts it (fast path) on the next request', async () => {
  const target = makeTarget();
  const tport = await listen(target);
  const proxy = createProxyServer({ target: `http://127.0.0.1:${tport}`, verifier: onSegmentVerifier(), silent: true });
  const pport = await listen(proxy);
  try {
    const first = await request(`http://127.0.0.1:${pport}/`);
    assert.equal(first.headers['x-echo-verified'], 'arp-verified');
    assert.equal(first.headers['x-echo-mac'], 'aa:bb:cc:dd:ee:ff');
    const token = cookieValue(first.setCookie, 'hereonly');
    assert.ok(token);
    const second = await request(`http://127.0.0.1:${pport}/`, { headers: { cookie: `hereonly=${encodeURIComponent(token)}` } });
    assert.equal(second.headers['x-echo-verified'], 'token');
  } finally {
    await close(proxy);
    await close(target);
  }
});

test('proxy returns 502 when the upstream is down', async () => {
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
    assert.equal((await request(`http://127.0.0.1:${pport}/`)).status, 502);
  } finally {
    await close(proxy);
  }
});

test('proxy bridges an allowed WebSocket upgrade and refuses a denied one', async () => {
  const target = makeTarget();
  const tport = await listen(target);
  const okProxy = createProxyServer({ target: `http://127.0.0.1:${tport}`, silent: true });
  const okPort = await listen(okProxy);
  const denyVerifier = createVerifier({ allowLoopback: false, allowSelf: false, silent: true });
  const denyProxy = createProxyServer({ target: `http://127.0.0.1:${tport}`, verifier: denyVerifier, silent: true });
  const denyPort = await listen(denyProxy);
  try {
    assert.match(await rawUpgrade(okPort), /101 Switching Protocols/);
    assert.match(await rawUpgrade(denyPort), /403 Forbidden/);
  } finally {
    await close(okProxy);
    await close(denyProxy);
    await close(target);
  }
});
