'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');

const { createAuthServer } = require('../../src/server/authserver.js');
const { createVerifier } = require('../../src/core/verifier.js');
const { listen, close, request } = require('./_client.js');

const SECRET = Buffer.from('integration-secret-integration!!', 'utf8');

// 127.0.0.1 is on-segment (fake ARP); loopback/self disabled so the full check runs.
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

test('forward-auth: allow returns 204 with X-HereOnly headers', async () => {
  const server = createAuthServer({ verifier: onSegmentVerifier(), silent: true });
  const port = await listen(server);
  try {
    const res = await request(`http://127.0.0.1:${port}/auth`);
    assert.equal(res.status, 204);
    assert.equal(res.headers['x-hereonly-verified'], 'arp-verified');
    assert.equal(res.headers['x-hereonly-present'], '1');
    assert.equal(res.headers['x-hereonly-mac'], 'aa:bb:cc:dd:ee:ff');
  } finally {
    await close(server);
  }
});

test('forward-auth: trusts X-Real-IP from a loopback proxy and denies an off-segment client', async () => {
  const server = createAuthServer({ verifier: onSegmentVerifier(), silent: true });
  const port = await listen(server);
  try {
    // Peer is loopback (trusted) so X-Real-IP is honored; 8.8.8.8 has no neighbor entry.
    const res = await request(`http://127.0.0.1:${port}/auth`, { headers: { 'x-real-ip': '8.8.8.8' } });
    assert.equal(res.status, 403);
    assert.equal(res.headers['x-hereonly-denied'], 'no-arp-entry');
    assert.equal(res.json().by, 'hereonly');
  } finally {
    await close(server);
  }
});

test('forward-auth: records the original request URI in the audit log', async () => {
  const verifier = onSegmentVerifier({ audit: true });
  const server = createAuthServer({ verifier, silent: true });
  const port = await listen(server);
  try {
    await request(`http://127.0.0.1:${port}/auth`, {
      headers: { 'x-forwarded-method': 'POST', 'x-forwarded-uri': '/admin/settings' },
    });
    const last = verifier.audit.tail().slice(-1)[0];
    assert.match(last.resource, /POST .*\/admin\/settings/);
    assert.equal(last.verdict, 'allow');
  } finally {
    await close(server);
  }
});
