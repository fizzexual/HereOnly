'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');

const {
  parseWindowsNetstat,
  parseLinuxListening,
  parseBsdNetstat,
  detectServices,
  parseConfiguredServices,
  mergeServices,
} = require('../../src/hub/services.js');

const WIN = `Active Connections
  Proto  Local Address          Foreign Address        State
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING
  TCP    0.0.0.0:3000           0.0.0.0:0              LISTENING
  TCP    127.0.0.1:5432         0.0.0.0:0              LISTENING
  TCP    [::]:8080              [::]:0                 LISTENING
  TCP    192.168.100.2:139      0.0.0.0:0              LISTENING`;

const SS = `State   Recv-Q  Send-Q  Local Address:Port  Peer Address:Port
LISTEN  0       128     0.0.0.0:22          0.0.0.0:*
LISTEN  0       128     127.0.0.1:3000      0.0.0.0:*
LISTEN  0       128     [::]:8080           [::]:*`;

const BSD = `Proto Recv-Q Send-Q  Local Address          Foreign Address        (state)
tcp4       0      0  *.22                   *.*                    LISTEN
tcp4       0      0  127.0.0.1.3000         *.*                    LISTEN
tcp6       0      0  *.8080                 *.*                    LISTEN`;

test('netstat parsers extract listening ports', () => {
  assert.deepEqual(parseWindowsNetstat(WIN).sort((a, b) => a - b), [135, 139, 3000, 5432, 8080]);
  assert.deepEqual(parseLinuxListening(SS).sort((a, b) => a - b), [22, 3000, 8080]);
  assert.deepEqual(parseBsdNetstat(BSD).sort((a, b) => a - b), [22, 3000, 8080]);
});

test('detectServices keeps HTTP responders, honors excludePorts + skip list', async () => {
  const run = async (file) => (file === 'netstat' ? { ok: true, stdout: WIN } : { ok: false });
  const probe = async (port) => ({ ok: port === 3000 || port === 8080, title: port === 3000 ? 'Grafana' : null });
  const svcs = await detectServices({ platform: 'win32', run, probe, excludePorts: [8080] });
  // 135 & 139 skipped (system), 8080 excluded, 5432 probed-but-not-http -> only 3000 remains.
  assert.equal(svcs.length, 1);
  assert.equal(svcs[0].port, 3000);
  assert.equal(svcs[0].name, 'Grafana');
});

test('parseConfiguredServices accepts name=port, bare port, and /path', () => {
  const out = parseConfiguredServices(['grafana=3000', '8080', 'docs=4000/help']);
  assert.deepEqual(
    out.map((s) => [s.name, s.port, s.path]),
    [
      ['grafana', 3000, '/'],
      ['service :8080', 8080, '/'],
      ['docs', 4000, '/help'],
    ],
  );
});

test('mergeServices lets configured override detected on the same port', () => {
  const configured = parseConfiguredServices(['MyApp=3000']);
  const detected = [{ id: '3000', name: 'service :3000', port: 3000, auto: true }, { id: '9000', name: 'other', port: 9000, auto: true }];
  const merged = mergeServices(configured, detected);
  const p3000 = merged.find((s) => s.port === 3000);
  assert.equal(p3000.name, 'MyApp'); // configured won
  assert.equal(merged.length, 2);
});
