'use strict';

/**
 * Local service detection for the hub.
 *
 * Each hub advertises the HTTP services running on its own machine. Services
 * come from two sources:
 *   - explicitly configured services (name + port + path), and
 *   - auto-detected ones: enumerate the host's own listening TCP ports and keep
 *     the ports that actually answer HTTP (grabbing the page <title> as a label).
 *
 * Only the host scans itself, so there is no cross-machine port scanning.
 */

const http = require('node:http');
const { run: defaultRun } = require('../os/exec.js');

// Ports that are almost never plain HTTP — skip probing them.
const SKIP_PORTS = new Set([
  22, 21, 25, 53, 110, 143, 135, 137, 138, 139, 445, 465, 587, 993, 995, 1900, 3389, 5353, 5040, 7680, 47471,
]);

function parseWindowsNetstat(text) {
  const ports = new Set();
  for (const line of String(text).split(/\r?\n/)) {
    const m = line.match(/^\s*TCP\s+(\S+)\s+\S+\s+LISTENING/i);
    if (m) {
      const p = Number(m[1].slice(m[1].lastIndexOf(':') + 1));
      if (p > 0) ports.add(p);
    }
  }
  return [...ports];
}

function parseLinuxListening(text) {
  const ports = new Set();
  for (const line of String(text).split(/\r?\n/)) {
    if (!/LISTEN/.test(line)) continue;
    const m = line.match(/(?:\[[0-9a-fA-F:]+\]|[\d.*]+):(\d+)\s/);
    if (m) {
      const p = Number(m[1]);
      if (p > 0) ports.add(p);
    }
  }
  return [...ports];
}

function parseBsdNetstat(text) {
  const ports = new Set();
  for (const line of String(text).split(/\r?\n/)) {
    if (!/LISTEN/.test(line)) continue;
    const m = line.match(/^\s*tcp\S*\s+\d+\s+\d+\s+\S+\.(\d+)\s/i);
    if (m) {
      const p = Number(m[1]);
      if (p > 0) ports.add(p);
    }
  }
  return [...ports];
}

async function getListeningPorts({ run = defaultRun, platform = process.platform } = {}) {
  if (platform === 'win32') {
    const r = await run('netstat', ['-an', '-p', 'tcp']);
    return r.ok ? parseWindowsNetstat(r.stdout) : [];
  }
  if (platform === 'linux') {
    const r = await run('ss', ['-ltn']);
    if (r.ok && r.stdout.trim()) return parseLinuxListening(r.stdout);
    const r2 = await run('netstat', ['-ltn']);
    return r2.ok ? parseLinuxListening(r2.stdout) : [];
  }
  if (platform === 'darwin') {
    const r = await run('netstat', ['-an', '-p', 'tcp']);
    return r.ok ? parseBsdNetstat(r.stdout) : [];
  }
  return [];
}

/** Probe one port for HTTP; resolves { ok, status, title }. */
function probeHttp(port, opts = {}) {
  const host = opts.host || '127.0.0.1';
  const timeoutMs = opts.timeoutMs || 400;
  return new Promise((resolve) => {
    const req = http.get({ host, port, path: '/', timeout: timeoutMs, headers: { 'user-agent': 'hereonly-hub' } }, (res) => {
      let body = '';
      res.on('data', (d) => {
        if (body.length < 4096) body += d;
        else res.destroy();
      });
      res.on('end', () => {
        const m = body.match(/<title[^>]*>([^<]*)<\/title>/i);
        resolve({ ok: true, status: res.statusCode, title: m ? m[1].trim() : null });
      });
      res.on('error', () => resolve({ ok: true, status: res.statusCode, title: null }));
    });
    req.on('timeout', () => {
      req.destroy();
      resolve({ ok: false });
    });
    req.on('error', () => resolve({ ok: false }));
  });
}

/** Detect HTTP services among the host's own listening ports. */
async function detectServices(opts = {}) {
  const { run, platform, excludePorts = [], host = '127.0.0.1', probe = probeHttp, max = 64 } = opts;
  const exclude = new Set(excludePorts.map(Number));
  const ports = (await getListeningPorts({ run, platform }))
    .filter((p) => !exclude.has(p) && !SKIP_PORTS.has(p))
    .slice(0, max);

  const out = [];
  // Modest concurrency so a box with many ports still probes quickly.
  const pool = 8;
  let i = 0;
  async function worker() {
    while (i < ports.length) {
      const port = ports[i++];
      const r = await probe(port, { host });
      if (r.ok) out.push({ id: String(port), name: r.title || `service :${port}`, port, proto: 'http', title: r.title || null, auto: true });
    }
  }
  await Promise.all(Array.from({ length: Math.min(pool, ports.length) }, worker));
  return out.sort((a, b) => a.port - b.port);
}

/** Normalize explicitly configured services ("name=port" or {name,port,path}). */
function parseConfiguredServices(list) {
  const out = [];
  for (const item of [].concat(list || [])) {
    if (!item) continue;
    if (typeof item === 'string') {
      const m = item.match(/^(?:(.+?)=)?(\d+)(\/.*)?$/);
      if (m) out.push({ id: m[2], name: m[1] || `service :${m[2]}`, port: Number(m[2]), path: m[3] || '/', proto: 'http', auto: false });
    } else if (item.port) {
      out.push({ id: String(item.port), name: item.name || `service :${item.port}`, port: Number(item.port), path: item.path || '/', proto: item.proto || 'http', auto: false });
    }
  }
  return out;
}

/** Merge configured + detected services, configured winning on port collisions. */
function mergeServices(configured, detected) {
  const byPort = new Map();
  for (const s of detected) byPort.set(s.port, s);
  for (const s of configured) byPort.set(s.port, s); // configured overrides
  return [...byPort.values()].sort((a, b) => a.port - b.port);
}

module.exports = {
  getListeningPorts,
  detectServices,
  probeHttp,
  parseConfiguredServices,
  mergeServices,
  parseWindowsNetstat,
  parseLinuxListening,
  parseBsdNetstat,
  SKIP_PORTS,
};
