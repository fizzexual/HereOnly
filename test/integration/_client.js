'use strict';

/**
 * Minimal HTTP test client + server helpers. Uses http.request with
 * `agent: false` so each request opens and closes its own connection — no
 * keep-alive pool keeping the test process alive after the tests pass.
 * Not named *.test.js, so the runner imports it without executing it.
 */

const http = require('node:http');
const net = require('node:net');

function listen(server) {
  return new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve(server.address().port)));
}

function close(server) {
  return new Promise((resolve) => {
    let done = false;
    const finish = () => {
      if (!done) {
        done = true;
        resolve();
      }
    };
    if (server.hereonly && server.hereonly.closeBridges) server.hereonly.closeBridges();
    server.close(finish);
    if (server.closeAllConnections) server.closeAllConnections();
    setTimeout(finish, 300).unref();
  });
}

function request(url, opts = {}) {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const req = http.request(
      { hostname: u.hostname, port: u.port, path: u.pathname + u.search, method: opts.method || 'GET', headers: opts.headers || {}, agent: false },
      (res) => {
        let body = '';
        res.setEncoding('utf8');
        res.on('data', (d) => (body += d));
        res.on('end', () =>
          resolve({ status: res.statusCode, headers: res.headers, body, setCookie: res.headers['set-cookie'] || [], json: () => JSON.parse(body) }),
        );
      },
    );
    req.on('error', reject);
    if (opts.body) req.write(opts.body);
    req.end();
  });
}

function rawUpgrade(port, { timeoutMs = 1500 } = {}) {
  return new Promise((resolve, reject) => {
    const socket = net.connect(port, '127.0.0.1', () => {
      socket.write(
        'GET /ws HTTP/1.1\r\n' +
          `Host: 127.0.0.1:${port}\r\n` +
          'Upgrade: websocket\r\nConnection: Upgrade\r\n' +
          'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n',
      );
    });
    let buf = '';
    const done = (err) => {
      clearTimeout(timer);
      socket.destroy();
      err ? reject(err) : resolve(buf);
    };
    const timer = setTimeout(() => done(null), timeoutMs);
    socket.on('data', (d) => {
      buf += d.toString('utf8');
      if (buf.includes('ECHO') || buf.includes('403')) done(null);
    });
    socket.on('error', done);
  });
}

function cookieValue(setCookieArr, name) {
  for (const c of setCookieArr || []) {
    const m = c.match(new RegExp('^' + name + '=([^;]+)'));
    if (m) return decodeURIComponent(m[1]);
  }
  return null;
}

module.exports = { listen, close, request, rawUpgrade, cookieValue };
