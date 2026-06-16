'use strict';

/**
 * The hub web server.
 *
 * A single, segment-gated page where any on-segment device sees every machine
 * running HereOnly and the services it advertises — with a direct link and a
 * click-through proxy for each. The page itself is gated by the HereOnly
 * verifier, so only on-segment devices can load the directory at all.
 */

const http = require('node:http');
const { createVerifier } = require('../core/verifier.js');
const respond = require('../server/respond.js');
const { createLogger, noopLogger } = require('../core/logger.js');
const { escapeHtml } = require('../server/respond.js');

function renderPage() {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>HereOnly Hub</title>
<style>
 :root{color-scheme:light dark}
 *{box-sizing:border-box}
 body{margin:0;font:15px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif;background:#0b0e14;color:#e6e6e6}
 header{padding:1.25rem 1.5rem;border-bottom:1px solid #1c2330;display:flex;align-items:baseline;gap:.75rem;flex-wrap:wrap}
 header h1{font-size:1.2rem;margin:0} .sub{color:#8a93a3;font-size:.85rem}
 main{padding:1.5rem;display:grid;gap:1rem;grid-template-columns:repeat(auto-fill,minmax(20rem,1fr));max-width:80rem;margin:0 auto}
 .card{border:1px solid #232a36;border-radius:14px;background:#11161f;padding:1rem 1.1rem}
 .card h2{font-size:1rem;margin:0 0 .15rem;display:flex;gap:.5rem;align-items:center}
 .badge{font-size:.65rem;background:#1f6feb;color:#fff;border-radius:999px;padding:.05rem .5rem;text-transform:uppercase;letter-spacing:.03em}
 .addr{color:#8a93a3;font-size:.8rem;margin-bottom:.6rem;font-family:ui-monospace,monospace}
 .svc{display:flex;align-items:center;justify-content:space-between;gap:.5rem;padding:.45rem 0;border-top:1px solid #1c2330}
 .svc .n{overflow:hidden;text-overflow:ellipsis;white-space:nowrap} .svc .p{color:#6b7280;font-size:.75rem}
 .svc a{font-size:.8rem;text-decoration:none;border:1px solid #2a3340;border-radius:8px;padding:.2rem .55rem;color:#cdd6e2;white-space:nowrap}
 .svc a:hover{background:#1b2230} .svc a.go{border-color:#1f6feb;color:#7fb0ff}
 .empty{color:#6b7280;font-size:.85rem;padding:.4rem 0}
 footer{color:#5b6472;font-size:.75rem;text-align:center;padding:1.5rem}
</style></head>
<body>
<header><h1>&#128274; HereOnly Hub</h1><span class="sub" id="sub">discovering devices on this segment&hellip;</span></header>
<main id="grid"></main>
<footer>Visible only to devices on this physical network segment.</footer>
<script>
async function tick(){
  let data; try{ data=await (await fetch('api/peers',{cache:'no-store'})).json(); }catch(e){ return; }
  document.getElementById('sub').textContent = data.entries.length+' device'+(data.entries.length===1?'':'s')+' on '+(data.network||'this segment');
  const grid=document.getElementById('grid'); grid.innerHTML='';
  for(const e of data.entries){
    const card=document.createElement('div'); card.className='card';
    let h='<h2>'+esc(e.host)+(e.self?' <span class="badge">this device</span>':'')+'</h2>';
    h+='<div class="addr">'+esc((e.addrs||[]).join(', '))+'</div>';
    if(!e.services||!e.services.length){ h+='<div class="empty">no HTTP services advertised</div>'; }
    for(const s of (e.services||[])){
      const direct = e.addrs&&e.addrs.length ? 'http://'+e.addrs[0]+':'+s.port+(s.path||'/') : null;
      h+='<div class="svc"><div class="n">'+esc(s.name)+' <span class="p">:'+s.port+'</span></div><div>';
      if(direct) h+='<a href="'+direct+'" target="_blank" rel="noopener">open</a> ';
      h+='<a class="go" href="go/'+encodeURIComponent(e.id)+'/'+s.port+(s.path||'/')+'" target="_blank" rel="noopener">via hub</a>';
      h+='</div></div>';
    }
    card.innerHTML=h; grid.appendChild(card);
  }
}
function esc(s){return String(s).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]))}
tick(); setInterval(tick,4000);
</script>
</body></html>`;
}

function createHubServer(options = {}) {
  const verifier = options.verifier || createVerifier(options);
  const logger = options.logger || (options.silent ? noopLogger : createLogger({ level: options.logLevel || 'info' }));
  const getEntries = options.getEntries || (() => []);
  const networkLabel = options.networkLabel || '';
  const cookieName = options.cookieName || 'hereonly';
  const headerName = options.headerName || 'x-hereonly-token';
  const trustForwardedHeader = !!options.trustForwardedHeader;
  const setCookie = options.setCookie !== false;
  const ttlSeconds = verifier.options.tokenTtlSeconds;
  const reqOpts = { cookieName, headerName, trustForwardedHeader };

  function proxyTo(host, port, path, req, res) {
    const upstream = http.request({ host, port, method: req.method, path, headers: { ...req.headers, host: `${host}:${port}` } }, (up) => {
      res.statusCode = up.statusCode || 502;
      for (const [k, v] of Object.entries(up.headers)) if (v !== undefined) res.setHeader(k, v);
      up.pipe(res);
    });
    upstream.on('error', () => {
      if (!res.headersSent) res.statusCode = 502;
      try {
        res.end('hub: peer service unavailable\n');
      } catch {
        /* ignore */
      }
    });
    req.pipe(upstream);
  }

  async function handle(req, res) {
    let verdict;
    try {
      verdict = await verifier.verifyRequest(req, reqOpts);
    } catch (e) {
      verdict = { allow: false, reason: 'error', detail: (e && e.message) || 'error' };
    }
    if (!verdict.allow) return respond.sendDeny(req, res, options.denyStatus || 403, verdict);
    if (setCookie && verdict.token) {
      respond.appendSetCookie(res, respond.buildSessionCookie(cookieName, verdict.token, { ttlSeconds }));
    }

    const url = req.url || '/';
    if (url === '/' || url.startsWith('/?')) {
      res.setHeader('Content-Type', 'text/html; charset=utf-8');
      return res.end(renderPage());
    }
    if (url === '/api/peers') {
      res.setHeader('Content-Type', 'application/json; charset=utf-8');
      res.setHeader('Cache-Control', 'no-store');
      const network = typeof networkLabel === 'function' ? networkLabel() : networkLabel;
      return res.end(JSON.stringify({ network, entries: getEntries() }));
    }
    const m = url.match(/^\/go\/([^/]+)\/(\d+)(\/.*)?$/);
    if (m) {
      const peer = getEntries().find((e) => e.id === decodeURIComponent(m[1]));
      if (!peer || !peer.addrs || !peer.addrs.length) {
        res.statusCode = 404;
        return res.end('hub: unknown peer');
      }
      return proxyTo(peer.addrs[0], Number(m[2]), m[3] || '/', req, res);
    }
    res.statusCode = 404;
    res.end('not found');
  }

  const server = options.server || http.createServer();
  server.on('request', handle);
  server.hereonly = { verifier, logger };
  return server;
}

module.exports = { createHubServer, renderPage };
