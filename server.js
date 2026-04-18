const http = require('http');
const https = require('https');
const net = require('net');
const url = require('url');

const PORT = process.env.PORT || 3000;
const BASE = process.env.RENDER_EXTERNAL_URL || ('http://localhost:' + PORT);

// ── URL REWRITING FOR WEB PROXY ──
function rewriteUrl(u, origin) {
  if (!u || u.startsWith('data:') || u.startsWith('blob:') || u.startsWith('javascript:') || u.startsWith('#') || u.startsWith('mailto:') || u.startsWith('tel:')) return u;
  try {
    let abs;
    if (u.startsWith('//')) abs = 'https:' + u;
    else if (u.startsWith('/')) abs = origin + u;
    else if (!u.startsWith('http')) abs = origin + '/' + u;
    else abs = u;
    return BASE + '/proxy?url=' + encodeURIComponent(abs);
  } catch(e) { return u; }
}

function rewriteHtml(html, origin) {
  html = html.replace(/(href|src|action)=["']([^"'#][^"']*)["']/gi, function(m, attr, val) {
    if (val.startsWith('data:') || val.startsWith('blob:') || val.startsWith('javascript:') || val.startsWith('mailto:') || val.startsWith('tel:')) return m;
    return attr + '="' + rewriteUrl(val, origin) + '"';
  });
  html = html.replace(/url\(["']?([^)"']+)["']?\)/gi, function(m, val) {
    if (val.startsWith('data:')) return m;
    return 'url("' + rewriteUrl(val, origin) + '")';
  });
  const inject = '<script>var _PB="' + BASE + '";var _oF=window.fetch;window.fetch=function(r,i){if(typeof r==="string"&&r.startsWith("http")&&!r.includes(location.hostname)){r=_PB+"/proxy?url="+encodeURIComponent(r);}return _oF(r,i);};var _oO=XMLHttpRequest.prototype.open;XMLHttpRequest.prototype.open=function(m,u){var a=Array.prototype.slice.call(arguments);if(typeof u==="string"&&u.startsWith("http")&&!u.includes(location.hostname)){a[1]=_PB+"/proxy?url="+encodeURIComponent(u);}return _oO.apply(this,a);};<\/script>';
  return html.includes('</head>') ? html.replace('</head>', inject + '</head>') : inject + html;
}

const server = http.createServer(function(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', '*');

  if (req.method === 'OPTIONS') { res.writeHead(200); res.end(); return; }

  // Health check
  if (req.url === '/' || req.url === '/health') {
    res.writeHead(200, {'Content-Type': 'text/plain'});
    res.end('SecureGate Proxy OK');
    return;
  }

  // ── FORWARD PROXY MODE (for iPad WiFi proxy) ──
  if (req.url.startsWith('http://') || req.url.startsWith('https://')) {
    const targetParsed = url.parse(req.url);
    const isHttps = targetParsed.protocol === 'https:';
    const lib = isHttps ? https : http;
    const opts = {
      hostname: targetParsed.hostname,
      port: targetParsed.port || (isHttps ? 443 : 80),
      path: targetParsed.path || '/',
      method: req.method,
      headers: req.headers,
    };
    delete opts.headers['proxy-connection'];
    const pr = lib.request(opts, function(pres) {
      res.writeHead(pres.statusCode, pres.headers);
      pres.pipe(res);
    });
    pr.on('error', function(e) { if (!res.headersSent) { res.writeHead(502); res.end(e.message); } });
    req.pipe(pr);
    return;
  }

  // ── WEB PROXY MODE (/proxy?url=...) ──
  const parsed = url.parse(req.url, true);
  if (parsed.pathname !== '/proxy' || !parsed.query.url) { res.writeHead(400); res.end('Missing ?url='); return; }

  let targetUrl;
  try { targetUrl = decodeURIComponent(parsed.query.url); new URL(targetUrl); }
  catch(e) { res.writeHead(400); res.end('Invalid URL'); return; }

  const tp = url.parse(targetUrl);
  const isHttps = tp.protocol === 'https:';
  const lib = isHttps ? https : http;
  const origin = tp.protocol + '//' + tp.host;

  const opts = {
    hostname: tp.hostname,
    port: tp.port || (isHttps ? 443 : 80),
    path: tp.path || '/',
    method: req.method,
    headers: {
      'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36',
      'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
      'Accept-Language': 'de-DE,de;q=0.9,en;q=0.8',
      'Accept-Encoding': 'identity',
      'Cache-Control': 'no-cache',
    },
    timeout: 20000,
  };

  const pr = lib.request(opts, function(pres) {
    const h = Object.assign({}, pres.headers);
    delete h['x-frame-options'];
    delete h['content-security-policy'];
    delete h['x-content-type-options'];
    delete h['strict-transport-security'];
    delete h['content-encoding'];
    h['access-control-allow-origin'] = '*';
    h['x-frame-options'] = 'ALLOWALL';

    if ([301,302,303,307,308].indexOf(pres.statusCode) > -1 && h['location']) {
      let loc = h['location'];
      if (!loc.startsWith('http')) loc = loc.startsWith('/') ? origin + loc : origin + '/' + loc;
      h['location'] = BASE + '/proxy?url=' + encodeURIComponent(loc);
      res.writeHead(pres.statusCode, h); res.end(); return;
    }

    const ct = (h['content-type'] || '').toLowerCase();
    if (ct.includes('text/html') || ct.includes('text/css')) {
      let body = '';
      pres.setEncoding('utf8');
      pres.on('data', function(c) { body += c; });
      pres.on('end', function() {
        if (ct.includes('text/html')) body = rewriteHtml(body, origin);
        else body = body.replace(/url\(["']?([^)"']+)["']?\)/gi, function(m, v) { return v.startsWith('data:') ? m : 'url("' + rewriteUrl(v, origin) + '")'; });
        delete h['content-length'];
        res.writeHead(pres.statusCode || 200, h);
        res.end(body);
      });
    } else {
      res.writeHead(pres.statusCode || 200, h);
      pres.pipe(res);
    }
  });

  pr.on('error', function(e) { if (!res.headersSent) { res.writeHead(502); res.end('Error: ' + e.message); } });
  pr.on('timeout', function() { pr.destroy(); if (!res.headersSent) { res.writeHead(504); res.end('Timeout'); } });
  if (req.method === 'POST') req.pipe(pr); else pr.end();
});

// ── CONNECT TUNNEL (for HTTPS via iPad proxy) ──
server.on('connect', function(req, clientSocket, head) {
  const [hostname, port] = req.url.split(':');
  const serverSocket = net.connect(parseInt(port) || 443, hostname, function() {
    clientSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
    if (head && head.length) serverSocket.write(head);
    serverSocket.pipe(clientSocket);
    clientSocket.pipe(serverSocket);
  });
  serverSocket.on('error', function(e) {
    clientSocket.end('HTTP/1.1 502 Bad Gateway\r\n\r\n');
  });
  clientSocket.on('error', function() { serverSocket.destroy(); });
});

server.listen(PORT, function() { console.log('SecureGate Proxy running on port ' + PORT); });
