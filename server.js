const http = require('http');
const https = require('https');
const url = require('url');

const PORT = process.env.PORT || 3000;

const server = http.createServer((req, res) => {
  // CORS headers
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', '*');

  if (req.method === 'OPTIONS') {
    res.writeHead(200);
    res.end();
    return;
  }

  // Health check
  if (req.url === '/' || req.url === '/health') {
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end('SecureGate Proxy OK');
    return;
  }

  // Parse target URL from /proxy?url=...
  const parsed = url.parse(req.url, true);
  if (parsed.pathname !== '/proxy' || !parsed.query.url) {
    res.writeHead(400, { 'Content-Type': 'text/plain' });
    res.end('Missing ?url= parameter');
    return;
  }

  let targetUrl;
  try {
    targetUrl = decodeURIComponent(parsed.query.url);
    new URL(targetUrl); // validate
  } catch {
    res.writeHead(400, { 'Content-Type': 'text/plain' });
    res.end('Invalid URL');
    return;
  }

  const targetParsed = url.parse(targetUrl);
  const isHttps = targetParsed.protocol === 'https:';
  const lib = isHttps ? https : http;

  const options = {
    hostname: targetParsed.hostname,
    port: targetParsed.port || (isHttps ? 443 : 80),
    path: targetParsed.path || '/',
    method: req.method,
    headers: {
      'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36',
      'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
      'Accept-Language': 'de-DE,de;q=0.9,en;q=0.8',
      'Accept-Encoding': 'identity',
      'Cache-Control': 'no-cache',
    },
    timeout: 15000,
  };

  const proxyReq = lib.request(options, (proxyRes) => {
    // Remove headers that block iframes
    const headers = { ...proxyRes.headers };
    delete headers['x-frame-options'];
    delete headers['content-security-policy'];
    delete headers['x-content-type-options'];
    delete headers['strict-transport-security'];
    delete headers['content-encoding'];

    // Allow iframe embedding
    headers['access-control-allow-origin'] = '*';
    headers['x-frame-options'] = 'ALLOWALL';

    // Handle redirects
    if ([301, 302, 303, 307, 308].includes(proxyRes.statusCode)) {
      const location = proxyRes.headers.location;
      if (location) {
        const redirectUrl = location.startsWith('http')
          ? location
          : `${targetParsed.protocol}//${targetParsed.hostname}${location}`;
        headers['location'] = `/proxy?url=${encodeURIComponent(redirectUrl)}`;
      }
    }

    res.writeHead(proxyRes.statusCode, headers);
    proxyRes.pipe(res);
  });

  proxyReq.on('error', (err) => {
    if (!res.headersSent) {
      res.writeHead(502, { 'Content-Type': 'text/plain' });
      res.end('Proxy error: ' + err.message);
    }
  });

  proxyReq.on('timeout', () => {
    proxyReq.destroy();
    if (!res.headersSent) {
      res.writeHead(504, { 'Content-Type': 'text/plain' });
      res.end('Gateway timeout');
    }
  });

  if (req.method === 'POST') {
    req.pipe(proxyReq);
  } else {
    proxyReq.end();
  }
});

server.listen(PORT, () => {
  console.log(`SecureGate Proxy läuft auf Port ${PORT}`);
});
