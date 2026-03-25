'use strict';

/**
 * ProxyPro — HTTP/HTTPS proxy server
 *
 * Supports:
 *   - HTTP request forwarding (all methods)
 *   - HTTPS tunnelling via the HTTP CONNECT method
 *   - Optional Basic proxy authentication (PROXY_USER / PROXY_PASS env vars)
 *   - SSRF protection — blocks requests to loopback and private IP ranges
 *   - Hop-by-hop header removal
 *   - Connection and request timeouts
 *
 * Deployment:
 *   Deploy to render.com (free tier) using render.yaml.
 *   The server listens on the PORT environment variable (default 8080).
 *
 * Browser setup (Firefox example):
 *   Settings → Network Settings → Manual proxy configuration
 *   HTTP Proxy: <your-app>.onrender.com   Port: 443
 *   ✓ Also use this proxy for HTTPS
 *   If auth is enabled, Firefox will prompt for credentials.
 */

const http = require('http');
const https = require('https');
const net = require('net');

// ─── Configuration ────────────────────────────────────────────────────────────

const PORT = parseInt(process.env.PORT, 10) || 8080;
const PROXY_USER = process.env.PROXY_USER || '';
const PROXY_PASS = process.env.PROXY_PASS || '';
const AUTH_REQUIRED = Boolean(PROXY_USER && PROXY_PASS);

/** Milliseconds to wait for an upstream connection / response. */
const UPSTREAM_TIMEOUT_MS = 30_000;

// ─── SSRF Protection ──────────────────────────────────────────────────────────

/**
 * Returns true if the hostname resolves to a private / loopback address range
 * that should never be reachable through a public proxy.
 *
 * We block based on hostname string patterns (quick pre-check).
 * Full DNS-based blocking would require async resolution; the patterns below
 * cover the most common SSRF vectors without extra dependencies.
 */
const PRIVATE_IP_RE = /^(localhost|.*\.local)$|^(10|127)\.\d+\.\d+\.\d+$|^172\.(1[6-9]|2\d|3[01])\.\d+\.\d+$|^192\.168\.\d+\.\d+$|^169\.254\.\d+\.\d+$|^::1$|^fc[0-9a-f]{2}:/i;

/**
 * @param {string} hostname
 * @returns {boolean}
 */
function isPrivateHost(hostname) {
  return PRIVATE_IP_RE.test(hostname);
}

// ─── Authentication ───────────────────────────────────────────────────────────

/**
 * Validates the Proxy-Authorization header against configured credentials.
 * Always returns true when authentication is not configured.
 *
 * @param {http.IncomingMessage} req
 * @returns {boolean}
 */
function isAuthenticated(req) {
  if (!AUTH_REQUIRED) return true;

  const authHeader = req.headers['proxy-authorization'];
  if (!authHeader) return false;

  const [scheme, encoded] = authHeader.split(' ');
  if (!scheme || scheme.toLowerCase() !== 'basic' || !encoded) return false;

  let decoded;
  try {
    decoded = Buffer.from(encoded, 'base64').toString('utf8');
  } catch {
    return false;
  }

  const colonIdx = decoded.indexOf(':');
  if (colonIdx === -1) return false;

  const user = decoded.slice(0, colonIdx);
  const pass = decoded.slice(colonIdx + 1);
  return user === PROXY_USER && pass === PROXY_PASS;
}

/** Send a 407 response through an HTTP response object (for HTTP requests). */
function send407(res) {
  res.writeHead(407, {
    'Proxy-Authenticate': 'Basic realm="ProxyPro"',
    'Content-Type': 'text/plain',
    'Content-Length': '26',
  });
  res.end('Proxy Authentication Required');
}

/** Write a 407 response directly to a raw socket (for CONNECT). */
function socket407(socket) {
  socket.write(
    'HTTP/1.1 407 Proxy Authentication Required\r\n' +
    'Proxy-Authenticate: Basic realm="ProxyPro"\r\n' +
    'Content-Length: 0\r\n' +
    '\r\n',
  );
  socket.end();
}

// ─── Header Utilities ─────────────────────────────────────────────────────────

/** RFC 7230 hop-by-hop headers that must not be forwarded. */
const HOP_BY_HOP = new Set([
  'connection',
  'keep-alive',
  'proxy-authenticate',
  'proxy-authorization',
  'proxy-connection',
  'te',
  'trailer',
  'trailers',
  'transfer-encoding',
  'upgrade',
]);

/**
 * Returns a shallow copy of `headers` with hop-by-hop entries removed.
 *
 * @param {Record<string, string | string[]>} headers
 * @returns {Record<string, string | string[]>}
 */
function stripHopByHop(headers) {
  const out = {};
  for (const [key, value] of Object.entries(headers)) {
    if (!HOP_BY_HOP.has(key.toLowerCase())) {
      out[key] = value;
    }
  }
  return out;
}

// ─── HTTP Request Handler ─────────────────────────────────────────────────────

/**
 * Forwards plain HTTP proxy requests to the target server and pipes the
 * response back to the client.
 *
 * @param {http.IncomingMessage} req
 * @param {http.ServerResponse} res
 */
function onRequest(req, res) {
  if (!isAuthenticated(req)) {
    return send407(res);
  }

  // req.url is an absolute URI when the request comes through a proxy.
  let target;
  try {
    target = new URL(req.url);
  } catch {
    res.writeHead(400, { 'Content-Type': 'text/plain' });
    return res.end('Bad Request: invalid URL');
  }

  if (isPrivateHost(target.hostname)) {
    res.writeHead(403, { 'Content-Type': 'text/plain' });
    return res.end('Forbidden: target host not allowed');
  }

  const isHttps = target.protocol === 'https:';
  const port = target.port
    ? parseInt(target.port, 10)
    : isHttps ? 443 : 80;

  const options = {
    hostname: target.hostname,
    port,
    path: target.pathname + target.search,
    method: req.method,
    headers: stripHopByHop(req.headers),
    timeout: UPSTREAM_TIMEOUT_MS,
  };

  const proto = isHttps ? https : http;
  const proxyReq = proto.request(options, (proxyRes) => {
    res.writeHead(proxyRes.statusCode, proxyRes.headers);
    proxyRes.pipe(res, { end: true });
  });

  proxyReq.on('timeout', () => {
    proxyReq.destroy();
    if (!res.headersSent) {
      res.writeHead(504, { 'Content-Type': 'text/plain' });
      res.end('Gateway Timeout');
    }
  });

  proxyReq.on('error', (err) => {
    if (!res.headersSent) {
      res.writeHead(502, { 'Content-Type': 'text/plain' });
      res.end(`Bad Gateway: ${err.message}`);
    }
  });

  req.pipe(proxyReq, { end: true });
}

// ─── CONNECT Tunnel Handler ───────────────────────────────────────────────────

/**
 * Handles the HTTP CONNECT method used by browsers for HTTPS tunnelling.
 * Opens a raw TCP socket to the target and splices it with the client socket.
 *
 * @param {http.IncomingMessage} req
 * @param {net.Socket} clientSocket
 * @param {Buffer} head
 */
function onConnect(req, clientSocket, head) {
  if (!isAuthenticated(req)) {
    return socket407(clientSocket);
  }

  // req.url is "hostname:port" for CONNECT requests.
  const lastColon = req.url.lastIndexOf(':');
  if (lastColon === -1) {
    clientSocket.write('HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n');
    return clientSocket.end();
  }

  const hostname = req.url.slice(0, lastColon);
  const port = parseInt(req.url.slice(lastColon + 1), 10) || 443;

  if (isPrivateHost(hostname)) {
    clientSocket.write('HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n');
    return clientSocket.end();
  }

  const serverSocket = net.connect(port, hostname, () => {
    clientSocket.write('HTTP/1.1 200 Connection Established\r\nProxy-Agent: ProxyPro/1.0\r\n\r\n');
    // Flush any bytes that arrived before the tunnel was ready.
    if (head && head.length > 0) {
      serverSocket.write(head);
    }
    serverSocket.pipe(clientSocket, { end: true });
    clientSocket.pipe(serverSocket, { end: true });
  });

  serverSocket.setTimeout(UPSTREAM_TIMEOUT_MS, () => {
    serverSocket.destroy();
    clientSocket.destroy();
  });

  serverSocket.on('error', () => {
    if (!clientSocket.destroyed) {
      clientSocket.write('HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n');
      clientSocket.end();
    }
  });

  clientSocket.on('error', () => {
    if (!serverSocket.destroyed) serverSocket.destroy();
  });
}

// ─── Server ───────────────────────────────────────────────────────────────────

const server = http.createServer(onRequest);
server.on('connect', onConnect);

// Prevent slow-loris / header-flooding attacks.
server.headersTimeout = 10_000;
server.requestTimeout = UPSTREAM_TIMEOUT_MS;

server.on('clientError', (err, socket) => {
  if (!socket.destroyed) {
    socket.write('HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n');
    socket.end();
  }
});

server.on('error', (err) => {
  console.error('[ProxyPro] Server error:', err.message);
  process.exit(1);
});

/* istanbul ignore next */
if (require.main === module) {
  server.listen(PORT, '0.0.0.0', () => {
    console.log(`[ProxyPro] Listening on port ${PORT}`);
    if (AUTH_REQUIRED) {
      console.log('[ProxyPro] Authentication: ENABLED');
    } else {
      console.log('[ProxyPro] Authentication: DISABLED (set PROXY_USER and PROXY_PASS to enable)');
    }
  });
}

module.exports = { server, isPrivateHost, isAuthenticated, stripHopByHop };
