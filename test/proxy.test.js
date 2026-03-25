'use strict';

/**
 * Tests for ProxyPro server.js
 * Uses the Node.js built-in test runner (node --test), available since Node 18.
 */

const { describe, it, before, after, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const net = require('node:net');

const { isPrivateHost, isAuthenticated, stripHopByHop, server } = require('../server');

// ─── Unit tests: isPrivateHost ────────────────────────────────────────────────

describe('isPrivateHost', () => {
  it('blocks localhost', () => {
    assert.equal(isPrivateHost('localhost'), true);
  });

  it('blocks 127.x.x.x loopback', () => {
    assert.equal(isPrivateHost('127.0.0.1'), true);
  });

  it('blocks 10.x.x.x private range', () => {
    assert.equal(isPrivateHost('10.0.0.1'), true);
  });

  it('blocks 172.16-31.x.x private range', () => {
    assert.equal(isPrivateHost('172.16.0.1'), true);
    assert.equal(isPrivateHost('172.31.255.255'), true);
  });

  it('does not block 172.15.x.x (outside private range)', () => {
    assert.equal(isPrivateHost('172.15.0.1'), false);
  });

  it('does not block 172.32.x.x (outside private range)', () => {
    assert.equal(isPrivateHost('172.32.0.1'), false);
  });

  it('blocks 192.168.x.x private range', () => {
    assert.equal(isPrivateHost('192.168.1.1'), true);
  });

  it('blocks 169.254.x.x link-local (AWS metadata)', () => {
    assert.equal(isPrivateHost('169.254.169.254'), true);
  });

  it('blocks IPv6 loopback ::1', () => {
    assert.equal(isPrivateHost('::1'), true);
  });

  it('blocks .local hostnames', () => {
    assert.equal(isPrivateHost('myserver.local'), true);
  });

  it('allows public IPs', () => {
    assert.equal(isPrivateHost('8.8.8.8'), false);
    assert.equal(isPrivateHost('1.1.1.1'), false);
    assert.equal(isPrivateHost('93.184.216.34'), false);
  });

  it('allows public hostnames', () => {
    assert.equal(isPrivateHost('example.com'), false);
    assert.equal(isPrivateHost('render.com'), false);
  });
});

// ─── Unit tests: stripHopByHop ────────────────────────────────────────────────

describe('stripHopByHop', () => {
  it('removes proxy-authorization header', () => {
    const headers = { 'proxy-authorization': 'Basic abc', 'content-type': 'text/html' };
    const result = stripHopByHop(headers);
    assert.equal('proxy-authorization' in result, false);
    assert.equal(result['content-type'], 'text/html');
  });

  it('removes connection, keep-alive, transfer-encoding', () => {
    const headers = {
      connection: 'keep-alive',
      'keep-alive': 'timeout=5',
      'transfer-encoding': 'chunked',
      host: 'example.com',
    };
    const result = stripHopByHop(headers);
    assert.equal('connection' in result, false);
    assert.equal('keep-alive' in result, false);
    assert.equal('transfer-encoding' in result, false);
    assert.equal(result['host'], 'example.com');
  });

  it('preserves normal headers', () => {
    const headers = { 'user-agent': 'TestBrowser', accept: '*/*' };
    const result = stripHopByHop(headers);
    assert.deepEqual(result, headers);
  });

  it('does not mutate the input object', () => {
    const headers = { 'proxy-authorization': 'Basic x', host: 'example.com' };
    stripHopByHop(headers);
    assert.equal('proxy-authorization' in headers, true);
  });
});

// ─── Unit tests: isAuthenticated ──────────────────────────────────────────────

describe('isAuthenticated', () => {
  /**
   * Build a minimal fake IncomingMessage with the given headers.
   * @param {Record<string,string>} headers
   */
  function fakeReq(headers = {}) {
    return { headers };
  }

  const originalUser = process.env.PROXY_USER;
  const originalPass = process.env.PROXY_PASS;

  // isAuthenticated reads module-level constants set at require-time, so we
  // test through the exported function directly by re-requiring won't work
  // without a module cache flush. Instead we test the observable behaviour of
  // the running module where AUTH_REQUIRED is determined by the env at load
  // time. Since tests run without PROXY_USER/PROXY_PASS set, AUTH_REQUIRED is
  // false and every request is treated as authenticated.

  it('returns true when no credentials are configured (open proxy mode)', () => {
    // No env vars set at require time → AUTH_REQUIRED === false
    assert.equal(isAuthenticated(fakeReq()), true);
  });

  it('returns true for any headers when auth is not required', () => {
    assert.equal(isAuthenticated(fakeReq({ 'proxy-authorization': 'garbage' })), true);
  });
});

// ─── Integration tests: HTTP proxy server ─────────────────────────────────────

describe('HTTP proxy server integration', () => {
  let proxyPort;

  before(async () => {
    await new Promise((resolve) => {
      server.listen(0, '127.0.0.1', resolve);
    });
    proxyPort = server.address().port;
  });

  after(async () => {
    await new Promise((resolve) => server.close(resolve));
  });

  /**
   * Send an HTTP request through the proxy.
   *
   * @param {object} opts
   * @param {string} opts.method
   * @param {string} opts.targetUrl  Absolute URL to request via proxy
   * @param {Record<string,string>} [opts.headers]
   * @returns {Promise<{statusCode: number, body: string}>}
   */
  function proxyRequest({ method = 'GET', targetUrl, headers = {} }) {
    return new Promise((resolve, reject) => {
      const req = http.request(
        {
          host: '127.0.0.1',
          port: proxyPort,
          method,
          path: targetUrl,
          headers: { host: new URL(targetUrl).host, ...headers },
        },
        (res) => {
          let body = '';
          res.on('data', (chunk) => { body += chunk; });
          res.on('end', () => resolve({ statusCode: res.statusCode, body }));
        },
      );
      req.on('error', reject);
      req.end();
    });
  }

  it('returns 403 for requests targeting a private IP (127.x.x.x)', async () => {
    const { statusCode } = await proxyRequest({ targetUrl: 'http://127.0.0.1:80/' });
    assert.equal(statusCode, 403);
  });

  it('returns 403 for requests targeting localhost', async () => {
    const { statusCode } = await proxyRequest({ targetUrl: 'http://localhost:80/' });
    assert.equal(statusCode, 403);
  });

  it('returns 403 for requests targeting link-local metadata address', async () => {
    const { statusCode } = await proxyRequest({ targetUrl: 'http://169.254.169.254/' });
    assert.equal(statusCode, 403);
  });

  it('returns 502 or 504 for an unreachable public host (TEST-NET per RFC 5737)', async () => {
    // 192.0.2.0/24 is documentation/test space — routable but no real host.
    // The proxy may return 502 (connection refused) or 504 (timeout).
    const { statusCode } = await proxyRequest({ targetUrl: 'http://192.0.2.1:80/' });
    assert.ok(statusCode === 502 || statusCode === 504, `Expected 502 or 504, got ${statusCode}`);
  });
});

// ─── Integration tests: CONNECT tunnel ───────────────────────────────────────

describe('CONNECT tunnel integration', () => {
  let proxyPort2;

  before(async () => {
    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
    proxyPort2 = server.address().port;
  });

  after(async () => {
    await new Promise((resolve) => server.close(resolve));
  });

  /**
   * Sends a raw CONNECT request to the proxy and reads the response line.
   * @param {string} target  e.g. "example.com:443"
   * @returns {Promise<string>} first response line, e.g. "HTTP/1.1 200 Connection Established"
   */
  function connectRequest(target) {
    return new Promise((resolve, reject) => {
      const socket = net.connect(proxyPort2, '127.0.0.1', () => {
        socket.write(`CONNECT ${target} HTTP/1.1\r\nHost: ${target}\r\n\r\n`);
      });
      let data = '';
      socket.on('data', (chunk) => {
        data += chunk.toString();
        if (data.includes('\r\n')) {
          const firstLine = data.split('\r\n')[0];
          socket.destroy();
          resolve(firstLine);
        }
      });
      socket.on('error', reject);
      socket.setTimeout(5000, () => {
        socket.destroy();
        reject(new Error('CONNECT timed out'));
      });
    });
  }

  it('rejects CONNECT to a private host with 403', async () => {
    const line = await connectRequest('localhost:443');
    assert.ok(line.includes('403'), `Expected 403, got: ${line}`);
  });

  it('returns 400 for a malformed CONNECT target (no colon)', async () => {
    const line = await connectRequest('nodotnocolon');
    assert.ok(line.includes('400'), `Expected 400, got: ${line}`);
  });
});
