import assert from 'node:assert/strict';
import test from 'node:test';
import http from 'node:http';
import net from 'node:net';
import { once } from 'node:events';
import { chromeProxyServer, parseProxy, startProxyRelay } from './proxy-relay.js';

async function listen(server) {
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  return server.address().port;
}

async function origin(t) {
  const server = http.createServer((request, response) => response.end(`origin:${request.url}`));
  const port = await listen(server);
  t.after(() => server.close());
  return port;
}

// HTTP proxy that only tunnels with the expected Basic credentials.
async function httpUpstream(t, expected) {
  const seen = [];
  const server = http.createServer((request, response) => response.writeHead(405).end());
  server.on('connect', (request, client) => {
    seen.push(request.headers['proxy-authorization']);
    if (request.headers['proxy-authorization'] !== expected) { client.end('HTTP/1.1 407 Proxy Authentication Required\r\n\r\n'); return; }
    const [host, port] = request.url.split(':');
    const upstream = net.connect(Number(port), host, () => {
      client.write('HTTP/1.1 200 Connection Established\r\n\r\n');
      upstream.pipe(client); client.pipe(upstream);
    });
  });
  const port = await listen(server);
  t.after(() => server.close());
  return { port, seen };
}

// Minimal SOCKS5 server with RFC 1929 username/password.
async function socksUpstream(t, user, pass) {
  const server = net.createServer((client) => {
    let stage = 0;
    client.on('data', function onData(chunk) {
      if (stage === 0) { client.write(Buffer.from([5, chunk.includes(2) ? 2 : 0xff])); stage = 1; return; }
      if (stage === 1) {
        const u = chunk.subarray(2, 2 + chunk[1]).toString(); const p = chunk.subarray(3 + chunk[1], 3 + chunk[1] + chunk[2 + chunk[1]]).toString();
        const ok = u === user && p === pass; client.write(Buffer.from([1, ok ? 0 : 1])); if (!ok) client.end(); stage = 2; return;
      }
      client.off('data', onData);
      const length = chunk[4]; const host = chunk.subarray(5, 5 + length).toString(); const port = chunk.readUInt16BE(5 + length);
      const upstream = net.connect(port, host === 'localhost' ? '127.0.0.1' : host, () => {
        client.write(Buffer.from([5, 0, 0, 1, 127, 0, 0, 1, 0, 0]));
        upstream.pipe(client); client.pipe(upstream);
      });
    });
  });
  const port = await listen(server);
  t.after(() => server.close());
  return port;
}

function viaRelay(relayUrl, targetPort, path = '/hello') {
  const relay = new URL(relayUrl);
  return new Promise((resolve, reject) => {
    const request = http.request({ host: relay.hostname, port: relay.port, method: 'CONNECT', path: `localhost:${targetPort}` });
    request.on('connect', (response, socket) => {
      if (response.statusCode !== 200) { socket.destroy(); resolve({ status: response.statusCode }); return; }
      const inner = http.request({ createConnection: () => socket, host: 'localhost', path }, (res) => {
        let body = ''; res.on('data', (c) => (body += c)); res.on('end', () => resolve({ status: 200, body }));
      });
      inner.on('error', reject); inner.end();
    });
    request.on('error', reject); request.end();
  });
}

test('parses credentials but exposes only a credential-free proxy URL', () => {
  const proxy = parseProxy(' http://us%40er:p%3Ass@proxy.example:8000 ');
  assert.deepEqual(proxy, { scheme: 'http', host: 'proxy.example', port: 8000, username: 'us@er', password: 'p:ss' });
  assert.equal(chromeProxyServer(proxy), 'http://proxy.example:8000');
  assert.equal(parseProxy(''), null);
  assert.throws(() => parseProxy('ftp://x:1'), /http, https or socks5/);
});

test('relays CONNECT through an authenticated HTTP upstream', async (t) => {
  const target = await origin(t);
  const upstream = await httpUpstream(t, 'Basic ' + Buffer.from('user:secret').toString('base64'));
  const relay = await startProxyRelay(parseProxy(`http://user:secret@127.0.0.1:${upstream.port}`));
  t.after(relay.close);
  assert.match(relay.url, /^http:\/\/127\.0\.0\.1:\d+$/);
  assert.deepEqual(await viaRelay(relay.url, target), { status: 200, body: 'origin:/hello' });
});

test('wrong upstream credentials surface as 502, never as a direct connection', async (t) => {
  const target = await origin(t);
  const upstream = await httpUpstream(t, 'Basic ' + Buffer.from('user:secret').toString('base64'));
  const relay = await startProxyRelay(parseProxy(`http://user:wrong@127.0.0.1:${upstream.port}`));
  t.after(relay.close);
  assert.equal((await viaRelay(relay.url, target)).status, 502);
  assert.equal(upstream.seen.length, 1);
});

test('relays through an authenticated SOCKS5 upstream', async (t) => {
  const target = await origin(t);
  const socks = await socksUpstream(t, 'user', 'secret');
  const relay = await startProxyRelay(parseProxy(`socks5://user:secret@127.0.0.1:${socks}`));
  t.after(relay.close);
  assert.deepEqual(await viaRelay(relay.url, target, '/socks'), { status: 200, body: 'origin:/socks' });
});

test('a busy preferred port falls back to a random loopback port', async (t) => {
  const blocker = net.createServer(); const busy = await listen(blocker); t.after(() => blocker.close());
  const relay = await startProxyRelay(parseProxy('http://u:p@127.0.0.1:9'), busy);
  t.after(relay.close);
  assert.notEqual(new URL(relay.url).port, String(busy));
});
