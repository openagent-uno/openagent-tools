import assert from 'node:assert/strict';
import test from 'node:test';
import { createServer } from 'node:http';
import {
  BlockedUrlError,
  assertPublicHttpUrl,
  fetchPublicPage,
  isNonPublicAddress,
} from '../dist/url-guard.js';
import { EnhancedContentExtractor } from '../dist/enhanced-content-extractor.js';
import { resolveChromiumExecutable } from '../dist/browser-executable.js';

const PUBLIC = [
  '8.8.8.8',
  '1.1.1.1',
  '93.184.216.34',
  '2606:4700:4700::1111',
  '2a00:1450:4001:80b::200e',
  '::ffff:8.8.8.8',
];

const NON_PUBLIC = [
  '0.0.0.0',
  '10.0.0.1',
  '100.64.0.1', // CGNAT / Tailscale
  '100.127.255.254',
  '127.0.0.1',
  '127.255.255.255',
  '169.254.169.254', // cloud metadata
  '172.16.0.1',
  '172.31.255.255',
  '192.0.2.1',
  '192.168.1.1',
  '198.18.0.1',
  '224.0.0.1',
  '255.255.255.255',
  '::',
  '::1',
  'fc00::1',
  'fd12:3456:789a::1',
  'fe80::1',
  'fe80::1%en0',
  'ff02::1',
  '2001:db8::1',
  '::ffff:127.0.0.1', // IPv4-mapped loopback
  '::ffff:7f00:1', // the same, as the URL parser writes it
  '::ffff:169.254.169.254',
  '64:ff9b::a00:1', // NAT64 of 10.0.0.1
  '2002:c0a8:101::1', // 6to4 of 192.168.1.1
  'not-an-address',
];

test('public unicast addresses pass, every non-public range is refused', () => {
  for (const address of PUBLIC) {
    assert.equal(isNonPublicAddress(address), false, `${address} should be public`);
  }
  for (const address of NON_PUBLIC) {
    assert.equal(isNonPublicAddress(address), true, `${address} should be refused`);
  }
});

test('only http and https URLs are accepted', async () => {
  for (const url of ['file:///etc/passwd', 'ftp://example.com/x', 'gopher://example.com/', 'data:text/html,hi',
    'javascript:alert(1)', 'not a url', '/relative/path']) {
    await assert.rejects(assertPublicHttpUrl(url), BlockedUrlError, url);
  }
});

test('IP literals are refused in every spelling the URL parser accepts', async () => {
  for (const url of [
    'http://127.0.0.1/',
    'http://2130706433/', // decimal 127.0.0.1
    'http://0x7f.1/', // hex shorthand
    'http://0177.0.0.1/', // octal
    'http://[::1]:8080/',
    'http://[::ffff:127.0.0.1]/',
    'http://169.254.169.254/latest/meta-data/',
    'https://10.0.0.5:8642/api/config',
    'http://100.100.100.100/',
  ]) {
    await assert.rejects(assertPublicHttpUrl(url, { resolve: async () => assert.fail('literal resolved') }),
      BlockedUrlError, url);
  }
  const url = await assertPublicHttpUrl('https://93.184.216.34/page');
  assert.equal(url.hostname, '93.184.216.34');
});

test('a hostname is refused when any of its addresses is non-public', async () => {
  const resolve = async (hostname) => ({
    'public.example': [{ address: '93.184.216.34', family: 4 }],
    'internal.example': [{ address: '10.1.2.3', family: 4 }],
    'mixed.example': [{ address: '93.184.216.34', family: 4 }, { address: 'fd00::1', family: 6 }],
    'empty.example': [],
  })[hostname];
  await assertPublicHttpUrl('https://public.example/a', { resolve });
  for (const host of ['internal.example', 'mixed.example', 'empty.example']) {
    await assert.rejects(assertPublicHttpUrl(`https://${host}/`, { resolve }), BlockedUrlError, host);
  }
});

// A dual-stack server lets one test policy allow 127.0.0.1 and refuse ::1:
// without the guard a redirect to [::1] would land on this same server, so
// "the server never saw /secret" is evidence, not a tautology.
const loopbackOnly = { isBlockedAddress: (address) => address !== '127.0.0.1' && isNonPublicAddress(address) };

async function startServer(t) {
  const hits = [];
  const server = createServer((req, res) => {
    hits.push(req.url);
    const port = server.address().port;
    const redirects = {
      '/to-ok': `http://127.0.0.1:${port}/ok`,
      '/to-v6': `http://[::1]:${port}/secret`,
      '/to-metadata': 'http://169.254.169.254/latest/meta-data/',
      '/to-file': 'file:///etc/passwd',
      '/reddit.com/to-v6': `http://[::1]:${port}/secret`,
      '/loop': '/loop',
    };
    if (redirects[req.url]) {
      res.writeHead(302, { Location: redirects[req.url] });
      res.end();
      return;
    }
    res.writeHead(200, { 'content-type': 'text/html' });
    res.end(`<html><body><main>${req.url === '/secret' ? 'secret' : 'ok'} ${'body text '.repeat(30)}</main></body></html>`);
  });
  try {
    await new Promise((resolve, reject) => {
      server.once('error', reject);
      server.listen(0, '::', resolve);
    });
  } catch (error) {
    t.skip(`dual-stack loopback unavailable: ${error.message}`);
    return null;
  }
  t.after(() => server.close());
  return { base: `http://127.0.0.1:${server.address().port}`, hits };
}

test('every redirect hop is re-validated before it is requested', async (t) => {
  const server = await startServer(t);
  if (!server) return;
  const { base, hits } = server;
  const config = { validateStatus: (status) => status < 400, timeout: 5000 };

  const ok = await fetchPublicPage(`${base}/to-ok`, config, loopbackOnly);
  assert.equal(ok.status, 200);
  assert.deepEqual(hits.splice(0), ['/to-ok', '/ok']);

  for (const path of ['/to-v6', '/to-metadata', '/to-file']) {
    await assert.rejects(fetchPublicPage(`${base}${path}`, config, loopbackOnly), BlockedUrlError, path);
  }
  assert.deepEqual(hits.splice(0), ['/to-v6', '/to-metadata', '/to-file'], 'a refused hop was requested');

  await assert.rejects(fetchPublicPage(`${base}/loop`, config, loopbackOnly), /Too many redirects/);
});

test('the connection is pinned to the checked addresses (DNS rebinding)', async (t) => {
  const server = await startServer(t);
  if (!server) return;
  const port = new URL(server.base).port;
  let calls = 0;
  const resolve = async () => (++calls === 1
    ? [{ address: '127.0.0.1', family: 4 }]
    : [{ address: '::1', family: 6 }]);
  await assert.rejects(
    fetchPublicPage(`http://rebind.example:${port}/ok`, { timeout: 5000 }, { ...loopbackOnly, resolve }),
    BlockedUrlError,
  );
  assert.equal(calls, 2, 'the socket did not use the guarded lookup');
  assert.deepEqual(server.hits, []);
});

test('a refused URL never falls back to the browser', async (t) => {
  const server = await startServer(t);
  if (!server) return;
  const browserCalls = [];
  t.mock.method(EnhancedContentExtractor.prototype, 'extractWithBrowser', async (options) => {
    browserCalls.push(options.url);
    return 'browser content';
  });

  // The JS-heavy-site heuristic matches "twitter.com"/"reddit.com" anywhere
  // in the URL, so these would reach the browser if a refusal fell through.
  const extractor = new EnhancedContentExtractor();
  await assert.rejects(extractor.extractContent({ url: 'http://169.254.169.254/latest/meta-data/?twitter.com' }),
    BlockedUrlError);
  const guarded = new EnhancedContentExtractor(loopbackOnly);
  await assert.rejects(guarded.extractContent({ url: `${server.base}/reddit.com/to-v6` }), BlockedUrlError);

  assert.deepEqual(browserCalls, []);
  assert.deepEqual(server.hits, ['/reddit.com/to-v6']);
});

test('the browser re-validates main-document redirects before following them', async (t) => {
  if (!resolveChromiumExecutable()) {
    t.skip('no Chromium executable on this host');
    return;
  }
  const server = await startServer(t);
  if (!server) return;
  const extractor = new EnhancedContentExtractor(loopbackOnly);
  t.after(() => extractor.closeAll());

  const content = await extractor.extractWithBrowser({ url: `${server.base}/to-ok`, timeout: 8000 });
  assert.match(content, /ok body text/);
  assert.deepEqual(server.hits.splice(0), ['/to-ok', '/ok']);

  await assert.rejects(extractor.extractWithBrowser({ url: `${server.base}/to-v6`, timeout: 8000 }), BlockedUrlError);
  assert.deepEqual(server.hits.splice(0), ['/to-v6'], 'the browser followed a refused redirect');
});
