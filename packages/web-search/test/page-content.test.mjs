import assert from 'node:assert/strict';
import test from 'node:test';
import { createServer } from 'node:http';
import { EnhancedContentExtractor } from '../dist/enhanced-content-extractor.js';
import { documentTitle, formatPageContent } from '../dist/page-content.js';
import { BlockedUrlError } from '../dist/url-guard.js';

const body = '<main><h1>IANA-managed Reserved Domains</h1><p>Certain domains are set aside for policy or technical purposes. Example domains remain available for documentation. This fixture requires no external network or model.</p></main>';
async function fixture(t, html) {
  let hits = 0;
  const server = createServer((req, res) => { hits++; res.writeHead(200, { 'Content-Type': 'text/html' }); res.end(html); });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => server.close());
  return { url: `http://127.0.0.1:${server.address().port}/domains/reserved`, hits: () => hits };
}
function extractor(t) {
  const instance = new EnhancedContentExtractor({ isBlockedAddress: address => address !== '127.0.0.1' });
  t.after(() => instance.closeAll());
  return instance;
}

test('single-page response uses the actual HTML title from the same fetch, not the URL', async t => {
  const page = await fixture(t, '<html><head><title>IANA-managed Reserved Domains</title></head><body>' + body + '</body></html>');
  const extracted = await extractor(t).extractPage({ url: page.url });
  assert.equal(extracted.title, 'IANA-managed Reserved Domains');
  const result = formatPageContent(page.url, extracted);
  assert.match(result, /\*\*Title:\*\* IANA-managed Reserved Domains\n/);
  assert.ok(result.includes('Example domains remain available'));
  assert.equal(page.hits(), 1, 'metadata must not require a second request');
});

test('legacy extractContent still returns only body text and obeys content truncation', async t => {
  const page = await fixture(t, '<html><head><title>A different metadata title</title></head><body>' + body + '</body></html>');
  const result = await extractor(t).extractContent({ url: page.url, maxContentLength: 150 });
  assert.equal(typeof result, 'string');
  assert.equal(result.length, 150);
  assert.ok(!result.includes('A different metadata title'));
  assert.equal(page.hits(), 1);
});

test('document title decodes entities, normalizes whitespace and remains bounded', () => {
  assert.equal(documentTitle('<head><title>  Studio &amp; Cinema\n   —  Notes </title></head>'), 'Studio & Cinema — Notes');
  assert.equal(documentTitle('<title>' + 'x'.repeat(2000) + '</title>').length, 1024);
});

test('missing or blank document titles are explicitly unavailable, never inferred from URL or heading', async t => {
  for (const title of ['', '<title> \n </title>']) {
    const page = await fixture(t, '<html><head>' + title + '</head><body>' + body + '</body></html>');
    const extracted = await extractor(t).extractPage({ url: page.url });
    assert.equal(extracted.title, null);
    assert.match(formatPageContent(page.url, extracted), /\*\*Title:\*\* Unavailable \(no document title\)/);
    assert.equal(page.hits(), 1);
  }
});

test('browser extraction preserves title metadata and closes its owned context', async t => {
  const instance = extractor(t);
  let closed = 0;
  instance.browserPool = { getLastUsedBrowserType: () => 'chromium', async getBrowser() {
    return { async newContext() { return {
      async addInitScript() {}, async close() { closed++; }, async newPage() { return {
        mouse: { async move() {} }, async waitForTimeout() {}, async waitForSelector() {},
        async content() { return '<html><head><title>Rendered &amp; ready</title></head><body>' + body + '</body></html>'; }
      }; }
    }; } };
  }, async closeAll() {} };
  instance.navigateGuarded = async () => {};
  const extracted = await instance.extractPageWithBrowser({ url: 'https://public.example/page' });
  assert.equal(extracted.title, 'Rendered & ready');
  assert.ok(extracted.content.includes('Example domains'));
  assert.equal(closed, 1);
});

test('new metadata API retains refusal of non-public URLs without browser fallback', async t => {
  const instance = new EnhancedContentExtractor();
  t.after(() => instance.closeAll());
  let fallback = 0;
  instance.extractPageWithBrowser = async () => { fallback++; throw new Error('must not run'); };
  await assert.rejects(instance.extractPage({ url: 'http://169.254.169.254/latest/meta-data/?twitter.com' }), BlockedUrlError);
  assert.equal(fallback, 0);
});
