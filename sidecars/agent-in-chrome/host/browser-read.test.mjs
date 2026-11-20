import assert from 'node:assert/strict';
import test from 'node:test';
import http from 'node:http';
import { once } from 'node:events';
import { mkdtemp, writeFile, access, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { validateRequest, pageState, readPage } from './browser-read.js';

const here = path.dirname(fileURLToPath(import.meta.url));
test('bounded read contract refuses non-web URLs, credentials and unbounded work', () => {
  const input = { pages: [{ url: 'https://example.test/grid/', selector: 'a' }] };
  assert.equal(validateRequest(input).maxScrolls, 0);
  for (const url of ['file:///tmp/secret', 'javascript:alert(1)', 'https://u:p@example.test/']) {
    assert.throws(() => validateRequest({ pages: [{ url, selector: 'a' }] }));
  }
  for (const change of [{ maxScrolls: 21 }, { pages: [] }, { pageTimeoutMs: 90000 }, { stopSelectors: [''] }]) {
    assert.throws(() => validateRequest({ ...input, ...change }));
  }
});

test('a login or checkpoint wins over matching tiles and redirects cannot be attributed', () => {
  const request = validateRequest({ pages: [{ url: 'https://example.test/grid/', selector: 'a' }], stopPathPrefixes: ['/checkpoint/', '/login/'] });
  const page = request.pages[0];
  assert.equal(pageState({ url: page.url, blocked: false }, page, request), 'ready');
  assert.equal(pageState({ url: 'https://example.test/checkpoint/x', rows: [{ text: '10' }] }, page, request), 'blocked');
  assert.equal(pageState({ url: page.url, blocked: true }, page, request), 'blocked');
  assert.equal(pageState({ url: 'https://example.test/other/' }, page, request), 'redirected');
});

test('blocked reads discard counters and never scroll or click', async () => {
  const calls = [];
  const cdp = { send: async (method) => { calls.push(method); return method === 'Runtime.evaluate' ? { result: { value: { url: 'https://example.test/checkpoint/', blocked: false, rows: [{ href: '/item/a', text: '99' }] } } } : {}; } };
  const request = validateRequest({ pages: [{ url: 'https://example.test/grid/', selector: 'a' }], stopPathPrefixes: ['/checkpoint/'], maxScrolls: 5 });
  const output = await readPage(cdp, 'session', request.pages[0], request);
  assert.equal(output.status, 'blocked'); assert.deepEqual(output.rows, []);
  assert.deepEqual(calls, ['Page.navigate', 'Runtime.evaluate']);
});

let binary;
for (const candidate of [process.env.OPENAGENT_TEST_CHROME_BINARY, '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome', '/usr/bin/chromium']) {
  if (!candidate) continue;
  try { await access(candidate); binary = candidate; break; } catch {}
}
test('real browser reads delayed counters before load ends, preserves auth and stops at checkpoint', { skip: !binary, timeout: 60000 }, async (t) => {
  let visits = [];
  const site = http.createServer((req, res) => {
    visits.push(req.url);
    if (req.url === '/never') return; // The page load event never fires.
    if (req.url === '/checkpoint/') { res.writeHead(200, { 'content-type': 'text/html' }); res.end('<h1>Checkpoint</h1>'); return; }
    if (req.url === '/blocked') { res.writeHead(302, { location: '/checkpoint/' }); res.end(); return; }
    res.writeHead(200, { 'content-type': 'text/html', 'set-cookie': 'authorized=fixture; Path=/; SameSite=Lax' });
    res.end(`<title>Grid</title><img src="/never"><a href="/item/hidden" style="display:none">999</a><script>setTimeout(()=>{document.body.insertAdjacentHTML('beforeend','<a href="/item/one">166K</a><a href="/item/two">8,208</a>')},350)</script>`);
  });
  site.listen(0, '127.0.0.1'); await once(site, 'listening');
  t.after(() => { site.closeAllConnections(); site.close(); });
  const origin = `http://127.0.0.1:${site.address().port}`;
  const directory = await mkdtemp(path.join(tmpdir(), 'oa-read-')); t.after(() => rm(directory, { recursive: true, force: true }));
  const requestFile = path.join(directory, 'request.json');
  await writeFile(requestFile, JSON.stringify({ pages: [
    { url: origin + '/grid/', selector: 'a', targets: ['/item/one', '/item/two'] },
    { url: origin + '/blocked', selector: 'a' }, { url: origin + '/forbidden', selector: 'a' },
  ], stopPathPrefixes: ['/checkpoint/'], pageTimeoutMs: 5000, settleMs: 200 }));
  const child = spawn(process.execPath, [path.join(here, 'browser-read.js'), '--request-file', requestFile], { env: { ...process.env,
    OPENAGENT_CHROME_PROFILE_DIR: path.join(directory, 'profile'), OPENAGENT_CHROME_BINARY: binary,
    OPENAGENT_CHROME_CDP_PORT: String(20000 + Math.floor(Math.random() * 20000)), OPENAGENT_CHROME_HEADLESS: 'true' }, stdio: ['ignore', 'pipe', 'pipe'] });
  let output = '', errors = ''; child.stdout.on('data', c => { output += c; }); child.stderr.on('data', c => { errors += c; });
  t.after(() => { if (child.exitCode === null) child.kill('SIGKILL'); });
  const [code] = await once(child, 'exit'); assert.equal(code, 0, errors + output);
  const result = JSON.parse(output);
  assert.equal(result.status, 'blocked'); assert.equal(result.pages.length, 2);
  assert.equal(result.pages[0].status, 'ok');
  assert.deepEqual(result.pages[0].rows.map(r => r.text), ['166K', '8,208']);
  assert.ok(result.pages[0].durationMs < 5000);
  assert.deepEqual(result.pages[1].rows, []); assert.equal(visits.includes('/forbidden'), false);
  await assert.rejects(access(requestFile));
  await access(path.join(directory, 'profile', 'Default', 'Cookies'));
});
