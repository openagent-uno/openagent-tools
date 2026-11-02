import assert from 'node:assert/strict';
import test from 'node:test';
import { setImmediate as tick } from 'node:timers/promises';
import { chromium } from 'playwright';
import { BrowserPool } from '../dist/browser-pool.js';
import { EnhancedContentExtractor } from '../dist/enhanced-content-extractor.js';

function deferred() {
  let resolve;
  const promise = new Promise(done => { resolve = done; });
  return { promise, resolve };
}

function fakeContext() {
  return {
    closed: 0,
    async close() { this.closed++; },
    async addInitScript() {},
    async newPage() {
      return {
        mouse: { async move() {} }, async waitForTimeout() {}, async waitForSelector() {},
        async content() { return '<main>Neutral extraction fixture with useful content.</main>'; },
      };
    },
  };
}

test('concurrent acquisition launches one owned browser per type', async t => {
  const gate = deferred();
  const browsers = [];
  const launch = t.mock.method(chromium, 'launch', async () => {
    await gate.promise;
    const browser = { isConnected: () => true, async newContext() { return fakeContext(); },
      closed: 0, async close() { this.closed++; } };
    browsers.push(browser);
    return browser;
  });
  const pool = new BrowserPool();
  const pending = Array.from({ length: 12 }, () => pool.getBrowser());
  await tick();
  gate.resolve();
  try {
    const acquired = await Promise.all(pending);
    assert.equal(launch.mock.callCount(), 1);
    assert.equal(new Set(acquired).size, 1);
  } finally { await pool.closeAll(); }
  assert.ok(browsers.every(browser => browser.closed === 1), 'every launched browser must be owned and closed');
});

test('shutdown drains an in-flight launch and leaves no late browser alive', async t => {
  const gate = deferred();
  const browser = { isConnected: () => true, closed: 0, async close() { this.closed++; } };
  t.mock.method(chromium, 'launch', async () => { await gate.promise; return browser; });
  const pool = new BrowserPool();
  const acquisition = pool.getBrowser();
  const shutdown = pool.closeAll();
  gate.resolve();
  await Promise.allSettled([acquisition, shutdown]);
  assert.equal(browser.closed, 1);
});

test('failed navigation and failed alternate HTTP extraction release every context', async () => {
  for (const alternate of [false, true]) {
    const contexts = [];
    const browser = { async newContext() {
      const context = fakeContext();
      context.newPage = async () => ({ async content() { throw new Error('content fixture failure'); } });
      contexts.push(context);
      return context;
    } };
    const extractor = new EnhancedContentExtractor();
    extractor.browserPool = { async getBrowser() { return browser; }, getLastUsedBrowserType() { return 'chromium'; } };
    let calls = 0;
    extractor.navigateGuarded = async () => {
      calls++;
      if (calls === 1) throw new Error(alternate ? 'ERR_HTTP2_PROTOCOL_ERROR' : 'navigation fixture failure');
    };
    await assert.rejects(extractor.extractWithBrowser({ url: 'https://public.example/page' }));
    assert.equal(contexts.length, alternate ? 2 : 1);
    assert.ok(contexts.every(context => context.closed === 1));
  }
});

test('a batch never reports completion while extraction continues in the background', async t => {
  const gate = deferred();
  const extractor = new EnhancedContentExtractor();
  extractor.extractContent = async () => { await gate.promise; return 'fixture content'; };
  const realTimeout = globalThis.setTimeout;
  t.mock.method(globalThis, 'setTimeout', (callback, delay, ...args) =>
    realTimeout(callback, delay === 8000 ? 0 : delay, ...args));
  let settled = false;
  const pending = extractor.extractContentForResults([{ title: 'Fixture', url: 'https://public.example/page' }])
    .then(result => { settled = true; return result; });
  try {
    await new Promise(done => realTimeout(done, 20));
    assert.equal(settled, false, 'timing out the caller must not abandon owned work');
  } finally { gate.resolve(); }
  assert.equal((await pending)[0].fetchStatus, 'success');
});

test('concurrent browser extractions use a bounded number of isolated contexts', async () => {
  const gate = deferred();
  const contexts = [];
  let active = 0, peak = 0;
  const browser = { async newContext() {
    const context = fakeContext();
    contexts.push(context);
    active++; peak = Math.max(peak, active);
    context.close = async () => { context.closed++; active--; };
    return context;
  } };
  const extractor = new EnhancedContentExtractor();
  extractor.browserPool = { async getBrowser() { return browser; }, getLastUsedBrowserType() { return 'chromium'; } };
  extractor.navigateGuarded = async () => gate.promise;
  const pending = Array.from({ length: 10 }, () => extractor.extractWithBrowser({ url: 'https://public.example/page' }));
  await tick(); await tick();
  gate.resolve();
  await Promise.all(pending);
  assert.ok(peak <= 2, `peak active contexts: ${peak}`);
  assert.equal(contexts.length, 10);
  assert.ok(contexts.every(context => context.closed === 1));
  assert.equal(active, 0);
});
