import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { chromium, firefox } from 'playwright';
import { BrowserPool } from '../dist/browser-pool.js';

function environment(t, values) {
  const previous = Object.fromEntries(Object.keys(values).map(key => [key, process.env[key]]));
  for (const [key, value] of Object.entries(values)) {
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }
  t.after(() => {
    for (const [key, value] of Object.entries(previous)) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
  });
}

function fakeBrowser() {
  return { isConnected: () => true, newContext: async () => ({ close: async () => {} }), close: async () => {} };
}

test('extraction pool honors the explicit Chrome binary and reuses its healthy browser', async t => {
  const directory = mkdtempSync(join(tmpdir(), 'openagent-browser-pool-'));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  const executable = join(directory, 'operator-chrome');
  writeFileSync(executable, '', { mode: 0o700 });
  environment(t, { OPENAGENT_CHROME_BINARY: executable, BROWSER_TYPES: 'chromium', BROWSER_HEADLESS: 'false' });
  const browser = fakeBrowser();
  const launch = t.mock.method(chromium, 'launch', async options => {
    assert.equal(options.executablePath, executable);
    assert.equal(options.headless, false);
    return browser;
  });
  const otherLaunch = t.mock.method(firefox, 'launch', async () => { throw new Error('unexpected Firefox'); });
  const close = t.mock.method(browser, 'close');
  const pool = new BrowserPool();
  try {
    assert.equal(await pool.getBrowser(), browser);
    assert.equal(await pool.getBrowser(), browser);
    assert.equal(pool.getLastUsedBrowserType(), 'chromium');
    assert.equal(launch.mock.callCount(), 1);
    assert.equal(otherLaunch.mock.callCount(), 0);
  } finally { await pool.closeAll(); }
  assert.equal(close.mock.callCount(), 1);
});

test('default extraction stays on provisioned Chromium instead of rotating to Firefox', async t => {
  environment(t, { BROWSER_TYPES: undefined, BROWSER_HEADLESS: undefined });
  const launch = t.mock.method(chromium, 'launch', async () => fakeBrowser());
  const otherLaunch = t.mock.method(firefox, 'launch', async () => { throw new Error('unexpected Firefox'); });
  const pool = new BrowserPool();
  try {
    await pool.getBrowser();
    await pool.getBrowser();
    assert.equal(launch.mock.callCount(), 1);
    assert.equal(otherLaunch.mock.callCount(), 0);
  } finally { await pool.closeAll(); }
});

test('an explicitly selected Firefox retains its own executable configuration', async t => {
  environment(t, { BROWSER_TYPES: 'firefox', OPENAGENT_CHROME_BINARY: process.execPath });
  const launch = t.mock.method(firefox, 'launch', async options => {
    assert.equal(Object.hasOwn(options, 'executablePath'), false);
    return fakeBrowser();
  });
  const pool = new BrowserPool();
  try {
    await pool.getBrowser();
    assert.equal(pool.getLastUsedBrowserType(), 'firefox');
    assert.equal(launch.mock.callCount(), 1);
  } finally { await pool.closeAll(); }
});
