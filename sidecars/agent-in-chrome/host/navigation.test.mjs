import assert from 'node:assert/strict';
import test from 'node:test';
import { once } from 'node:events';
import { access, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { setTimeout as delay } from 'node:timers/promises';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { navigationTarget } from './navigation.js';

test('navigate refuses local-file and script schemes', () => {
  for (const url of ['file:///etc/passwd', 'FILE:///task/openagent.yaml', ' file://localhost/etc/hosts',
    'file:etc/passwd', 'filesystem:file:///tmp/x', 'view-source:file:///etc/passwd',
    'data:text/html,<p>x</p>', 'javascript:alert(1)', 'blob:null/abc']) {
    const resolved = navigationTarget(url);
    assert.ok(resolved.error, `${url} must be refused`);
    assert.equal(resolved.url, undefined);
  }
});

test('navigate keeps web and browser URLs and completes bare hosts', () => {
  assert.equal(navigationTarget('https://example.test/a?b=1').url, 'https://example.test/a?b=1');
  assert.equal(navigationTarget('http://127.0.0.1:8080/').url, 'http://127.0.0.1:8080/');
  assert.equal(navigationTarget('example.test/path').url, 'https://example.test/path');
  assert.equal(navigationTarget('about:blank').url, 'about:blank');
  assert.ok(navigationTarget('https://exa mple.test').error);
});

async function existingBrowserBinary() {
  for (const candidate of [process.env.OPENAGENT_TEST_CHROME_BINARY,
    '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
    '/usr/bin/chromium', '/usr/bin/chromium-browser', '/usr/bin/google-chrome']) {
    if (!candidate) continue;
    try { await access(candidate); return candidate; } catch {}
  }
  return null;
}

const binary = await existingBrowserBinary();

test('real MCP tools cannot read a local file through the browser', { skip: !binary }, async (t) => {
  const temporary = await mkdtemp(path.join(tmpdir(), 'openagent-browser-file-'));
  const profile = path.join(temporary, 'profile');
  const secretPath = path.join(temporary, 'openagent.yaml');
  const secret = 'proxy-password-' + Math.random().toString(36).slice(2);
  await writeFile(secretPath, `proxy: http://user:${secret}@proxy.test:8080\n`, { mode: 0o600 });
  const fileUrl = pathToFileURL(secretPath).href;

  const child = spawn(binary, ['--headless=new', '--no-first-run', '--no-default-browser-check',
    '--disable-background-networking', '--remote-debugging-port=0', `--user-data-dir=${profile}`, 'about:blank'],
    { stdio: ['ignore', 'ignore', 'ignore'] });
  let client;
  t.after(async () => {
    await client?.close();
    child.kill('SIGTERM');
    await Promise.race([once(child, 'close'), delay(2000)]);
    if (child.exitCode == null) child.kill('SIGKILL');
    await rm(temporary, { recursive: true, force: true });
  });
  let port;
  const deadline = Date.now() + 15_000;
  while (!port && Date.now() < deadline) {
    try { port = Number((await readFile(path.join(profile, 'DevToolsActivePort'), 'utf8')).split('\n')[0]); }
    catch { await delay(100); }
  }
  assert.ok(port, 'test browser exposed a CDP port');

  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [fileURLToPath(new URL('./mcp-server.js', import.meta.url))],
    env: { ...process.env, OPENAGENT_CHROME_PROFILE_DIR: profile,
      OPENAGENT_CHROME_CDP_PORT: String(port), OPENAGENT_BROWSER_EXTERNAL: '1' },
    stderr: 'pipe',
  });
  client = new Client({ name: 'browser-file-test', version: '1' });
  await client.connect(transport);
  const created = await client.callTool({ name: 'tabs_create_mcp', arguments: {} });
  const tabId = Number(created.content[0].text.match(/Tab ID: (\d+)/)[1]);
  const call = (name, args) => client.callTool({ name, arguments: { tabId, ...args } });
  const seen = [];

  const navigated = await call('navigate', { url: fileUrl });
  assert.equal(navigated.isError, true, JSON.stringify(navigated));
  seen.push(navigated);

  // Page-initiated attempts: Chromium must keep a non-file page out of file URLs.
  seen.push(await call('javascript_tool', { action: 'javascript_exec',
    text: `fetch(${JSON.stringify(fileUrl)}).then((r) => r.text()).catch((e) => 'blocked: ' + e)` }));
  seen.push(await call('javascript_tool', { action: 'javascript_exec',
    text: `location.href = ${JSON.stringify(fileUrl)}; 'requested'` }));
  await delay(500);
  seen.push(await call('javascript_tool', { action: 'javascript_exec',
    text: `window.open(${JSON.stringify(fileUrl)}) ? 'opened' : 'refused'` }));
  await delay(500);
  seen.push(await call('get_page_text', {}));
  const tabs = await client.callTool({ name: 'tabs_context_mcp', arguments: {} });
  seen.push(tabs);

  const transcript = JSON.stringify(seen);
  assert.ok(!transcript.includes(secret), 'no tool result carries the file content');
  assert.ok(!tabs.content[0].text.includes('file://'), tabs.content[0].text);
});
