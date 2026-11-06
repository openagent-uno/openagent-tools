import assert from 'node:assert/strict';
import test from 'node:test';
import { once } from 'node:events';
import { mkdtemp, readFile, rm, access } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { setTimeout as delay } from 'node:timers/promises';
import { WebSocketServer } from 'ws';
import { CDPConnection } from './cdp.js';
import { PAGE_SCRIPT } from './page-script.js';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { fileURLToPath } from 'node:url';

async function websocketFixture(t, handler) {
  const server = new WebSocketServer({ host: '127.0.0.1', port: 0 });
  await once(server, 'listening');
  server.on('connection', (socket) => socket.on('message', (raw) => handler(JSON.parse(raw), socket)));
  const client = new CDPConnection(`ws://127.0.0.1:${server.address().port}`, { requestTimeoutMs: 300 });
  await client.connect();
  t.after(async () => {
    client.close();
    for (const socket of server.clients) socket.terminate();
    await new Promise((resolve) => server.close(resolve));
  });
  return client;
}


test('CDP close settles pending commands and event waiters immediately', async (t) => {
  const client = await websocketFixture(t, () => {});
  const command = client.send('Page.test');
  const event = client.once('Page.loadEventFired', { timeout: 30_000 });
  const rejected = assert.rejects(command, /closed/);
  client.close();
  await rejected;
  assert.equal(await event, null);
  assert.equal(client.pending.size, 0);
  assert.equal(client.listeners.size, 0);
});

test('CDP response stays bound to its requested session', async (t) => {
  const client = await websocketFixture(t, (request, socket) => {
    socket.send(JSON.stringify({ id: request.id, sessionId: 'different-tab', result: { secret: 'other tab' } }));
  });
  await assert.rejects(client.send('Runtime.evaluate', {}, 'expected-tab'), /session does not match/);
  assert.equal(client.pending.size, 0);
});

test('CDP cancellation ignores late responses and never replays dispatched commands', async (t) => {
  const requests = [];
  let deliver;
  const ready = new Promise((resolve) => { deliver = resolve; });
  const client = await websocketFixture(t, (request, socket) => {
    requests.push(request);
    if (requests.length === 1) { deliver({ request, socket }); return; }
    socket.send(JSON.stringify({ id: request.id, result: { accepted: true } }));
  });
  const abort = new AbortController();
  const first = client.send('Input.insertText', { text: 'only once' }, undefined, { signal: abort.signal });
  const delivered = await ready;
  abort.abort();
  await assert.rejects(first, { name: 'AbortError' });
  delivered.socket.send(JSON.stringify({ id: delivered.request.id, result: { late: true } }));
  assert.deepEqual(await client.send('Browser.getVersion'), { accepted: true });
  assert.equal(requests.filter((r) => r.method === 'Input.insertText').length, 1);
  assert.equal(client.pending.size, 0);
});

test('CDP session detach rejects only that target while other requests continue', async (t) => {
  let signalDetached;
  const detached = new Promise((resolve) => { signalDetached = resolve; });
  const client = await websocketFixture(t, (request, socket) => {
    if (request.sessionId === 'dead') {
      socket.send(JSON.stringify({ method: 'Target.detachedFromTarget', params: { sessionId: 'dead' } }));
      signalDetached();
    } else socket.send(JSON.stringify({ id: request.id, sessionId: request.sessionId, result: { alive: true } }));
  });
  const failed = assert.rejects(client.send('Runtime.evaluate', {}, 'dead'), /detached/);
  await detached;
  assert.deepEqual(await client.send('Runtime.evaluate', {}, 'alive'), { alive: true });
  await failed;
  assert.equal(client.pending.size, 0);
});

test('CDP timeout and aborted event waits clean up listeners', async (t) => {
  const client = await websocketFixture(t, () => {});
  await assert.rejects(client.send('Page.never'), /timed out/);
  const abort = new AbortController();
  const wait = client.once('Page.loadEventFired', { signal: abort.signal });
  abort.abort('explicit cancellation');
  await assert.rejects(wait, (error) => error === 'explicit cancellation');
  assert.equal(client.listeners.size, 0);
  assert.equal(client._closeHandlers.length, 0);
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

async function browserFixture(t) {
  const temporary = await mkdtemp(path.join(tmpdir(), 'openagent-browser-reliability-'));
  const profile = path.join(temporary, 'profile');
  const child = spawn(binary, ['--headless=new', '--no-first-run', '--no-default-browser-check',
    '--disable-background-networking', '--remote-debugging-port=0', `--user-data-dir=${profile}`, 'about:blank'],
    { stdio: ['ignore', 'ignore', 'ignore'] });
  let client;
  t.after(async () => {
    client?.close();
    child.kill('SIGTERM');
    await Promise.race([once(child, 'close'), delay(2000)]);
    if (child.exitCode == null) child.kill('SIGKILL');
    await rm(temporary, { recursive: true, force: true });
  });
  let port;
  let endpoint;
  const deadline = Date.now() + 15_000;
  while (Date.now() < deadline) {
    if (child.exitCode != null) throw new Error(`Test browser exited: ${child.exitCode}`);
    try {
      const marker = (await readFile(path.join(profile, 'DevToolsActivePort'), 'utf8')).trim().split('\n');
      port = Number(marker[0]);
      endpoint = `ws://127.0.0.1:${port}${marker[1]}`;
      break;
    } catch { await delay(30); }
  }
  assert.ok(endpoint, 'isolated test browser started');
  client = new CDPConnection(endpoint);
  await client.connect();
  async function tab(html) {
    const { targetId } = await client.send('Target.createTarget', { url: 'about:blank' });
    const { sessionId } = await client.send('Target.attachToTarget', { targetId, flatten: true });
    await client.send('Page.enable', {}, sessionId);
    await client.send('Runtime.enable', {}, sessionId);
    await evaluate(sessionId, `document.body.innerHTML=${JSON.stringify(html)}`);
    await evaluate(sessionId, PAGE_SCRIPT);
    return sessionId;
  }
  async function evaluate(sessionId, expression) {
    const result = await client.send('Runtime.evaluate', { expression, returnByValue: true, awaitPromise: true }, sessionId);
    assert.equal(result.exceptionDetails, undefined, JSON.stringify(result.exceptionDetails));
    return result.result.value;
  }
  return { client, tab, evaluate, profile, port };
}

test('real Chromium refs cannot alias another tab, detached node, frame or new document', { skip: !binary }, async (t) => {
  const { client, tab, evaluate } = await browserFixture(t);
  const a = await tab('<button>target</button>');
  const b = await tab('<button>target</button>');
  const refA = await evaluate(a, 'window.__openagentChrome.findElements("target").find(e=>e.role==="button").ref');
  const refB = await evaluate(b, 'window.__openagentChrome.findElements("target").find(e=>e.role==="button").ref');
  assert.notEqual(refA, refB);
  assert.equal(await evaluate(b, `window.__openagentChrome.getRefCoordinates(${JSON.stringify(refA)})`), null);
  assert.equal(await evaluate(a, 'window.__openagentChrome.resolveRef("__proto__")'), null);
  await evaluate(a, `window.saved=document.querySelector('button');
    const frame=document.createElement('iframe');document.body.append(frame);
    frame.contentDocument.body.appendChild(frame.contentDocument.adoptNode(saved));`);
  assert.equal(await evaluate(a, `window.__openagentChrome.getRefCoordinates(${JSON.stringify(refA)})`), null);
  await client.send('Page.addScriptToEvaluateOnNewDocument', { source: PAGE_SCRIPT }, a);
  const loaded = client.once('Page.loadEventFired', { sessionId: a });
  await client.send('Page.navigate', { url: 'data:text/html,<button>target</button>' }, a);
  assert.ok(await loaded);
  const newRef = await evaluate(a, 'window.__openagentChrome.findElements("target").find(e=>e.role==="button").ref');
  assert.notEqual(refA, newRef);
  assert.equal(await evaluate(a, `window.__openagentChrome.getRefCoordinates(${JSON.stringify(refA)})`), null);
});

test('real Chromium form_input rejects ambiguity and invalid targets without false success', { skip: !binary }, async (t) => {
  const { tab, evaluate } = await browserFixture(t);
  const session = await tab('<form aria-label="pair"><input value="one"><input value="two"></form>' +
    '<input aria-label="locked" readonly value="original"><select aria-label="choice"><option value="a">Alpha</option></select>' +
    '<button>not a field</button><input type="checkbox" aria-label="toggle">');
  const check = (expression) => evaluate(session, expression);
  const refs = await check(`({
    form:window.__openagentChrome.findElements("pair").find(e=>e.role==="form").ref,
    locked:window.__openagentChrome.findElements("locked").find(e=>e.role==="textbox").ref,
    select:window.__openagentChrome.findElements("choice").find(e=>e.role==="combobox").ref,
    button:window.__openagentChrome.findElements("not a field").find(e=>e.role==="button").ref,
    toggle:window.__openagentChrome.findElements("toggle").find(e=>e.role==="checkbox").ref
  })`);
  for (const [name, value] of [['form', 'changed'], ['locked', 'changed'], ['select', 'missing'], ['button', 'changed'], ['toggle', 'maybe']]) {
    const result = await check(`window.__openagentChrome.setFormValue(${JSON.stringify(refs[name])},${JSON.stringify(value)})`);
    assert.ok(result.error, name);
  }
  assert.deepEqual(await check('Array.from(document.querySelectorAll("input")).map(e=>e.value)'), ['one', 'two', 'original', 'on']);
  assert.equal(await check('document.querySelector("select").value'), 'a');
  const selected = await check(`window.__openagentChrome.setFormValue(${JSON.stringify(refs.select)},"Alpha")`);
  assert.equal(selected.success, true);
  const checked = await check(`window.__openagentChrome.setFormValue(${JSON.stringify(refs.toggle)},true)`);
  assert.equal(checked.checked, true);
  assert.deepEqual(await check('window.__openagentChrome.findElements("   ")'), []);
});


test('real Chromium find prioritizes actionable matches beyond matching containers', { skip: !binary }, async (t) => {
  const { tab, evaluate } = await browserFixture(t);
  const session = await tab('<div>'.repeat(35) + '<button>Find action</button>' + '</div>'.repeat(35));
  const results = await evaluate(session, 'window.__openagentChrome.findElements("Find action")');
  assert.equal(results.length, 20);
  assert.equal(results[0].role, 'button');
  assert.equal(results[0].name, 'Find action');
});


test('real MCP tools propagate cancellation and stale-ref errors without replacing the supervised browser', { skip: !binary }, async (t) => {
  const { profile, port } = await browserFixture(t);
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [fileURLToPath(new URL('./mcp-server.js', import.meta.url))],
    env: { ...process.env, OPENAGENT_CHROME_PROFILE_DIR: profile,
      OPENAGENT_CHROME_CDP_PORT: String(port), OPENAGENT_BROWSER_EXTERNAL: '1' },
    stderr: 'pipe',
  });
  const client = new Client({ name: 'browser-reliability-test', version: '1' });
  await client.connect(transport);
  t.after(() => client.close());
  const created = await client.callTool({ name: 'tabs_create_mcp', arguments: {} });
  assert.equal(created.isError, undefined, JSON.stringify(created));
  const tabId = Number(created.content[0].text.match(/Tab ID: (\d+)/)[1]);
  const set = await client.callTool({ name: 'javascript_tool', arguments: {
    tabId, action: 'javascript_exec', text: 'document.body.innerHTML="<button>Unique action</button>"' } });
  assert.equal(set.isError, undefined, JSON.stringify(set));
  const simultaneous = await Promise.all([1, 2].map(() => client.callTool({
    name: 'read_page', arguments: { tabId, filter: 'interactive' }
  })));
  assert.ok(simultaneous.every((result) => !result.isError), JSON.stringify(simultaneous));
  const stale = await client.callTool({ name: 'computer', arguments: { tabId, action: 'left_click', ref: 'ref_from_another_document' } });
  assert.equal(stale.isError, true);
  const abort = new AbortController();
  const wait = client.callTool({ name: 'computer', arguments: { tabId, action: 'wait', duration: 20 } }, undefined, { signal: abort.signal });
  await delay(100);
  abort.abort();
  await assert.rejects(wait, /abort/i);
  const read = await client.callTool({ name: 'get_page_text', arguments: { tabId } });
  assert.equal(read.isError, undefined, JSON.stringify(read));
  assert.match(read.content[0].text, /Unique action/);
  const started = Date.now();
  const zero = await client.callTool({ name: 'computer', arguments: { tabId, action: 'wait', duration: 0 } });
  assert.equal(zero.isError, undefined, JSON.stringify(zero));
  assert.match(zero.content[0].text, /Waited 0s/);
  assert.ok(Date.now() - started < 1000, 'explicit zero wait is preserved');
});


test('real Chromium element coordinates reject an intercepted or disabled target', { skip: !binary }, async (t) => {
  const { tab, evaluate } = await browserFixture(t);
  const session = await tab('<button style="position:fixed;left:20px;top:20px;width:100px;height:40px">Original</button>');
  const ref = await evaluate(session, 'window.__openagentChrome.findElements("Original")[0].ref');
  assert.ok(await evaluate(session, `window.__openagentChrome.getRefCoordinates(${JSON.stringify(ref)})`));
  await evaluate(session, 'const overlay=document.createElement("div");overlay.style="position:fixed;inset:0;z-index:9999;background:white";document.body.append(overlay)');
  assert.equal(await evaluate(session, `window.__openagentChrome.getRefCoordinates(${JSON.stringify(ref)})`), null);
  await evaluate(session, 'document.querySelector("div").remove();document.querySelector("button").disabled=true');
  assert.equal(await evaluate(session, `window.__openagentChrome.getRefCoordinates(${JSON.stringify(ref)})`), null);
});
