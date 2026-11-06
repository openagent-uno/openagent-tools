import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { once } from 'node:events';
import { spawn } from 'node:child_process';
import { mkdtemp, readFile, rm, access, writeFile } from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { fileURLToPath } from 'node:url';
import { setTimeout as delay } from 'node:timers/promises';
import { createHmac, randomUUID } from 'node:crypto';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { CDPConnection } from './cdp.js';
import { canonicalJSON, configuredBrowserSlots, AdvancedBrowser } from './browser-advanced.js';

async function binary() {
  for (const name of [process.env.OPENAGENT_TEST_CHROME_BINARY, '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome', '/usr/bin/chromium', '/usr/bin/google-chrome']) {
    if (!name) continue; try { await access(name); return name; } catch {}
  }
  return null;
}
const chrome = await binary();
const secret = 'local-fixture-control-key-' + randomUUID();

async function chromeFixture(t) {
  const temporary = await mkdtemp(path.join(os.tmpdir(), 'openagent-browser-advanced-'));
  const profile = path.join(temporary, 'profile');
  const child = spawn(chrome, ['--headless=new', '--no-first-run', '--no-default-browser-check', '--disable-background-networking', '--remote-debugging-port=0', '--site-per-process', `--user-data-dir=${profile}`, 'about:blank'], { stdio: 'ignore' });
  const closed = once(child, 'close');
  let endpoint, port;
  const deadline = Date.now() + 20000;
  while (Date.now() < deadline) {
    try { const [p, route] = (await readFile(path.join(profile, 'DevToolsActivePort'), 'utf8')).trim().split('\n'); port = Number(p); endpoint = `ws://127.0.0.1:${port}${route}`; break; }
    catch { if (child.exitCode != null) throw new Error('Test Chrome failed'); await delay(30); }
  }
  assert.ok(endpoint);
  const cdp = new CDPConnection(endpoint); await cdp.connect();
  t.after(async () => { try { await cdp.send('Browser.close'); } catch {} cdp.close(); child.kill('SIGTERM'); await Promise.race([closed, delay(2000)]); if (child.exitCode == null && child.signalCode == null) { child.kill('SIGKILL'); await closed; } await rm(temporary, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 }); });
  return { profile, port, endpoint, cdp, temporary };
}

async function fixture(t, { registry = false } = {}) {
  const browser = await chromeFixture(t);
  let other;
  if (registry) other = await chromeFixture(t);
  let frameOrigin;
  const payload = Buffer.from('fixture-download-content-é');
  const httpServer = http.createServer((request, response) => {
    response.setHeader('Content-Type','text/html');
    if (request.url === '/download') { response.writeHead(200, { 'Content-Type': 'application/octet-stream', 'Content-Disposition': 'attachment; filename="fixture.txt"' }); response.end(payload); return; }
    if (request.url === '/frame') { response.setHeader('Content-Type','text/html'); response.end('<label>Frame field<input id="frameField"></label><button onclick="document.body.dataset.clicked=\'yes\'">Frame action</button>'); return; }
    if (request.url === '/later') { response.end('<button onclick="document.body.dataset.clicked=\'yes\'">Late action</button>'); return; }
    if (request.url === '/race') { response.end('<p>Old document</p><script>setTimeout(()=>location.href="/later",100)</script>'); return; }
    response.end(`<!doctype html><title>Fixture</title><label>User name<input id="name"></label>
      <button id="go" onclick="document.body.dataset.clicked='yes'">Submit action</button>
      <button>Duplicate</button><button>Duplicate</button><label>Upload<input id="file" type="file" onchange="document.body.dataset.upload=this.files[0]?.name||''"></label>
      <input id="hiddenFile" type="file" style="display:none"><button id="chooser" onclick="document.querySelector('#hiddenFile').click()">Choose file</button>
      <a href="/download">Download fixture</a><iframe title="Foreign frame" src="${frameOrigin}/frame"></iframe>
      <script>setTimeout(()=>{const b=document.createElement('button');b.textContent='Delayed action';b.onclick=()=>document.body.dataset.delayed='yes';document.body.append(b)},250)</script>`);
  });
  httpServer.listen(0, '127.0.0.1'); await once(httpServer, 'listening');
  const httpPort = httpServer.address().port;
  // Different sites force the frame onto a distinct Chromium target.
  const frameServer = http.createServer((request, response) => {response.setHeader('Content-Type','text/html');response.end('<label>Frame field<input id="frameField"></label><button onclick="document.body.dataset.clicked=\'yes\'">Frame action</button>')});
  frameServer.listen(0); await once(frameServer, 'listening');
  frameOrigin = `http://localhost:${frameServer.address().port}`;
  t.after(async () => { httpServer.closeAllConnections(); frameServer.closeAllConnections(); await Promise.all([new Promise((r) => httpServer.close(r)), new Promise((r) => frameServer.close(r))]); });
  const origin = `http://127.0.0.1:${httpPort}`;
  const env = { ...process.env, OPENAGENT_CHROME_PROFILE_DIR: browser.profile, OPENAGENT_CHROME_CDP_PORT: String(browser.port), OPENAGENT_BROWSER_EXTERNAL: '1', OPENAGENT_BROWSER_CONTROL_SECRET: secret, OPENAGENT_BROWSER_UPLOAD_ROOTS: JSON.stringify([browser.temporary]) };
  if (other) env.OPENAGENT_BROWSER_TARGETS = JSON.stringify([{ id: 'secondary', profile_dir: other.profile, cdp_port: other.port, label: 'Second fixture', allow_downloads: true }]);
  const transport = new StdioClientTransport({ command: process.execPath, args: [fileURLToPath(new URL('./mcp-server.js', import.meta.url))], env, stderr: 'pipe' });
  let stderr = ''; transport.stderr?.on('data', (chunk) => { stderr += chunk; });
  const client = new Client({ name: 'advanced-browser-test', version: '1' });
  await client.connect(transport); t.after(() => client.close());
  async function call(name, args, options, meta) {
    const result = await client.callTool({ name, arguments: args, ...(meta ? { _meta: meta } : {}) }, undefined, options);
    if (result.isError) { const error = new Error(result.content?.[0]?.text || 'Browser tool failed'); error.code = result.structuredContent?.error?.code; error.details = result.structuredContent?.error; throw error; }
    return result.structuredContent || result.content?.[0]?.text;
  }
  const tab = await call('tabs_create_mcp', {});
  const tabId = Number(tab.match(/Tab ID: (\d+)/)[1]);
  await call('navigate', { tabId, url: origin + '/main' });
  return { ...browser, other, client, call, origin, frameOrigin, tabId, payload, stderr: () => stderr };
}

function proof(action, args) {
  const payload = { version: 1, action, browser_id: args.browser_id || 'dedicated', tab_id: args.tabId, request_id: args.request_id, nonce: randomUUID(), expires_at_ms: Date.now() + 30000, origin: args.origin ?? null, permissions: [...(args.permissions || [])].sort() };
  return { 'openagent/browser-approval': { payload, signature: createHmac('sha256', secret).update(canonicalJSON(payload)).digest('hex') } };
}


test('browser registry rejects arbitrary/duplicate identities and invalid upload policy', () => {
  assert.throws(() => configuredBrowserSlots({ OPENAGENT_BROWSER_TARGETS: '[{"id":"dedicated"}]' }), /invalid_browser_registry/);
  assert.throws(() => configuredBrowserSlots({ OPENAGENT_BROWSER_TARGETS: '[{"id":"other","profile_dir":"relative","cdp_port":9222}]' }), /invalid_browser_registry/);
  assert.throws(() => new AdvancedBrowser({}, { id: 'test' }, { uploadRoots: '["relative"]' }), /invalid_upload_roots/);
});


test('actual MCP semantic locators, bounded waits, cross-origin frames and document revocation', { skip: !chrome }, async (t) => {
  const f = await fixture(t);
  const listed = await f.client.listTools();
  for (const name of ['browser_capabilities','browser_frames','browser_locate','browser_action','browser_upload','browser_downloads','browser_file_chooser','browser_control','browser_permissions']) assert.ok(listed.tools.some((tool) => tool.name === name), name);
  const capabilities = await f.call('browser_capabilities', {});
  assert.equal(capabilities.browsers[0].cross_origin_frames, true);
  assert.ok(capabilities.browsers[0].unsupported_backends.includes('firefox'));
  const frames = await f.call('browser_frames', { tabId: f.tabId });
  assert.equal(frames.frames.length, 2);
  const foreign = frames.frames.find((frame) => frame.url.startsWith(f.frameOrigin));
  assert.ok(foreign, JSON.stringify(frames));
  await f.call('browser_action', { tabId: f.tabId, frame_ref: foreign.frame_ref, document_id: foreign.document_id, locator: { label: 'Frame field' }, action: 'fill', value: 'foreign value' });
  const located = await f.call('browser_locate', { tabId: f.tabId, frame_ref: foreign.frame_ref, locator: { role: 'button', name: 'Frame action' } });
  assert.equal(located.matches.length, 1);
  await f.call('browser_action', { tabId: f.tabId, frame_ref: foreign.frame_ref, element_ref: located.matches[0].element_ref, action: 'click' });
  await assert.rejects(f.call('browser_action', { tabId: f.tabId, locator: { role: 'button', name: 'Duplicate' }, action: 'click' }), (e) => e.code === 'multiple_matches');
  await f.call('browser_action', { tabId: f.tabId, locator: { role: 'button', name: 'Delayed action' }, action: 'click', timeout_ms: 3000 });
  const state = await f.call('javascript_tool', { tabId: f.tabId, action: 'javascript_exec', text: 'document.body.dataset.delayed' });
  assert.match(state, /yes/);
  await f.call('navigate', { tabId: f.tabId, url: f.origin + '/main' });
  await assert.rejects(f.call('browser_action', { tabId: f.tabId, frame_ref: foreign.frame_ref, element_ref: located.matches[0].element_ref, action: 'click' }), /frame|document/i);
  const missing = await f.call('browser_locate', { tabId: f.tabId, locator: { text: 'Never exists' }, wait_for: 'detached', timeout_ms: 100 });
  assert.equal(missing.matches.length, 0);
});


test('actual MCP uploads, file chooser, bounded download lifecycle and wrong target refusal', { skip: !chrome }, async (t) => {
  const f = await fixture(t);
  const file = { name: 'payload.txt', mime_type: 'text/plain', data_base64: Buffer.from('fixture upload').toString('base64') };
  await f.call('browser_upload', { tabId: f.tabId, locator: { label: 'Upload' }, files: [file] });
  assert.match(await f.call('javascript_tool', { tabId: f.tabId, action: 'javascript_exec', text: 'document.body.dataset.upload' }), /payload.txt/);
  const localPath = path.join(f.temporary, 'local.txt'); await writeFile(localPath, 'owned path');
  await f.call('browser_upload', { tabId: f.tabId, locator: { css: '#file' }, files: [{ path: localPath }] });
  await assert.rejects(f.call('browser_upload', { tabId: f.tabId, locator: { css: '#file' }, files: [{ path: '/etc/hosts' }] }), (e) => e.code === 'upload_path_not_allowed');
  const waiting = f.call('browser_file_chooser', { tabId: f.tabId, action: 'wait', timeout_ms: 3000 });
  await f.call('browser_action', { tabId: f.tabId, locator: { role: 'button', name: 'Choose file' }, action: 'click' });
  const chooser = (await waiting).choosers[0];
  assert.ok(chooser.chooser_id);
  await f.call('browser_file_chooser', { tabId: f.tabId, action: 'set', chooser_id: chooser.chooser_id, files: [file] });
  assert.match(await f.call('javascript_tool', { tabId: f.tabId, action: 'javascript_exec', text: 'document.querySelector("#hiddenFile").files[0].name' }), /payload.txt/);
  await assert.rejects(f.call('browser_file_chooser', { tabId: f.tabId, action: 'set', chooser_id: chooser.chooser_id, files: [file] }), /chooser/i);
  await f.call('browser_action', { tabId: f.tabId, locator: { role: 'link', name: 'Download fixture' }, action: 'click' });
  let download; const deadline = Date.now() + 5000;
  while (Date.now() < deadline) { const all = await f.call('browser_downloads', { tabId: f.tabId, action: 'list' }); download = all.downloads.find((item) => item.state === 'completed'); if (download) break; await delay(30); }
  assert.ok(download, f.stderr());
  const chunk = await f.call('browser_downloads', { tabId: f.tabId, action: 'read', download_id: download.download_id, max_bytes: 5 });
  assert.equal(Buffer.from(chunk.data_base64, 'base64').toString(), f.payload.subarray(0, 5).toString());
  const rest = await f.call('browser_downloads', { tabId: f.tabId, action: 'read', download_id: download.download_id, offset: 5 });
  assert.deepEqual(Buffer.concat([Buffer.from(chunk.data_base64, 'base64'), Buffer.from(rest.data_base64, 'base64')]), f.payload);
  assert.equal(rest.eof, true);
  const created = await f.call('tabs_create_mcp', {}); const otherTab = Number(created.match(/Tab ID: (\d+)/)[1]);
  await assert.rejects(f.call('browser_downloads', { tabId: otherTab, action: 'read', download_id: download.download_id }), (e) => e.code === 'wrong_download_target');
  await f.call('browser_downloads', { tabId: f.tabId, action: 'release', download_id: download.download_id });
  await assert.rejects(f.call('browser_downloads', { tabId: f.tabId, action: 'read', download_id: download.download_id }), /download/i);
});


test('actual MCP takeover/permissions require one-use host approval; explicit browser selection stays isolated', { skip: !chrome }, async (t) => {
  const f = await fixture(t, { registry: true });
  const capabilities = await f.call('browser_capabilities', {});
  assert.equal(capabilities.browsers.length, 2);
  const secondary = await f.call('browser_control', { browser_id: 'secondary', action: 'attach' });
  assert.ok(secondary.tabs.length);
  const main = (await f.call('browser_frames', { tabId: f.tabId })).frames.find((frame) => frame.parent_ref === null);
  await assert.rejects(f.call('browser_action', { browser_id: 'secondary', tabId: secondary.tabs[0].tabId, frame_ref: main.frame_ref, locator: { text: 'x' }, action: 'click' }), /frame/i);
  await assert.rejects(f.call('browser_control', { browser_id: 'unknown', action: 'attach' }), /browser_not_configured/);
  const secondTakeover = await f.call('browser_control', { browser_id:'secondary', tabId:secondary.tabs[0].tabId, action:'request_takeover' });
  const inventory = await f.call('browser_control', { action:'inventory' });
  assert.equal(inventory.browsers.length,2);
  assert.ok(inventory.pending_decisions.some(item=>item.request_id===secondTakeover.request_id && item.browser_id==='secondary'));

  const takeover = await f.call('browser_control', { tabId: f.tabId, action: 'request_takeover', reason: 'Synthetic human step' });
  assert.equal(takeover.requires_user_action, true);
  await assert.rejects(f.call('computer', { tabId: f.tabId, action: 'type', text: 'must not type' }), /human_control_active/);
  await assert.rejects(f.call('browser_action', { tabId: f.tabId, locator: { label: 'User name' }, action: 'fill', value: 'blocked' }), (e) => e.code === 'human_control_active');
  const resumeArgs = { tabId: f.tabId, action: 'resume', request_id: takeover.request_id };
  await assert.rejects(f.call('browser_control', resumeArgs), /approv/i);
  const signed = proof('resume', resumeArgs);
  assert.equal((await f.call('browser_control', resumeArgs, undefined, signed)).resumed, true);
  await assert.rejects(f.call('browser_control', resumeArgs, undefined, signed), /approv/i);
  const request = await f.call('browser_permissions', { tabId: f.tabId, action: 'request', origin: f.origin, permissions: ['geolocation'] });
  const grantArgs = { tabId: f.tabId, action: 'grant', origin: f.origin, permissions: ['geolocation'], request_id: request.request_id };
  await assert.rejects(f.call('browser_permissions', grantArgs), /approv/i);
  await f.call('browser_permissions', grantArgs, undefined, proof('grant', grantArgs));
  const granted = await f.call('browser_permissions', { tabId: f.tabId, action: 'query', permissions: ['geolocation'] });
  assert.equal(granted.permissions[0].state, 'granted');
  const revokeRequest = await f.call('browser_permissions', { tabId: f.tabId, action: 'request', origin: f.origin, permissions: ['geolocation'] });
  const revokeArgs = { ...grantArgs, action: 'revoke', request_id: revokeRequest.request_id };
  await f.call('browser_permissions', revokeArgs, undefined, proof('revoke', revokeArgs));
  const revoked = await f.call('browser_permissions', { tabId: f.tabId, action: 'query', permissions: ['geolocation'] });
  assert.equal(revoked.permissions[0].state, 'prompt');
  await assert.rejects(f.call('browser_permissions', { tabId: f.tabId, action: 'request', origin: f.frameOrigin, permissions: ['geolocation'] }), /origin/i);
});


test('actual MCP cancellation and navigation races never replay a locator mutation on a new document', { skip: !chrome }, async (t) => {
  const f = await fixture(t);
  const abort = new AbortController();
  const waiting = f.call('browser_action', { tabId: f.tabId, locator: { role: 'button', name: 'Never exists' }, action: 'click', timeout_ms: 10000 }, { signal: abort.signal });
  await delay(100); abort.abort(); await assert.rejects(waiting, /abort/i);
  // Give cancellation cleanup a chance to disconnect its own Playwright client.
  await delay(100);
  assert.ok((await f.call('browser_frames', { tabId: f.tabId })).frames.length);
  await f.call('browser_frames', { tabId: f.tabId });
  await f.call('javascript_tool', { tabId: f.tabId, action: 'javascript_exec', text: 'document.body.innerHTML="<p>Old document</p>";setTimeout(()=>location.href="/later",150)' });
  await assert.rejects(f.call('browser_action', { tabId: f.tabId, locator: { role: 'button', name: 'Late action' }, action: 'click', timeout_ms: 2000 }), (e) => e.code === 'stale_document');
  assert.match(await f.call('javascript_tool', { tabId: f.tabId, action: 'javascript_exec', text: 'document.body.dataset.clicked||"not-clicked"' }), /not-clicked/);
  const initial = await f.call('browser_locate', { tabId: f.tabId, locator: { role: 'button', name: 'Late action' } });
  await f.call('browser_control', { action: 'detach' });
  await assert.rejects(f.call('browser_action', { tabId: f.tabId, element_ref: initial.matches[0].element_ref, action: 'click' }), /stale|frame|reference/i);
  // Detach releases automation, preserving the exact supervised browser.
  assert.ok(await f.cdp.send('Browser.getVersion'));
});
