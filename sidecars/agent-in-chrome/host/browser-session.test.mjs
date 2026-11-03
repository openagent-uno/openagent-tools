import assert from 'node:assert/strict';
import test from 'node:test';
import http from 'node:http';
import { once } from 'node:events';
import { access, mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import WebSocket from 'ws';
import { authorized, inputCommands, parseArgs } from './browser-session.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const TOKEN = 'live-view-token-for-tests-0123456789abcdef';

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

test('arguments are bounded and only http(s) start pages are accepted', () => {
  assert.deepEqual(
    { ...parseArgs(['--url', 'https://example.com/login', '--listen', '0.0.0.0:9300', '--timeout', '600']) },
    { url: 'https://example.com/login', listen: '0.0.0.0:9300', timeout: 600, quality: 60, maxWidth: 1280, host: '0.0.0.0', port: 9300 },
  );
  assert.throws(() => parseArgs(['--url', 'file:///etc/passwd']), /http/);
  assert.throws(() => parseArgs(['--timeout', '5']), /timeout/);
  assert.throws(() => parseArgs(['--listen', 'nope']), /host:port/);
  assert.throws(() => parseArgs(['--quality', '100']), /quality/);
});

test('the live view requires the exact bearer token', () => {
  assert.equal(authorized(`Bearer ${TOKEN}`, TOKEN), true);
  assert.equal(authorized(`Bearer ${TOKEN}x`, TOKEN), false);
  assert.equal(authorized(undefined, TOKEN), false);
});

test('viewer input maps normalized coordinates and rejects unsafe messages', () => {
  const frame = { deviceWidth: 1000, deviceHeight: 500 };
  assert.deepEqual(inputCommands({ type: 'mouse', action: 'press', x: 0.5, y: 0.2 }, frame),
    [['Input.dispatchMouseEvent', { type: 'mousePressed', x: 500, y: 100, button: 'left', clickCount: 1 }]]);
  assert.deepEqual(inputCommands({ type: 'text', text: 'ciao' }, frame), [['Input.insertText', { text: 'ciao' }]]);
  assert.equal(inputCommands({ type: 'key', key: 'Enter' }, frame)[0][1].windowsVirtualKeyCode, 13);
  assert.throws(() => inputCommands({ type: 'mouse', action: 'press', x: 2, y: 0 }, frame), /0-1/);
  assert.throws(() => inputCommands({ type: 'navigate', url: 'javascript:alert(1)' }, frame), /http/);
  assert.throws(() => inputCommands({ type: 'key', key: 'F13' }, frame), /special key/);
  assert.throws(() => inputCommands({ type: 'eval', code: '1' }, frame), /unsupported/);
});

test('real Chromium session streams frames, accepts input and exits cleanly on done', { skip: !binary, timeout: 90000 }, async (t) => {
  const site = http.createServer((request, response) => {
    response.writeHead(200, { 'Content-Type': 'text/html' });
    response.end(request.url === '/next'
      ? '<title>Next</title><h1>second page</h1>'
      : '<title>Start</title><input id=q autofocus><a href="/next" style="display:block;width:100vw;height:100vh">go</a>');
  });
  site.listen(0, '127.0.0.1'); await once(site, 'listening'); t.after(() => site.close());
  const origin = `http://127.0.0.1:${site.address().port}`;
  const profile = await mkdtemp(path.join(tmpdir(), 'oa-session-'));
  t.after(() => rm(profile, { recursive: true, force: true }));
  const livePort = 20000 + Math.floor(Math.random() * 20000);
  const child = spawn(process.execPath, [path.join(here, 'browser-session.js'), '--url', `${origin}/`, '--listen', `127.0.0.1:${livePort}`, '--timeout', '60'], {
    env: { ...process.env, OPENAGENT_BROWSER_LIVE_TOKEN: TOKEN, OPENAGENT_CHROME_PROFILE_DIR: profile,
      OPENAGENT_CHROME_BINARY: binary, OPENAGENT_CHROME_CDP_PORT: String(livePort + 1), OPENAGENT_CHROME_HEADLESS: 'true' },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let stdout = ''; child.stdout.on('data', (c) => (stdout += c));
  t.after(() => { if (child.exitCode === null) child.kill('SIGKILL'); });

  let socket;
  for (let attempt = 0; attempt < 60 && !socket; attempt += 1) {
    await new Promise((r) => setTimeout(r, 500));
    try {
      const candidate = new WebSocket(`ws://127.0.0.1:${livePort}/live`, { headers: { Authorization: `Bearer ${TOKEN}` } });
      await once(candidate, 'open'); socket = candidate;
    } catch {}
  }
  assert.ok(socket, 'live view did not come up');
  const rejected = new WebSocket(`ws://127.0.0.1:${livePort}/live`, { headers: { Authorization: 'Bearer wrong' } });
  await assert.rejects(once(rejected, 'open'), /401/);

  const messages = [];
  let frames = 0, firstFrame = null;
  socket.on('message', (raw, isBinary) => {
    if (isBinary) { frames += 1; firstFrame ??= raw; return; }
    messages.push(JSON.parse(raw.toString()));
  });
  const waitFor = async (predicate, label) => {
    for (let i = 0; i < 100; i += 1) { const found = messages.find(predicate); if (found) return found; await new Promise((r) => setTimeout(r, 100)); }
    throw new Error(`timed out waiting for ${label}`);
  };
  for (let i = 0; i < 100 && !firstFrame; i += 1) await new Promise((r) => setTimeout(r, 100));
  assert.ok(firstFrame && firstFrame.subarray(0, 2).equals(Buffer.from([0xff, 0xd8])), 'binary JPEG frame');
  // Flow control: the click changes the page, but no new frame arrives before frame_ack.
  const before = frames;
  socket.send(JSON.stringify({ type: 'mouse', action: 'press', x: 0.5, y: 0.6 }));
  socket.send(JSON.stringify({ type: 'mouse', action: 'release', x: 0.5, y: 0.6 }));
  await waitFor((m) => m.type === 'page' && m.url.endsWith('/next'), 'navigation after click');
  await new Promise((r) => setTimeout(r, 800));
  assert.equal(frames, before, 'frames must wait for frame_ack');
  socket.send(JSON.stringify({ type: 'frame_ack' }));
  for (let i = 0; i < 50 && frames === before; i += 1) await new Promise((r) => setTimeout(r, 100));
  assert.equal(frames, before + 1, 'ack releases exactly the latest frame');
  socket.send(JSON.stringify({ type: 'navigate', url: 'javascript:alert(1)' }));
  await waitFor((m) => m.type === 'error', 'rejected navigation');
  socket.send(JSON.stringify({ type: 'done' }));
  const [code] = await once(child, 'exit');
  assert.equal(code, 0);
  assert.deepEqual(JSON.parse(stdout.trim().split('\n').pop()), { status: 'done' });
});

test('a foreign host lock is cleared only when the host declares exclusive ownership', async (t) => {
  const { clearForeignProfileLock } = await import('./browser.js');
  const { symlink, readlink } = await import('node:fs/promises');
  const profile = await mkdtemp(path.join(tmpdir(), 'oa-lock-'));
  t.after(() => rm(profile, { recursive: true, force: true }));
  await symlink('old-pod-host-31', path.join(profile, 'SingletonLock'));
  await symlink('/tmp/x/SingletonSocket', path.join(profile, 'SingletonSocket'));
  delete process.env.OPENAGENT_CHROME_PROFILE_EXCLUSIVE;
  assert.equal(clearForeignProfileLock(profile, 'new-pod-host'), false);
  assert.equal(await readlink(path.join(profile, 'SingletonLock')), 'old-pod-host-31');
  process.env.OPENAGENT_CHROME_PROFILE_EXCLUSIVE = '1';
  t.after(() => { delete process.env.OPENAGENT_CHROME_PROFILE_EXCLUSIVE; });
  assert.equal(clearForeignProfileLock(profile, 'old-pod-host'), false, 'own host lock is left to Chromium');
  assert.equal(clearForeignProfileLock(profile, 'new-pod-host'), true);
  await assert.rejects(readlink(path.join(profile, 'SingletonLock')));
  await assert.rejects(readlink(path.join(profile, 'SingletonSocket')));
});

test('done leaves no profile lock behind and a second session reuses the profile', { skip: !binary, timeout: 120000 }, async (t) => {
  const profile = await mkdtemp(path.join(tmpdir(), 'oa-reuse-'));
  t.after(() => rm(profile, { recursive: true, force: true }));
  const { readlink } = await import('node:fs/promises');
  for (let round = 0; round < 2; round += 1) {
    const livePort = 20000 + Math.floor(Math.random() * 20000);
    const child = spawn(process.execPath, [path.join(here, 'browser-session.js'), '--url', 'about:blank', '--listen', `127.0.0.1:${livePort}`, '--timeout', '60'], {
      env: { ...process.env, OPENAGENT_BROWSER_LIVE_TOKEN: TOKEN, OPENAGENT_CHROME_PROFILE_DIR: profile, OPENAGENT_CHROME_BINARY: binary,
        OPENAGENT_CHROME_CDP_PORT: String(livePort + 1), OPENAGENT_CHROME_HEADLESS: 'true' }, stdio: ['ignore', 'pipe', 'pipe'] });
    t.after(() => { if (child.exitCode === null) child.kill('SIGKILL'); });
    let socket;
    for (let attempt = 0; attempt < 60 && !socket; attempt += 1) {
      await new Promise((r) => setTimeout(r, 500));
      try { const c = new WebSocket(`ws://127.0.0.1:${livePort}/live`, { headers: { Authorization: `Bearer ${TOKEN}` } }); await once(c, 'open'); socket = c; } catch {}
    }
    assert.ok(socket, `round ${round}: live view did not come up`);
    socket.send(JSON.stringify({ type: 'done' }));
    const [code] = await once(child, 'exit');
    assert.equal(code, 0);
    await assert.rejects(readlink(path.join(profile, 'SingletonLock')), `round ${round}: lock left behind`);
  }
});
