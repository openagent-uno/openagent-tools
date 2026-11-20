#!/usr/bin/env node
// A bounded DOM read, without a model, arbitrary scripts, clicks or form input.
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';
import { setTimeout as delay } from 'node:timers/promises';
import { CDP_PORT, ensureBrowser, closeDedicatedBrowser } from './browser.js';
import { CDPConnection } from './cdp.js';

function bounded(value, fallback, min, max, name) {
  const number = value ?? fallback;
  if (!Number.isInteger(number) || number < min || number > max) throw new Error(`Invalid ${name}`);
  return number;
}

export function validateRequest(input) {
  if (!input || !Array.isArray(input.pages) || input.pages.length < 1 || input.pages.length > 20) throw new Error('Expected 1-20 pages');
  const pages = input.pages.map((page) => {
    const url = new URL(page.url);
    if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password || url.hash) throw new Error('Pages require credential-free http(s) URLs');
    if (typeof page.selector !== 'string' || !page.selector || page.selector.length > 500) throw new Error('Invalid selector');
    const targets = page.targets ?? [];
    if (!Array.isArray(targets) || targets.length > 100 || targets.some(v => typeof v !== 'string' || !v || v.length > 256)) throw new Error('Invalid targets');
    return { url: url.href, selector: page.selector, targets };
  });
  const stopPathPrefixes = input.stopPathPrefixes ?? [];
  const stopSelectors = input.stopSelectors ?? [];
  if (!Array.isArray(stopPathPrefixes) || stopPathPrefixes.length > 20 || stopPathPrefixes.some(v => typeof v !== 'string' || !v.startsWith('/') || v.length > 128)) throw new Error('Invalid stopPathPrefixes');
  if (!Array.isArray(stopSelectors) || stopSelectors.length > 20 || stopSelectors.some(v => typeof v !== 'string' || !v || v.length > 256)) throw new Error('Invalid stopSelectors');
  return { pages, stopPathPrefixes, stopSelectors,
    pageTimeoutMs: bounded(input.pageTimeoutMs, 20000, 1000, 60000, 'pageTimeoutMs'),
    settleMs: bounded(input.settleMs, 1000, 100, 5000, 'settleMs'),
    maxScrolls: bounded(input.maxScrolls, 0, 0, 20, 'maxScrolls'),
    maxRows: bounded(input.maxRows, 500, 1, 1000, 'maxRows') };
}

// Runs only this fixed read in the page. The host supplies selectors and href
// substrings as data, never JavaScript. Hidden nodes and form values are excluded.
export function readDocument({ selector, stopSelectors, maxRows }) {
  const visible = element => element.getClientRects().length > 0 && getComputedStyle(element).visibility !== 'hidden' && getComputedStyle(element).display !== 'none';
  const blocked = stopSelectors.some(s => [...document.querySelectorAll(s)].some(visible));
  if (blocked) return { url: location.href, blocked: true, rows: [] };
  const rows = [...document.querySelectorAll(selector)].filter(visible).slice(0, maxRows).map(element => ({
    href: element.href || element.getAttribute('href') || '',
    text: String(element.innerText || '').trim().slice(0, 1000),
  }));
  return { url: location.href, blocked: false, rows };
}

export function pageState(snapshot, page, request) {
  const url = new URL(snapshot.url);
  if (request.stopPathPrefixes.some(prefix => url.pathname.startsWith(prefix)) || snapshot.blocked) return 'blocked';
  // A successful navigation command is not proof that the requested page loaded.
  if (url.href !== page.url) return url.href === 'about:blank' ? 'loading' : 'redirected';
  return 'ready';
}

export async function readPage(cdp, session, page, request, signal) {
  const started = Date.now(), rows = new Map();
  let scrolls = 0, lastChange = started, lastSignature = '', seenPage = false;
  const result = status => ({ requestedUrl: page.url, status, observedAt: new Date().toISOString(),
    durationMs: Date.now() - started, scrolls, rows: [...rows.values()] });
  // Do not wait for load/network-idle: media and long-lived requests need not
  // finish before a DOM counter exists. Every CDP request and page has a deadline.
  const navigated = await cdp.send('Page.navigate', { url: page.url }, session, { signal });
  if (navigated.errorText) return result('navigation_failed');
  while (Date.now() - started < request.pageTimeoutMs) {
    signal?.throwIfAborted();
    let snapshot;
    try {
      const evaluated = await cdp.send('Runtime.evaluate', { expression: `(${readDocument.toString()})(${JSON.stringify({ selector: page.selector, stopSelectors: request.stopSelectors, maxRows: request.maxRows })})`, returnByValue: true }, session, { signal });
      if (evaluated.exceptionDetails) return result('invalid_selector');
      snapshot = evaluated.result?.value;
      if (!snapshot) return result('read_failed');
    } catch (error) {
      if (signal?.aborted) throw error;
      // Navigation may replace the execution context between two commands.
      if (!/context.*(destroyed|not found)|Cannot find context/i.test(error.message)) throw error;
      await delay(100, undefined, { signal }); continue;
    }
    const state = pageState(snapshot, page, request);
    if (state === 'blocked') return { ...result('blocked'), rows: [] };
    if (state === 'redirected') return { ...result('redirected'), rows: [] };
    if (state === 'ready') {
      seenPage = true;
      for (const row of snapshot.rows) {
        if (rows.size >= request.maxRows && !rows.has(row.href + '\n' + row.text)) break;
        // Keep conflicting text as separate rows so the host can reject ambiguity.
        rows.set(row.href + '\n' + row.text, row);
      }
      const signature = JSON.stringify(snapshot.rows);
      if (signature !== lastSignature) { lastSignature = signature; lastChange = Date.now(); }
      const complete = page.targets.length ? page.targets.every(target => [...rows.values()].some(r => r.href.includes(target) && r.text)) : rows.size > 0;
      if (complete && Date.now() - lastChange >= request.settleMs) return result('ok');
      if (Date.now() - lastChange >= request.settleMs && scrolls < request.maxScrolls && snapshot.rows.length) {
        await cdp.send('Runtime.evaluate', { expression: 'window.scrollBy(0, Math.max(400, window.innerHeight * 0.8))' }, session, { signal });
        scrolls++; lastChange = Date.now();
      }
    }
    await delay(200, undefined, { signal });
  }
  return result(seenPage ? 'incomplete' : 'navigation_timeout');
}

export async function runRead(input) {
  const request = validateRequest(input), results = [];
  const controller = new AbortController();
  const abort = () => controller.abort(new Error('Browser read stopped'));
  const timer = setTimeout(abort, 30000 + request.pages.length * (request.pageTimeoutMs + 10000));
  const stopSignals = ['SIGTERM', 'SIGINT'];
  for (const name of stopSignals) process.on(name, abort);
  let launched, cdp;
  try {
    launched = await ensureBrowser({ port: CDP_PORT });
    controller.signal.throwIfAborted();
    cdp = new CDPConnection(launched.wsUrl, { requestTimeoutMs: 10000 });
    await cdp.connect();
    const target = await cdp.send('Target.createTarget', { url: 'about:blank' }, undefined, { signal: controller.signal });
    const { sessionId } = await cdp.send('Target.attachToTarget', { targetId: target.targetId, flatten: true }, undefined, { signal: controller.signal });
    await cdp.send('Page.enable', {}, sessionId, { signal: controller.signal });
    for (const page of request.pages) {
      // Reset between pages so a previous document cannot be read as the next one.
      await cdp.send('Page.navigate', { url: 'about:blank' }, sessionId, { signal: controller.signal });
      const result = await readPage(cdp, sessionId, page, request, controller.signal);
      results.push(result);
      if (['blocked', 'redirected'].includes(result.status)) break;
    }
    return { status: results.some(r => r.status === 'blocked') ? 'blocked' : 'completed', pages: results };
  } finally {
    clearTimeout(timer);
    for (const name of stopSignals) process.removeListener(name, abort);
    if (launched) await closeDedicatedBrowser(cdp, { ownsBrowser: launched.ownsBrowser, browserPid: launched.pid, port: CDP_PORT });
  }
}

export async function main(argv = process.argv.slice(2)) {
  if (argv.length !== 2 || argv[0] !== '--request-file') throw new Error('Use --request-file <writable JSON file>');
  const file = argv[1];
  if (fs.lstatSync(file).isSymbolicLink()) throw new Error('Request must not be a symbolic link');
  const fd = fs.openSync(file, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0));
  let text;
  try {
    if (fs.fstatSync(fd).size > 128 * 1024) throw new Error('Request exceeds 128 KiB');
    text = fs.readFileSync(fd, 'utf8');
  } finally { fs.closeSync(fd); }
  fs.unlinkSync(file);
  return runRead(JSON.parse(text));
}

if (process.argv[1] && fs.realpathSync(process.argv[1]) === fs.realpathSync(fileURLToPath(import.meta.url))) {
  main().then(result => { process.stdout.write(JSON.stringify(result) + '\n'); process.exit(0); })
    .catch(() => { process.stdout.write(JSON.stringify({ status: 'error', error: 'browser_read_failed' }) + '\n'); process.exit(1); });
}
