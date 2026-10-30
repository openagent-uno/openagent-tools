import { chromium } from 'playwright-core';
import { createHmac, randomUUID, timingSafeEqual } from 'node:crypto';
import { mkdtemp, mkdir, readFile, realpath, open, stat, unlink, rm } from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { setTimeout as delay } from 'node:timers/promises';

export const MAX_FILE_BYTES = 32 * 1024 * 1024;
const TTL = 120_000;
const MAX_REFS = 512;
const MAX_DOWNLOADS = 32;
const PERMISSIONS = ['geolocation', 'notifications', 'camera', 'microphone', 'clipboard-read', 'clipboard-write'];

export class BrowserOperationError extends Error {
  constructor(code, message, details = {}) { super(message); this.code = code; this.details = details; }
}
const fail = (code, message, details) => { throw new BrowserOperationError(code, message, details); };
export function canonicalJSON(value) {
  if (Array.isArray(value)) return '[' + value.map(canonicalJSON).join(',') + ']';
  if (value && typeof value === 'object') return '{' + Object.keys(value).sort().map((k) => JSON.stringify(k) + ':' + canonicalJSON(value[k])).join(',') + '}';
  return JSON.stringify(value);
}

export function configuredBrowserSlots(env = process.env) {
  const slots = [{ id: 'dedicated', label: 'Dedicated Chromium profile', backend: 'chromium-cdp', allow_downloads: true }];
  const extra = JSON.parse(env.OPENAGENT_BROWSER_TARGETS || '[]');
  if (!Array.isArray(extra) || extra.length > 8) throw new Error('invalid_browser_registry');
  for (const item of extra) {
    if (!item || !/^[a-z][a-z0-9_-]{0,63}$/.test(item.id) || slots.some((s) => s.id === item.id) ||
        typeof item.profile_dir !== 'string' || !path.isAbsolute(item.profile_dir) ||
        !Number.isInteger(item.cdp_port) || item.cdp_port < 1 || item.cdp_port > 65535) throw new Error('invalid_browser_registry');
    slots.push({ id: item.id, label: String(item.label || item.id).slice(0, 120), backend: 'chromium-cdp',
      profile_dir: item.profile_dir, cdp_port: item.cdp_port, external: true, allow_downloads: item.allow_downloads === true });
  }
  return slots;
}

export function jsonToZod(schema, z) {
  let result;
  if (schema.enum) result = z.enum(schema.enum);
  else if (schema.type === 'object') {
    const required = new Set(schema.required || []);
    const shape = Object.fromEntries(Object.entries(schema.properties || {}).map(([k, s]) => {
      const type = jsonToZod(s, z); return [k, required.has(k) ? type : type.optional()];
    }));
    result = z.object(shape);
    if (schema.additionalProperties === false) result = result.strict();
  } else if (schema.type === 'array') {
    result = z.array(jsonToZod(schema.items, z));
    if (schema.minItems !== undefined) result = result.min(schema.minItems);
    if (schema.maxItems !== undefined) result = result.max(schema.maxItems);
    if (schema.uniqueItems) result = result.refine((items) => new Set(items).size === items.length, 'items must be unique');
  } else if (schema.type === 'integer' || schema.type === 'number') {
    result = z.number().finite();
    if (schema.type === 'integer') result = result.int();
    if (schema.minimum !== undefined) result = result.min(schema.minimum);
    if (schema.maximum !== undefined) result = result.max(schema.maximum);
  } else if (schema.type === 'boolean') result = z.boolean();
  else {
    result = z.string();
    if (schema.minLength !== undefined) result = result.min(schema.minLength);
    if (schema.maxLength !== undefined) result = result.max(schema.maxLength);
  }
  return result;
}

export class AdvancedBrowser {
  constructor(controller, slot, { secret = process.env.OPENAGENT_BROWSER_CONTROL_SECRET, uploadRoots = process.env.OPENAGENT_BROWSER_UPLOAD_ROOTS } = {}) {
    this.controller = controller; this.slot = slot; this.secret = secret;
    this.uploadRoots = JSON.parse(uploadRoots || '[]');
    if (!Array.isArray(this.uploadRoots) || this.uploadRoots.some((p) => typeof p !== 'string' || !path.isAbsolute(p))) throw new Error('invalid_upload_roots');
    this.browser = null; this.connecting = null; this.connection = null;
    this.pages = new Map(); this.frames = new Map(); this.currentFrames = new WeakMap(); this.elements = new Map();
    this.downloads = new Map(); this.choosers = new Map(); this.requests = new Map(); this.usedApprovals = new Map();
    this.artifacts = null; this.artifactDirs = new Set(); this.offProgress = []; this.downloadGuids = new Set(); this.downloadFrames = new Set();
  }

  support() {
    return { browser_id: this.slot.id, backend: this.slot.backend, availability: this.controller.cdp && !this.controller.cdp.closed ? 'connected' : 'not_probed', semantic_locators: true,
      bounded_waits: true, cross_origin_frames: true, file_upload_payloads: true,
      file_upload_paths: this.uploadRoots.length > 0, downloads: this.slot.allow_downloads,
      file_chooser: true, takeover: true, signed_host_decisions: Boolean(this.secret),
      permission_query: true, provider_credential_storage: false, openai_service_required: false,
      unsupported_backends: ['safari', 'webkit', 'firefox'], human_control: Boolean(this.controller.humanControl),
      limits: { timeout_ms: 30000, file_bytes: MAX_FILE_BYTES, files_per_upload: 10, download_count: MAX_DOWNLOADS, element_refs: MAX_REFS } };
  }

  assertAutomated() {
    if (this.controller.humanControl) fail('human_control_active', 'Automation is paused for human control.', { request_id: this.controller.humanControl.request_id, requires_user_action: true });
  }

  async ensure(signal) {
    signal?.throwIfAborted(); this.assertAutomated();
    await this.controller.ensure();
    if (this.browser?.isConnected() && this.connection === this.controller.cdp) return;
    if (this.connecting) return this.connecting;
    this.connecting = (async () => {
      await this.disconnect();
      this.artifacts = await mkdtemp(path.join(os.tmpdir(), 'openagent-browser-artifacts-'));
      this.artifactDirs.add(this.artifacts);
      const connection = this.controller.cdp;
      const browser = await chromium.connectOverCDP(connection.wsUrl, { timeout: 15000, noDefaults: !this.slot.allow_downloads, artifactsDir: this.artifacts, isLocal: true });
      if (this.controller.cdp !== connection) { await browser.close(); fail('browser_replaced', 'Browser connection changed during attachment.'); }
      this.browser = browser; this.connection = connection;
      browser.on('disconnected', () => { if (this.browser === browser) { this.browser = null; this.invalidate(); } });
      this.offProgress.push(connection.on('Browser.downloadWillBegin', (event) => {
        if (this.downloadFrames.has(event.frameId)) this.downloadGuids.add(event.guid);
      }));
      this.offProgress.push(connection.on('Browser.downloadProgress', (event) => {
        if (this.downloadGuids.has(event.guid) && (event.receivedBytes > MAX_FILE_BYTES || event.totalBytes > MAX_FILE_BYTES)) {
          void connection.send('Browser.cancelDownload', { guid: event.guid }).catch(() => {});
        }
        if (event.state === 'completed' || event.state === 'canceled') this.downloadGuids.delete(event.guid);
      }));
    })();
    try { await this.connecting; } finally { this.connecting = null; }
    signal?.throwIfAborted();
  }

  invalidate() {
    for (const item of this.elements.values()) void item.handle.dispose().catch(() => {});
    this.elements.clear(); this.frames.clear(); this.currentFrames = new WeakMap(); this.pages.clear(); this.choosers.clear(); this.downloadFrames.clear();
  }

  async disconnect() {
    const browser = this.browser; this.browser = null; this.connection = null;
    this.invalidate(); for (const off of this.offProgress.splice(0)) off();
    // connectOverCDP's close path disconnects its own transport, not Chrome.
    if (browser) await browser.close().catch(() => {});
  }

  async close() {
    for (const record of this.downloads.values()) if (record.state === 'downloading') await record.download.cancel().catch(() => {});
    await this.disconnect();
    this.downloads.clear(); this.requests.clear(); this.usedApprovals.clear();
    for (const directory of this.artifactDirs) await rm(directory, { recursive: true, force: true });
    this.artifactDirs.clear();
    this.artifacts = null;
  }

  async abortable(operation, signal) {
    signal?.throwIfAborted();
    let off;
    const cancelled = new Promise((_, reject) => {
      off = () => { void this.disconnect().finally(() => reject(signal?.reason || new DOMException('Browser action cancelled; dispatched outcome may be unknown', 'AbortError'))); };
      signal?.addEventListener('abort', off, { once: true });
    });
    let timer;
    const timed = new Promise((_, reject) => { timer = setTimeout(() => { void this.disconnect().finally(() => reject(new BrowserOperationError('browser_timeout', 'Browser operation exceeded its 30 second deadline; dispatched outcome may be unknown.'))); }, 30000); });
    try { return await Promise.race([operation(), cancelled, timed]); }
    finally { clearTimeout(timer); signal?.removeEventListener('abort', off); }
  }

  async page(tabId, signal) {
    await this.ensure(signal);
    const target = this.controller.targetForTab(tabId);
    if (!target) fail('tab_not_found', 'Exact tab is unavailable; list tabs again.');
    let record = this.pages.get(target);
    const deadline = Date.now() + 5000;
    while (!record && Date.now() < deadline) {
      for (const context of this.browser.contexts()) for (const page of context.pages()) {
        const session = await context.newCDPSession(page);
        let info; try { info = await session.send('Target.getTargetInfo'); } finally { await session.detach(); }
        if (info.targetInfo.targetId !== target) continue;
        record = { page, tabId, target, contextId: info.targetInfo.browserContextId };
        this.pages.set(target, record);
        page.on('framenavigated', (frame) => { this.currentFrames.delete(frame); if (frame === page.mainFrame()) for (const [id, request] of this.requests) if (request.tab_id === tabId && request.action !== 'resume') this.requests.delete(id); });
        page.on('framedetached', (frame) => { this.currentFrames.delete(frame); });
        page.on('filechooser', (chooser) => { void this.recordChooser(record, chooser).catch(() => {}); });
        page.on('download', (download) => { void this.recordDownload(record, download).catch(() => {}); });
        page.on('close', () => { this.pages.delete(target); });
        const tree = await this.controller.cdp.send('Page.getFrameTree', {}, (await this.controller.ensureAttached(tabId)).sessionId);
        const add = (node) => { this.downloadFrames.add(node.frame.id); for (const child of node.childFrames || []) add(child); };
        add(tree.frameTree);
        break;
      }
      if (!record) { signal?.throwIfAborted(); await delay(25, undefined, { signal }); }
    }
    if (!record || record.page.isClosed()) fail('tab_not_found', 'Exact tab is no longer available.');
    signal?.throwIfAborted(); return record;
  }

  frameRecord(frame, pageRecord) {
    let record = this.currentFrames.get(frame);
    if (!record) {
      record = { frame, pageRecord, frame_ref: 'frame_' + randomUUID(), document_id: 'document_' + randomUUID(), created: Date.now() };
      this.currentFrames.set(frame, record); this.frames.set(record.frame_ref, record);
      while (this.frames.size > MAX_REFS) this.frames.delete(this.frames.keys().next().value);
    }
    return record;
  }
  validFrame(record) {
    if (!record || record.frame.isDetached() || record.frame.page().isClosed() || this.currentFrames.get(record.frame) !== record) fail('stale_document', 'Frame/document changed; call browser_frames again.');
  }
  async resolveFrame(args, signal) {
    const page = await this.page(args.tabId, signal);
    const frame = args.frame_ref ? this.frames.get(args.frame_ref) : this.frameRecord(page.page.mainFrame(), page);
    if (!frame || frame.pageRecord.target !== page.target) fail('wrong_frame_target', 'Frame handle belongs to another tab or browser.');
    this.validFrame(frame);
    if (args.document_id && args.document_id !== frame.document_id) fail('stale_document', 'Document handle does not match the selected frame.');
    return frame;
  }

  locator(frame, spec) {
    if (!spec || typeof spec !== 'object') fail('invalid_locator', 'One locator strategy is required.');
    const keys = ['role', 'text', 'label', 'placeholder', 'test_id', 'css'].filter((k) => spec[k] !== undefined);
    if (keys.length !== 1 || typeof spec[keys[0]] !== 'string' || !spec[keys[0]].trim() || (spec.name !== undefined && keys[0] !== 'role')) fail('invalid_locator', 'Use exactly one role/text/label/placeholder/test_id/css strategy; name is only valid with role.');
    const exact = spec.exact ?? true;
    switch (keys[0]) {
      case 'role': return frame.getByRole(spec.role, { name: spec.name, exact });
      case 'text': return frame.getByText(spec.text, { exact });
      case 'label': return frame.getByLabel(spec.label, { exact });
      case 'placeholder': return frame.getByPlaceholder(spec.placeholder, { exact });
      case 'test_id': return frame.getByTestId(spec.test_id);
      case 'css': if (spec.css.includes('>>')) fail('invalid_locator', 'CSS locator cannot contain selector-engine chaining.'); return frame.locator('css=' + spec.css);
    }
  }

  async locate(args, signal) {
    const frame = await this.resolveFrame(args, signal);
    const locator = this.locator(frame.frame, args.locator);
    const state = args.wait_for || 'visible';
    // waitFor is strict; fail on ambiguity rather than silently selecting nth(0).
    await this.abortable(() => locator.waitFor({ state, timeout: args.timeout_ms ?? 5000 }), signal);
    this.validFrame(frame);
    if (state === 'hidden' || state === 'detached') return { frame_ref: frame.frame_ref, document_id: frame.document_id, matches: [] };
    const count = await locator.count();
    if (count > 50) fail('too_many_matches', 'Narrow the locator before creating element references.', { count });
    const handles = await locator.elementHandles();
    this.validFrame(frame);
    const matches = [];
    for (const handle of handles) {
      const ref = 'element_' + randomUUID();
      const info = await handle.evaluate((el) => ({ tag: el.tagName.toLowerCase(), text: (el.innerText || el.textContent || '').slice(0, 300), enabled: !el.matches(':disabled'), visible: Boolean(el.getClientRects().length) }));
      this.elements.set(ref, { handle, frame, expires: Date.now() + TTL });
      matches.push({ element_ref: ref, ...info });
    }
    this.prune();
    return { frame_ref: frame.frame_ref, document_id: frame.document_id, matches };
  }

  prune() {
    const now = Date.now();
    for (const [id, record] of this.elements) if (record.expires < now || this.elements.size > MAX_REFS) { this.elements.delete(id); void record.handle.dispose().catch(() => {}); }
    for (const [id, record] of this.requests) if (record.expires < now) this.requests.delete(id);
    for (const [id, expiry] of this.usedApprovals) if (expiry < now) this.usedApprovals.delete(id);
  }

  async element(args, signal) {
    this.prune();
    if (Boolean(args.element_ref) === Boolean(args.locator)) fail('invalid_element_target', 'Supply exactly one element_ref or locator.');
    const frame = await this.resolveFrame(args, signal);
    let record;
    if (args.element_ref) record = this.elements.get(args.element_ref);
    else {
      const located = await this.locate(args, signal);
      if (located.matches.length !== 1) fail('multiple_matches', 'Action requires exactly one matching element.', { count: located.matches.length });
      record = this.elements.get(located.matches[0].element_ref);
    }
    if (!record || record.frame !== frame) fail('wrong_element_target', 'Element reference is stale or belongs to another frame/tab/browser.');
    this.validFrame(frame);
    if (!(await record.handle.evaluate((el) => el.isConnected))) fail('detached_element', 'Element was detached; locate it again.');
    return record;
  }

  async action(args, signal) {
    this.assertAutomated(); const record = await this.element(args, signal);
    const timeout = args.timeout_ms ?? 5000;
    const operation = async () => {
      this.validFrame(record.frame); signal?.throwIfAborted();
      switch (args.action) {
        case 'click': await record.handle.click({ timeout }); break;
        case 'fill': if (args.value === undefined) fail('invalid_value', 'fill requires value.'); await record.handle.fill(args.value, { timeout }); break;
        case 'check': await record.handle.check({ timeout }); break;
        case 'uncheck': await record.handle.uncheck({ timeout }); break;
        case 'select': if (args.value === undefined) fail('invalid_value', 'select requires value.'); await record.handle.selectOption({ value: args.value }, { timeout }); break;
        case 'press': if (!args.key) fail('invalid_key', 'press requires key.'); await record.handle.press(args.key, { timeout }); break;
        case 'hover': await record.handle.hover({ timeout }); break;
        case 'focus': await record.handle.focus(); break;
        case 'scroll': await record.handle.scrollIntoViewIfNeeded({ timeout }); break;
        default: fail('unknown_browser_action', 'Unknown browser action.');
      }
    };
    await this.abortable(operation, signal);
    return { ok: true, action: args.action, frame_ref: record.frame.frame_ref, document_id: record.frame.document_id, requires_fresh_observation: true };
  }

  async files(specs) {
    if (!Array.isArray(specs) || specs.length > 10) fail('invalid_files', 'files must contain at most 10 items.');
    let total = 0; const files = [];
    const roots = await Promise.all(this.uploadRoots.map((root) => realpath(root)));
    for (const spec of specs) {
      if (!spec || Boolean(spec.path) === (spec.data_base64 !== undefined)) fail('invalid_file', 'Each file requires exactly one path or data_base64.');
      let buffer; let name = spec.name;
      if (spec.path) {
        if (!path.isAbsolute(spec.path)) fail('upload_path_not_allowed', 'Upload path must be absolute.');
        const resolved = await realpath(spec.path);
        if (!roots.some((root) => resolved === root || resolved.startsWith(root + path.sep))) fail('upload_path_not_allowed', 'Upload path is outside host-configured roots.');
        const handle = await open(resolved, 'r');
        try {
          const info = await handle.stat(); if (!info.isFile() || info.size > MAX_FILE_BYTES) fail('invalid_file', 'Upload requires a bounded regular file.');
          const bytes = Buffer.alloc(Math.min(info.size + 1, MAX_FILE_BYTES + 1));
          let length = 0;
          while (length < bytes.length) { const result = await handle.read(bytes, length, bytes.length - length, null); if (!result.bytesRead) break; length += result.bytesRead; }
          if (length > info.size) fail('file_changed', 'Upload file grew while being read; retry from a fresh file observation.');
          buffer = bytes.subarray(0, length);
        }
        finally { await handle.close(); }
        name ||= path.basename(resolved);
      } else {
        if (typeof spec.data_base64 !== 'string' || spec.data_base64.length > Math.ceil(MAX_FILE_BYTES / 3) * 4 || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(spec.data_base64)) fail('invalid_file', 'Invalid or oversized base64 file payload.');
        buffer = Buffer.from(spec.data_base64, 'base64');
      }
      if (!name || name === '.' || name === '..' || /[\\/\0]/.test(name)) fail('invalid_filename', 'A plain nonempty file name is required.');
      total += buffer.length; if (total > MAX_FILE_BYTES) fail('file_limit', 'Upload exceeds 32 MiB total.');
      files.push({ name, mimeType: spec.mime_type || 'application/octet-stream', buffer });
    }
    return files;
  }
  async upload(args, signal) {
    const files = await this.files(args.files); const record = await this.element(args, signal);
    await this.abortable(() => record.handle.setInputFiles(files, { timeout: args.timeout_ms ?? 5000 }), signal);
    return { ok: true, files: files.map((f) => ({ name: f.name, bytes: f.buffer.length })) };
  }

  async recordChooser(page, chooser) {
    try {
      if (this.pages.get(page.target) !== page || !this.browser?.isConnected()) return;
      const frame = await chooser.element().ownerFrame();
      const record = { chooser, page, frame: this.frameRecord(frame, page), chooser_id: 'chooser_' + randomUUID(), expires: Date.now() + TTL, multiple: chooser.isMultiple() };
      this.choosers.set(record.chooser_id, record);
      while (this.choosers.size > 32) this.choosers.delete(this.choosers.keys().next().value);
    } catch {}
  }
  async chooser(args, signal) {
    const page = await this.page(args.tabId, signal);
    const list = () => [...this.choosers.values()].filter((r) => r.page.target === page.target && r.expires >= Date.now() && this.currentFrames.get(r.frame.frame) === r.frame)
      .map((r) => ({ chooser_id: r.chooser_id, multiple: r.multiple, frame_ref: r.frame.frame_ref, document_id: r.frame.document_id }));
    if (args.action === 'wait') {
      const deadline = Date.now() + (args.timeout_ms ?? 5000);
      while (!list().length && Date.now() < deadline) { signal?.throwIfAborted(); await delay(25, undefined, { signal }); }
      if (!list().length) fail('chooser_timeout', 'No file chooser opened before the deadline.');
    }
    if (args.action === 'list' || args.action === 'wait') return { choosers: list() };
    const record = this.choosers.get(args.chooser_id);
    if (!record || record.page.target !== page.target || record.expires < Date.now()) fail('wrong_chooser_target', 'File chooser is expired or belongs to another tab/browser.');
    this.validFrame(record.frame); this.choosers.delete(record.chooser_id);
    const files = args.action === 'cancel' ? [] : await this.files(args.files);
    if (!record.multiple && files.length > 1) fail('invalid_files', 'This chooser accepts one file.');
    await this.abortable(() => record.chooser.setFiles(files, { timeout: args.timeout_ms ?? 5000 }), signal);
    return { ok: true, chooser_id: record.chooser_id, action: args.action, files: files.map((f) => ({ name: f.name, bytes: f.buffer.length })) };
  }

  async recordDownload(page, download) {
    if (this.pages.get(page.target) !== page || !this.browser?.isConnected()) return;
    if (!this.slot.allow_downloads) { await download.cancel().catch(() => {}); return; }
    if (this.downloads.size >= MAX_DOWNLOADS) { await download.cancel().catch(() => {}); return; }
    const id = 'download_' + randomUUID();
    const record = { download, page, download_id: id, filename: download.suggestedFilename(), url: download.url(), state: 'downloading', bytes: 0,
      file: path.join(this.artifacts, id), created: Date.now() };
    let finished; record.done = new Promise((resolve) => { finished = resolve; });
    this.downloads.set(id, record);
    try {
      await download.saveAs(record.file);
      const info = await stat(record.file);
      if (info.size > MAX_FILE_BYTES) { await unlink(record.file); fail('file_limit', 'Download exceeds 32 MiB.'); }
      record.bytes = info.size; record.state = 'completed';
    } catch (error) { record.state = record.state === 'cancelled' ? 'cancelled' : 'failed'; record.error = String(error.message || error).slice(0, 300); }
    finally { finished(); }
  }
  async download(args, signal) {
    await this.page(args.tabId, signal);
    const view = (r) => ({ download_id: r.download_id, tabId: r.page.tabId, filename: r.filename, url: r.url, state: r.state, bytes: r.bytes, error: r.error });
    if (args.action === 'list') return { downloads: [...this.downloads.values()].filter((r) => r.page.tabId === args.tabId).map(view) };
    const record = this.downloads.get(args.download_id);
    if (!record || record.page.tabId !== args.tabId) fail('wrong_download_target', 'Download belongs to another tab/browser or was released.');
    if (args.action === 'status') return view(record);
    if (args.action === 'cancel') { if (record.state === 'completed') return view(record); await record.download.cancel(); record.state = 'cancelled'; return view(record); }
    if (args.action === 'release') {
      if (record.state === 'downloading') await record.download.cancel();
      let timer;
      try { await Promise.race([record.done, new Promise((_, reject) => { timer = setTimeout(() => reject(new BrowserOperationError('download_drain_timeout', 'Download is still draining; retry release after observing its status.')), 5000); })]); } finally { clearTimeout(timer); }
      await unlink(record.file).catch((e) => { if (e.code !== 'ENOENT') throw e; });
      this.downloads.delete(record.download_id); return { released: true, download_id: record.download_id };
    }
    if (record.state !== 'completed') fail('download_not_complete', 'Download is not complete.', view(record));
    const offset = args.offset ?? 0; const maximum = args.max_bytes ?? 65536;
    const file = await open(record.file, 'r');
    try {
      const buffer = Buffer.alloc(Math.min(maximum, Math.max(0, record.bytes - offset)));
      const { bytesRead } = await file.read(buffer, 0, buffer.length, offset);
      return { ...view(record), offset, data_base64: buffer.subarray(0, bytesRead).toString('base64'), next_offset: offset + bytesRead, eof: offset + bytesRead >= record.bytes };
    } finally { await file.close(); }
  }

  pending(action, args) {
    this.prune();
    if (this.requests.size >= 128) fail('request_limit', 'Too many pending browser decisions.');
    const request = { request_id: 'request_' + randomUUID(), action, browser_id: this.slot.id, tab_id: args.tabId,
      origin: args.origin ?? null, permissions: [...(args.permissions || [])].sort(), expires: Date.now() + (action === 'resume' ? 24 * 60 * 60 * 1000 : TTL) };
    this.requests.set(request.request_id, request);
    return request;
  }
  approval(action, args, meta) {
    this.prune(); const request = this.requests.get(args.request_id);
    if (!this.secret || !request || (action === 'resume' ? request.action !== 'resume' : request.action !== 'permission') || request.browser_id !== this.slot.id || request.tab_id !== args.tabId) fail('host_approval_required', 'A current host-approved human decision is required.', { requires_user_action: true });
    const signed = meta?.['openagent/browser-approval'];
    const payload = signed?.payload;
    const expected = { version: 1, action, browser_id: this.slot.id, tab_id: args.tabId, request_id: args.request_id,
      nonce: payload?.nonce, expires_at_ms: payload?.expires_at_ms, origin: args.origin ?? null, permissions: [...(args.permissions || [])].sort() };
    if (!payload || canonicalJSON(payload) !== canonicalJSON(expected) || typeof payload.nonce !== 'string' || payload.nonce.length < 16 ||
        !Number.isSafeInteger(payload.expires_at_ms) || payload.expires_at_ms < Date.now() || payload.expires_at_ms > Date.now() + 60000 ||
        this.usedApprovals.has(payload.nonce) || request.origin !== expected.origin || canonicalJSON(request.permissions) !== canonicalJSON(expected.permissions)) fail('host_approval_invalid', 'Host approval is expired, reused or bound to another operation.');
    const actual = createHmac('sha256', this.secret).update(canonicalJSON(payload)).digest();
    const signature = typeof signed.signature === 'string' && /^[a-f0-9]{64}$/.test(signed.signature) ? Buffer.from(signed.signature, 'hex') : Buffer.alloc(0);
    if (signature.length !== actual.length || !timingSafeEqual(signature, actual)) fail('host_approval_invalid', 'Host approval signature is invalid.');
    this.usedApprovals.set(payload.nonce, payload.expires_at_ms); this.requests.delete(request.request_id);
  }
  async control(args, signal, meta) {
    if (args.action === 'inventory') { this.prune(); return { browser: this.support(), tabs: this.controller.cdp ? await this.controller.listTabs() : [], pending_decisions: [...this.requests.values()].map((request) => ({ request_id: request.request_id, action: request.action, tab_id: request.tab_id, browser_id: request.browser_id, origin: request.origin, permissions: request.permissions, expires_at_ms: request.expires })) }; }
    if (args.action === 'detach') { this.assertAutomated(); await this.close(); return { detached: true, browser_id: this.slot.id }; }
    if (args.action === 'resume') {
      this.approval('resume', args, meta);
      if (!this.controller.humanControl || this.controller.humanControl.request_id !== args.request_id) fail('takeover_not_current', 'This is not the current human-control request.');
      this.controller.humanControl = null; return { resumed: true, browser_id: this.slot.id, tabId: args.tabId };
    }
    if (args.action === 'recover' && this.controller.humanControl) return { requires_user_action: true, request_id: this.controller.humanControl.request_id, human_control: true, browser_id: this.slot.id };
    if (args.action === 'attach' && args.tabId === undefined) { await this.ensure(signal); return { attached: true, browser_id: this.slot.id, tabs: await this.controller.listTabs(), ...this.support() }; }
    const page = await this.page(args.tabId, signal);
    if (args.action === 'request_takeover') {
      const request = this.pending('resume', args);
      this.controller.humanControl = request; await this.disconnect();
      return { requires_user_action: true, request_id: request.request_id, browser_id: this.slot.id, tabId: args.tabId, reason: args.reason || 'Complete the requested step manually in this browser.', expires_at_ms: request.expires };
    }
    if (args.action === 'recover') return { requires_user_action: true, suggested_action: 'request_takeover', browser_id: this.slot.id, tabId: args.tabId,
      url: page.page.url(), no_automatic_credential_access: true, instructions: 'A human may complete login, CAPTCHA or site verification in this profile; resume requires host approval.' };
    return { attached: true, browser_id: this.slot.id, tabId: args.tabId, ...this.support() };
  }
  async permissions(args, signal, meta) {
    const page = await this.page(args.tabId, signal);
    const current = new URL(page.page.url()).origin;
    const origin = args.origin || current;
    if (!/^https?:\/\//.test(origin) || new URL(origin).origin !== origin || origin !== current) fail('permission_origin_mismatch', 'Permissions apply only to the exact current page origin.');
    args = { ...args, origin };
    const permissions = args.permissions || PERMISSIONS;
    if (args.action === 'query') return { origin, permissions: await page.page.evaluate(async (names) => {
      const entries = [];
      for (const name of names) { try { entries.push({ name, state: (await navigator.permissions.query({ name })).state }); } catch { entries.push({ name, state: 'unsupported' }); } }
      return entries;
    }, permissions), host_approval_required_for_changes: true };
    if (args.action === 'request') { const request = this.pending('permission', { ...args, permissions }); return { requires_user_action: true, ...request, expires_at_ms: request.expires }; }
    this.approval(args.action, { ...args, permissions }, meta);
    if (args.action === 'grant') await page.page.context().grantPermissions(permissions, { origin });
    else for (const name of permissions) await this.controller.cdp.send('Browser.setPermission', {
      permission: { name }, setting: 'prompt', origin, ...(page.contextId ? { browserContextId: page.contextId } : {})
    });
    return { ok: true, action: args.action, origin, permissions };
  }
}
