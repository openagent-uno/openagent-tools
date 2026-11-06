#!/usr/bin/env node
// Interactive browser session with an authenticated live view.
//
// Launches the same dedicated browser Agent in Chrome uses (profile, flags,
// egress proxy relay) without any model, opens a URL and serves a WebSocket
// live view: screencast frames out, pointer/keyboard input in. A person uses
// it to sign in, pass a site verification or configure the profile once; the
// agent later reuses the profile. The session ends on {"type":"done"}, after
// --timeout seconds or on SIGTERM, always closing the browser cleanly so its
// cookies are flushed to the profile.
//
// Env: OPENAGENT_BROWSER_LIVE_TOKEN (required, >= 32 chars, Bearer token for
// every live-view connection), OPENAGENT_CHROME_PROFILE_DIR, OPENAGENT_CHROME_PROXY,
// OPENAGENT_CHROME_CDP_PORT. Stdout carries one final JSON status line.

import http from "node:http";
import crypto from "node:crypto";
import fs from "node:fs";
import { fileURLToPath } from "node:url";
import { WebSocketServer } from "ws";
import { CDP_PORT, ensureBrowser, closeDedicatedBrowser } from "./browser.js";
import { CDPConnection } from "./cdp.js";

const MAX_MESSAGE_BYTES = 64 * 1024;
const SPECIAL_KEYS = {
  Enter: 13, Backspace: 8, Tab: 9, Escape: 27, Delete: 46,
  ArrowLeft: 37, ArrowUp: 38, ArrowRight: 39, ArrowDown: 40, Home: 36, End: 35, PageUp: 33, PageDown: 34,
};
const BUTTONS = new Set(["left", "middle", "right"]);

export function parseArgs(argv) {
  const options = { url: "about:blank", listen: "127.0.0.1:9300", timeout: 1800, quality: 60, maxWidth: 1280, inFlight: 2 };
  for (let i = 0; i < argv.length; i += 1) {
    const [key, value] = [argv[i], argv[i + 1]];
    if (key === "--url") { options.url = value; i += 1; }
    else if (key === "--listen") { options.listen = value; i += 1; }
    else if (key === "--timeout") { options.timeout = Number(value); i += 1; }
    else if (key === "--quality") { options.quality = Number(value); i += 1; }
    else if (key === "--max-width") { options.maxWidth = Number(value); i += 1; }
    else if (key === "--frames-in-flight") { options.inFlight = Number(value); i += 1; }
    else throw new Error(`unknown argument ${key}`);
  }
  const target = new URL(options.url);
  if (!["http:", "https:", "about:"].includes(target.protocol)) throw new Error("--url must be http(s)");
  const separator = options.listen.lastIndexOf(":");
  options.host = options.listen.slice(0, separator) || "127.0.0.1";
  options.port = Number(options.listen.slice(separator + 1));
  if (!Number.isInteger(options.port) || options.port < 1 || options.port > 65535) throw new Error("--listen needs host:port");
  if (!(options.timeout >= 30 && options.timeout <= 86400)) throw new Error("--timeout must be 30-86400 seconds");
  if (!(Number.isInteger(options.quality) && options.quality >= 20 && options.quality <= 95)) throw new Error("--quality must be 20-95");
  if (!(Number.isInteger(options.maxWidth) && options.maxWidth >= 320 && options.maxWidth <= 2560)) throw new Error("--max-width must be 320-2560");
  if (!(Number.isInteger(options.inFlight) && options.inFlight >= 1 && options.inFlight <= 4)) throw new Error("--frames-in-flight must be 1-4");
  return options;
}

export function authorized(header, token) {
  const expected = Buffer.from(`Bearer ${token}`);
  const actual = Buffer.from(String(header || ""));
  return actual.length === expected.length && crypto.timingSafeEqual(actual, expected);
}

/** Translate one validated viewer message into CDP input commands. */
export function inputCommands(message, frame) {
  const width = frame?.deviceWidth || 0, height = frame?.deviceHeight || 0;
  const point = (m) => {
    if (!(m.x >= 0 && m.x <= 1 && m.y >= 0 && m.y <= 1) || !width || !height) throw new Error("x/y must be 0-1 within a frame");
    return { x: Math.round(m.x * width), y: Math.round(m.y * height) };
  };
  switch (message.type) {
    case "mouse": {
      const types = { press: "mousePressed", release: "mouseReleased", move: "mouseMoved" };
      if (!types[message.action]) throw new Error("mouse.action must be press, release or move");
      const button = message.action === "move" ? "none" : (BUTTONS.has(message.button) ? message.button : "left");
      return [["Input.dispatchMouseEvent", { type: types[message.action], ...point(message), button, clickCount: message.action === "move" ? 0 : 1 }]];
    }
    case "wheel":
      return [["Input.dispatchMouseEvent", { type: "mouseWheel", ...point(message), deltaX: Number(message.dx) || 0, deltaY: Number(message.dy) || 0 }]];
    case "text":
      if (typeof message.text !== "string" || !message.text || message.text.length > 2000) throw new Error("text must be 1-2000 characters");
      return [["Input.insertText", { text: message.text }]];
    case "key": {
      const code = SPECIAL_KEYS[message.key];
      if (!code) throw new Error("key must be a supported special key");
      const modifiers = (message.shift ? 8 : 0) | (message.ctrl ? 2 : 0) | (message.alt ? 1 : 0) | (message.meta ? 4 : 0);
      const base = { key: message.key, code: message.key, windowsVirtualKeyCode: code, modifiers };
      return [["Input.dispatchKeyEvent", { type: "rawKeyDown", ...base, ...(message.key === "Enter" ? { text: "\r" } : {}) }],
        ["Input.dispatchKeyEvent", { type: "keyUp", ...base }]];
    }
    case "navigate": {
      const url = new URL(String(message.url));
      if (!["http:", "https:"].includes(url.protocol)) throw new Error("navigate.url must be http(s)");
      return [["Page.navigate", { url: url.href }]];
    }
    case "back":
      return [["Runtime.evaluate", { expression: "history.back()" }]];
    default:
      throw new Error("unsupported message type");
  }
}

async function main() {
  const options = parseArgs(process.argv.slice(2));
  const token = process.env.OPENAGENT_BROWSER_LIVE_TOKEN || "";
  if (token.length < 32) throw new Error("OPENAGENT_BROWSER_LIVE_TOKEN must be at least 32 characters");

  const port = CDP_PORT;
  const launched = await ensureBrowser({ port });
  const cdp = new CDPConnection(launched.wsUrl);
  await cdp.connect();

  // Flow control: each viewer has at most --frames-in-flight unacknowledged frames
  // (binary JPEG) and acknowledges each with {"type":"frame_ack"} once shown; frames
  // arriving meanwhile replace the pending one. Two in flight hide one network round
  // trip without letting frames queue on a slow link.
  const viewers = new Map();
  let session = null, targetId = null, frame = null, finished = false;
  const broadcast = (payload) => {
    const text = JSON.stringify(payload);
    for (const viewer of viewers.keys()) if (viewer.readyState === 1) viewer.send(text);
  };
  const deliver = (viewer, state) => {
    if (!state.latest || viewer.readyState !== 1 || state.inFlight >= options.inFlight) return;
    viewer.send(state.latest, { binary: true });
    state.latest = null; state.inFlight += 1; state.sentAt = Date.now();
  };
  const screencast = { format: "jpeg", quality: options.quality, maxWidth: options.maxWidth, maxHeight: Math.round(options.maxWidth * 0.75), everyNthFrame: 1 };

  async function follow(id) {
    if (session) { try { await cdp.send("Page.stopScreencast", {}, session); } catch {} }
    const attached = await cdp.send("Target.attachToTarget", { targetId: id, flatten: true });
    session = attached.sessionId; targetId = id;
    await cdp.send("Page.enable", {}, session);
    await cdp.send("Page.startScreencast", screencast, session);
  }

  cdp.on("Page.screencastFrame", async (params, sid) => {
    if (sid !== session) return;
    const resized = !frame || frame.deviceWidth !== params.metadata.deviceWidth || frame.deviceHeight !== params.metadata.deviceHeight;
    frame = params.metadata;
    if (resized) broadcast({ type: "viewport", width: frame.deviceWidth, height: frame.deviceHeight });
    const jpeg = Buffer.from(params.data, "base64");
    for (const [viewer, state] of viewers) {
      state.latest = jpeg;
      // A viewer silent for 5 s may have lost acks; resume instead of freezing.
      if (state.inFlight && Date.now() - state.sentAt > 5000) state.inFlight = 0;
      deliver(viewer, state);
    }
    try { await cdp.send("Page.screencastFrameAck", { sessionId: params.sessionId }, session); } catch {}
  }, "*");
  cdp.on("Page.frameNavigated", async (params, sid) => {
    if (sid !== session || params.frame.parentId) return;
    broadcast({ type: "page", url: params.frame.url });
  }, "*");
  // Sign-in flows open popups (OAuth, identity providers): the view follows the newest page.
  await cdp.send("Target.setDiscoverTargets", { discover: true });
  cdp.on("Target.targetCreated", async ({ targetInfo }) => {
    if (targetInfo.type === "page" && targetInfo.targetId !== targetId && targetInfo.openerId) await follow(targetInfo.targetId).catch(() => {});
  });
  cdp.on("Target.targetDestroyed", async ({ targetId: gone }) => {
    if (gone !== targetId) return;
    const pages = (await cdp.send("Target.getTargets")).targetInfos.filter((t) => t.type === "page");
    if (pages.length) await follow(pages[pages.length - 1].targetId).catch(() => {});
  });

  const pages = (await cdp.send("Target.getTargets")).targetInfos.filter((t) => t.type === "page");
  const first = pages.length ? pages[0].targetId : (await cdp.send("Target.createTarget", { url: "about:blank" })).targetId;
  await follow(first);
  await cdp.send("Page.navigate", { url: options.url }, session);

  async function finish(status, code = 0) {
    if (finished) return;
    finished = true;
    broadcast({ type: "closed", status });
    for (const viewer of viewers.keys()) { try { viewer.close(1000, status); } catch {} }
    server.close();
    await closeDedicatedBrowser(cdp, { ownsBrowser: launched.ownsBrowser, browserPid: launched.pid, port });
    process.stdout.write(JSON.stringify({ status }) + "\n");
    process.exit(code);
  }

  const server = http.createServer((request, response) => {
    if (request.url === "/health") { response.writeHead(200, { "Content-Type": "application/json" }).end('{"ready":true}'); return; }
    response.writeHead(404).end();
  });
  const live = new WebSocketServer({ noServer: true, maxPayload: MAX_MESSAGE_BYTES });
  server.on("upgrade", (request, socket, head) => {
    if (new URL(request.url, "http://x").pathname !== "/live" || !authorized(request.headers.authorization, token)) {
      socket.end("HTTP/1.1 401 Unauthorized\r\n\r\n");
      return;
    }
    live.handleUpgrade(request, socket, head, (viewer) => {
      const state = { inFlight: 0, sentAt: 0, latest: null };
      viewers.set(viewer, state);
      viewer.on("close", () => viewers.delete(viewer));
      viewer.on("message", async (raw) => {
        let message;
        try { message = JSON.parse(raw.toString()); } catch { viewer.send('{"type":"error","error":"invalid JSON"}'); return; }
        if (message.type === "frame_ack") { state.inFlight = Math.max(0, state.inFlight - 1); deliver(viewer, state); return; }
        if (message.type === "done") { await finish("done"); return; }
        try {
          for (const [method, params] of inputCommands(message, frame)) await cdp.send(method, params, session);
        } catch (error) {
          viewer.send(JSON.stringify({ type: "error", error: String(error.message || error) }));
        }
      });
      viewer.send(JSON.stringify({ type: "ready", url: options.url }));
      if (frame) viewer.send(JSON.stringify({ type: "viewport", width: frame.deviceWidth, height: frame.deviceHeight }));
      // Force a fresh frame for a late viewer.
      cdp.send("Page.stopScreencast", {}, session).then(() =>
        cdp.send("Page.startScreencast", screencast, session)).catch(() => {});
    });
  });
  server.listen(options.port, options.host);
  const timer = setTimeout(() => finish("timeout"), options.timeout * 1000);
  timer.unref();
  for (const signal of ["SIGTERM", "SIGINT"]) process.on(signal, () => finish("stopped"));
  cdp.onClose?.(() => finish("browser_closed", 1));
  process.stderr.write(`[agent-in-chrome] live browser session on ${options.host}:${options.port}\n`);
}

const invokedDirectly = (() => {
  try { return Boolean(process.argv[1]) && fs.realpathSync(process.argv[1]) === fs.realpathSync(fileURLToPath(import.meta.url)); }
  catch { return false; }
})();
if (invokedDirectly) {
  main().catch((error) => {
    process.stdout.write(JSON.stringify({ status: "error", error: String(error.message || error) }) + "\n");
    process.exit(1);
  });
}
