// Minimal Chrome DevTools Protocol client over a single WebSocket.
//
// Connects to the *browser-level* endpoint (ws://.../devtools/browser/<id>)
// and uses flattened sessions (Target.attachToTarget {flatten:true}) so every
// page target is driven over the same socket, keyed by sessionId. This is the
// whole transport for OpenAgent in Chrome — no extension, no native messaging,
// no HTTP bridge. One connection, request/response by id, events fanned out to
// listeners.

import WebSocket from "ws";
import { createPipeSocket } from "./native-browser.js";

const REQUEST_TIMEOUT_MS = 30000;

export class CDPConnection {
  constructor(wsUrl, { requestTimeoutMs = REQUEST_TIMEOUT_MS } = {}) {
    if (!Number.isFinite(requestTimeoutMs) || requestTimeoutMs <= 0) {
      throw new TypeError("requestTimeoutMs must be a positive finite duration");
    }
    this.wsUrl = wsUrl;
    this.ws = null;
    this.nextId = 0;
    this.pending = new Map(); // id -> { resolve, reject, timer }
    // Event listeners keyed by "<sessionId|''>:<method>" and "*:<method>".
    this.listeners = new Map();
    this.closed = false;
    this.requestTimeoutMs = requestTimeoutMs;
    this._didClose = false;
    this._closeHandlers = [];
  }

  connect() {
    if (this.ws || this.closed) return Promise.reject(new Error("CDP connection cannot be reopened"));
    return new Promise((resolve, reject) => {
      // maxPayload high enough for full-page base64 screenshots.
      this.ws = typeof this.wsUrl === "object" ? createPipeSocket(this.wsUrl) : new WebSocket(this.wsUrl, {
        maxPayload: 512 * 1024 * 1024,
        perMessageDeflate: false,
        handshakeTimeout: this.requestTimeoutMs,
      });

      const onOpenError = (err) => { this._onClose(); reject(err); };
      const onEarlyClose = () => { this._onClose(); reject(new Error("CDP connection closed before opening")); };
      this.ws.once("error", onOpenError);
      this.ws.once("close", onEarlyClose);

      this.ws.once("open", () => {
        this.ws.removeListener("error", onOpenError);
        this.ws.removeListener("close", onEarlyClose);
        this.ws.on("error", () => {}); // keep-alive; real failures surface via close
        this.ws.on("message", (data) => this._onMessage(data));
        this.ws.on("close", () => this._onClose());
        resolve();
      });
    });
  }

  _onMessage(data) {
    let msg;
    try {
      msg = JSON.parse(data.toString("utf-8"));
    } catch {
      return;
    }
    if (!msg || typeof msg !== "object" || Array.isArray(msg)) return;

    if (msg.id !== undefined && this.pending.has(msg.id)) {
      const { resolve, reject, cleanup, sessionId } = this.pending.get(msg.id);
      cleanup();
      this.pending.delete(msg.id);
      if ((msg.sessionId || undefined) !== sessionId) {
        reject(new Error("CDP response session does not match the requested target"));
      } else if (msg.error) {
        reject(new Error(msg.error.message || JSON.stringify(msg.error)));
      } else {
        resolve(msg.result);
      }
      return;
    }

    if (msg.method) {
      if (msg.method === "Target.detachedFromTarget" && msg.params?.sessionId) {
        this._rejectSession(msg.params.sessionId);
      }
      const sid = msg.sessionId || "";
      this._emit(`${sid}:${msg.method}`, msg.params, sid);
      this._emit(`*:${msg.method}`, msg.params, sid);
    }
  }

  _emit(key, params, sessionId) {
    const set = this.listeners.get(key);
    if (!set) return;
    for (const cb of set) {
      try {
        cb(params, sessionId);
      } catch {
        /* listener errors are non-fatal */
      }
    }
  }

  _onClose() {
    if (this._didClose) return;
    this._didClose = true;
    this.closed = true;
    for (const [, { reject, cleanup }] of this.pending) {
      cleanup();
      reject(new Error("CDP connection closed"));
    }
    this.pending.clear();
    for (const h of this._closeHandlers) {
      try {
        h();
      } catch {}
    }
    this._closeHandlers = [];
    this.listeners.clear();
  }

  _rejectSession(sessionId) {
    for (const [id, pending] of this.pending) {
      if (pending.sessionId !== sessionId) continue;
      this.pending.delete(id);
      pending.cleanup();
      pending.reject(new Error("CDP target session was detached"));
    }
  }

  onClose(handler) {
    this._closeHandlers.push(handler);
    return () => { this._closeHandlers = this._closeHandlers.filter((h) => h !== handler); };
  }

  /**
   * Send a CDP command. `sessionId` omitted → browser-level command.
   * Resolves with the `result` object, rejects on protocol error / timeout.
   */
  send(method, params = {}, sessionId = undefined, { signal } = {}) {
    if (signal?.aborted) return Promise.reject(signal.reason || new DOMException("CDP command cancelled", "AbortError"));
    if (this.closed || !this.ws || this.ws.readyState !== WebSocket.OPEN) {
      return Promise.reject(new Error("CDP connection is not open"));
    }
    const id = ++this.nextId;
    const payload = { id, method, params };
    if (sessionId) payload.sessionId = sessionId;

    return new Promise((resolve, reject) => {
      const cleanup = () => { clearTimeout(timer); signal?.removeEventListener("abort", cancel); };
      const cancel = () => {
        this.pending.delete(id);
        cleanup();
        // CDP has no general undo/cancel command. A dispatched mutation can
        // have happened; discarding its late response must never trigger replay.
        reject(signal.reason || new DOMException("CDP command cancelled; outcome may be unknown", "AbortError"));
      };
      const timer = setTimeout(() => {
        this.pending.delete(id);
        cleanup();
        reject(new Error(`CDP command '${method}' timed out after ${this.requestTimeoutMs}ms`));
      }, this.requestTimeoutMs);
      this.pending.set(id, { resolve, reject, cleanup, sessionId });
      signal?.addEventListener("abort", cancel, { once: true });
      try {
        this.ws.send(JSON.stringify(payload));
      } catch (err) {
        cleanup();
        this.pending.delete(id);
        reject(err);
      }
    });
  }

  /** Register an event listener. Returns an unsubscribe function. */
  on(method, handler, sessionId = "") {
    const key = `${sessionId}:${method}`;
    let set = this.listeners.get(key);
    if (!set) {
      set = new Set();
      this.listeners.set(key, set);
    }
    set.add(handler);
    return () => {
      set.delete(handler);
      if (!set.size) this.listeners.delete(key);
    };
  }

  /** Wait for a single event (optionally scoped to a session), with timeout. */
  once(method, { sessionId = "", timeout = REQUEST_TIMEOUT_MS, predicate, signal } = {}) {
    if (this.closed) return Promise.resolve(null);
    if (signal?.aborted) return Promise.reject(signal.reason || new DOMException("CDP wait cancelled", "AbortError"));
    return new Promise((resolve, reject) => {
      let done = false;
      const finish = (val, error) => {
        if (done) return;
        done = true;
        clearTimeout(timer);
        off();
        offClose();
        signal?.removeEventListener("abort", cancel);
        if (error !== undefined) reject(error); else resolve(val);
      };
      const off = this.on(
        method,
        (params) => {
          if (predicate && !predicate(params)) return;
          finish(params);
        },
        sessionId,
      );
      const offClose = this.onClose(() => finish(null));
      const cancel = () => finish(undefined, signal.reason || new DOMException("CDP wait cancelled", "AbortError"));
      const timer = setTimeout(() => finish(null), timeout);
      signal?.addEventListener("abort", cancel, { once: true });
    });
  }

  close() {
    this._onClose();
    try {
      if (this.ws) this.ws.close();
    } catch {}
  }
}
