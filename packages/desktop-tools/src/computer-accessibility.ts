import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { performance } from "node:perf_hooks";

export type ComputerInvocationContext = {
  workspaceId: string;
  computerId: string;
  generation: number;
  actorUserId: string;
  sessionId: string;
  systemAudioEnabled?: boolean;
  sharedMcpServers?: readonly string[];
};
export type ComputerAccessibilityLaunch = { command: string; args: string[] };
type NativeAction =
  | "windows"
  | "accessibility_snapshot"
  | "accessibility_action";
type RecordValue = Record<string, unknown>;
type Pending = {
  resolve(value: RecordValue): void;
  reject(error: Error): void;
  timer: ReturnType<typeof setTimeout>;
};
type SnapshotLease = {
  scope: string;
  epoch: number;
  expires: number;
  target: string;
  elements: Set<string>;
};

const MAX_LINE_BYTES = 8 * 1024 * 1024;
const MAX_PENDING = 16;
const MAX_PAGES = 32;
const MAX_TOOLS = 2048;
const MAX_TTL_MS = 120_000;
const MAX_SNAPSHOTS = 8;
const TOOL_NAMES = {
  windows: "computer_list_windows",
  accessibility_snapshot: "computer_accessibility_snapshot",
  accessibility_action: "computer_accessibility_action",
} as const;

export class ComputerAccessibilityError extends Error {
  constructor(
    readonly code: string,
    detail = code,
  ) {
    super(detail === code ? code : `${code}: ${detail}`);
    this.name = "ComputerAccessibilityError";
  }
}

function error(code: string, detail?: string): ComputerAccessibilityError {
  return new ComputerAccessibilityError(code, detail);
}
function record(value: unknown): value is RecordValue {
  return !!value && typeof value === "object" && !Array.isArray(value);
}
function identifier(value: unknown, max = 512): value is string {
  return (
    typeof value === "string" &&
    value.length > 0 &&
    value.length <= max &&
    !/[\u0000-\u001f\u007f]/.test(value)
  );
}
function scopeKey(context: ComputerInvocationContext): string {
  if (
    !record(context) ||
    ![
      context.workspaceId,
      context.computerId,
      context.actorUserId,
      context.sessionId,
    ].every((value) => identifier(value)) ||
    !Number.isSafeInteger(context.generation) ||
    context.generation < 1
  ) {
    throw error(
      "computer_accessibility_scope_unavailable",
      "An authenticated workspace, computer, generation, actor and session are required",
    );
  }
  return JSON.stringify([
    context.workspaceId,
    context.computerId,
    context.generation,
    context.actorUserId,
    context.sessionId,
  ]);
}
function integer(value: unknown, min: number, max: number): value is number {
  return (
    typeof value === "number" &&
    Number.isSafeInteger(value) &&
    value >= min &&
    value <= max
  );
}

/** Main-process adapter to the shared Tools sidecar. It never substitutes input coordinates. */
export class ComputerAccessibilityClient {
  private child: ChildProcessWithoutNullStreams | null = null;
  private starting: Promise<void> | null = null;
  private retirement: Promise<void> = Promise.resolve();
  private buffer = "";
  private sequence = 0;
  private epoch = 0;
  private tools = new Set<string>();
  private pending = new Map<number, Pending>();
  private snapshots = new Map<string, SnapshotLease>();
  private seenSnapshots = new Set<string>();
  private readonly requestTimeoutMs: number;

  constructor(
    private readonly launch: ComputerAccessibilityLaunch,
    options: { requestTimeoutMs?: number } = {},
  ) {
    if (
      !identifier(launch.command, 4096) ||
      !Array.isArray(launch.args) ||
      launch.args.length > 64 ||
      !launch.args.every(
        (arg) =>
          typeof arg === "string" &&
          !arg.includes("\0") &&
          Buffer.byteLength(arg) <= 1024 * 1024,
      )
    ) {
      throw error("computer_accessibility_invalid_launch");
    }
    this.requestTimeoutMs = options.requestTimeoutMs ?? 15_000;
    if (!integer(this.requestTimeoutMs, 50, 30_000))
      throw error("computer_accessibility_invalid_timeout");
  }

  async invoke(
    action: NativeAction,
    args: RecordValue,
    context: ComputerInvocationContext,
    signal?: AbortSignal,
  ): Promise<unknown> {
    if (signal?.aborted) throw error("computer_accessibility_cancelled");
    const scope = scopeKey(context);
    if (!record(args) || !Object.hasOwn(TOOL_NAMES, action))
      throw error("invalid_accessibility_arguments");
    let nativeArgs: RecordValue = {};
    let lease: SnapshotLease | undefined;
    if (action === "accessibility_snapshot") {
      if (
        !integer(args.window_id, 0, 0xffff_ffff) ||
        !integer(args.pid, 1, 0xffff_ffff) ||
        (args.max_depth !== undefined && !integer(args.max_depth, 1, 30)) ||
        (args.max_nodes !== undefined && !integer(args.max_nodes, 1, 1000))
      ) {
        throw error(
          "invalid_accessibility_arguments",
          "Use an exact window_id/pid and bounded tree limits",
        );
      }
      nativeArgs = { window_id: args.window_id, pid: args.pid };
      if (args.max_depth !== undefined) nativeArgs.max_depth = args.max_depth;
      if (args.max_nodes !== undefined) nativeArgs.max_nodes = args.max_nodes;
    } else if (action === "accessibility_action") {
      if (!identifier(args.snapshot_id, 128))
        throw error("stale_accessibility_snapshot", "Take a fresh snapshot");
      lease = this.snapshots.get(args.snapshot_id);
      if (
        !lease ||
        lease.epoch !== this.epoch ||
        performance.now() >= lease.expires
      ) {
        this.snapshots.delete(args.snapshot_id);
        throw error(
          "stale_accessibility_snapshot",
          "Snapshot expired or was already used; take a fresh snapshot",
        );
      }
      if (lease.scope !== scope)
        throw error(
          "computer_accessibility_scope_mismatch",
          "Snapshot belongs to a different authenticated interaction",
        );
      // An authorized attempt consumes its observation even if validation or execution fails.
      this.snapshots.delete(args.snapshot_id);
      if (
        !identifier(args.element_id, 128) ||
        !lease.elements.has(args.element_id) ||
        typeof args.element_action !== "string" ||
        !["press", "show_menu", "set_value"].includes(args.element_action) ||
        (args.element_action === "set_value"
          ? typeof args.value !== "string" ||
            Buffer.byteLength(args.value) > 16 * 1024
          : args.value !== undefined)
      ) {
        throw error(
          "invalid_accessibility_arguments",
          "Select an observed element and press, show_menu or set_value; only set_value accepts text, up to 16 KiB",
        );
      }
      nativeArgs = {
        snapshot_id: args.snapshot_id,
        element_id: args.element_id,
        action: args.element_action,
      };
      if (args.value !== undefined) nativeArgs.value = args.value;
    }
    const onAbort = () =>
      this.retire(
        error(
          "computer_accessibility_cancelled",
          "The sidecar was stopped; observe a new snapshot before continuing",
        ),
      );
    signal?.addEventListener("abort", onAbort, { once: true });
    try {
      if (signal?.aborted) {
        onAbort();
        throw error("computer_accessibility_cancelled");
      }
      await this.ensureStarted();
      if (signal?.aborted) throw error("computer_accessibility_cancelled");
      if (!this.tools.has(TOOL_NAMES[action]))
        throw error(
          "computer_accessibility_unsupported",
          "The installed shared computer-control bundle does not expose this tool; update its verified bundle",
        );
      if (lease && lease.epoch !== this.epoch)
        throw error(
          "stale_accessibility_snapshot",
          "The executor changed; take a fresh snapshot",
        );
      const epoch = this.epoch;
      const observedAt = performance.now();
      const response = await this.request("tools/call", {
        name: TOOL_NAMES[action],
        arguments: nativeArgs,
      });
      if (epoch !== this.epoch)
        throw error("computer_accessibility_disconnected");
      const result = this.toolResult(response);
      if (action === "accessibility_snapshot")
        this.rememberSnapshot(result, nativeArgs, scope, epoch, observedAt);
      return result;
    } catch (cause) {
      if (signal?.aborted) throw error("computer_accessibility_cancelled");
      throw cause;
    } finally {
      signal?.removeEventListener("abort", onAbort);
    }
  }

  stop(): void {
    this.retire(
      error(
        "computer_accessibility_stopped",
        "The executor stopped; previous snapshots are invalid",
      ),
    );
  }

  private async ensureStarted(): Promise<void> {
    if (this.starting) return this.starting;
    if (this.child && this.tools.size) return;
    const operation = this.initialize();
    this.starting = operation;
    operation.then(
      () => {
        if (this.starting === operation) this.starting = null;
      },
      () => {
        if (this.starting === operation) this.starting = null;
      },
    );
    return operation;
  }

  private async initialize(): Promise<void> {
    const epoch = this.epoch;
    await this.retirement;
    if (epoch !== this.epoch) throw error("computer_accessibility_stopped");
    const child = spawn(this.launch.command, this.launch.args, {
      stdio: ["pipe", "pipe", "pipe"],
      shell: false,
      windowsHide: true,
    });
    this.child = child;
    this.buffer = "";
    child.stdout.setEncoding("utf8");
    child.stdout.on("data", (chunk: string) => this.receive(child, chunk));
    child.stderr.resume();
    child.stdin.on("error", () => {
      if (this.child === child)
        this.retire(error("computer_accessibility_disconnected"));
    });
    child.on("error", () => {
      if (this.child === child)
        this.retire(
          error(
            "computer_accessibility_unavailable",
            "The shared computer-control executable could not start",
          ),
        );
    });
    child.on("exit", () => {
      if (this.child === child)
        this.retire(
          error(
            "computer_accessibility_disconnected",
            "The shared computer-control process exited",
          ),
        );
    });
    try {
      const initialized = await this.request("initialize", {
        protocolVersion: "2024-11-05",
        capabilities: {},
        clientInfo: {
          name: "openagent-computer-accessibility-adapter",
          version: "1",
        },
      });
      if (
        !record(initialized.serverInfo) ||
        initialized.serverInfo.name !== "computer-control" ||
        !identifier(initialized.protocolVersion, 64) ||
        !record(initialized.capabilities) ||
        !record(initialized.capabilities.tools)
      ) {
        throw error(
          "computer_accessibility_unsupported",
          "The installed bundle is not a compatible computer-control MCP server",
        );
      }
      this.notify("notifications/initialized");
      const names = new Set<string>();
      const cursors = new Set<string>();
      let cursor: string | undefined;
      for (let page = 0; page < MAX_PAGES; page++) {
        const listed = await this.request(
          "tools/list",
          cursor === undefined ? {} : { cursor },
        );
        if (!Array.isArray(listed.tools))
          throw error(
            "computer_accessibility_protocol_error",
            "Invalid MCP tool catalog",
          );
        for (const tool of listed.tools) {
          if (
            !record(tool) ||
            !identifier(tool.name, 128) ||
            names.has(tool.name) ||
            !record(tool.inputSchema) ||
            tool.inputSchema.type !== "object" ||
            (tool.inputSchema.properties !== undefined &&
              !record(tool.inputSchema.properties)) ||
            (tool.inputSchema.required !== undefined &&
              (!Array.isArray(tool.inputSchema.required) ||
                !tool.inputSchema.required.every((item) =>
                  identifier(item, 128),
                )))
          ) {
            throw error(
              "computer_accessibility_protocol_error",
              "Invalid or duplicate tool metadata",
            );
          }
          names.add(tool.name);
          if (names.size > MAX_TOOLS)
            throw error(
              "computer_accessibility_protocol_error",
              "MCP tool catalog exceeds its bound",
            );
        }
        if (listed.nextCursor === undefined || listed.nextCursor === null) {
          if (!names.size)
            throw error(
              "computer_accessibility_unsupported",
              "The shared bundle exposes no computer tools",
            );
          this.tools = names;
          return;
        }
        if (
          !identifier(listed.nextCursor, 2048) ||
          cursors.has(listed.nextCursor)
        )
          throw error(
            "computer_accessibility_protocol_error",
            "MCP pagination cursor repeated or is invalid",
          );
        cursor = listed.nextCursor;
        cursors.add(cursor);
      }
      throw error(
        "computer_accessibility_protocol_error",
        "MCP pagination exceeds its page bound",
      );
    } catch (cause) {
      if (this.child === child)
        this.retire(
          cause instanceof Error
            ? cause
            : error("computer_accessibility_protocol_error"),
        );
      await this.retirement;
      throw cause;
    }
  }

  private request(method: string, params: RecordValue): Promise<RecordValue> {
    const child = this.child;
    if (!child || child.killed || child.exitCode !== null)
      return Promise.reject(error("computer_accessibility_disconnected"));
    if (this.pending.size >= MAX_PENDING)
      return Promise.reject(error("computer_accessibility_busy"));
    const id = ++this.sequence;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        if (this.pending.has(id) && this.child === child)
          this.retire(
            error(
              "computer_accessibility_timeout",
              "The executor was stopped; an interrupted action must not be replayed",
            ),
          );
      }, this.requestTimeoutMs);
      this.pending.set(id, { resolve, reject, timer });
      const onError = () => {
        if (this.child === child)
          this.retire(error("computer_accessibility_disconnected"));
      };
      try {
        child.stdin.write(
          `${JSON.stringify({ jsonrpc: "2.0", id, method, params })}\n`,
          (cause) => {
            if (cause) onError();
          },
        );
      } catch {
        onError();
      }
    });
  }

  private notify(method: string): void {
    const child = this.child;
    if (!child) throw error("computer_accessibility_disconnected");
    child.stdin.write(
      `${JSON.stringify({ jsonrpc: "2.0", method, params: {} })}\n`,
      (cause) => {
        if (cause && this.child === child)
          this.retire(error("computer_accessibility_disconnected"));
      },
    );
  }

  private receive(child: ChildProcessWithoutNullStreams, chunk: string): void {
    if (this.child !== child) return;
    this.buffer += chunk;
    for (;;) {
      const newline = this.buffer.indexOf("\n");
      if (newline < 0) break;
      const line = this.buffer.slice(0, newline);
      this.buffer = this.buffer.slice(newline + 1);
      if (Buffer.byteLength(line) > MAX_LINE_BYTES) {
        this.retire(
          error(
            "computer_accessibility_protocol_error",
            "MCP frame exceeds its byte bound",
          ),
        );
        return;
      }
      if (!line.trim()) continue;
      let frame: unknown;
      try {
        frame = JSON.parse(line);
      } catch {
        this.retire(
          error(
            "computer_accessibility_protocol_error",
            "MCP emitted malformed JSON",
          ),
        );
        return;
      }
      if (!record(frame) || frame.jsonrpc !== "2.0") {
        this.retire(
          error(
            "computer_accessibility_protocol_error",
            "Invalid MCP envelope",
          ),
        );
        return;
      }
      if (frame.id === undefined && typeof frame.method === "string") {
        if (frame.method === "notifications/tools/list_changed") {
          this.retire(
            error(
              "computer_accessibility_catalog_changed",
              "Discover tools again before continuing",
            ),
          );
          return;
        }
        continue;
      }
      if (
        !Number.isSafeInteger(frame.id) ||
        record(frame.result) === record(frame.error) ||
        (frame.error !== undefined &&
          (!record(frame.error) ||
            typeof frame.error.message !== "string" ||
            !Number.isInteger(frame.error.code)))
      ) {
        this.retire(
          error(
            "computer_accessibility_protocol_error",
            "Invalid MCP response",
          ),
        );
        return;
      }
      const pending = this.pending.get(frame.id as number);
      if (!pending) continue;
      clearTimeout(pending.timer);
      this.pending.delete(frame.id as number);
      if (record(frame.error))
        pending.reject(
          error(
            "computer_accessibility_rpc_error",
            frame.error.message as string,
          ),
        );
      else pending.resolve(frame.result as RecordValue);
      if (this.child !== child) return;
    }
    if (Buffer.byteLength(this.buffer) > MAX_LINE_BYTES)
      this.retire(
        error(
          "computer_accessibility_protocol_error",
          "MCP frame exceeds its byte bound",
        ),
      );
  }

  private toolResult(response: RecordValue): RecordValue {
    if (
      (response.isError !== undefined &&
        typeof response.isError !== "boolean") ||
      !Array.isArray(response.content) ||
      response.content.length !== 1 ||
      !record(response.content[0]) ||
      response.content[0].type !== "text" ||
      typeof response.content[0].text !== "string"
    ) {
      this.retire(
        error(
          "computer_accessibility_protocol_error",
          "Expected one JSON text result from computer-control",
        ),
      );
      throw error("computer_accessibility_protocol_error");
    }
    const text = response.content[0].text;
    if (response.isError) {
      const match = /^([a-z][a-z0-9_]{0,79})(?::|$)/.exec(text);
      throw error(
        match?.[1] ?? "computer_accessibility_failed",
        text.slice(0, 4096),
      );
    }
    let result: unknown;
    try {
      result = JSON.parse(text);
    } catch {
      this.retire(
        error(
          "computer_accessibility_protocol_error",
          "Computer tool returned invalid JSON",
        ),
      );
      throw error("computer_accessibility_protocol_error");
    }
    if (!record(result)) {
      this.retire(error("computer_accessibility_protocol_error"));
      throw error("computer_accessibility_protocol_error");
    }
    return result;
  }

  private rememberSnapshot(
    result: RecordValue,
    args: RecordValue,
    scope: string,
    epoch: number,
    observedAt: number,
  ): void {
    if (
      !identifier(result.snapshot_id, 128) ||
      this.seenSnapshots.has(result.snapshot_id) ||
      result.single_use !== true ||
      !integer(result.expires_in_ms, 1, MAX_TTL_MS) ||
      !record(result.window) ||
      result.window.window_id !== args.window_id ||
      result.window.pid !== args.pid ||
      !Array.isArray(result.elements) ||
      result.elements.length > 1000
    ) {
      this.retire(
        error(
          "computer_accessibility_protocol_error",
          "Invalid snapshot metadata",
        ),
      );
      throw error("computer_accessibility_protocol_error");
    }
    const elements = new Set<string>();
    for (const element of result.elements) {
      if (
        !record(element) ||
        !identifier(element.element_id, 128) ||
        !/^element-(?:0|[1-9][0-9]{0,2})$/.test(element.element_id) ||
        elements.has(element.element_id)
      ) {
        this.retire(
          error(
            "computer_accessibility_protocol_error",
            "Invalid snapshot element metadata",
          ),
        );
        throw error("computer_accessibility_protocol_error");
      }
      elements.add(element.element_id);
    }
    const target = JSON.stringify([args.window_id, args.pid]);
    for (const [id, lease] of this.snapshots) {
      if (lease.target === target || performance.now() >= lease.expires)
        this.snapshots.delete(id);
    }
    while (this.snapshots.size >= MAX_SNAPSHOTS)
      this.snapshots.delete(this.snapshots.keys().next().value!);
    if (this.seenSnapshots.size >= 4096) {
      this.retire(
        error(
          "computer_accessibility_snapshot_limit",
          "Restart the sidecar to continue observing",
        ),
      );
      throw error("computer_accessibility_snapshot_limit");
    }
    this.seenSnapshots.add(result.snapshot_id);
    this.snapshots.set(result.snapshot_id, {
      scope,
      epoch,
      target,
      elements,
      expires: observedAt + result.expires_in_ms,
    });
  }

  private retire(reason: Error): void {
    const child = this.child;
    this.child = null;
    this.epoch++;
    this.tools.clear();
    this.buffer = "";
    this.snapshots.clear();
    this.seenSnapshots.clear();
    for (const pending of this.pending.values()) {
      clearTimeout(pending.timer);
      pending.reject(reason);
    }
    this.pending.clear();
    if (child) {
      const previous = this.retirement;
      this.retirement = Promise.all([previous, this.terminate(child)]).then(
        () => {},
      );
      void this.retirement.catch(() => {});
    }
  }

  private terminate(child: ChildProcessWithoutNullStreams): Promise<void> {
    return new Promise((resolve, reject) => {
      let done = false;
      const finish = () => {
        if (done) return;
        done = true;
        clearTimeout(force);
        clearTimeout(timeout);
        resolve();
      };
      const force = setTimeout(() => {
        if (child.exitCode === null && child.signalCode === null)
          child.kill("SIGKILL");
      }, 500);
      const timeout = setTimeout(() => {
        if (done) return;
        done = true;
        clearTimeout(force);
        reject(error("computer_accessibility_shutdown_timeout"));
      }, 1500);
      force.unref();
      timeout.unref();
      child.once("close", finish);
      if (child.exitCode !== null || child.signalCode !== null) {
        finish();
        return;
      }
      child.kill("SIGTERM");
    });
  }
}
