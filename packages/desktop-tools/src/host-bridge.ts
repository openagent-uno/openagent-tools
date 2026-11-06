import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import type { DesktopHostSelection } from "./contracts";
import { type ClientToolCall, CapabilityProtocolError } from "./protocol";

const CONTROL_PROTOCOL = "openagent-host-tools/1";
const RESPONSE_TIMEOUT_MS = 10_000;
const MAX_LINE_BYTES = 96 * 1024 * 1024;

export interface HostToolsLaunch {
  command: string;
  args: string[];
  cwd?: string;
  env?: NodeJS.ProcessEnv;
  source: "override" | "packaged" | "development" | "path";
  unavailableReason?: string;
}

interface Pending {
  resolve: (value: unknown) => void;
  reject: (error: Error) => void;
  timer: ReturnType<typeof setTimeout>;
  dispose: () => void;
}

/** Main-process-only NDJSON bridge; renderer code never receives an invoke surface. */
export class HostProcessBridge {
  private child: ChildProcessWithoutNullStreams | null = null;
  private supportsResources = false;
  private buffer = "";
  private pending = new Map<string, Pending>();
  private principal: Record<string, unknown> | null = null;
  private lifecycle = 0;
  private closed = new WeakMap<ChildProcessWithoutNullStreams, Promise<void>>();
  private stopping = new WeakMap<
    ChildProcessWithoutNullStreams,
    Promise<void>
  >();
  private retiring = new Set<Promise<void>>();

  constructor(
    private readonly launch: HostToolsLaunch,
    private readonly certifiedAccount: () => Promise<string>,
    private readonly browserScope?: string,
  ) {
    if (browserScope !== undefined && !/^[a-f0-9]{64}$/.test(browserScope))
      throw new Error("invalid_browser_scope");
  }

  async start(
    selection: DesktopHostSelection,
    generation: number,
  ): Promise<void> {
    const revision = ++this.lifecycle;
    await this.retire(this.child, "host_tools_stopped");
    await Promise.all(this.retiring);
    if (revision !== this.lifecycle)
      throw new CapabilityProtocolError("host_tools_stopped");
    if (this.launch.unavailableReason)
      throw new CapabilityProtocolError(this.launch.unavailableReason);
    const accountID = await this.certifiedAccount();
    if (!/^[A-Za-z0-9_-]{1,128}$/.test(accountID))
      throw new CapabilityProtocolError("account_context_required");
    if (revision !== this.lifecycle)
      throw new CapabilityProtocolError("host_tools_stopped");
    const child = spawn(this.launch.command, this.launch.args, {
      cwd: this.launch.cwd,
      stdio: ["pipe", "pipe", "pipe"],
      shell: false,
      windowsHide: true,
      env: {
        ...process.env,
        ...this.launch.env,
        PYTHONIOENCODING: "utf-8",
        PYTHONUTF8: "1",
      },
    });
    this.child = child;
    this.buffer = "";
    this.closed.set(
      child,
      new Promise((resolve) => child.once("close", () => resolve())),
    );
    child.stdout.setEncoding("utf8");
    child.stdout.on("data", (chunk: string) => {
      if (this.child === child) this.receive(chunk, child);
    });
    // Drain diagnostics without retaining tool bodies or credentials. A blocked
    // stderr pipe otherwise prevents a healthy helper from returning results.
    child.stderr.resume();
    child.stdin.on("error", () => {
      void this.retire(child, "host_transport_lost").catch(() => {});
    });
    child.on("error", () => {
      void this.retire(child, "host_tools_unavailable").catch(() => {});
    });
    child.on("exit", () => {
      void this.retire(child, "host_tools_disconnected").catch(() => {});
    });
    this.principal = {
      ...(this.browserScope ? { browser_scope: this.browserScope } : {}),
      kind: "interactive-client",
      client_instance_id: selection.deviceId,
      device_label: selection.deviceLabel,
      device_id: selection.deviceId,
      generation,
      account_id: accountID,
      network_id: selection.workspaceId,
    };
    try {
      const initialized = await this.request(
        {
          type: "initialize",
          protocol: CONTROL_PROTOCOL,
          principal: this.principal,
        },
        RESPONSE_TIMEOUT_MS,
        child,
      );
      this.supportsResources =
        !!initialized &&
        typeof initialized === "object" &&
        (initialized as { features?: { mcp_app_resources?: unknown } }).features
          ?.mcp_app_resources === 1;
      await this.request(
        { type: "set_consent", enabled: true, consent_version: 1 },
        RESPONSE_TIMEOUT_MS,
        child,
      );
    } catch (error) {
      await this.retire(child, "host_transport_lost");
      throw error;
    }
  }

  async catalog(signal?: AbortSignal): Promise<unknown> {
    return this.request(
      { type: "catalog" },
      RESPONSE_TIMEOUT_MS,
      this.child,
      signal,
    );
  }

  // Trusted per-server relay callers retain the exact computer/session binding.
  async readResource(
    request: {
      callId: string;
      server: string;
      uri: string;
      deadlineMs?: number;
    },
    signal?: AbortSignal,
  ): Promise<unknown> {
    if (!this.supportsResources)
      throw new CapabilityProtocolError("mcp_app_resources_unsupported");
    const child = this.child;
    return this.request(
      {
        type: "read_resource",
        call_id: request.callId,
        server: request.server,
        uri: request.uri,
        principal: this.principal,
        deadline_ms: request.deadlineMs,
      },
      requestTimeout(request.deadlineMs),
      child,
      signal,
      () => {
        if (this.child === child)
          void this.request(
            { type: "cancel", call_id: request.callId },
            2000,
            child,
          ).catch(() => {});
      },
    );
  }

  async invoke(call: ClientToolCall, signal?: AbortSignal): Promise<unknown> {
    if (signal?.aborted) throw new CapabilityProtocolError("cancelled");
    const timeout = requestTimeout(call.deadlineMs);
    const child = this.child;
    return this.request(
      {
        type: "call",
        call_id: call.callId,
        server: call.server,
        tool: call.tool,
        args: call.args,
        idempotency_key: call.idempotencyKey,
        arguments_sha256: call.argumentsSha256,
        deadline_ms: call.deadlineMs,
        principal: this.principal,
      },
      timeout,
      child,
      signal,
      () => {
        // Cancellation belongs to the process that received this operation.
        // It must never address a replacement host with a reused call id.
        if (this.child === child) {
          void this.request(
            { type: "cancel", call_id: call.callId },
            2_000,
            child,
          ).catch(() => {});
        }
      },
    );
  }

  /** Read only operator inventory for this bridge's selected connection. */
  async browserInventory(): Promise<unknown> {
    const args = { action: "inventory" };
    const callId = `operator_inventory_${randomBytes(12).toString("base64url")}`;
    const child = this.child;
    return this.request(
      {
        type: "call",
        call_id: callId,
        server: "agent-in-chrome",
        tool: "browser_control",
        args,
        idempotency_key: callId,
        arguments_sha256: createHash("sha256")
          .update(JSON.stringify(args))
          .digest("hex"),
        principal: this.principal,
      },
      RESPONSE_TIMEOUT_MS,
      child,
      undefined,
      () => {
        if (this.child === child)
          void this.request(
            { type: "cancel", call_id: callId },
            2_000,
            child,
          ).catch(() => {});
      },
    );
  }

  /** Trusted desktop UI decisions only; principal comes from the selected connection. */
  async providerControl(
    decision: {
      tool: "browser_control" | "browser_permissions";
      args: Record<string, unknown>;
      principal?: Record<string, unknown>;
    },
    signal?: AbortSignal,
  ): Promise<unknown> {
    if (signal?.aborted) throw new CapabilityProtocolError("cancelled");
    const child = this.child;
    const callId = `operator_${randomBytes(12).toString("base64url")}`;
    return this.request(
      {
        type: "provider_control",
        call_id: callId,
        server: "agent-in-chrome",
        tool: decision.tool,
        args: decision.args,
        principal: this.principal,
      },
      32_000,
      child,
      signal,
      () => {
        if (this.child === child) {
          void this.request(
            { type: "cancel", call_id: callId },
            2_000,
            child,
          ).catch(() => {});
        }
      },
    );
  }

  async stop(): Promise<void> {
    ++this.lifecycle;
    const child = this.child;
    if (!child) {
      await Promise.all(this.retiring);
      return;
    }
    try {
      await this.request({ type: "shutdown" }, 1_500, child);
    } catch {
      /* An unresponsive owned helper is terminated below. */
    }
    await this.retire(child, "host_tools_stopped");
    await Promise.all(this.retiring);
  }

  async hardStop(): Promise<void> {
    ++this.lifecycle;
    await this.retire(this.child, "host_tools_stopped");
    await Promise.all(this.retiring);
  }

  private async retire(
    child: ChildProcessWithoutNullStreams | null,
    code: string,
  ): Promise<void> {
    if (!child) return;
    if (this.child === child) {
      this.child = null;
      this.principal = null;
      this.supportsResources = false;
      this.buffer = "";
      this.failAll(code);
    }
    const existing = this.stopping.get(child);
    if (existing) return existing;
    const operation = this.terminate(child);
    this.stopping.set(child, operation);
    this.retiring.add(operation);
    // A failed retirement remains a barrier to launching another executor.
    operation.then(
      () => this.retiring.delete(operation),
      () => {},
    );
    return operation;
  }

  private async terminate(
    child: ChildProcessWithoutNullStreams,
  ): Promise<void> {
    if (child.exitCode != null || child.signalCode != null) return;
    child.kill("SIGTERM");
    if (await this.waitForClose(child, 1_500)) return;
    child.kill("SIGKILL");
    if (!(await this.waitForClose(child, 1_000)))
      throw new CapabilityProtocolError("host_stop_timeout");
  }

  private async waitForClose(
    child: ChildProcessWithoutNullStreams,
    timeoutMs: number,
  ): Promise<boolean> {
    const closed = this.closed.get(child);
    if (!closed) return child.exitCode != null || child.signalCode != null;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const result = await Promise.race([
      closed.then(() => true),
      new Promise<false>((resolve) => {
        timer = setTimeout(() => resolve(false), timeoutMs);
      }),
    ]);
    clearTimeout(timer);
    return result;
  }

  private request(
    body: Record<string, unknown>,
    timeoutMs = RESPONSE_TIMEOUT_MS,
    child = this.child,
    signal?: AbortSignal,
    onCancel?: () => void,
  ): Promise<unknown> {
    if (
      !child ||
      this.child !== child ||
      child.exitCode != null ||
      child.signalCode != null ||
      child.killed
    ) {
      return Promise.reject(
        new CapabilityProtocolError("host_tools_disconnected"),
      );
    }
    if (signal?.aborted)
      return Promise.reject(new CapabilityProtocolError("cancelled"));
    const id = `req_${randomBytes(12).toString("base64url")}`;
    // Serialize before installing pending state, so malformed direct callers
    // cannot leak a timer or an abort listener.
    const frame = `${JSON.stringify({ id, ...body })}\n`;
    return new Promise((resolve, reject) => {
      const finish = (error: Error) => {
        const pending = this.pending.get(id);
        if (!pending) return;
        this.pending.delete(id);
        clearTimeout(pending.timer);
        pending.dispose();
        reject(error);
      };
      const cancel = () => {
        finish(new CapabilityProtocolError("cancelled"));
        onCancel?.();
      };
      const timer = setTimeout(() => {
        finish(new CapabilityProtocolError("host_tools_timeout"));
        onCancel?.();
      }, timeoutMs);
      this.pending.set(id, {
        resolve,
        reject,
        timer,
        dispose: () => signal?.removeEventListener("abort", cancel),
      });
      signal?.addEventListener("abort", cancel, { once: true });
      if (signal?.aborted) {
        cancel();
        return;
      }
      try {
        child.stdin.write(frame, "utf8", (error) => {
          if (error)
            void this.retire(child, "host_transport_lost").catch(() => {});
        });
      } catch {
        void this.retire(child, "host_transport_lost").catch(() => {});
      }
    });
  }

  private receive(chunk: string, child: ChildProcessWithoutNullStreams): void {
    this.buffer += chunk;
    for (;;) {
      if (this.child !== child) return;
      const newline = this.buffer.indexOf("\n");
      if (newline < 0) {
        if (Buffer.byteLength(this.buffer, "utf8") > MAX_LINE_BYTES)
          void this.retire(child, "host_transport_lost").catch(() => {});
        return;
      }
      const line = this.buffer.slice(0, newline);
      this.buffer = this.buffer.slice(newline + 1);
      if (Buffer.byteLength(line, "utf8") > MAX_LINE_BYTES) {
        void this.retire(child, "host_transport_lost").catch(() => {});
        return;
      }
      if (!line.trim()) continue;
      let value: unknown;
      try {
        value = JSON.parse(line);
      } catch {
        void this.retire(child, "host_transport_lost").catch(() => {});
        return;
      }
      if (!value || typeof value !== "object" || Array.isArray(value)) {
        void this.retire(child, "host_transport_lost").catch(() => {});
        return;
      }
      const frame = value as Record<string, unknown>;
      // Catalog/state/completion notifications are not request responses.
      if (frame.type === "event") continue;
      if (
        frame.type !== "response" ||
        typeof frame.id !== "string" ||
        typeof frame.ok !== "boolean"
      ) {
        void this.retire(child, "host_transport_lost").catch(() => {});
        return;
      }
      if (
        !frame.ok &&
        (!frame.error ||
          typeof frame.error !== "object" ||
          Array.isArray(frame.error))
      ) {
        void this.retire(child, "host_transport_lost").catch(() => {});
        return;
      }
      const pending = this.pending.get(frame.id);
      if (!pending) continue;
      clearTimeout(pending.timer);
      pending.dispose();
      this.pending.delete(frame.id);
      if (frame.ok) pending.resolve(frame.result);
      else {
        const error = frame.error as Record<string, unknown>;
        const code =
          typeof error.code === "string" && /^[a-z0-9_]{1,64}$/.test(error.code)
            ? error.code
            : "host_tools_rejected";
        pending.reject(
          new CapabilityProtocolError(
            code,
            typeof error.message === "string" ? error.message : code,
          ),
        );
      }
    }
  }

  private failAll(code: string): void {
    for (const pending of this.pending.values()) {
      clearTimeout(pending.timer);
      pending.dispose();
      pending.reject(new CapabilityProtocolError(code));
    }
    this.pending.clear();
  }
}

function requestTimeout(deadlineMs?: number): number {
  if (deadlineMs === undefined) return 120_000;
  if (!Number.isFinite(deadlineMs) || deadlineMs <= 0)
    throw new CapabilityProtocolError("invalid_deadline");
  const remaining =
    deadlineMs > 1_000_000_000_000 ? deadlineMs - Date.now() : deadlineMs;
  if (remaining <= 0) throw new CapabilityProtocolError("deadline_expired");
  return Math.max(1, Math.min(remaining, 24 * 60 * 60 * 1_000));
}
