import { ComputerMcpTools } from "./computer-mcp-tools";
import { ComputerScopedTools } from "./computer-scoped-tools";
import type { HostToolsLaunch } from "./host-bridge";
import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { open, writeFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { randomUUID } from "node:crypto";
import path from "node:path";

import {
  ComputerAccessibilityClient,
  type ComputerInvocationContext,
} from "./computer-accessibility";

export type ComputerOperation = {
  tool:
    | "read_file"
    | "write_file"
    | "shell"
    | "computer"
    | "native"
    | "browser"
    | "mcp";
  args: Record<string, unknown>;
};

export class ComputerShellError extends Error {
  constructor(
    readonly code:
      | "computer_shell_timeout"
      | "computer_disconnected"
      | "computer_shell_output_limit",
  ) {
    super(code);
    this.name = "ComputerShellError";
  }
}

/** The caller must authenticate a v2 operation grant; this is never renderer IPC. */
export class ComputerExecutor {
  private child: ChildProcessWithoutNullStreams | null = null;
  private starting: Promise<void> | null = null;
  private buffer = "";
  private pending = new Map<
    string,
    {
      resolve(value: unknown): void;
      reject(error: Error): void;
      timer: ReturnType<typeof setTimeout>;
    }
  >();
  private shells = new Map<
    ReturnType<typeof spawn>,
    (reason: ComputerShellError) => void
  >();
  private readonly shellTimeoutMs: number;
  private readonly accessibility: ComputerAccessibilityClient | null;
  private readonly mcpTools: ComputerMcpTools | null;
  private readonly scopedTools: ComputerScopedTools | null;
  constructor(
    private readonly binary: string,
    options: {
      hostToolsLaunch?: HostToolsLaunch;
      shellTimeoutMs?: number;
      accessibilityLaunch?: { command: string; args: string[] };
    } = {},
  ) {
    this.mcpTools = options.hostToolsLaunch
      ? new ComputerMcpTools(options.hostToolsLaunch)
      : null;
    this.scopedTools = options.hostToolsLaunch
      ? new ComputerScopedTools(options.hostToolsLaunch)
      : null;
    this.accessibility = options.accessibilityLaunch
      ? new ComputerAccessibilityClient(options.accessibilityLaunch)
      : null;
    this.shellTimeoutMs = options.shellTimeoutMs ?? 20_000;
    if (
      !Number.isInteger(this.shellTimeoutMs) ||
      this.shellTimeoutMs < 100 ||
      this.shellTimeoutMs > 20_000
    )
      throw new Error("invalid_shell_timeout");
  }

  async browserInventories() {
    return this.scopedTools?.browserInventories() ?? [];
  }
  async browserDecision(
    scopeId: string,
    decision: {
      tool: "browser_control" | "browser_permissions";
      args: Record<string, unknown>;
    },
  ): Promise<unknown> {
    if (!this.scopedTools) throw new Error("computer_scope_expired");
    return this.scopedTools.browserDecision(scopeId, decision);
  }

  start(): Promise<void> {
    if (this.starting) return this.starting;
    this.starting = this.startHelper().finally(() => {
      this.starting = null;
    });
    return this.starting;
  }

  private async startHelper() {
    if (this.child) return;
    if (!existsSync(this.binary))
      throw new Error("computer_helper_not_packaged");
    const child = spawn(this.binary, ["--desktop-stdio"], {
      stdio: ["pipe", "pipe", "pipe"],
      shell: false,
      windowsHide: true,
    });
    this.child = child;
    child.stderr.resume();
    child.stdin.on("error", () => {
      if (this.child === child) this.stop();
    });
    child.stdout.setEncoding("utf8");
    child.stdout.on("data", (chunk: string) => {
      if (this.child !== child) return;
      this.buffer += chunk;
      if (Buffer.byteLength(this.buffer) > 64 * 1024 * 1024) {
        this.stop();
        return;
      }
      for (;;) {
        const end = this.buffer.indexOf("\n");
        if (end < 0) break;
        const line = this.buffer.slice(0, end);
        this.buffer = this.buffer.slice(end + 1);
        try {
          const response: unknown = JSON.parse(line);
          if (
            !response ||
            typeof response !== "object" ||
            Array.isArray(response)
          )
            throw new Error("invalid_computer_response");
          const frame = response as Record<string, unknown>;
          if (typeof frame.id !== "string" || typeof frame.ok !== "boolean")
            throw new Error("invalid_computer_response");
          const pending = this.pending.get(frame.id);
          if (!pending) continue;
          this.pending.delete(frame.id);
          clearTimeout(pending.timer);
          if (frame.ok) pending.resolve(frame.result);
          else
            pending.reject(
              new Error(
                typeof frame.error === "string"
                  ? frame.error
                  : "computer_operation_failed",
              ),
            );
        } catch {
          this.stop();
          return;
        }
      }
    });
    child.on("error", () => {
      if (this.child === child) this.stop();
    });
    child.on("exit", () => {
      if (this.child === child) this.stop();
    });
    try {
      const hello = await this.native({ action: "hello" });
      if (
        !hello ||
        typeof hello !== "object" ||
        Array.isArray(hello) ||
        (hello as { protocol?: unknown }).protocol !== "openagent-desktop/1"
      ) {
        throw new Error("computer_helper_protocol_mismatch");
      }
    } catch (error) {
      if (this.child === child) this.stop();
      throw error;
    }
  }

  stop() {
    this.mcpTools?.stop();
    this.scopedTools?.stop();
    this.accessibility?.stop();
    const child = this.child;
    this.child = null;
    this.buffer = "";
    child?.kill();
    for (const pending of this.pending.values()) {
      clearTimeout(pending.timer);
      pending.reject(new Error("computer_disconnected"));
    }
    this.pending.clear();
    for (const cancel of this.shells.values())
      cancel(new ComputerShellError("computer_disconnected"));
    this.shells.clear();
  }

  async invoke(
    operation: ComputerOperation,
    signal?: AbortSignal,
    context?: ComputerInvocationContext,
  ): Promise<unknown> {
    if (!this.child || signal?.aborted)
      throw new Error("computer_disconnected");
    const args = operation.args;
    switch (operation.tool) {
      case "mcp": {
        if (!context || !this.mcpTools)
          throw new Error("computer_mcp_unavailable");
        return this.mcpTools.invoke(args, context, signal);
      }
      case "native":
      case "browser": {
        if (!context) throw new Error("computer_scope_unavailable");
        if (
          operation.tool === "native" &&
          args.name === "computer_audio_start" &&
          context.systemAudioEnabled !== true
        )
          throw new Error("computer_system_audio_consent_required");
        if (!this.scopedTools)
          throw new Error("computer_scoped_tools_not_packaged");
        return this.scopedTools.invoke(operation.tool, args, context, signal);
      }
      case "computer": {
        if (
          args.action === "windows" ||
          args.action === "accessibility_snapshot" ||
          args.action === "accessibility_action"
        ) {
          if (!context)
            throw new Error("computer_accessibility_scope_unavailable");
          if (!this.accessibility)
            throw new Error("computer_accessibility_not_packaged");
          return this.accessibility.invoke(args.action, args, context, signal);
        }
        return this.native(args, signal);
      }
      case "read_file": {
        const file = this.filePath(args.path);
        const handle = await open(file, "r");
        try {
          if (!(await handle.stat()).isFile())
            throw new Error("regular_file_required");
          const data = Buffer.alloc(1024 * 1024 + 1);
          let length = 0;
          while (length < data.length) {
            signal?.throwIfAborted();
            const { bytesRead } = await handle.read(
              data,
              length,
              data.length - length,
              null,
            );
            if (!bytesRead) break;
            length += bytesRead;
          }
          if (length > 1024 * 1024) throw new Error("file_too_large");
          return { text: data.subarray(0, length).toString("utf8") };
        } finally {
          await handle.close();
        }
      }
      case "write_file": {
        const file = this.filePath(args.path);
        if (
          typeof args.text !== "string" ||
          Buffer.byteLength(args.text) > 1024 * 1024
        )
          throw new Error("invalid_file_content");
        await writeFile(file, args.text, { encoding: "utf8", signal });
        return { written: true };
      }
      case "shell":
        return this.shell(args, signal);
      default:
        throw new Error("unknown_computer_tool");
    }
  }

  releaseScope(
    workspaceId: string,
    computerId: string,
    generation: number,
  ): void {
    this.mcpTools?.release(workspaceId, computerId, generation);
    this.scopedTools?.release(workspaceId, computerId, generation);
  }

  private filePath(value: unknown): string {
    if (
      typeof value !== "string" ||
      !path.isAbsolute(value) ||
      value.includes("\0")
    )
      throw new Error("absolute_path_required");
    return value;
  }

  private native(
    args: Record<string, unknown>,
    signal?: AbortSignal,
  ): Promise<unknown> {
    if (!this.child || signal?.aborted)
      return Promise.reject(new Error("computer_disconnected"));
    const id = randomUUID();
    return new Promise((resolve, reject) => {
      const cancel = () => {
        const pending = this.pending.get(id);
        if (!pending) return;
        // The native protocol is sequential: killing it also discards queued input.
        this.stop();
      };
      const done = (fn: () => void) => {
        signal?.removeEventListener("abort", cancel);
        fn();
      };
      const timer = setTimeout(
        cancel,
        args.action === "screenshot" ? 15_000 : 6_000,
      );
      this.pending.set(id, {
        timer,
        resolve: (value) => done(() => resolve(value)),
        reject: (error) => done(() => reject(error)),
      });
      signal?.addEventListener("abort", cancel, { once: true });
      this.child!.stdin.write(
        `${JSON.stringify({ ...args, id })}\n`,
        (error) => {
          if (error) cancel();
        },
      );
    });
  }

  private killShell(child: ReturnType<typeof spawn>) {
    if (!child.pid) return;
    if (process.platform === "win32") {
      const killer = spawn(
        "taskkill.exe",
        ["/PID", String(child.pid), "/T", "/F"],
        { windowsHide: true, stdio: "ignore", shell: false },
      );
      killer.on("error", () => child.kill());
    } else {
      try {
        process.kill(-child.pid, "SIGKILL");
      } catch {
        child.kill();
      }
    }
  }

  private shell(
    args: Record<string, unknown>,
    signal?: AbortSignal,
  ): Promise<unknown> {
    if (
      typeof args.command !== "string" ||
      !args.command ||
      args.command.length > 65536
    )
      throw new Error("invalid_command");
    const command = args.command;
    const cwd = args.cwd === undefined ? undefined : this.filePath(args.cwd);
    return new Promise((resolve, reject) => {
      // Windows PowerShell otherwise emits the legacy console code page, which
      // corrupts accents/emoji when Node reads UTF-8. A fixed encoded launcher
      // reads the script via UTF-8 stdin, preserving quotes and the input size
      // limit without exceeding Windows' much smaller command-line limit.
      const windows = process.platform === "win32";
      const launcher =
        "$ProgressPreference = 'SilentlyContinue'; [Console]::InputEncoding = [Text.UTF8Encoding]::new($false); $OutputEncoding = [Console]::OutputEncoding = [Text.UTF8Encoding]::new($false); & ([scriptblock]::Create([Console]::In.ReadToEnd()))";
      const child = spawn(
        windows ? "powershell.exe" : "/bin/sh",
        windows
          ? [
              "-NoProfile",
              "-NonInteractive",
              "-OutputFormat",
              "Text",
              "-EncodedCommand",
              Buffer.from(launcher, "utf16le").toString("base64"),
            ]
          : ["-c", command],
        {
          cwd,
          windowsHide: true,
          shell: false,
          detached: !windows,
          stdio: [windows ? "pipe" : "ignore", "pipe", "pipe"],
        },
      );
      let termination: ComputerShellError | null = null;
      const terminate = (reason: ComputerShellError) => {
        if (termination) return;
        termination = reason;
        this.killShell(child);
      };
      this.shells.set(child, terminate);
      const cancel = () =>
        terminate(new ComputerShellError("computer_disconnected"));
      signal?.addEventListener("abort", cancel, { once: true });
      // Include cold PowerShell startup in a bounded execution budget. The
      // broker has a 25-second deadline and can still revoke/cancel immediately.
      const timeout = setTimeout(
        () => terminate(new ComputerShellError("computer_shell_timeout")),
        this.shellTimeoutMs,
      );
      const cleanup = () => {
        clearTimeout(timeout);
        signal?.removeEventListener("abort", cancel);
        this.shells.delete(child);
      };
      let output = "";
      const append = (text: string) => {
        const chunk = Buffer.from(text, "utf8");
        const remaining = 1024 * 1024 - Buffer.byteLength(output);
        output += chunk.subarray(0, Math.max(0, remaining)).toString("utf8");
        if (chunk.length >= remaining)
          terminate(new ComputerShellError("computer_shell_output_limit"));
      };
      child.stdout!.setEncoding("utf8").on("data", append);
      child.stderr!.setEncoding("utf8").on("data", append);
      child.on("error", (error) => {
        cleanup();
        reject(termination ?? error);
      });
      child.on("close", (exitCode) => {
        cleanup();
        if (termination) reject(termination);
        else resolve({ exitCode, output });
      });
      if (windows) {
        child.stdin!.on("error", (error) => {
          this.killShell(child);
          cleanup();
          reject(termination ?? error);
        });
        child.stdin!.end(Buffer.from(command, "utf8"));
      }
    });
  }
}
