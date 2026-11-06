/** Explicit per-server sharing over authenticated Computers v2, never the legacy relay. */
import { createHash, randomUUID } from "node:crypto";
import { HostProcessBridge, type HostToolsLaunch } from "./host-bridge";
import { digestArguments, type ClientToolCall } from "./protocol";
import type { ComputerInvocationContext } from "./computer-accessibility";

type Row = {
  server: string;
  version: string;
  resource_protocol: "mcp-app-resources/1";
  tools: Record<string, unknown>[];
  catalog_digest: string;
};
type Entry = {
  bridge: HostProcessBridge;
  ready: Promise<void>;
  context: ComputerInvocationContext;
};
const record = (value: unknown): value is Record<string, unknown> =>
  !!value && typeof value === "object" && !Array.isArray(value);
const safeName = (value: unknown): value is string =>
  typeof value === "string" && /^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/.test(value);
function scope(context: ComputerInvocationContext): string {
  if (
    !context ||
    ![
      context.workspaceId,
      context.computerId,
      context.actorUserId,
      context.sessionId,
    ].every(
      (value) =>
        typeof value === "string" &&
        /^[A-Za-z0-9][A-Za-z0-9_.:@-]{0,255}$/.test(value),
    ) ||
    !Number.isSafeInteger(context.generation) ||
    context.generation < 1
  )
    throw new Error("computer_mcp_scope_unavailable");
  return JSON.stringify([
    context.workspaceId,
    context.computerId,
    context.generation,
    context.actorUserId,
    context.sessionId,
  ]);
}
export function sharedMcpServers(value: unknown): string[] {
  if (value === undefined) return [];
  if (
    !Array.isArray(value) ||
    value.length > 32 ||
    value.some((name) => !safeName(name)) ||
    new Set(value).size !== value.length
  )
    throw new Error("invalid_shared_mcp_servers");
  return [...value] as string[];
}
function ready(promise: Promise<void>, signal?: AbortSignal): Promise<void> {
  if (!signal) return promise;
  if (signal.aborted) return Promise.reject(new Error("computer_disconnected"));
  return new Promise((resolve, reject) => {
    const abort = () => {
      signal.removeEventListener("abort", abort);
      reject(new Error("computer_disconnected"));
    };
    signal.addEventListener("abort", abort, { once: true });
    promise.then(
      () => {
        signal.removeEventListener("abort", abort);
        resolve();
      },
      (error) => {
        signal.removeEventListener("abort", abort);
        reject(error);
      },
    );
  });
}
function declared(tool: Record<string, unknown>): unknown {
  const meta = record(tool._meta) ? tool._meta : {},
    ui = record(meta.ui) ? meta.ui : {};
  return ui.resourceUri ?? meta["ui/resourceUri"];
}
function normalizeCatalog(value: unknown, allowed: string[]): Row[] {
  if (
    !record(value) ||
    !Array.isArray(value.servers) ||
    value.servers.length > 128
  )
    throw new Error("computer_mcp_invalid_catalog");
  const rows: Row[] = [],
    seen = new Set<string>();
  for (const source of value.servers) {
    if (
      !record(source) ||
      !safeName(source.name) ||
      !allowed.includes(source.name) ||
      source.resource_protocol !== "mcp-app-resources/1"
    )
      continue;
    if (
      seen.has(source.name) ||
      !Array.isArray(source.tools) ||
      source.tools.length > 512
    )
      throw new Error("computer_mcp_invalid_catalog");
    seen.add(source.name);
    const names = new Set<string>(),
      tools: Record<string, unknown>[] = [];
    for (const raw of source.tools) {
      if (
        !record(raw) ||
        !safeName(raw.name) ||
        names.has(raw.name) ||
        !record(raw.input_schema) ||
        (raw._meta !== undefined && !record(raw._meta))
      )
        throw new Error("computer_mcp_invalid_catalog");
      names.add(raw.name);
      const metadata = record(raw._meta) ? raw._meta : {};
      if (Buffer.byteLength(JSON.stringify(metadata)) > 65536)
        throw new Error("computer_mcp_invalid_catalog");
      const classification = raw.classification ?? "mutating";
      if (
        !["read_only", "idempotent", "mutating"].includes(
          String(classification),
        )
      )
        throw new Error("computer_mcp_invalid_catalog");
      tools.push({
        name: raw.name,
        description: typeof raw.description === "string" ? raw.description : "",
        input_schema: raw.input_schema,
        classification,
        ...(record(raw.classification_by_argument)
          ? { classification_by_argument: raw.classification_by_argument }
          : {}),
        ...(Object.keys(metadata).length ? { _meta: metadata } : {}),
      });
    }
    const entry = {
      server: source.name,
      version: typeof source.version === "string" ? source.version : "unknown",
      resource_protocol: "mcp-app-resources/1" as const,
      tools,
    };
    if (Buffer.byteLength(JSON.stringify(entry)) > 1024 * 1024)
      throw new Error("computer_mcp_catalog_limit");
    rows.push({ ...entry, catalog_digest: digestArguments(entry) });
  }
  if (Buffer.byteLength(JSON.stringify(rows)) > 2 * 1024 * 1024)
    throw new Error("computer_mcp_catalog_limit");
  return rows;
}

export class ComputerMcpTools {
  private entries = new Map<string, Entry>();
  private epoch = 0;
  constructor(private readonly launch: HostToolsLaunch | (() => Promise<HostToolsLaunch>)) {}
  async invoke(
    args: Record<string, unknown>,
    context: ComputerInvocationContext,
    signal?: AbortSignal,
  ): Promise<unknown> {
    const key = scope(context),
      allowed = sharedMcpServers(context.sharedMcpServers);
    if (!record(args)) throw new Error("computer_mcp_invalid_operation");
    const operation = args.operation;
    if (
      !record(args) ||
      Object.keys(args).some(
        (name) =>
          ![
            "operation",
            "server",
            "name",
            "arguments",
            "uri",
            "catalog_digest",
          ].includes(name),
      ) ||
      !["catalog", "call", "read_resource"].includes(String(operation))
    )
      throw new Error("computer_mcp_invalid_operation");
    if (signal?.aborted) throw new Error("computer_disconnected");
    if (!allowed.length) {
      if (operation === "catalog") return { servers: [] };
      throw new Error("computer_mcp_not_shared");
    }
    if (
      operation !== "catalog" &&
      (!safeName(args.server) || !allowed.includes(args.server))
    )
      throw new Error("computer_mcp_not_shared");
    if (
      operation === "catalog" &&
      args.server !== undefined &&
      !safeName(args.server)
    )
      throw new Error("computer_mcp_invalid_operation");
    const selected =
      typeof args.server === "string"
        ? allowed.filter((name) => name === args.server)
        : allowed;
    if (operation === "catalog" && !selected.length) return { servers: [] };
    const revision = this.epoch;
    let entry = this.entries.get(key);
    if (!entry) {
      if (this.entries.size >= 8) throw new Error("computer_mcp_busy");
      const digest = createHash("sha256").update(key).digest("hex"),
        bridge = new HostProcessBridge(
          this.launch,
          async () => context.actorUserId,
          digest,
        );
      const ready = bridge.start(
        {
          workspaceId: context.workspaceId,
          agentId: "computer-session",
          sessionId: context.sessionId,
          deviceId: "scoped_" + digest,
          deviceLabel: "Shared computer " + context.computerId,
        },
        context.generation,
      );
      entry = {
        bridge,
        ready,
        context: { ...context, sharedMcpServers: [...allowed] },
      };
      this.entries.set(key, entry);
      ready.catch(() => {
        if (this.entries.get(key)?.bridge === bridge) this.entries.delete(key);
      });
    }
    await ready(entry.ready, signal);
    this.current(key, entry, revision, signal);
    const rows = normalizeCatalog(await entry.bridge.catalog(signal), selected);
    this.current(key, entry, revision, signal);
    if (operation === "catalog") return { servers: rows };
    const source = rows.find((row) => row.server === args.server);
    if (
      !source ||
      typeof args.catalog_digest !== "string" ||
      args.catalog_digest !== source.catalog_digest
    )
      throw new Error("computer_mcp_catalog_changed");
    let result: unknown;
    if (operation === "read_resource") {
      if (
        typeof args.uri !== "string" ||
        !args.uri.startsWith("ui://") ||
        args.uri.length > 4096 ||
        /[\u0000-\u001f\u007f]/.test(args.uri) ||
        !source.tools.some((tool) => declared(tool) === args.uri)
      )
        throw new Error("computer_mcp_resource_not_declared");
      result = await entry.bridge.readResource(
        {
          callId: randomUUID(),
          server: source.server,
          uri: args.uri,
          deadlineMs: 20000,
        },
        signal,
      );
    } else {
      if (
        !safeName(args.name) ||
        !record(args.arguments) ||
        !source.tools.some((tool) => tool.name === args.name)
      )
        throw new Error("computer_mcp_tool_not_declared");
      const call: ClientToolCall = {
        type: "client_tool_call",
        callId: randomUUID(),
        generation: context.generation,
        workspaceId: context.workspaceId,
        agentId: "computer-session",
        sessionId: context.sessionId,
        deviceId: context.computerId,
        server: source.server,
        tool: args.name,
        classification: "mutating",
        args: args.arguments,
        idempotencyKey: randomUUID(),
        argumentsSha256: digestArguments(args.arguments),
        deadlineMs: 20000,
      };
      result = await entry.bridge.invoke(call, signal);
    }
    this.current(key, entry, revision, signal);
    const after = normalizeCatalog(
      await entry.bridge.catalog(signal),
      sharedMcpServers(context.sharedMcpServers).filter(
        (name) => name === source.server,
      ),
    ).find((row) => row.server === source.server);
    if (after?.catalog_digest !== source.catalog_digest)
      throw new Error("computer_mcp_catalog_changed");
    this.current(key, entry, revision, signal);
    return result;
  }
  private current(
    key: string,
    entry: Entry,
    revision: number,
    signal?: AbortSignal,
  ) {
    if (
      revision !== this.epoch ||
      this.entries.get(key) !== entry ||
      signal?.aborted
    )
      throw new Error("computer_disconnected");
  }
  release(workspaceId: string, computerId: string, generation: number): void {
    for (const [key, entry] of this.entries)
      if (
        entry.context.workspaceId === workspaceId &&
        entry.context.computerId === computerId &&
        entry.context.generation === generation
      ) {
        this.entries.delete(key);
        void entry.bridge.hardStop().catch(() => {});
      }
  }
  async close(): Promise<void> {
    this.epoch++;
    const entries = [...this.entries.values()];
    this.entries.clear();
    await Promise.all(entries.map((entry) => entry.bridge.hardStop()));
  }
  stop(): void {
    void this.close().catch(() => {});
  }
}
