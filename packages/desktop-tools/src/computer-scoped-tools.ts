import { createHash, randomUUID } from "node:crypto";
import { HostProcessBridge, type HostToolsLaunch } from "./host-bridge";
import { digestArguments, type ClientToolCall } from "./protocol";
import type { ComputerInvocationContext } from "./computer-accessibility";

// Float32 stereo at24kHz plus base64 must fit the existing32MiB v2 frame.
// The standalone native provider may retain its longer local-only limit.
const MAX_SHARED_AUDIO_MS = 120_000;
type ScopedTool = {
  name?: string;
  input_schema?: Record<string, unknown>;
  [key: string]: unknown;
};
function sharedNativeCatalog(tools: ScopedTool[]): ScopedTool[] {
  return tools.map((tool) => {
    if (tool.name !== "computer_audio_start" || !tool.input_schema) return tool;
    const schema = structuredClone(tool.input_schema),
      properties = schema.properties as Record<string, unknown> | undefined;
    if (
      properties &&
      properties.max_duration_ms &&
      typeof properties.max_duration_ms === "object"
    ) {
      properties.max_duration_ms = {
        ...properties.max_duration_ms,
        maximum: MAX_SHARED_AUDIO_MS,
      };
    }
    return { ...tool, input_schema: schema };
  });
}

function scopeKey(context: ComputerInvocationContext): string {
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
    throw new Error("computer_scope_unavailable");
  return JSON.stringify([
    context.workspaceId,
    context.computerId,
    context.generation,
    context.actorUserId,
    context.sessionId,
  ]);
}
export type BrowserScopeInventory = ComputerInvocationContext & {
  scopeId: string;
  inventory: unknown;
};
type Entry = {
  context: ComputerInvocationContext;
  bridge: HostProcessBridge;
  ready: Promise<void>;
};

/** Product adapter only. Shared native/browser implementation stays in Tools. */
export class ComputerScopedTools {
  private entries = new Map<string, Entry>();
  private epoch = 0;
  constructor(private readonly launch: HostToolsLaunch) {}

  async invoke(
    kind: "native" | "browser",
    args: Record<string, unknown>,
    context: ComputerInvocationContext,
    signal?: AbortSignal,
  ): Promise<unknown> {
    const key = scopeKey(context);
    if (signal?.aborted) throw new Error("computer_disconnected");
    const listing = args.action === "catalog";
    if (
      !listing &&
      (typeof args.name !== "string" ||
        !/^[A-Za-z][A-Za-z0-9_-]{0,127}$/.test(args.name) ||
        !args.arguments ||
        typeof args.arguments !== "object" ||
        Array.isArray(args.arguments))
    )
      throw new Error("invalid_computer_tool_arguments");
    const server = kind === "native" ? "computer-control" : "agent-in-chrome";
    if (
      !listing &&
      kind === "native" &&
      !(args.name as string).startsWith("computer")
    )
      throw new Error("invalid_computer_native_tool");
    if (!listing && kind === "native" && args.name === "computer_audio_start") {
      const duration = (args.arguments as Record<string, unknown>)
        .max_duration_ms;
      if (
        duration !== undefined &&
        (typeof duration !== "number" ||
          !Number.isSafeInteger(duration) ||
          duration < 1 ||
          duration > MAX_SHARED_AUDIO_MS)
      )
        throw new Error("computer_audio_transport_duration_limit_120000ms");
    }
    const revision = this.epoch;
    let entry = this.entries.get(key);
    if (!entry) {
      if (this.entries.size >= 8) throw new Error("computer_scoped_tools_busy");
      const bridge = new HostProcessBridge(
        this.launch,
        async () => context.actorUserId,
        createHash("sha256").update(key).digest("hex"),
      );
      const selected = {
        workspaceId: context.workspaceId,
        agentId: "computer-session",
        sessionId: context.sessionId,
        deviceId: "scoped_" + createHash("sha256").update(key).digest("hex"),
        deviceLabel: "Shared computer " + context.computerId,
      };
      const ready = bridge.start(selected, context.generation);
      entry = { context: { ...context }, bridge, ready };
      this.entries.set(key, entry);
      ready.catch(() => {
        if (this.entries.get(key)?.bridge === bridge) this.entries.delete(key);
      });
    }
    await entry.ready;
    if (
      revision !== this.epoch ||
      this.entries.get(key) !== entry ||
      signal?.aborted
    )
      throw new Error("computer_disconnected");
    const catalog = (await entry.bridge.catalog()) as {
      servers?: Array<{ name?: string; tools?: ScopedTool[] }>;
    };
    const source = catalog?.servers?.find((value) => value.name === server);
    if (listing)
      return {
        server,
        available: !!source,
        tools:
          kind === "native"
            ? sharedNativeCatalog(source?.tools ?? [])
            : (source?.tools ?? []),
      };
    if (
      !catalog?.servers?.some(
        (source) =>
          source.name === server &&
          source.tools?.some((tool) => tool.name === args.name),
      )
    )
      throw new Error("computer_tool_unsupported_by_installed_bundle");
    const arguments_ = args.arguments as Record<string, unknown>;
    const call: ClientToolCall = {
      type: "client_tool_call",
      callId: randomUUID(),
      generation: context.generation,
      workspaceId: context.workspaceId,
      agentId: "computer-session",
      sessionId: context.sessionId,
      deviceId: context.computerId,
      server,
      tool: args.name as string,
      classification: "mutating",
      args: arguments_,
      idempotencyKey: randomUUID(),
      argumentsSha256: digestArguments(arguments_),
      deadlineMs: 20_000,
    };
    return entry.bridge.invoke(call, signal);
  }

  async browserInventories(): Promise<BrowserScopeInventory[]> {
    const revision = this.epoch;
    return Promise.all(
      [...this.entries].map(async ([key, entry]) => {
        await entry.ready;
        if (revision !== this.epoch || this.entries.get(key) !== entry)
          throw new Error("computer_disconnected");
        const inventory = await entry.bridge.browserInventory();
        if (revision !== this.epoch || this.entries.get(key) !== entry)
          throw new Error("computer_disconnected");
        return {
          scopeId: createHash("sha256").update(key).digest("hex"),
          ...entry.context,
          inventory,
        };
      }),
    );
  }

  async browserDecision(
    scopeId: string,
    decision: {
      tool: "browser_control" | "browser_permissions";
      args: Record<string, unknown>;
    },
  ): Promise<unknown> {
    const pair = [...this.entries].find(
      ([key]) => createHash("sha256").update(key).digest("hex") === scopeId,
    );
    if (!pair) throw new Error("computer_scope_expired");
    const [key, entry] = pair;
    const revision = this.epoch;
    await entry.ready;
    if (revision !== this.epoch || this.entries.get(key) !== entry)
      throw new Error("computer_disconnected");
    return entry.bridge.providerControl(decision);
  }

  release(workspaceId: string, computerId: string, generation: number): void {
    for (const [key, entry] of this.entries) {
      if (
        entry.context.workspaceId !== workspaceId ||
        entry.context.computerId !== computerId ||
        entry.context.generation !== generation
      )
        continue;
      this.entries.delete(key);
      void entry.bridge.hardStop().catch(() => {});
    }
  }
  stop(): void {
    this.epoch++;
    for (const entry of this.entries.values())
      void entry.bridge.hardStop().catch(() => {});
    this.entries.clear();
  }
}
