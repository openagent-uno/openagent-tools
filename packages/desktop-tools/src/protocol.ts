import { createHash } from "node:crypto";
import {
  CLIENT_CAPABILITIES_PROTOCOL,
  type CapabilityToolClassification,
  type DesktopHostSelection,
} from "./contracts";

export interface CapabilityHello {
  type: "capability_hello";
  protocol: typeof CLIENT_CAPABILITIES_PROTOCOL;
  clientInstanceId: string;
  generation: number;
  host: DesktopHostSelection;
  tools: Array<{
    server: string;
    name: string;
    classification: CapabilityToolClassification;
  }>;
}

export interface ClientToolCall {
  type: "client_tool_call";
  callId: string;
  generation: number;
  workspaceId: string;
  agentId: string;
  sessionId: string;
  deviceId: string;
  server: string;
  tool: string;
  classification: CapabilityToolClassification;
  args: Record<string, unknown>;
  idempotencyKey: string;
  argumentsSha256: string;
  deadlineMs?: number;
}

export class CapabilityProtocolError extends Error {
  constructor(
    public readonly code: string,
    message = code,
  ) {
    super(message);
    this.name = "CapabilityProtocolError";
  }
}

export function parseClientToolCall(value: unknown): ClientToolCall {
  if (!value || typeof value !== "object" || Array.isArray(value))
    throw new CapabilityProtocolError("invalid_frame");
  const frame = value as Record<string, unknown>;
  if (frame.type !== "client_tool_call")
    throw new CapabilityProtocolError("unknown_frame");
  const required = [
    "callId",
    "workspaceId",
    "agentId",
    "sessionId",
    "deviceId",
    "server",
    "tool",
    "idempotencyKey",
  ] as const;
  for (const key of required) requireSafeString(frame[key]);
  if (!Number.isInteger(frame.generation) || (frame.generation as number) < 1)
    throw new CapabilityProtocolError("invalid_generation");
  if (
    !frame.args ||
    typeof frame.args !== "object" ||
    Array.isArray(frame.args)
  )
    throw new CapabilityProtocolError("invalid_arguments");
  if (!isClassification(frame.classification))
    throw new CapabilityProtocolError("invalid_classification");
  if (
    typeof frame.argumentsSha256 !== "string" ||
    !/^[a-f0-9]{64}$/.test(frame.argumentsSha256)
  ) {
    throw new CapabilityProtocolError("invalid_arguments_digest");
  }
  if (
    digestArguments(frame.args as Record<string, unknown>) !==
    frame.argumentsSha256
  ) {
    throw new CapabilityProtocolError("arguments_digest_mismatch");
  }
  if (
    frame.deadlineMs !== undefined &&
    (!Number.isFinite(frame.deadlineMs) || (frame.deadlineMs as number) <= 0)
  ) {
    throw new CapabilityProtocolError("invalid_deadline");
  }
  return frame as unknown as ClientToolCall;
}

export function digestArguments(args: Record<string, unknown>): string {
  return createHash("sha256").update(canonicalJSON(args)).digest("hex");
}

function canonicalJSON(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJSON).join(",")}]`;
  const record = value as Record<string, unknown>;
  return `{${Object.keys(record)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${canonicalJSON(record[key])}`)
    .join(",")}}`;
}

function requireSafeString(value: unknown): asserts value is string {
  if (
    typeof value !== "string" ||
    value.length < 1 ||
    value.length > 512 ||
    /[\u0000-\u001f\u007f]/.test(value)
  ) {
    throw new CapabilityProtocolError("invalid_frame");
  }
}

function isClassification(
  value: unknown,
): value is CapabilityToolClassification {
  return (
    value === "read_only" || value === "idempotent" || value === "mutating"
  );
}
