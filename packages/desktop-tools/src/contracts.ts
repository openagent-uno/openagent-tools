export const CLIENT_CAPABILITIES_PROTOCOL = "client-capabilities/1" as const;
export type CapabilityToolClassification =
  | "read_only"
  | "idempotent"
  | "mutating";
export interface DesktopHostSelection {
  workspaceId: string;
  agentId: string;
  sessionId: string;
  deviceId: string;
  deviceLabel: string;
}
