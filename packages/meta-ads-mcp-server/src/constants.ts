export const FB_API_VERSION = "v22.0";
export const FB_GRAPH_URL = `https://graph.facebook.com/${FB_API_VERSION}`;

export const CHARACTER_LIMIT = 25000;

/**
 * Feature flag: enable mutating tools (create/update/delete/pause/resume) on
 * campaigns, ad sets, and ads. Off by default — these operations are
 * destructive or hard to reverse, so an operator must opt in explicitly.
 *
 * Enable with: META_ADS_ENABLE_WRITE_TOOLS=true (also accepts "1", "yes", "on").
 */
export function isWriteToolsEnabled(): boolean {
  const raw = process.env.META_ADS_ENABLE_WRITE_TOOLS;
  if (!raw) return false;
  return ["true", "1", "yes", "on"].includes(raw.trim().toLowerCase());
}

export const DEFAULT_AD_ACCOUNT_FIELDS = [
  "name",
  "business_name",
  "age",
  "account_status",
  "balance",
  "amount_spent",
  "attribution_spec",
  "account_id",
  "business",
  "business_city",
  "brand_safety_content_filter_levels",
  "currency",
  "created_time",
  "id",
];

export const DATE_PRESETS = [
  "today",
  "yesterday",
  "this_month",
  "last_month",
  "this_quarter",
  "maximum",
  "last_3d",
  "last_7d",
  "last_14d",
  "last_28d",
  "last_30d",
  "last_90d",
  "last_week_mon_sun",
  "last_week_sun_sat",
  "last_quarter",
  "last_year",
  "this_week_mon_today",
  "this_week_sun_today",
  "this_year",
] as const;

export const EFFECTIVE_STATUS_VALUES = [
  "ACTIVE",
  "PAUSED",
  "DELETED",
  "PENDING_REVIEW",
  "DISAPPROVED",
  "PREAPPROVED",
  "PENDING_BILLING_INFO",
  "CAMPAIGN_PAUSED",
  "ARCHIVED",
  "ADSET_PAUSED",
  "IN_PROCESS",
  "WITH_ISSUES",
] as const;
