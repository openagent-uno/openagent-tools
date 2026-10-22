# Central OAuth activation audit — 21 October 2026

**22 October update:** Gmail's subsequent [central technical qualification](central-gmail-qualification-2026-10-22.md)
passed using six unchanged operation paths plus the corrected live attachment
path. Its general availability remains disabled pending Google review. The
findings below retain the original 21 October audit snapshot.

The production ConfigMap was read without reading Secret values: the existing
broker has 15 configured OAuth provider profiles. The central/v1 service serves
catalog revision 2, with only CoinGecko qualified and available. **None of the
15 OAuth profiles currently has sufficient evidence for general central/v1
activation.** This is distinct from their working legacy/local connections.
No registration, secret, scope, provider grant, qualification list or production
configuration was changed for this audit. No new account or subscription was
requested or created.

The SDK13 [central qualification](../deploy/connector-auth/qualification-2026-10-21-central-v1.json)
qualifies the shared protocol with synthetic OAuth providers and a real public
CoinGecko read. It does not qualify real OAuth accounts in central custody.
Existing apps and credentials can be retained; creating duplicate apps is not
the missing step. Existing user tokens must not be imported, silently migrated
or relabelled as centrally consented credentials.

## Reusable evidence and remaining gates

Provider IDs below are broker IDs. Some catalog IDs differ: `google-calendar`,
`google-drive`, `google-analytics`, `outlook-mail`, `outlook-calendar` and
`slack-import` use hyphens. Qualification configuration accepts exact catalog IDs.

| Provider IDs | Existing real legacy evidence | Remaining specific gates for central activation |
| --- | --- | --- |
| `clickup` | OAuth, read, generated task write/cleanup, restart/read and disconnect; non-expiring token, no refresh claim. [Checkpoint](../deploy/connector-auth/qualification-2026-10-14.md) | Fresh central lifecycle; remaining tools are not all covered by the limited task trial. Public app identity verification remains recorded as pending. |
| `github` | Selected QA repository, OAuth, repository read, issue create/read/close, refresh, restart/read and disconnect. [Receipt](https://github.com/openagent-uno/openagent/blob/main/docs/qualification/github-oauth-2026-10-16.json) | Fresh central lifecycle with the same GitHub App installation/repository restriction. No additional mandatory connection Config found in current adapters; empty OAuth scopes are intentional app-defined permissions. |
| `notion` | Selected QA page, read, reversible update/cleanup, refresh, restart/read and disconnect. [Receipt](https://github.com/openagent-uno/openagent/blob/main/docs/qualification/notion-oauth-2026-10-16.json) | Fresh central lifecycle and remaining operations; public OAuth connection is distinct from its unpublished marketplace listing. No mandatory Config bootstrap found; global revocation is not qualified by the limited trial. |
| `slack_import` | QA workspace/channel, OAuth, reads, message create/read/delete, refresh after correction, restart/read and disconnect. [Receipt](https://github.com/openagent-uno/openagent/blob/main/docs/qualification/slack-oauth-2026-10-16.json) | Fresh central lifecycle. Public Distribution is recorded active; this is not Marketplace approval. Verified team identity is already extracted by OAuth and copied into Binding.ExternalID; no additional mandatory Config found. |
| `gmail` | Read, new draft and one self-addressed send, refresh, restart/read and disconnect. [Google demo](https://github.com/openagent-uno/openagent/blob/main/docs/qualification/google-demo-product-1.1.0b47-2026-10-19.json) | Fresh central lifecycle, Google review and treatment/disclosure alignment below. Other recipients, attachments and remaining operations not qualified. |
| `google_drive` | Search, generated file create/download/update and lifecycle; UI cleanup verified by API. [Google demo](https://github.com/openagent-uno/openagent/blob/main/docs/qualification/google-demo-product-1.1.0b47-2026-10-19.json) | Fresh central lifecycle and Google gates. API trash is not exposed/qualified; no inference of complete Drive surface acceptance. |
| `google_calendar` | Calendar list; owner-verified primary-calendar event create/get/ETag-update/get/delete without invitees; lifecycle. [Google demo](https://github.com/openagent-uno/openagent/blob/main/docs/qualification/google-demo-product-1.1.0b47-2026-10-19.json) | Fresh central lifecycle and Google gates. No invitation/attendee acceptance. Adapter requires empty Config; calendar/event IDs remain typed operation arguments. |
| `google_analytics` | Non-empty account summaries, refresh, restart/read and disconnect. [Receipt](https://github.com/openagent-uno/openagent/blob/main/docs/qualification/google-four-product45-oauth-2026-10-19.json) | Fresh central lifecycle and Google gates; no real report operation is qualified. No mandatory account Config bootstrap found. |
| `outlook_mail` | Separate Mail app, folders.list, refresh, restart/read and disconnect. [Receipt](https://github.com/openagent-uno/openagent/blob/main/docs/qualification/microsoft-three-product45-oauth-2026-10-19.json) | Fix central OAuth scope construction below, then fresh central lifecycle. Body/draft/send not qualified. Retain the separate Mail app, not the superseded cumulative app. |
| `outlook_calendar` | Separate Calendar app; editable-calendar event create/read/update/read/delete without attendees; refresh, restart/read and disconnect. [Receipt](https://github.com/openagent-uno/openagent/blob/main/docs/qualification/outlook-calendar-product-1.1.0b47-2026-10-19.json) | Fix central scope construction, then fresh central lifecycle. No primary/private-calendar or invitation guarantee. |
| `onedrive` | Separate app, non-empty drives.list and lifecycle. [Receipt](https://github.com/openagent-uno/openagent/blob/main/docs/qualification/microsoft-three-product45-oauth-2026-10-19.json) | Fix central scopes; add verified hosted drive selection/binding for operations beyond drives.list; real file-content and central lifecycle acceptance. No automatic drive provisioning. |
| `sharepoint` | Personal account rejected before consent; pending connection normally disconnected. [Receipt](https://github.com/openagent-uno/openagent/blob/main/docs/qualification/microsoft-three-product45-oauth-2026-10-19.json) | Fix central scopes and hosted site/drive binding. Requires an already eligible work/school account for real consent/site read and lifecycle. No callback/token/site-data acceptance exists; no paid-license requirement is inferred. |
| `atlassian` | Private app-owner trial of all nine released operations, refresh, restart/read and disconnect; UI-reconciled absence of generated issue, not captured API delete success. [Receipt](https://github.com/openagent-uno/openagent/blob/main/docs/qualification/jira-product-1.1.0b49-2026-10-19.json) | Hosted verified Jira site selection/persistence and fresh central lifecycle. Public sharing remains disabled; Personal Data Reporting API and erasure/refresh obligations are not implemented/qualified. |
| `postiz` | OAuth and disconnect succeeded; advertised integrations read failed, with provider HTTP cause unobserved. [Receipt](https://github.com/openagent-uno/openagent/blob/main/docs/qualification/postiz-product-1.1.0b47-2026-10-19.json) | Fix central credential scheme; establish real API access and central lifecycle. The 19 October account UI showed a plan/card prerequisite and no subscription was activated; that observation does not establish the failed call's HTTP cause. Refresh is not supported by the recorded protocol. |
| `shopify` | Original approved app, bounded two-host reads/rotation/recovery and restart; synthetic privacy exercises, later genuine uninstall receipt processing on already disconnected profiles. [Receipt](https://github.com/openagent-uno/openagent/blob/main/docs/qualification/shopify-product-1.1.0b51-2026-10-19.json) | New central architecture qualification, issuer/rotation/recovery coordination, genuine privacy delivery and selective data actions with verified recipient completion. Previously empty credentials and synthetic exports do not prove real customer-content erasure. General legacy enrollment remains paused; central is hard-denied in three code paths. |

## Concrete implementation gaps

These are findings in released SDK13, not new provider acceptance claims:

1. **Microsoft authorization scope selection.** Central `create` unions only
   selected operations' `RequiredScopes` and supplies them explicitly to
   `BeginCentral` ([server](../packages/connectors/central/server.go)). All four
   Microsoft families require `User.Read` for verified account identity and
   `offline_access` for renewal in the existing OAuth engine
   ([provider](../packages/connectors/oauth/provider.go)). Selected operation
   scope lists do not include these bootstrap requirements. Read operations can
   request Basic scopes not present exactly in the configured ReadWrite profile;
   OAuth request validation is exact. The runtime has a provider-owned operation
   scope policy, but that does not repair the earlier authorization request.
   Preserve the existing per-family apps and approved scopes; implement scope
   construction in the shared service/library, not in each consumer.
2. **Hosted source selection.** Jira's eight non-discovery operations require a
   verified `Config.cloud_id`; OneDrive requires `drive_id` beyond drives.list;
   SharePoint binds `site_id` and then `drive_id` for its full file surface.
   Central currently persists initial `Create.Config` but has no hosted,
   post-OAuth verified selection/update flow. Legacy site/drive discovery and CAS
   selection exist in the product code; reuse/extract those semantics upstream.
   Do not require provider-specific consumer forms or let model arguments select
   the bound site/drive. Discovery alone does not qualify the remaining tools.
3. **Postiz credential scheme.** Central invocation hardcodes
   `Authorization: Bearer`; the trusted Postiz manifest requires `Authorization`
   without a scheme. `Credential.Apply` rejects that mismatch before provider IO
   ([central](../packages/connectors/central/server.go),
   [manifest](../packages/connectors/providers/manifests.go),
   [credential contract](../packages/connectors/domain/types.go)). Choose the
   credential target from the trusted shared adapter contract; do not add a
   provider condition in consuming products.
4. **Qualification granularity.** Current `qualified_catalog_ids` enables an
   entire descriptor, not an independent tested-operation subset. Many historical
   receipts cover only selected tools. Connection grants pin explicit operation
   sets, but this alone is not proof that every advertised operation was tested.

Google's branding and `is_agentic` were confirmed in the authenticated console
on 21 October; data access remained in review. No restricted-scope approval or
security assessment completion is documented. The submitted
[verification dossier](https://github.com/openagent-uno/openagent/blob/main/docs/verification/google-production-verification-2026-10-19.md)
describes the earlier receiving-host credential/API path. It does not attest
the new central custody/processing path. Reconcile the actual data flow,
disclosures and verification evidence before claiming general approval. The
review is a provider gate, not a reason to create another Google app.

## Smallest next qualification sequence

First candidates are ClickUp, GitHub, Notion and Slack: they have limited real
legacy lifecycles and no additional mandatory resource-selection bootstrap was
found. This prioritization is an inference from the existing receipts and code,
not a finding that they are already central-qualified. Next address Microsoft
shared scope construction, Calendar/Mail, then the hosted file/site selections.
Google, Jira public sharing, SharePoint account eligibility, Postiz account/API
access and Shopify retain the separate gates above.

For each candidate retain the same official app, add a fresh consent disclosing
central custody to an explicitly bound recipient, and qualify the real central
path: encrypted save, selected read/authorized temporary write as applicable,
refresh where supported, service/vault reopen after restart, recipient isolation,
no reusable tokens in consumer responses, disconnect and subsequent denial.
Synthetic OAuth tests and broker health cannot replace these real acceptance
receipts. No consumer needs a provider-specific OAuth implementation for the
currently supported generic hosted authorization/status contract.
