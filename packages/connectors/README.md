# OpenAgent official connectors

Shared Go module `github.com/openagent-uno/openagent-tools/packages/connectors`.
The published SDK/runner is **0.1.6**. The working source candidate is **0.1.7**;
it adds Google Calendar, Outlook Mail and Outlook Calendar and must complete
remote qualification before publication. Embedding hosts link this module into
their local gateways. The standalone server invokes the same adapters through
`openagent-connector-runner` and the `openagent-connectors` Python package.
OpenAgent Core receives managed capability sources through its public catalog
APIs; it does not import product accounts, OAuth or storage code.

Published 0.1.6 contains nineteen official entries, including five read-only
keyless services. The [SDK qualification](../../docs/connector-keyless-0.1.6-qualification.json)
and [coverage index](../../docs/chatgpt-app-coverage.md) distinguish fixture checks,
actual provider calls, product execution and native acquisition. These are
finite operation subsets, not full feature parity with ChatGPT apps.

Google Calendar and Outlook's candidate boundaries, account binding, scopes,
page/sync cursors and remaining registration gates are in the
[candidate contract](../../docs/connector-calendar-mail-0.1.7-candidate.md).
Product-local credential storage, authorization and API execution remain the
host's responsibility. API writes have no automatic retry.

Common-provider enrollment is enabled only for the specifically admitted
provider/app configurations. Provider registration alone is not activation.
The [16 October registration checkpoint](../../deploy/connector-auth/qualification-2026-10-16.md)
is historical; use the current public coverage/status pages for later evidence.
Legacy own-app connections retain their issuer and require new consent to move
registrations.

Version 0.1.2 adds a durable fence for the calling installation/provider/app grant during revocation and explicit installation/store admission for real-provider QA. This fence does not correlate other Google aliases, consents or servers by account; those bindings depend on Google's project-wide revocation and local handling of `401`/`invalid_grant`. No additional account-identity scopes are requested. The QA mode is unavailable to public enrollment and reports `/readyz` as 503. See [the operator procedure and exact revocation limits](../../deploy/connector-auth/qa-enrollment.md). Rollback must retain the new broker and its metadata; an older broker can lose revocation tombstones. Artifacts use the exact Go 1.26.9 toolchain, record it in their manifests and pin `golang.org/x/text` 0.41.0. The versioned library does not activate provider apps or bypass product privacy/release gates.

Version 0.1.3 is a Postiz protocol correction: its registered app determines the callback, authorization/token requests omit `redirect_uri`, and the confidential code exchange uses JSON. The [official Postiz OAuth contract](https://docs.postiz.com/oauth) returns non-expiring access tokens; refresh is not applicable, and account holders revoke access through Postiz Approved Apps. The previous test incorrectly modeled Postiz as an expiring PKCE/form provider. Dedicated fixtures now verify exact request fields/content type, callback omission, sanitized failures and no retry/redirect of code exchange. Catalog IDs, tools, scopes and product credentials are unchanged. This candidate does not establish a real Postiz registration or user grant; a real Postiz registration still needs operator verification, and public common enrollment remains closed. Version 0.1.2 artifacts and existing host pins remain immutable until consumers explicitly adopt a qualified 0.1.3 release.

## Ownership and compatibility

The module includes the complete implemented adapter set, its schemas, pagination, controlled egress, scope gates and tests. `provenance.json` identifies the extraction source and original file digests. Existing catalog IDs and tool names are preserved; GitHub fills its existing ID, Notion and Atlassian add new IDs, and Slack implements the existing `slack-import` catalog ID with provider identity `slack_import`. Slack is no longer an unimplemented placeholder in the 0.1.4 source candidate; this does not change immutable published 0.1.3 catalogs. An implemented OAuth adapter still requires the receiving host to enable a qualified registration; the server marks unavailable authorizations accordingly. Custom MCP management remains a host capability.

The consuming host supplies a previously authorized `Binding`, credential, operation ID and audit. It owns users, tenant/project ACLs, grants, budgets, durable encrypted credential storage, local privacy actions and concurrency with revocation. `Runtime.Tools` applies catalog/scope/write gates; tool arguments cannot choose another credential or installation. Normal provider API traffic originates at the consuming host, never the broker. Existing provider-specific retry budgets stay in the adapters. Token exchange, refresh and mutating calls are not blindly retried.

The Python runner protocol is trusted server IPC, not a network endpoint. Credentials travel only in stdin, nested separately from tool arguments. It never accepts tool arguments as process configuration. `openagent_connectors.mcp.serve_connector` is an MCP transport adapter for a host-supplied, authorizing connector factory.

## Authentication contract v1

`connector-auth` runs separately on `auth.openagent.uno`. Only installation/product metadata, token fingerprints, Shopify group versions and encrypted minimized webhook jobs are durable. No access/refresh tokens, codes or installation private keys belong in broker state, manifests, logs or backups. Token fingerprints use a keyed HMAC; the peer credential digest additionally verifies that encrypted peer content came from the current broker exchange.

Installations use persistent Ed25519 signing and X25519 encryption identities. Signed requests cover method, path/query, body hash, timestamp and nonce. Registration is open to third parties, subject to limits. The consent page displays the operator-supplied product/name, cryptographic installation ID and permissions; it explicitly does not imply endorsement.

After the CSRF-protected consent POST, the broker shows an explicit provider authorization link. The user opens that link to continue on ClickUp, Google, Shopify or Postiz. This avoids a cross-origin redirect after a form submission while preserving `form-action 'self'`, all other CSP directives, no-referrer navigation and the existing recipient/state checks. It does not exchange credentials or activate a provider before the provider's callback.

Reopening that page recovers the same provider link only after a successful consent POST, while the transaction is pending, unexpired and its provider/app/recipient remain admitted. A missing or rejected POST still shows the disclosure form; GET never approves consent or rearms its consumed CSRF token.

| Endpoint | Purpose |
| --- | --- |
| `POST /v1/installations` | Self-signed identity registration |
| `POST /v1/transactions` | Provider/scopes bound, ten-minute authorization |
| `GET/POST /authorize/{id}` | Recipient disclosure and CSRF-protected consent |
| `GET /v1/oauth/{provider}/callback` | Provider callback, state and Shopify HMAC verification |
| `GET /v1/transactions/{id}` | Signed owner-only status |
| `POST /v1/transactions/{id}/redeem` | Single-use exchange; transient token response |
| `POST /v1/refresh` | App/installation/scope-bound renewal |
| `POST /v1/revoke` | Explicit global provider revocation (where supported) |
| `POST /v1/groups/{id}/commit` | Acknowledge atomic local persistence |
| `POST /v1/groups/{id}/disconnect` | Remove only this recipient |
| `POST /v1/groups/{id}/recover` | Ask a current peer for an encrypted copy |
| `GET/POST /v1/mail` | Temporary encrypted envelopes and recovery requests |
| `POST /v1/webhooks/shopify` | HMAC-verified mandatory privacy/uninstall webhooks |
| `GET /v1/events`, `POST /v1/events/{id}/ack` | Durable retryable, deduplicated host delivery |

## Shopify rotation

One lock and generation exist per OAuth app and shop. Acquisition and refresh reserve that lock before contacting Shopify. The requesting host stores the entire new pair atomically, then commits and publishes one signed X25519/AES-GCM envelope per previously authorized recipient. Envelopes expire within ten minutes and exist only in broker memory. Peers validate the broker's current app/shop/scopes/generation/grant timestamp and credential digest before saving. No recipient joins without its own verified Shopify consent. Host tool permissions remain independent.

A missed envelope is recovered from a current peer via outgoing polling. If no current copy is available, the host requests new consent. A broker crash during an uncertain provider exchange persists `reconnect:true`; it cannot silently reuse an older generation. A host that already saved a completed exchange can commit that checkpoint after broker restart. The first implementation is deliberately single writer: one replica, `Recreate`, one PVC. Do not scale it or mount the same metadata file from multiple processes; a distributed transactional store is required before HA.

Privacy recipients remain in the durable delivery set after product disconnection. Jobs retain only the customer/order identifiers needed by the recipient, encrypted at rest. Hosts acknowledge durable local receipt, retry their local processing and deduplicate. A delayed uninstall from an older grant cannot revoke a later reauthorization. The standalone retains a local encrypted privacy inbox; processing/export/redaction of stored agent content is not yet implemented in that product and blocks Shopify activation there.

## Build and release

Version 0.1.1 binds Shopify grants to their numeric shop ID with a fixed, minimal GraphQL identity query during confidential OAuth exchange. Only ID/domain authorization metadata are retained; no shop contents are archived centrally. Signed webhook IDs must match this identity before acting on a group, since the body's HMAC does not authenticate routing headers. Peers verify the same identity during recovery.

Reviewed `--legacy-shopify-webhooks` routes preserve the existing app's product privacy processor through a durable encrypted outbox, including shops not yet enrolled in a broker group. Notifications are minimized, signed for the same app, keep their webhook ID/time, and retry offline recipients after restart without following redirects. A native recipient's acknowledgment cannot remove a payload still owed to the legacy processor. Qualify this compatibility path before replacing provider webhook URLs. Version 0.1.0 artifacts remain immutable.

Run `GOWORK=off go test -race ./...` inside this module. Build artifacts with `python3 scripts/build_connectors.py --out <empty-directory>` at the Tools repository root. The builder snapshots all tracked/nonignored sources once, records source digests, cross-compiles runner and broker for macOS/Linux/Windows arm64/x64 and creates the Python wheel, catalog, manifest and `SHA256SUMS`. Dirty sources require explicit `--allow-dirty` and produce unqualified artifacts. After publication, Go module tags use `packages/connectors/v<version>`; the currently published tag is `packages/connectors/v0.1.6`. Binaries use the matching version. Verify both archive and extracted binary checksums. Cross-compilation is not native OS qualification.

## Host-owned privacy binding

The Python adapter includes the pure `openagent_connectors.privacy` helper.
`result_fragments("shopify", operation_id, provider_json)` selects reviewed
provider records independently; `invocation_selection("shopify", operation_id,
arguments)` classifies the compiled operation's inputs before host persistence.
These functions return schema paths, subject selectors and explicit nonpersonal
classifications, not identities or consent. The trusted host must bind every
selection to its verified app, installation, tenant, shop and authorization.
Unknown subject data stays unknown; an unsupported provider is rejected.
The helper has no Core dependency and does not enable Shopify enrollment or
supply a storage/export/redaction implementation.

## Optional own apps

The standalone accepts a host-owned `connectors.oauth_providers_file` containing an array of the same provider descriptors. The current local loopback implementation explicitly admits only Gmail, Google Drive, Google Analytics, ClickUp and Postiz. Their own-app callbacks bind only to explicit `http://127.0.0.1:<port>/<path>` URLs registered with that provider. The runner handles state, PKCE, single-use exchange and issuer-bound renewal locally; central availability is irrelevant for these credentials. Secret files remain on the user's server and never become tool arguments. Protect configuration/key files and reserve unique callback ports when multiple agents use own-app flows on one machine.

GitHub, Notion, Slack and Atlassian protocol support in the 0.1.4 broker does not add them to that local allowlist; configuring those providers in the loopback flow is rejected. Shopify own apps that serve several servers use a separately configured instance of the broker, preserving the same group coordination. Host-owned app setup remains compatible with its existing callbacks.

See [deployment and activation](../../deploy/connector-auth/README.md). Provider activation and real merchant/user acceptance remain separate from code/build tests.

## Remote qualification staging

Paid GitHub Actions qualification is on hold under the current resource/cost
instruction; do not dispatch the manual workflow for this candidate. The current
0.1.4 source evidence is the bounded remote Linux worker
[workspace receipt](../../docs/connector-candidate-0.1.4-workspace-qualification.json),
not a new macOS/native or real-provider qualification.

The existing manual `Qualify shared connectors` Actions recipe accepts a reviewed full
source SHA and runs one standard hosted macOS ARM64 job. Builds and tests run
sequentially with Go 1.26.9, `GOMAXPROCS=2` and `-p=1`; no credentials, provider
grants, tags or releases are created. It verifies all six bundles, installs the
SDK normally with the checksum-verified public beta 38/Core 21/Tools dependency
closure, exercises the installed public host's acquisition contract, and runs
native macOS runner/broker fixtures. Windows/Linux remain cross-compilation
only. Artifacts and evidence stay in workflow staging pending operator review.
The legacy public host keeps its existing SDK pin in a separate environment.
This describes the staged recipe, not an executed or approved 0.1.4 run.
