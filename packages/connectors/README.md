# OpenAgent official connectors

Shared Go module `github.com/openagent-uno/openagent-tools/packages/connectors`, version 0.1.0. GlassPalace and ICS link this module into their local gateways. The standalone server invokes the same adapters through `openagent-connector-runner` and the `openagent-connectors` Python package. OpenAgent Core receives managed capability sources through its public catalog APIs; it does not import product accounts, OAuth or storage code.

## Ownership and compatibility

The module includes the complete implemented GlassPalace adapter set, its schemas, pagination, controlled egress, scope gates and tests. `provenance.json` identifies the extraction source and original file digests. Catalog IDs and tool names are preserved. Catalog entries with no implemented operations (GitHub and Slack import) report `available:false`. Custom MCP management remains a host capability.

The consuming host supplies a previously authorized `Binding`, credential, operation ID and audit. It owns users, tenant/project ACLs, grants, budgets, durable encrypted credential storage, local privacy actions and concurrency with revocation. `Runtime.Tools` applies catalog/scope/write gates; tool arguments cannot choose another credential or installation. Normal provider API traffic originates at the consuming host, never the broker. Existing provider-specific retry budgets stay in the adapters. Token exchange, refresh and mutating calls are not blindly retried.

The Python runner protocol is trusted server IPC, not a network endpoint. Credentials travel only in stdin, nested separately from tool arguments. It never accepts tool arguments as process configuration. `openagent_connectors.mcp.serve_connector` is an MCP transport adapter for a host-supplied, authorizing connector factory.

## Authentication contract v1

`connector-auth` runs separately on `auth.openagent.uno`. Only installation/product metadata, token fingerprints, Shopify group versions and encrypted minimized webhook jobs are durable. No access/refresh tokens, codes or installation private keys belong in broker state, manifests, logs or backups. Token fingerprints use a keyed HMAC; the peer credential digest additionally verifies that encrypted peer content came from the current broker exchange.

Installations use persistent Ed25519 signing and X25519 encryption identities. Signed requests cover method, path/query, body hash, timestamp and nonce. Registration is open to third parties, subject to limits. The consent page displays the operator-supplied product/name, cryptographic installation ID and permissions; it explicitly does not imply endorsement.

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

Run `go test -race ./...` inside this module. Build artifacts with `python3 scripts/build_connectors.py --out <empty-directory>` at the Tools repository root. The builder snapshots all tracked/nonignored sources once, records source digests, cross-compiles runner and broker for macOS/Linux/Windows arm64/x64 and creates the Python wheel, catalog, manifest and `SHA256SUMS`. Dirty sources require explicit `--allow-dirty` and produce unqualified artifacts. The Go module tag is `packages/connectors/v0.1.0`; binaries use the matching version. Verify both archive and extracted binary checksums. Cross-compilation is not native OS qualification.

## Optional own apps

The standalone accepts a host-owned `connectors.oauth_providers_file` containing an array of the same provider descriptors. Google, ClickUp and Postiz own-app callbacks bind only to explicit `http://127.0.0.1:<port>/<path>` URLs registered with that provider. The runner handles state, PKCE, single-use exchange and issuer-bound renewal locally; central availability is irrelevant for these credentials. Secret files remain on the user's server and never become tool arguments. Protect configuration/key files and reserve unique callback ports when multiple agents use own-app flows on one machine. Shopify own apps that serve several servers use a separately configured instance of the broker, preserving the same group coordination. Native GlassPalace/ICS own-app setup remains compatible with its existing callbacks.

See [deployment and activation](../../deploy/connector-auth/README.md). Provider activation and real merchant/user acceptance remain separate from code/build tests.
