# Shared connector qualification, 12 October 2026

This is a bootstrap and development qualification, not authorization to enable common OAuth apps.

## Published code and artifacts

- Library: `packages/connectors/v0.1.0`; clean source `cd40539756144419e6d86d235855d8b92d86596e`.
- [Qualification prerelease](https://github.com/openagent-uno/openagent-tools/releases/tag/connectors-v0.1.0): six macOS/Linux/Windows arm64/x64 runner/broker bundles, Python wheel, catalog, manifest and SHA256SUMS. Archives and extracted binaries verified. Cross-compilation does not qualify native runtime or signing.
- Shared catalog: all ten implemented GlassPalace entries, including token connectors. Existing gateway adapters and their tests moved upstream; identifiers/contracts preserved. GitHub and Slack import remain unavailable placeholders. Custom MCP stays host-owned.
- Shared Go race tests and vet passed, including replay/recipient binding, scope checks, local direct API egress, concurrent Shopify refresh, encrypted recovery, crash fences and durable webhook deduplication. Provider exchanges in these tests are mocked.

## Mixout bootstrap, live verified

- DNS: GoDaddy A `auth` → `51.77.111.243`, actually saved with TTL 600 seconds after SMS verification. Authoritative DNS and Cloudflare public resolver returned the address.
- Namespace `openagent-connectors`; exactly one broker writer, `Recreate`, node `mixout-server`, dedicated bound 1 GiB metadata PVC. Persistent event-encryption key generated on production, preserved outside source/manifests.
- Image: `localhost:5000/openagent-connector-auth@sha256:41e9f04ecb0e49f6dcc3a2657afd8cb063957f2e501dd2cc859466473a4fea22`; source revision above.
- Server dry-run passed; deployment reached 1/1 Running with zero restarts. Traefik/`letsencrypt-prod` issued the certificate.
- HTTPS certificate validation passed without bypass. `/healthz`: HTTP 200, contract `openagent-connectors/v1`, `configured_providers:0`. `/readyz`: HTTP 503, `provider activation pending`.
- Bootstrap CPU request 10m: live control-plane node already reserved 1969m of 2000m. Capacity/load testing and a production request budget are prerequisites to enrollment.
- No provider secrets copied or existing GlassPalace OAuth registrations changed. Host opt-in flags remain disabled. Tailscale primary `spicysparks.com` profile restored after operations.

## Host implementation checks

- GlassPalace and ICS gateways tested using the published module with `GOWORK=off`, no sibling replacement; all normal gateway packages passed. Control-plane server/operations/HTTP/collaboration packages passed.
- Both hosts' real isolated PostgreSQL contracts cover consent through a real broker HTTP handler with a mocked provider, encrypted local persistence, authority revoked mid-exchange, preserved installation/connection identity and retry after a lost completion response.
- Focused frontend connector suites: 46 tests in each host. All three clients passed TypeScript checks. Standalone policy/storage suite: eight tests covering local encryption, cross-principal/audience denial, revocation, restart and issuer migration fences.
- Standalone visual fixture used the actual component/theme and mocked management responses; connection controls, write-permission toggle and local disconnect visually checked. It is not real provider or installed-app acceptance.
- Two GlassPalace database suite failures also occur on unmodified HEAD: `TestPostgresPersistsPerAgentRuntimeIntentAndObservation` and `TestShopifyRedactGenerationMigrationBackfillsLegacyRequests`. These remain baseline issues, not a passing full suite.

## Required before activation

1. Register/approve OpenAgent-branded apps and exact broker callbacks without retiring legacy registrations. Production Google/ClickUp/Shopify IDs are GlassPalace registrations; Postiz still has a review-pending placeholder. Restricted Google scopes/security assessment remain provider gates.
2. Complete standalone privacy export/redaction for stored agent content and qualify product-local privacy processing.
3. Qualify actual OAuth cancel/read/authorized write/refresh/restart/disconnect visually in all three products. Test two real Shopify servers on one shop, simultaneous rotation, offline peer, expired/lost envelope, recovery and new consent. Test duplicate webhooks/offline recipients.
4. Build/sign/accept standalone and native host releases on supported OSs. Validate native privacy workers with central notifications and recovery UX.
5. Load/capacity qualify the broker, switch readiness to `/readyz` and activate host allowlists only after the preceding gates. The bootstrap alone does not fulfill the complete release plan.
