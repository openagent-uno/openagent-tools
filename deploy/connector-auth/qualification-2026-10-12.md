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
- The released macOS arm64 runner performed actual signed HTTPS registration and mailbox access against the bootstrap. Shopify start returned `provider_not_configured`. Following a `Recreate` restart, mailbox access succeeded without re-registering; the persistent event secret was unchanged and existing GlassPalace deployments remained ready. One named qualification installation is retained, with public identity metadata only.
- Bootstrap CPU request 10m: live control-plane node already reserved 1969m of 2000m. Capacity/load testing and a production request budget are prerequisites to enrollment.
- No provider secrets copied or existing GlassPalace OAuth registrations changed. Host opt-in flags remain disabled. Tailscale primary `spicysparks.com` profile restored after operations.

## Public identity and Google preparation

- The docs-only [product PR #3](https://github.com/openagent-uno/openagent/pull/3) merged as `d0b286a3c697aa35df7a6e9e62e7813139172e08`. [Pages deployment](https://github.com/openagent-uno/openagent/actions/runs/38259240807) succeeded. `/privacy` and `/guide/connectors` are public, linked from the homepage, and visually checked in Chrome. Service commercial name: AI Agent; support/privacy contact: `geroale2000@gmail.com`.
- Google project `openagent-connectors` now has app branding OpenAgent, the existing OpenAgent logo, the public homepage/privacy URLs, authorized domain `openagent.uno`, and the requested support/developer contact. External audience remains in Testing. User confirmed acceptance of Google's API Services User Data Policy. This is not Google verification or a security-assessment receipt.
- A web OAuth client form named OpenAgent Shared Connectors is prepared with the three broker callback URLs and Google's AI-agent designation. Its creation awaits action-time confirmation; no new client secret has been generated, copied or activated.

## Host implementation checks

- GlassPalace and ICS gateways tested using the published module with `GOWORK=off`, no sibling replacement; all normal gateway packages passed. Control-plane server/operations/HTTP/collaboration packages passed.
- Both hosts' real isolated PostgreSQL contracts cover consent through a real broker HTTP handler with a mocked provider, encrypted local persistence, authority revoked mid-exchange, preserved installation/connection identity and retry after a lost completion response.
- Focused frontend connector suites: 46 tests in each host. All three clients passed TypeScript checks. Standalone: sixteen policy/storage tests covering local encryption, cross-principal/audience denial, revocation, restart and issuer migration fences, plus six acquisition integrity/path-traversal tests. Clean-snapshot server wheel and docs build passed; the wheel is a qualification artifact and does not replace the published product release.
- The actual released macOS runner and Python standalone host discovered all four real Replio tool schemas and rejected a cross-connection invocation before provider IO, using a disposable local encrypted store and dummy key.
- Standalone visual fixture used the actual component/theme and mocked management responses; connection controls, write-permission toggle, local disconnect, disabled enrollment, visible setup form and secure mail settings visually checked. It is not real provider or installed-app acceptance.
- Two database failures originally reproduced on unmodified GlassPalace HEAD. The Shopify migration fixture has now been corrected to construct its actual historical schema and upgraded successfully in fresh isolated databases for both products. `TestPostgresPersistsPerAgentRuntimeIntentAndObservation` remains an unrelated baseline failure; a passing full suite is not claimed.

## Required before activation

1. Register/approve OpenAgent-branded apps and exact broker callbacks without retiring legacy registrations. Production Google/ClickUp/Shopify IDs are GlassPalace registrations; a separate Google project `openagent-connectors` has been created, with OAuth still unconfigured pending operator/privacy contacts; Postiz still has a review-pending placeholder. Restricted Google scopes/security assessment remain provider gates.
2. Complete standalone privacy export/redaction for stored agent content and qualify product-local privacy processing. Standalone Shopify enrollment is explicitly blocked in code until that implementation is complete; all other common consents require host opt-in.
3. Qualify actual OAuth cancel/read/authorized write/refresh/restart/disconnect visually in all three products. Test two real Shopify servers on one shop, simultaneous rotation, offline peer, expired/lost envelope, recovery and new consent. Test duplicate webhooks/offline recipients.
4. Build/sign/accept standalone and native host releases on supported OSs. Validate native privacy workers with central notifications and recovery UX.
5. Load/capacity qualify the broker, switch readiness to `/readyz` and activate host allowlists only after the preceding gates. The bootstrap alone does not fulfill the complete release plan.
