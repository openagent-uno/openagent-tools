# Allowlisted real-provider qualification

This procedure prepares real OAuth qualification without public enrollment. It
does not qualify provider review, product privacy processing or release. Do not
apply the bootstrap image: the reviewed broker revision must include QA admission
and the durable revocation fence. Library/runner `0.1.1` tags remain immutable;
older clients can use the unchanged wire contract (unknown new errors remain
sanitized as `request_failed`).

`providers-reviewed.json` contains public registration metadata and mounted
secret references only. It selects the existing ClickUp and approved Shopify app
and the new Google Testing registration. The file is not loaded by bootstrap.
The issuer includes the actual client-registration ID and must remain stable
after credentials are saved. Postiz is deliberately absent until a real app
exists. Google scopes are split by connector; choosing Gmail does not ask for
Drive or Analytics access.

## Admission and readiness

Supply `--qa-enrollment=/config/qa-enrollment.json` at startup. The strict JSON
contract contains `installations` (1–50 distinct SHA-256 signing-key fingerprints)
and, for Shopify, `shopify_stores` (1–10 exact dedicated QA domains). Product and
installation display names are never admission criteria. An empty/invalid list,
unknown JSON field, legacy webhook forwarding configuration, or a persisted group
or grant outside the QA cohort aborts startup. Use one reviewed provider at a time.

| Request | Result in QA |
| --- | --- |
| Invalid installation signature | 401 `invalid_installation_signature` |
| Signed registration from a non-allowlisted identity | 403 `qa_installation_not_admitted`; nothing persisted |
| Any authenticated request from a previously registered non-QA identity | 403 `qa_installation_not_admitted` |
| Shopify start with omitted or non-allowlisted shop | 403 `qa_shop_not_admitted`; no transaction/provider call |
| Signed webhook for a non-allowlisted shop | 403 `qa_shop_not_admitted` |
| Admitted start for an absent provider | 503 `provider_not_configured` |
| Admitted start | 201; recipient disclosure and provider consent still required |
| `/healthz` | 200 with `enrollment: "qa"`; provider count is configuration, not release |
| `/readyz` | 503 throughout QA, including with configured providers |

The deployment's pod readiness remains `/healthz` so the existing HTTPS callback
works; public `/readyz` continues to announce enrollment as unavailable. Only
allowlisted identities can create a transaction. No code-routing proxy, second
writer, new domain, callback or provider app is introduced. Shopify QA must use a
dedicated store with no GlassPalace or other production installation of this app:
acquiring an expiring token can retire another current app/store credential.
The allowlist alone cannot prove the merchant's production usage.

## Prepare and review the live change

1. Generate separate host-owned durable identities for each QA server and obtain
   their public installation fingerprints. Never put identity private keys in
   the configuration or repository. Verify both local product authorizations.
2. Build the reviewed broker commit and push a unique image, recording its digest.
   Preserve the live metadata, event key, Secret and deployment/configuration in a
   root-only consistent backup. Verify the currently active profile and single
   writer before any Mixout command.
3. Prepare files with `prepare-qa-overlay.py --provider clickup --installation
   <fingerprint> --image localhost:5000/openagent-connector-auth@sha256:<digest>
   --output <new-directory>`. The script rejects mutable images, the old bootstrap
   digest, unsafe shop names and existing output directories; it never reads
   secrets, builds images or applies objects. Repeat `--installation` for each QA
   recipient; Shopify additionally requires `--shop <dedicated-store.myshopify.com>`.
4. Render with `kubectl kustomize <new-directory>`, inspect the manifest diff and
   server dry-run. The intended changes are the immutable broker image,
   `--qa-enrollment` argument and hashed provider/admission ConfigMap. The existing
   namespace, Secret, PVC, one replica, Recreate strategy, routes and webhook
   registrations are retained. Do not change any other project's reservations.
5. Apply only after review. Wait for zero old writers, one healthy new writer and
   valid HTTPS. Confirm health reports QA, readiness 503, denied/non-QA requests
   never reach a provider, and actual resource usage/restarts are within the
   request budget. The 10m reservation remains an unqualified bootstrap setting;
   a small QA exercise does not resolve production capacity admission.

The exact current ClickUp callback path requires a real roundtrip because its
registration UI normalized the saved redirect to the origin. Do not change it
again based on fixtures. Follow provider consent in the actual product UI and
stop for action-time human approval where required; a prepared app or declared
scope is not a user-data grant.

## Acceptance and evidence

Record status/timings and hashes, never codes, tokens, secrets, API payloads or
customer data. For ClickUp, inspect the selected authorized workspace and perform
an approved reversible task operation; its current OAuth tokens do not expire,
so record refresh as not applicable rather than fabricate renewal. For Google,
record connector-specific scopes, cancellation, real read/approved reversible
write, refresh, restart and both local disconnect and explicit provider revoke.
Global Google revocation can affect other scopes and clients in the same project.

The broker fences a grant durably before contacting a revocation endpoint. A
provider failure leaves local renewal fenced and revocation can be retried with
the same locally held token. An in-flight refresh checks the fence again before
returning a new credential (409 `token_grant_revoked`). No automatic retry is made
for code exchange or refresh. Existing access tokens remain solely local; the
broker cannot recall an already returned wire response, so the receiving host
must recheck local authorization before storage and invocation.

For Shopify, qualify two **distinct** installations on the dedicated same shop:
both verified consents, atomic local save then commit, concurrent renewal with
only one provider call, offline second recipient, expiry/loss of temporary mail,
peer recovery and no surviving updated copy followed by fresh consent. Confirm
separate local tool permissions. Inject signed duplicate notifications for that
QA shop, confirm durable receipt/retry and each product's actual processing. Do
not migrate production webhooks during QA. Mocked two-server and uninstall tests
remain contract evidence, not this real acceptance.

Check broker metadata contains only coordination fingerprints and encrypted
privacy events, and no OAuth token/code. Verify ordinary API traffic goes from
the products directly to the provider. Publish exact tested products, issuer,
commit/image and untested boundaries; do not equate consent success with release.

## Rollback

Keep the **new reviewed broker image** and durable metadata/key. Disable the
provider list (`providers.json=[]`) and retain the QA argument/admission ConfigMap
while finishing QA cleanup; public readiness remains 503. Render/dry-run/apply
that configuration through the same Recreate deployment, verify one writer,
zero providers and failed new consents. Disconnect local QA products and retain
or explicitly revoke their credentials as appropriate; Google revocation has
project-wide consequences and Shopify uninstall affects the app/store cohort.
Do not restore a stale metadata snapshot or roll back to the old broker binary:
that could lose credential generations or durable revocation tombstones.
Never delete the PVC, event key, Secret, legacy product data or provider app.

Public activation, production webhook migration and product release require the
remaining privacy, dual-server, capacity, platform and provider approval gates in
[the checkpoint](qualification-2026-10-13.md). After qualification, remove the QA
gate only through a separately reviewed public-enrollment configuration change.
