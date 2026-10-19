# Connector authentication deployment

This optional service has its own namespace/PVC. Receiving hosts and the public OpenAgent website keep independent deployments. The bootstrap overlay has **zero enabled providers**; `/healthz` tests the process, `/readyz` returns 503 until provider activation. Host `OPENAGENT_CONNECTOR_AUTH_PROVIDERS` remains unset during bootstrap.

## Production prerequisites

- K3s, Traefik, `letsencrypt-prod`, registry on `localhost:5000`, and `local-path` storage. Verify the live cluster before applying.
- DNS: `auth.openagent.uno` A record to the operator-controlled ingress; verify ownership/TLS. Domain DNS is currently delegated to GoDaddy.
- Namespace-local Kubernetes Secret `connector-auth-secrets`: `event-key` is a persistent 32-byte random key represented as hex. Back it up with metadata. Mount provider secrets by filename; never put values into this repository, environment logs or manifests.
- Build the pinned `packages/connectors/Dockerfile`, push a uniquely versioned image, and replace the overlay image with its digest. Inspect the rendered overlay and server dry-run before apply.
- Exactly one writer, including rollouts. Preserve the PVC and event key. Process memory (OAuth transactions/envelopes) is intentionally not backed up.

## App registrations and activation

Read existing provider registration metadata and secret references from the receiving operator's protected inventory; keep secret bytes inside that operator's production environment. Reusing an existing client requires verified ownership and callback compatibility. A placeholder configuration does not prove either a completed registration or that no account exists elsewhere. Host-specific legacy callback details remain in the operator's inventory, outside this repository.

Register the OpenAgent recipient/service/domain, public connector/privacy documentation, and these exact callbacks with the providers:

- ClickUp: `https://auth.openagent.uno/v1/oauth/clickup/callback`.
- Google: `/v1/oauth/gmail/callback`, `/v1/oauth/google_drive/callback`, `/v1/oauth/google_analytics/callback` on the same origin. Keep Gmail restricted-scope verification and any required security assessment as release gates.
- Shopify: `/v1/oauth/shopify/callback`; all four mandatory/privacy lifecycle topics delivered to `/v1/webhooks/shopify`. Require expiring offline tokens, reviewed managed-install scopes and authenticated merchant consent. A shared app/shop grant is coordinated centrally.
- Postiz: the existing OpenAgent registration uses `/v1/oauth/postiz/callback`.
  Its credentials are staged, but the provider stays disabled until the client
  secret is rotated and verified in protected custody, followed by real product
  acceptance. Reuse this registration; do not create another account or app.
- GitHub: `/v1/oauth/github/callback`. The registered OpenAgent Connectors GitHub App uses expiring user tokens and selected-repository installation; its fine-grained repository permissions are configured in the app, not OAuth scope strings. The separate private app key is held in its own unmounted production Secret. Its limited user-token, refresh and host lifecycle passed; common enrollment is open in the three-provider public beta. Remaining tool coverage and native App provider acceptance are separate.
- Notion: `/v1/oauth/notion/callback`. The registered OpenAgent public connection uses `owner=user`, page selection and no OAuth scope strings; token/refresh requests require Basic client authentication, JSON and `Notion-Version: 2026-03-11`. Marketplace listing is unpublished. Its limited selected-page consent and host lifecycle passed; common enrollment is open in the three-provider public beta. Remaining tools and native App provider acceptance are separate.

Preserve old callback registrations and old app identity for existing credentials. Do not rename/switch app credentials implicitly: a host's encrypted credential records its issuer. Reusing an existing registration under the OpenAgent brand needs provider confirmation and an explicit migration design; creating a new registration does not invalidate old connections.

`registrations/google.json` records the new OpenAgent Google registration and production secret references. It is operator metadata, not a provider configuration, and is not loaded by the bootstrap. The app remains in Testing with the declared scopes, test user and required APIs configured; real consent and applicable verification remain pending. On 13 October the approved authentication control-plane patch and secrets-encryption rotation completed: the live datastore is encrypted, broker Secret values were preserved and a matching protected backup was verified. See the qualification checkpoint for the exact version and evidence. Capacity/request-budget qualification remains required before common-app enrollment.

The user selected reuse of the existing ClickUp app instead of creating a second registration, then explicitly requested retirement of its legacy host redirect. `registrations/clickup.json` records the provider's actual normalized OpenAgent origin after save/reload, and the unchanged credentials. Qualify the complete callback path and receiving-product cutover before activation.

Shopify also reuses the existing provider app; do not create a new app or rotate its credentials. `registrations/shopify.json` records the released `openagent-branding-20261012` version on the same app (401590648833), with the name OpenAgent and both the legacy and shared callbacks. The released version preserves the embedded page, existing webhook delivery, required scopes and optional `read_orders`. Central privacy delivery must preserve obligations for legacy recipients before replacing webhook endpoints. Registration metadata is not an active broker configuration.

Provider JSON is an array of `oauth.Provider`, with `id`, stable `app_id` (include client-registration identity), `client_id`, `secret_file`, `authorization_url`, `token_url`, `redirect_uri`, `scopes`, `pkce`, optional `revocation_url`. Shopify URL templates use `{shop}`, never unvalidated arbitrary tenant URLs. The secret paths refer to `/secrets/<filename>`. Google uses PKCE/offline consent; ClickUp uses JSON code exchange. Never add unsupported placeholder providers to the active config.

There is no per-row `enabled` or `disabled` field: every row passed to the broker
is validated at startup and opens its referenced secret. An unrecognized field
does not disable a row. `registrations/postiz.json` and
`registrations/atlassian.json` therefore keep their prepared provider rows nested
inside metadata-only registration records, outside the loadable provider array.
They are not deployment inputs. Postiz still requires credential rotation;
Atlassian still requires verified secret custody and selected-site consent.
Neither record changes the active provider configuration or QA admission choices.

After approval, create a reviewed config overlay, switch readiness to `/readyz`, dry-run, deploy, and test canceled/replayed/misdirected consent; locally revoked roles/device sessions; concurrent Shopify rotation; offline/missing-envelope recovery; broker restart; duplicate and late webhooks. Test real read/authorized write/refresh/restart/disconnect visually in each supported receiving product. Confirm direct product API egress and absence of broker token persistence. Only then opt each host into new consents with `OPENAGENT_CONNECTOR_AUTH_IDENTITY_FILE`, `OPENAGENT_CONNECTOR_AUTH_URL`, `OPENAGENT_CONNECTOR_AUTH_PROVIDERS`.

The identity file must be durably host-owned and survive restart. Kubernetes hosts should provision a private identity into a secret-backed file; local installers use the customer data directory. Never share an installation identity between different product servers.

A provider outage leaves valid local tokens usable. New consents and renewals requiring app secrets fail closed. Legacy own-app configuration remains supported; do not replace old app config while old credentials rely on it. Disable new official enrollment to roll back, preserving official credentials/identity for their renewals.

## Current image checkpoint

The [19 October image checkpoint](qualification-2026-10-19.md) preserves the
initial SDK18 image-only rollout with three providers. The subsequent
[eleven-provider activation checkpoint](qualification-2026-10-19-activation.md)
records the startup fix, normal raw scan and atomic trial configuration/Secret
mount rollout. Google remains in Testing; token exchange, consent and receiving
product qualification are not claimed by readiness. These changes made no
provider calls or new grants. The base still has zero configured providers
and must not replace the live provider overlay.

## Qualification still required

For a real-provider trial before public activation, use the explicit
[allowlisted QA procedure](qa-enrollment.md) and reviewed provider configuration.
It retains one writer and the registered callbacks; public readiness stays 503.
The prepared overlay is not deployed automatically and the bootstrap image does
not implement this gate.

See the [14 October checkpoint](qualification-2026-10-14.md) for auth-only
`0.1.6`, the real allowlisted standalone ClickUp trial and remaining activation
gates. The [13 October checkpoint](qualification-2026-10-13.md) retains the
earlier isolated infrastructure and bootstrap admission evidence.

No public activation is justified by mocked OAuth endpoints or compiled binaries. Native Windows/Linux runtime acceptance, provider review, DNS/TLS, actual dual-server Shopify consent, and standalone privacy-content processing must be qualified before turning on common apps. Do not describe bootstrap as an operational connector release.
