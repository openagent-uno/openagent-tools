# Connector authentication on Mixout

This optional service has its own namespace/PVC. It does not change GlassPalace, ICS hosting or the public OpenAgent site's hosting. The bootstrap overlay has **zero enabled providers**; `/healthz` tests the process, `/readyz` returns 503 until provider activation. Host `OPENAGENT_CONNECTOR_AUTH_PROVIDERS` remains unset during bootstrap.

## Production prerequisites

- Mixout K3s, Traefik, `letsencrypt-prod`, registry on `localhost:5000`, and `local-path` storage. Verify the live cluster before applying.
- DNS: `auth.openagent.uno` A record to the Mixout ingress (currently `51.77.111.243`); verify ownership/TLS. Domain DNS is currently delegated to GoDaddy.
- Namespace-local Kubernetes Secret `connector-auth-secrets`: `event-key` is a persistent 32-byte random key represented as hex. Back it up with metadata. Mount provider secrets by filename; never put values into this repository, environment logs or manifests.
- Build the pinned `packages/connectors/Dockerfile`, push a uniquely versioned image, and replace the overlay image with its digest. Inspect the rendered overlay and server dry-run before apply.
- Exactly one writer, including rollouts. Preserve the PVC and event key. Process memory (OAuth transactions/envelopes) is intentionally not backed up.

## App registrations and activation

Read existing public registration metadata from GlassPalace's production `glasspalace-platform-secrets/OAUTH_PROVIDERS_JSON`; keep secret bytes inside production. On 2026-10-12 it contained actual Google, Shopify and ClickUp client IDs, and `glasspalace-postiz-review-pending` as the Postiz placeholder. Those registrations are evidence of current GlassPalace setup, **not evidence of OpenAgent branding approval or new redirect registration**.

Register the OpenAgent recipient/service/domain, public connector/privacy documentation, and these exact callbacks with the providers:

- ClickUp: `https://auth.openagent.uno/v1/oauth/clickup/callback`.
- Google: `/v1/oauth/gmail/callback`, `/v1/oauth/google_drive/callback`, `/v1/oauth/google_analytics/callback` on the same origin. Keep Gmail restricted-scope verification and any required security assessment as release gates.
- Shopify: `/v1/oauth/shopify/callback`; all four mandatory/privacy lifecycle topics delivered to `/v1/webhooks/shopify`. Require expiring offline tokens, reviewed managed-install scopes and authenticated merchant consent. A shared app/shop grant is coordinated centrally.
- Postiz: `/v1/oauth/postiz/callback`, after an actual client registration replaces the pending placeholder.

Preserve old callback registrations and old app identity for existing credentials. Do not rename/switch app credentials implicitly: a host's encrypted credential records its issuer. Reusing an existing registration under the OpenAgent brand needs provider confirmation and an explicit migration design; creating a new registration does not invalidate old connections.

`registrations/google.json` records the new OpenAgent Google registration and production secret references. It is operator metadata, not a provider configuration, and is not loaded by the bootstrap. The app remains in Testing with API/scope declaration and verification pending. Current Mixout K3s reports secrets-at-rest encryption disabled; qualify dedicated secret storage or encrypted Kubernetes storage before common-app enrollment, preserving existing production services and keys.

The user selected reuse of the existing ClickUp app instead of creating a second registration. `registrations/clickup.json` records the verified production client ID and copied secret references. Its current GlassPalace callbacks/credentials must remain available; add the broker callback through the registered app owner's console and complete public-identity/real-flow checks before activation.

Provider JSON is an array of `oauth.Provider`, with `id`, stable `app_id` (include client-registration identity), `client_id`, `secret_file`, `authorization_url`, `token_url`, `redirect_uri`, `scopes`, `pkce`, optional `revocation_url`. Shopify URL templates use `{shop}`, never unvalidated arbitrary tenant URLs. The secret paths refer to `/secrets/<filename>`. Google uses PKCE/offline consent; ClickUp uses JSON code exchange. Never add unsupported placeholder providers to the active config.

After approval, create a reviewed config overlay, switch readiness to `/readyz`, dry-run, deploy, and test canceled/replayed/misdirected consent; locally revoked roles/device sessions; concurrent Shopify rotation; offline/missing-envelope recovery; broker restart; duplicate and late webhooks. Test real read/authorized write/refresh/restart/disconnect visually in all three products. Confirm direct product API egress and absence of broker token persistence. Only then opt each host into new consents with `OPENAGENT_CONNECTOR_AUTH_IDENTITY_FILE`, `OPENAGENT_CONNECTOR_AUTH_URL`, `OPENAGENT_CONNECTOR_AUTH_PROVIDERS`.

The identity file must be durably host-owned and survive restart. Kubernetes hosts should provision a private identity into a secret-backed file; local installers use the customer data directory. Never share an installation identity between different product servers.

A provider outage leaves valid local tokens usable. New consents and renewals requiring app secrets fail closed. Legacy own-app configuration remains supported; do not replace old app config while old credentials rely on it. Disable new official enrollment to roll back, preserving official credentials/identity for their renewals.

## Qualification still required

No public activation is justified by mocked OAuth endpoints or compiled binaries. Native Windows/Linux runtime acceptance, provider review, DNS/TLS, actual dual-server Shopify consent, and standalone privacy-content processing must be qualified before turning on common apps. Do not describe bootstrap as an operational connector release.
