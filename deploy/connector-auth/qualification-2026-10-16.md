# Shared connector source/registration checkpoint — 16 October 2026

The shared SDK/runner **0.1.4 is now published**, from clean source
`709e6634edbf71c6d53711b01482a0509eb7bfa0`, with 17 GitHub, 8 Notion,
9 Slack and 9 Atlassian/Jira typed operations. Its bounded Linux qualification
passed race/vet/govulncheck, six platform bundles, normal wheel installation and
native Linux x64 runner/broker smoke. Other targets have cross-compilation,
checksum and toolchain coverage only. The
[publication receipt](../../docs/connector-release-0.1.4-publication.json)
links the public manifest and exact asset digests. Consumer version pins and
real provider acceptance remain independent. GitHub, Notion and Slack completed
limited standalone lifecycles recorded in the
[product receipts](https://openagent.uno/guide/chatgpt-apps); Jira remains pending.
Common enrollment is closed. The earlier source cohorts below remain historical
evidence, rather than proof for a different runtime or provider grant.

## Earlier GitHub/Notion source qualification

`go test -count=1 ./...`, `go vet ./...`, the runner build and runner catalog
passed on one temporary Linux x64 worker with Go 1.26.9. CPU was limited to
1500m and memory to 2 GiB, with `GOMAXPROCS=2`, `GOMEMLIMIT=1GiB`, `-p=1` and
no service-account token or production credential mounts. The exact Go source
digests and limits are in
[the candidate receipt](../../docs/connector-candidate-0.1.4-qualification.json).
The temporary pod and its disposable caches were removed afterward. No local
Mac compilation or paid GitHub Actions workflow was started.

Fixtures cover fixed origins/version headers, routes, bounded schemas and
pagination, rejection before I/O, duplicate-key ambiguity, local credentials,
workspace/write gates, read retry and no write retry. GitHub content preserves
base64 and truncated-tree metadata within the response cap. Notion preserves
opaque cursors. OAuth protocol fixtures cover GitHub JSON responses/PKCE and
Notion owner=user, Basic/JSON exchange, pinned version and rotating refresh.
They use synthetic HTTP servers and do not establish actual provider consent.

## Integrated workspace source candidate — remote checks passed

The later source containing Slack and Atlassian/Jira passed the remote worker's
`go test ./...`, `go vet ./...`, `go build ./cmd/connector-auth` and
`go build ./cmd/connector-runner`. The separate
[workspace candidate receipt](../../docs/connector-candidate-0.1.4-workspace-qualification.json)
records this cohort; the earlier receipt above remains evidence for its own
GitHub/Notion source snapshot. No local Mac build or paid CI was used for these
checks. Source fixtures are not real provider grants or published release assets.
The integrated source index is
`1f7f60a41354903508625ae35cebd11be3f38e7462ee4a70b222a0d395f490c4`.

The integrated candidate adds nine typed Jira operations on the fixed
`api.atlassian.com` origin. The receiving host binds `cloud_id` from the current
token's accessible-resources response; a tool argument cannot choose a site.
Enhanced JQL search uses `/rest/api/3/search/jql`, with explicit
`nextPageToken` pagination. Classic `read:jira-work` and `write:jira-work`
scopes remain separate from Jira permissions. Resource-level grants restrict
the token to sites selected in consent and use the same 3LO endpoints.

Slack uses the `slack_import` provider identity and a confidential user-token
OAuth flow. It requests `user_scope`, selects only `authed_user` credentials
on initial exchange and user credentials on refresh, and rejects bot-only or
organization-wide grants. The provider-confirmed workspace ID is immutable
broker metadata and is checked before refresh I/O. Refresh responses that omit
the workspace retain the verified prior binding. Existing empty bindings for
older providers remain empty and usable. Slack histories retain the declared
rate/pagination bounds; no claim of Marketplace approval is made.

The next OAuth source also adds Notion's Basic/JSON/versioned token revocation
and GitHub's Basic/JSON DELETE of a single app user token. GitHub single-token
revocation does not claim to revoke the user's entire provider authorization.
Protocol, identity-binding, argument-boundary and negative fixtures passed in
the remote Go suite for this source cohort. The Slack HTTP-200 protocol guard
rejects `ok:false`, absent/ambiguous flags and permission failures while retaining
real request/response byte counts and attempt accounting. All Slack calls are
sent once: the generic two-second retry cap must not shorten Slack's
`Retry-After` guidance. History/replies default to and are capped at 15 messages,
with explicit opaque-cursor pagination. No Slack MCP access is claimed.

`providers-reviewed.json` is an input inventory, never the active deployment.
It now includes the registered GitHub and Notion client IDs and secret-file
references. The Atlassian registration was subsequently created as recorded
below, but its secret has not entered production custody; an app registration
does not make its planned secret reference runnable. Slack app registration is
now recorded below, with verified production secret custody but no authorized
installation or grant. Inventory/overlay activation
remains separate from registration metadata. The QA overlay admits GitHub and
Notion only in addition to the previously supported choices; Slack/Atlassian
remain rejected even through the
generator's Python API. Bootstrap configuration remains `providers.json=[]`.
Go qualification does not establish the status of the separately prepared Python
overlay fixtures; they are not reported here as passing.

## Provider registrations

The authorized operator inspected the existing personal developer registrations
before creating the GitHub and Notion apps below. The later Atlassian and Slack
setup status is recorded independently.

- **GitHub:** OpenAgent Connectors, GitHub App `5345616`, owned by `geroale`.
  Contents/metadata/pull requests are read-only; issues are read/write.
  Installation allows explicit repository selection. User tokens expire;
  webhooks and device flow are disabled. OAuth scopes are empty because this
  registration uses GitHub App fine-grained permissions. The client secret was
  added to `connector-auth-secrets`; its readback matched. The app private key
  fingerprint matched GitHub and the key was stored separately in
  `connector-github-app-private-key`, not mounted in the broker.
- **Notion:** OpenAgent public OAuth connection
  `3fbd872b-594c-8157-8fb9-0037e6a6efb2`. The operator confirmed the login terms
  and the separate Developer Terms at their respective submission steps.
  Callback `/v1/oauth/notion/callback`, any-workspace installation, content
  read/update/insert, profile access without email addresses, comments disabled.
  Marketplace listing remains unpublished. Its secret was added to
  `connector-auth-secrets`; readback matched.
- **Atlassian:** OpenAgent app `25ac00a3-d831-4dfc-b785-eab01fd7f2f7`, client ID
  `nShjjeUGI1OrLWnmBshOEe8nS9JIfURl`. The callback
  `https://auth.openagent.uno/v1/oauth/atlassian/callback` was saved, resource-level
  consent is configured, and classic `read:jira-work` / `write:jira-work` scopes
  were selected; the OAuth request also includes `offline_access` for refresh.
  Secret custody, broker activation, selected-site consent and
  actual Jira operations remain pending. The adapter uses public Jira REST APIs;
  this does not qualify the separate commercial Rovo MCP service.
- **Slack:** OpenAgent app `A0C9XC9JHTK`, client ID
  `12333069497846.12337417629937`, was created and its saved manifest and OAuth
  settings were verified in the provider UI. The callback is
  `https://auth.openagent.uno/v1/oauth/slack_import/callback`. The ten configured
  user scopes are `channels:read`, `channels:history`, `groups:read`,
  `groups:history`, `im:read`, `im:history`, `mpim:read`, `mpim:history`,
  `users:read` and `chat:write`; there are no bot scopes or events. Token rotation
  is enabled and PKCE is disabled. The client secret was saved and verified in
  private local custody with mode 0600. It was subsequently merged into encrypted
  Kubernetes `connector-auth-secrets` as `slack-client-id` and
  `slack-client-secret`, preserving the other keys; remote/local digest comparison
  matched without recording secret values here. No installation or real OAuth
  grant has been authorized, and the app remains inactive in the current
  restricted GitHub QA broker configuration. Registration does not qualify
  access to Slack's separate MCP service.

Secret bytes and provider user credentials are not part of this checkpoint or
repository. Existing production secret keys were preserved. Registration did
not activate providers; the later image-only infrastructure update is recorded
separately below.
The registration metadata is recorded separately in `registrations/github.json`,
`registrations/notion.json`, `registrations/atlassian.json` and
`registrations/slack.json`; those files are not active configuration.
The Atlassian row in `providers-reviewed.json` deliberately retains an empty
client ID and remains inert until secret custody and the separate admission
checks are satisfied. The registration's existence does not validate that row.

## Live Auth infrastructure checkpoint

An unversioned candidate Auth image
`sha256:cf5d5bbb3d98eee602915e1d4b8fb641335407c2f9dfd214535c93ea74bfc882`
was initially deployed with an image-only update. Configuration and all existing
secret hashes were preserved at that step; no new consent was obtained by the
image update. HTTPS `/healthz` returned 200 while readiness remained 503 under
the then-active restricted ClickUp QA enrollment configuration.

The later restricted QA configuration is `connector-auth-github-qa-20261016`,
using the same image digest above. The real standalone source candidate completed
these GitHub stages on 16 October (UTC): OAuth acquired by the product poll at
15:18:39; verified repository read at 15:23:24; owner refresh at 15:25:54;
disposable issue creation/read/closure confirmed at 15:49:10; read after server
restart at 15:51:16; local disconnect at 15:51:32, with the connection disabled.
The temporary receiving-server pod was then removed.

The GitHub App installation was restricted to the explicitly approved private
QA repository, whose Actions were disabled. No model was used. The selected
repository and the closed issue were also verified in the provider UI. The
normal certified product connection and ordinary workflows executed the provider
calls; no synthetic provider client was substituted.

Early result-detail reads exposed a product bug: `ApiProblem(503, warming)`
escaped the workflow detail handler and became HTTP 500 while its authorized
history projection was being prepared. Authenticated workflow history returned
the canonical successful provider results. A narrow handler fix passed a
separate remote regression on the public
Core/Storage 22 and Identity 39 dependencies: real signed native certificates,
503 while warming, then owner 200 with trace and another principal 404 without
data. It remains a source fix pending receiving-product publication. Using
history for QA
does not waive that barrier or qualify the old 500 behavior.

The [product lifecycle receipt](https://github.com/openagent-uno/openagent/blob/main/docs/qualification/github-oauth-2026-10-16.json)
records source pins and sanitized evidence hashes. Earlier source-only receipts
retain their cohort-specific flags. No Auth, SDK, runner or receiving-product
release was published by this QA run; consumer pins remain `0.1.3`. General
enrollment stays closed. Notion, Slack and Atlassian consent is not implied.

## Notion real-provider lifecycle

The same broker image was then configured for Notion-only QA in
`connector-auth-notion-qa-20261016`, preserving its metadata PVC, event key and
Secrets. One approved installation received consent to one newly created empty
private QA page. The standalone candidate used normal private server/CLI wheels
from product `9f54c97d996475e58c0759ef7203a4400c28ebd5`, public Core/Storage
beta 22 and SDK 0.1.3 with the supported private runner override. The runner was
built from Tools `52e8de4838de2f3af6a33b2dd254c67a98e67cbe`; its SHA-256 is
`dec3ef647ceee4a0ab81deb58a4c48b223a1a9db40a5d438f8e2f87aa3368345`.

On 16 October (UTC), product polling confirmed consent at 17:13:15, page reading
at 17:14:31, reversible title update with independent reads and exact title/local
write-policy restoration at 17:17:02, owner refresh at 17:17:51, reading after an
actual server process restart at 17:18:31, and local disconnection at 17:19:03.
The receiving server was subsequently stopped; its credentials were not copied
into the evidence. The workflow-detail path correctly returned temporary typed
503 warming responses. No history fallback, model, private Core overlay or
automatic provider-write retry was used. An initial harness preflight rejected
SQLite 0/1 permission flags before any mutation; the reviewed harness now
normalizes only canonical bool or integer 0/1 values.

The [Notion lifecycle receipt](https://github.com/openagent-uno/openagent/blob/main/docs/qualification/notion-oauth-2026-10-16.json)
records the limited page cohort and evidence hashes. This does not qualify
remaining Notion operations, provider-wide revocation, native App delivery or
multi-source application synchronization. No release or public enrollment was
enabled.

## Remaining gates

GitHub still needs a qualified runner/SDK release, explicit consumer adoption,
remaining-tool qualification and native App acceptance. Notion needs remaining
tools, native App acceptance and qualified release/adoption. Slack and Atlassian
still need an explicitly authorized receiving installation and consent, then
reads, permitted writes, renewal, restart and disconnect. Atlassian needs verified secret custody and site
selection; Slack needs an authorized installation and separate broker admission.
Existing installations are never silently upgraded or activated.

The [complete public-directory inventory](../../docs/chatgpt-app-coverage.md)
retains the remaining services and primary-interface research. Its Popular
order is editorial, not an adoption ranking; it is not a claim that thousands
of unimplemented providers are ready.
