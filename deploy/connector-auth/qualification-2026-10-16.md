# Shared connector source/registration checkpoint — 16 October 2026

The shared library/runner source candidate is **0.1.4**, with 17 GitHub,
8 Notion, 9 Slack and 9 Atlassian/Jira typed operations. The integrated candidate
passed Go test, vet and runner build on a remote worker. Published artifacts and
consumer pins remain **0.1.3**. This is not real-provider acceptance, a native
platform qualification or a common-enrollment release.

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
does not make its planned secret reference runnable. Slack app registration
remains pending and has no persistent app ID. Inventory/overlay activation
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
- **Slack:** the setup workspace was created, but app creation was not completed
  because the console required an installation grant. No persistent Slack app ID,
  client secret or real OAuth grant is recorded. Registration and any subsequent
  installation/consent remain pending; an existing directory card is not an
  approval for OpenAgent to use Slack's separate MCP service.

Secret bytes and provider user credentials are not part of this checkpoint or
repository. Existing production secret keys were preserved. Registration did
not activate providers; the later image-only infrastructure update is recorded
separately below.
The registrations are recorded separately in `registrations/github.json` and
`registrations/notion.json`, with the incomplete Atlassian state in
`registrations/atlassian.json`; those files are metadata, not active configuration.
The Atlassian row in `providers-reviewed.json` deliberately retains an empty
client ID and remains inert until secret custody and the separate admission
checks are satisfied. The registration's existence does not validate that row.

## Live Auth infrastructure checkpoint

An unversioned candidate Auth image
`sha256:cf5d5bbb3d98eee602915e1d4b8fb641335407c2f9dfd214535c93ea74bfc882`
was deployed with an image-only update. Configuration and all existing secret
hashes were preserved; no new consent was obtained.
HTTPS `/healthz` returned 200 while readiness remained 503 under the existing
restricted ClickUp QA enrollment configuration. No GitHub, Notion, Slack or
Atlassian provider was activated. This infrastructure observation does not
publish Auth `0.1.7`, qualify provider consent or establish general readiness;
the shared connector artifacts still remain `0.1.3`.

## Remaining gates

All four providers still need a real, explicitly authorized receiving installation
and provider consent, reads, permitted reversible writes, refresh, restart and
disconnect. GitHub also needs explicit repository selection during installation;
Notion needs explicit page selection. Then qualify/publish the candidate runner
and SDK, and adopt them in receiving products through their existing public
contracts. Older installations are not silently upgraded or activated.
Atlassian additionally requires secret custody and explicit site selection;
Slack still requires app registration and an authorized installation. No new
provider is enabled in the active configuration by this source qualification.

The [complete public-directory inventory](../../docs/chatgpt-app-coverage.md)
retains the remaining services and primary-interface research. Its Popular
order is editorial, not an adoption ranking; it is not a claim that thousands
of unimplemented providers are ready.
