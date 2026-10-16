# GitHub and Notion source/registration checkpoint — 16 October 2026

The shared library/runner source candidate is **0.1.4**, with 17 GitHub and
8 Notion typed operations. Published artifacts and consumer pins remain
**0.1.3**. This is not a real-provider acceptance or a common-enrollment release.

## Source qualification

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

## Provider registrations

The authorized operator signed into both services with the requested account.
Existing personal developer registrations were inspected before creating these
apps; neither service exposed an existing relevant registration in that account.

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

Secret bytes and provider user credentials are not part of this checkpoint or
repository. Existing production secret keys were preserved. No provider was
added to the active configuration and no production deployment was restarted.
The registrations are recorded separately in `registrations/github.json` and
`registrations/notion.json`; those files are metadata, not active configuration.

## Remaining gates

Both providers still need a real, explicitly authorized receiving installation
and provider consent, reads, permitted reversible writes, refresh, restart and
disconnect. GitHub also needs explicit repository selection during installation;
Notion needs explicit page selection. Then qualify/publish the candidate runner
and SDK, and adopt them in receiving products through their existing public
contracts. Older installations are not silently upgraded or activated.

The [complete public-directory inventory](../../docs/chatgpt-app-coverage.md)
retains the remaining services and primary-interface research. Its Popular
order is editorial, not an adoption ranking; it is not a claim that thousands
of unimplemented providers are ready.
