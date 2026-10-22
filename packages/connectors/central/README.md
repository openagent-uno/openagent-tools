# Shared catalog and central execution

This opt-in source package supplies a signed catalog, an installation-authenticated client, and a service-side execution boundary. Provider tokens remain inside the service's encrypted vault; the client receives connection handles and authorized results. The legacy host-token API and local runner remain separate and unchanged. Source availability is not evidence of deployment, provider enrollment or completed qualification.

## Optional service setup

The `connector-auth` command mounts the central profile only when started with `-central-config /absolute/path/central.json`. Without that flag the existing broker routes remain the only profile; no central catalog or execution endpoint is enabled. Existing `-state`, `-providers`, `-event-key`, `-listen` and `-origin` flags keep their broker meanings. The shared TLS origin serves broker installation registration/consent and the separate central routes below.

The strict `ServiceConfig` JSON contains file references, not key values:

```json
{
  "revision": 1,
  "signing_key_id": "registry-key-1",
  "signing_key_file": "/private/connector-service/registry-signing.hex",
  "vault_path": "/private/connector-service/central-vault.json",
  "vault_key_id": "vault-key-1",
  "vault_key_files": {
    "vault-key-1": "/private/connector-service/vault-key.hex"
  },
  "qualified_catalog_ids": []
}
```

`signing_key_file` contains the hex-encoded 64-byte Ed25519 private key, including its consistent public-key suffix. Each vault-key file contains a hex-encoded 32-byte encryption key. Key references and the vault path are absolute; key files must be private regular files. Configure the corresponding registry **public** key explicitly in each client's `TrustKeys`. Never publish the private key, vault keys, vault data or secret-bearing provider configuration.

`qualified_catalog_ids` uses exact catalog IDs, not provider aliases. Empty means every visible catalog entry is unavailable for central execution. Unknown or duplicate IDs reject startup. Explicit qualification does not bypass absent OAuth configuration, unsupported credential setup or Shopify's separate gate. This list represents an operator-reviewed qualification decision; it does not establish that provider approval or user consent has happened. The supplied example activates no provider.

The vault requires a private local directory supporting exclusive OS file locks, atomic rename and directory fsync. The service-side vault currently supports Linux/macOS; Windows and other targets fail closed because a qualified vault lock is not implemented. Windows clients can consume a qualified remote service, but a cross-compiled binary does not establish Windows vault-server support. Retain prior vault keys needed to decrypt existing state and follow the vault's single-writer/backup procedures. No shared multi-node vault mount, stale-lock deletion or automatic legacy-token import is supported.

## Catalog and execution contract

The protocol identifier is `openagent-connectors-central/v1`. `GET /v1/registry/catalog` returns `SignedCatalog{key_id,payload,signature}`. The signature is Ed25519 over the exact `payload` bytes and uses unpadded URL-safe base64. The payload contains `protocol`, `revision`, `issued_at`, `expires_at` and `connectors`.

Each descriptor contains an `item`, `contract_sha256`, finite `operations`, and `setup`. Setup declares `{mode: item.auth, credential_custody: "service", execution: "service", interaction: "none" | "hosted"}`. `none` needs no setup; for `hosted`, open the connection's `authorization_url` in a browser and poll `Client.Connection`. Status polling completes a ready OAuth transaction into the vault; consumers do not implement provider-specific forms. Future service-owned token/credential forms use the same hosted URL/status contract; those setup modes remain unavailable in this release. The versioned JSON Schema is available at `GET /v1/registry/schema` and as `central-v1.schema.json` in release assets. The contract hash binds connector/provider identity, capability, authentication kind, read/write tool sets, complete operation contracts and setup. Display and availability changes do not alter that hash. All descriptor fields are nevertheless bound by the catalog signature and revision. Unqualified entries can be visible while unavailable. API-token, credential and custom-MCP setup are not enabled by this profile. Central Shopify enrollment remains separately gated.

`NewRegistry(revision, keyID, privateKey, descriptors)` creates an immutable registry. `Snapshot(now)` signs a five-minute snapshot; `Lookup(id)` returns an independent descriptor copy. Replace the registry with a higher revision to publish changed descriptors. New signature timestamps may renew the same revision; descriptor content may not drift at that revision. Public operations cannot be raw, internal-only, or inconsistent with the declared provider/capability/tool set.

Execution routes use the existing installation signature headers, covering the method, path/query, body digest, timestamp and nonce:

| Method and path | Request |
| --- | --- |
| `POST /v1/execution/connections` | `CreateRequest`: catalog ID, exact contract hash, authenticated recipient, explicitly selected operation names, optional non-secret configuration object |
| `POST /v1/execution/connections/{id}/status` | `{"recipient":{"workspace_id":"…","subject_id":"…"}}` |
| `POST /v1/execution/connections/{id}/complete` | Same recipient wrapper; completes an authorized OAuth transaction into service custody |
| `POST /v1/execution/connections/{id}/refresh` | Same recipient wrapper; refreshes service-held credentials where supported |
| `POST /v1/execution/connections/{id}/disconnect` | Same recipient wrapper; disables this central handle and removes its usable token material; does not claim provider-global grant revocation |
| `POST /v1/execution/connections/{id}/invoke` | `InvokeRequest`: recipient, contract hash, grant revision, invocation ID, operation, argument object, trusted host approval ID when required |
| `POST /v1/execution/connections/{id}/invocations/{invocation_id}` | Same recipient wrapper; reads durable invocation status |

The host constructs the recipient from its authenticated principal and enforces its own tenant/project/session/audience ACLs before every management or invocation action. It must not take recipient, contract, grant revision or approval fields from model arguments. Installation signatures identify the host installation; they are not proof of arbitrary cross-host user authority. Connection handles cannot be used by another installation or recipient.

`Connection` carries protocol, opaque ID, catalog ID, contract hash, recipient, admitted operations, grant revision, status and an optional authorization URL. It never carries provider access/refresh tokens. Status is `pending`, `connected`, `disconnected`, `failed` or `revoked`.

An invocation reports `running`, `succeeded`, `failed` or `outcome_unknown`. A first successful response can contain `result` with `result_available: true`. Replays and status reads contain only outcome metadata, with `result_available: false`; the service does not persist provider content to make results replayable. The host must handle missing result content explicitly. The same invocation ID cannot admit a changed request, and mutations are never blindly retried after a lost response. Repeated submission is not a way to retrieve content again.

## Minimal Go client integration

Use the public `central` package from the adopted module version. The operator supplies a fixed HTTPS origin and an explicitly trusted registry public key. Persist the normal installation identity privately and register it with the existing broker before creating central connections. No provider secret belongs in client configuration.

For the official shared service, `central.OfficialClient(identity)` supplies
`https://auth.openagent.uno` and the compiled Ed25519 trust pin
`central-registry-20261021-1` (`35N3Qb16evtD9iJGSZ-OqkCpUv092HEySnz9e4Z1pR0`).
Call `client.Register(ctx)` before creating connections. Each constructed client
owns independent trust-key bytes. Custom deployments can still configure
`Client` explicitly; SDK adoption does not grant access or qualify providers.

```go
identity, err := auth.LoadIdentity(identityPath, productName, installationName)
if err != nil { return err }
broker := &auth.Client{Origin: serviceOrigin, Identity: identity}
if err := broker.Register(ctx); err != nil { return err }

client := &central.Client{
    Origin: serviceOrigin,
    Identity: identity,
    TrustKeys: map[string]ed25519.PublicKey{trustedKeyID: trustedPublicKey},
}
catalog, err := client.Catalog(ctx)
if err != nil { return err }
// Select an available descriptor and explicit operations through the host's
// authorized installation flow. Catalog presence itself grants nothing.
connection, err := client.Create(ctx, central.CreateRequest{
    CatalogID: selected.Item.ID,
    ContractSHA256: selected.ContractSHA256,
    Recipient: central.Recipient{WorkspaceID: authenticatedWorkspace, SubjectID: authenticatedSubject},
    Operations: explicitlyApprovedOperations,
})
if err != nil { return err }
// Present connection.AuthorizationURL through the trusted UI when pending.
// After provider consent, use Complete(ctx, connection.ID, connection.Recipient).
```

`Connection`, `Complete`, `Refresh` and `Disconnect` take `(ctx, id, recipient)`. `Invoke` takes `(ctx, id, InvokeRequest)`; `Invocation` takes `(ctx, id, invocationID, recipient)`. Renew the catalog before admitting new contracts. Pin the admitted operation set/hash on the host: refreshing a feed must not expand an existing local grant. Existing service connections are checked against current availability and their pinned contract before execution.

The client enforces HTTPS, with explicit HTTP allowance only for `localhost`/`127.0.0.1` fixtures. It disables redirects even on a supplied HTTP client, bounds responses to 4 MiB, uses bounded requests, rejects ambiguous/unknown typed response fields, verifies catalog signatures/freshness and rejects revision rollback or same-revision content drift. Its revision high-water mark is in memory per client, not a durable offline cache. Trust keys and origin are explicit configuration; no network key discovery or automatic key rollover is implemented. Configure the client before concurrent use and do not copy it afterward.

New service adapters can be discovered without adding provider-specific client code, provided they fit the supported protocol, schemas, custody and host policy. A deployment or consumer adopting this package still needs its normal compatibility/security/provider qualification. This package does not install adapters from arbitrary feed URLs, migrate legacy credentials, supply cross-host delegations, activate provider apps or prove privacy-sink coverage.

## OAuth activation audit

### Private Gmail qualification

An optional `gmail_qualification` object in `ServiceConfig` admits a temporary
trial for **one already registered installation and one exact host recipient**:

```json
{
  "id": "gmail-qa-1",
  "revision": 1,
  "catalog_id": "gmail",
  "installation_id": "<existing 64-character lowercase key fingerprint>",
  "recipient": {"workspace_id": "<trusted workspace>", "subject_id": "<trusted subject>"},
  "expires_at": "<absolute UTC deadline no more than 24 hours ahead>"
}
```

These placeholders are deliberately not an executable enrollment. An absent
object closes the trial. Unknown fields, wildcards, other connectors, malformed
identities, zero revisions, missing expiry and deadlines more than 24 hours
ahead reject startup. A retained expired row remains disabled without blocking
the public service's restart. The configured Gmail provider must reuse its
existing app, callback and secret reference, enable PKCE, and declare exactly
`gmail.modify` and `gmail.send`. No new app, legacy token import, provider-wide
QA gate, account creation or provider consent is implied by this configuration.

The authenticated host calls `client.QualificationCatalog(ctx, recipient)`;
`POST /v1/registry/qualification` uses the ordinary installation signature,
nonce and timestamp with the same recipient wrapper as connection status.
Only the exact admitted host/principal receives the signed private catalog.
Its payload contains `qualification` with the complete rule, a lifetime no
longer than five minutes or the remaining rule deadline, and the existing seven
typed Gmail operations. Its cache/revision is separate from `Catalog`.
The public catalog is unchanged: private qualification does not mark Gmail
available for other consumers. Never merge private availability into a public
catalog or into another principal's discovery cache.

Pass the private catalog's `qualification.id` as `CreateRequest.QualificationID`
alongside its exact contract hash, recipient and selected operations. The normal
OAuth, status, refresh and invocation routes apply; `Connection.QualificationID`
identifies the temporary grant. Host ACLs and per-action approval remain
mandatory. Selecting read tools does not make the Google token read-only:
`gmail.modify` also permits sending at Google.

Each grant stores a hash of the entire immutable admission in the encrypted
vault. Removing/changing the row or passing its deadline denies discovery,
creation, pending consent/completion, refresh, execution and outcome reads;
the same old grant cannot fall back to a later public Gmail descriptor.
Checks also fence token acceptance and result publication after provider IO.
An expired/removed trial can still disconnect its own handle through the normal
authenticated cleanup route. To revoke a pending transaction immediately on a
configuration change, restart the broker with the service: transactions are
in memory, and configuration is startup-only. Do not replace only an HTTP
handler while retaining an older broker's pending consent sessions.

Before a live trial, deploy accurate central-custody/privacy disclosures,
independently verify the intended installation and principal, record the exact
temporary operator rule, obtain the provider consent and any write approvals
required by the QA plan, and complete the provider/tool/lifecycle/isolation
checks. Disable the rule and disconnect test handles afterward. Source tests
are synthetic; they neither qualify live Gmail nor complete Google's review
or any required security assessment. Public activation remains a separate,
reviewed decision after those gates.

See the [21 October per-provider activation gates](../../../docs/central-oauth-activation-2026-10-21.md) before enabling an OAuth descriptor. Existing broker configuration and legacy lifecycle receipts do not qualify the new central custody and execution path.
