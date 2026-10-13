# Connector qualification checkpoint, 13 October 2026

The common broker remains healthy over HTTPS with zero enabled providers.
Library/runner 0.1.1 publication is separate from common enrollment and product
release. Google, ClickUp and Shopify registration preparation remains as recorded
in the preceding checkpoint; real provider flows and required reviews are not
claimed complete.

## Documentation and host acceptance

The public documentation now covers [usage](https://openagent.uno/guide/connectors),
[shared Core/Tools/connector/MCP boundaries](https://openagent.uno/guide/shared-components),
[operator setup and recovery](https://openagent.uno/guide/connector-operations)
and [remaining gates](https://openagent.uno/guide/connector-status).

Standalone integration includes current canonical main and verified Core/SQLite
beta 20 wheels. Its 25 focused connector authorization/storage and acquisition
checks passed without a Core overlay. The host now refuses to silently replace
a missing encryption key when encrypted credentials or privacy events exist.
Independent host private native acceptance also verified local disconnection, removal of
credential/nonce, full server restart and retention of the authenticated catalog.
These are development/contract proofs, not signed native or real provider tests.

## Prepared infrastructure qualification

A protected consistent datastore snapshot, original binary, server token and
configuration were retained. An offline controller restored the snapshot,
performed a compatible same-minor patch transition, enabled/rotated encryption
and restarted. Broker secret values were unchanged and the current copied
datastore record was encrypted. The test used network and mount namespaces,
bounded CPU/memory and no agent/kubelet. Node bootstrap annotation was reproduced
explicitly in the copied database, so it is not worker runtime acceptance.

An initial network-only attempt exposed a K3s compatibility-symlink write outside
the requested data directory. The administrative kubeconfig was restored from
backup; the final mount-isolated run preserved it byte-for-byte. All isolated
controllers are stopped. The following production maintenance was performed
after the operator explicitly approved it; the isolated test alone did not
authorize a shared-cluster change.

## Production secret storage and admission

The production control plane was upgraded from `v1.33.6+k3s1` to the official
`v1.33.13+k3s2` binary (SHA-256
`1572f0f23bd5a844bd405b71875877aacacc7ab79e279d3d73735654c37c7735`).
A fresh consistent SQLite snapshot, original binary, server token, credentials
and configuration were protected before the transition. The vendor sequence
`secrets-encrypt enable`, configuration/restart, `rotate-keys` and final restart
completed. Live status reports **Enabled**, **reencrypt_finished**, **All hashes
match**. Both nodes are Ready; the worker retains the same-minor `v1.33.6+k3s1`.
The broker Secret values remained unchanged, its current datastore record is
encrypted, and a matching post-rotation backup was integrity-checked. Backups
include sensitive encryption material and remain root-only on the server.
The broker returned to one ready replica and HTTPS health with zero providers.

A real outgoing client pinned to the published Go module `v0.1.1` verified TLS,
signed registration/mailbox access, unsigned/replayed request rejection and
disabled-provider rejection. A bounded burst of 130 mailbox requests at maximum
concurrency four produced 118 successful responses and 12 rate-limit responses;
the preceding two admitted requests complete the 120-per-minute quota. There
were no unexpected responses. Median latency was 184 ms, p95 299 ms and maximum
376 ms over 6.1 seconds. Broker memory measured 7 MiB after the burst, with no
restart. This qualifies **bootstrap mailbox admission only**, not real provider
exchange/rotation or privacy backlog capacity. The current 10m CPU reservation
is still a bootstrap setting; production request-budget/admission qualification
remains required before enrollment. The prior Tailscale profile was restored.

Product-local standalone privacy-content lineage/export/redaction, provider
activation, actual dual-server Shopify acceptance, native qualification and
coordinated rollout remain separate gates. No provider or webhook migration was
enabled on the basis of these infrastructure tests.
