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
ICS private native acceptance also verified local disconnection, removal of
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
controllers are stopped. No live datastore, binary or encryption configuration
was changed. Applying the prepared shared-cluster maintenance remains pending.

Product-local standalone privacy-content lineage/export/redaction, provider
activation, actual dual-server Shopify acceptance, native qualification and
coordinated rollout remain separate gates. No provider or webhook migration was
enabled on the basis of these infrastructure tests.
