# Connector qualification checkpoint, 14 October 2026

This checkpoint records a real, allowlisted ClickUp trial through the published
standalone product. It does **not** activate public enrollment or qualify other
providers, arbitrary receiving hosts, or shared Shopify.

## Authentication deployment

Auth-only `0.1.6` is published and deployed from source
`d61f23e33352c74a6dc6c5b3948b67c0f625cd6a`. The live immutable image digest is
`sha256:443fec0b631ea771ca5fc667a02f013f12df84fb6e8830ca834bd0a84850adfa`.
The image-only rollout preserved installation metadata, secrets and provider
configuration. The isolated private restore check passed; no credential values
are reproduced in this checkpoint.

The disclosure page previously applied `Referrer-Policy: no-referrer` while its
form POST required an exact `Origin`. For a basic browser form POST, that policy
can make the origin `null`. Auth `0.1.6` uses `same-origin` only on the unapproved
disclosure page. The exact-origin check, secure consent cookie, CSRF comparison,
single-use consent and `form-action 'self'` remain in place. The provider
navigation page and its outbound link retain `no-referrer` protection.
See the [Fetch origin-header algorithm](https://fetch.spec.whatwg.org/#append-a-request-origin-header).

A real browser disclosure POST succeeded after the fix. The provider then
accepted the operator-authorized ClickUp workspace grant and returned through
the registered callback. The receiving product redeemed the result using its
ordinary authenticated polling API and committed encrypted credentials locally.
Browser cookie values, OAuth codes, access tokens and user data are not evidence
fields in this document.

## Receiving-product acceptance

The trial used the normal public server/CLI `1.1.0-beta.39` dependency assembly:
Core/SQLite beta 22, connector adapter/runner `0.1.3` and Host Tools `1.0.0b6`.
The original receiving installation identity was preserved. Client access used
ordinary SRP authentication, a certified device and Iroh; it did not use a
substituted identity, extracted provider token or central API-content proxy.

| Recorded check | Result and boundary |
| --- | --- |
| Disclosure and provider consent | Real browser POST, provider grant and registered callback passed for the allowlisted recipient. |
| Product credential commit | Ordinary authenticated poll completed; encrypted local storage passed. |
| Read | A normal workflow performed the authorized ClickUp read. |
| Write and cleanup | Creation and deletion of the trial's own QA object passed; this is not acceptance for unrelated provider mutations. |
| Product restart | The authorized read passed after restart with the preserved installation and credentials. |
| Local disconnection | The connection became disabled; a read-only local database check confirmed credential, nonce and transaction removal. |
| Trial teardown | The owned server process stopped and its PID file was removed; no QA task remained. |

ClickUp's issued credential is non-expiring in this trial, so this sequence does
not claim a real refresh-token renewal. Existing fixture-based renewal and
revocation tests remain separate contract evidence.

No local Mac build or GitHub Actions run was used for this auth fix and trial.
Publication and actual-provider acceptance are distinct from the earlier
contract tests and from the independently published connector module/runner.

## Remaining gates

- Enrollment remains restricted to the explicitly allowlisted QA installations.
  No public provider activation or additional provider configuration changed.
- Google real consent and applicable verification/security assessment remain
  pending. Postiz real consent and acceptance remain separate.
- Common Shopify remains disabled. Real two-server consent/rotation/recovery,
  mandatory webhook delivery and receiving-product content processing still
  require acceptance before activation.
- Public Core beta 22 and standalone beta 39 qualify opt-in processing for a
  fresh canonical text-history cohort. Historical content, media, Vault/files
  and unqualified host callbacks remain outside that coverage and fail closed.
  A durable webhook receipt does not mean content actions are complete.
- Provider exchange/rotation/privacy backlog capacity and each receiving host's
  rollout require their own qualification. This ClickUp trial does not establish
  those gates or native GUI acceptance on every supported platform.

The [13 October checkpoint](qualification-2026-10-13.md) retains the earlier
infrastructure and bootstrap admission evidence. The [QA enrollment procedure](qa-enrollment.md)
describes the restricted trial boundary.
