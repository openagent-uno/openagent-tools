# Authenticated Shopify legacy relay (source candidate)

The existing approved app and secret remain in use. No webhook destination or
enrollment configuration has been changed by this source patch.

The broker retains its encrypted native receipt, projects legacy uninstall to
exactly `{id: positive uint64}`, and recomputes the Shopify body HMAC over the
forwarded bytes. All four topics include the reviewed API version `2026-07`,
original delivery ID and original `X-Shopify-Triggered-At`.

A separate domain-separated HMAC authenticates relay transport. Version 1 signs
these newline-separated fields: `openagent-shopify-legacy-relay/v1`, exact
operator-configured audience URL, delivery-attempt time, topic, shop domain,
webhook ID, API version, original occurrence timestamp, and lowercase SHA-256 of
the exact forwarded body. Fields cannot contain CR/LF/NUL. Relay headers are
singletons; partial, duplicate, unknown-version, altered or expired envelopes
are rejected. Delivery freshness is two minutes past / one minute future. The
key is the existing app secret, with a different MAC domain from Shopify's body
signature; no credential is moved or logged.

The receiver independently verifies the body HMAC and all existing payload,
routing, future-time and durable deduplication rules. Only a verified relay may
carry an uninstall older than the direct receiver's unchanged 24-hour bound.
Retries refresh the transport timestamp/signature only. They never rewrite the
original occurrence time or identity. Compliance receives that authenticated
original time through the already-supported control-plane contract.

The legacy SQL recipient must remain generation-aware: a late event from before
a reinstall must not revoke the new grant or erase its newer content. Existing
conflicting event/body ledgers fail closed; this patch does not reset them.
Genuine provider delivery, production compatibility, offline replay and public
enrollment are separate operational gates. Synthetic fixtures are not evidence
of Shopify delivering a notification.

## Staged cutover without early public enrollment

Start the broker with `--shopify-new-consents-disabled` while configuring the
legacy routes and qualifying the central callback. `/healthz` reports
`shopify_enrollment: "paused"`; the service and other providers remain ready.
Only a new Shopify transaction is denied (`503 authorization_not_ready`).
Existing valid pending callbacks/redeem, refresh, mail and privacy delivery keep
their original authorization. The flag requires an actual Shopify provider row.
After the reviewed genuine delivery/cutover gates pass, remove only this startup
flag through a fresh image/config-preserving CAS rollout. This is not a caller
privacy assertion or a bypass of the receiving host's qualification gate.

## Native privacy receipt compatibility

New Shopify enrollment requires the host to explicitly negotiate receipt version 2; upgrading the SDK alone does not enable it. Native v2 `shop/redact` receipts preserve the provider notification time and carry a separate authenticated uninstall cutoff. A verified, schema-marked v2 uninstall from the same app/shop must be the unique unused eligible counterpart at least 48 hours earlier, with a five-minute provider-clock tolerance. The persisted pairing becomes immutable before first emission. Historical v1 records are never upgraded by inference.

Missing or ambiguous counterparts remain durable, are not emitted or acknowledged, and require investigation of the retained authenticated event history. Shopify supplies no uninstall correlation identifier, so ordering alone cannot establish a pair. Operators must not clear the queue, rewrite occurrence times, or mark the obligation complete to unblock enrollment. Legacy direct events continue under their existing contract; authenticated relay consumers must apply the same unique-counterpart guard to the original notification time. Old native v1 requests with pending `shop/redact` receive `unsupported_receipt_version` (HTTP 426).
