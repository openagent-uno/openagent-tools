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
