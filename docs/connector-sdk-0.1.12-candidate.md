# Connector SDK 0.1.12 candidate

Not published or qualified yet. Catalog114 plus Custom MCP, operation schemas, permissions and host defaults remain unchanged. Existing public product beta49/SDK0.1.11 clients retain the same broker API; this candidate does not imply a product50 or App rebuild.

The shared legacy Shopify delivery MAC binds a fresh delivery timestamp and operator-configured receiver audience to the exact forwarded body digest and immutable original topic, shop, webhook ID, API version and occurrence timestamp. It supplements the provider body HMAC and durable deduplication; receivers retain every original metadata check and permit an occurrence older than24hours only after verifying the separate relay envelope. Original occurrence continues fencing older events against newer consent generations. Legacy uninstall projection is exact id-only, while native encrypted receipts retain verified shop binding.

Qualification and release are pending. A future release must build all six native targets from one frozen source and verify public bytes and source provenance. Synthetic relay fixtures do not establish real provider delivery or actual receiver acceptance. General broker enrollment and each host's derived privacy qualification are separate operational boundaries.
