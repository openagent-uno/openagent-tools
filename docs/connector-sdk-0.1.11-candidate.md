# Connector SDK 0.1.11 patch qualification

[SDK 0.1.11](https://github.com/openagent-uno/openagent-tools/releases/tag/connectors-v0.1.11) is published from source `20bc4d3d1747ce8676c70c34ad2edaa86e33901d` after canonical remote qualification. The [receipt](connector-sdk-0.1.11-qualification.json) binds the 11 public assets, anonymous downloads and Go Proxy source provenance. The catalog remains 114 official connectors plus Custom MCP; operations, scopes and product defaults are unchanged.

The Python privacy selector recognizes only the compiled Shopify products-list `data.productsCount` object with exactly `count` and `precision`. The count must be a nonnegative GraphQL Int (at most 2^31−1), excluding booleans; precision must be `EXACT` or `AT_LEAST`. This technical fragment retains the host-provided app, shop, grant and tenant lineage. Unknown paths, extra fields and malformed values remain fenced.

Primary contracts: [Count](https://shopify.dev/docs/api/admin-graphql/2026-07/objects/Count), [CountPrecision](https://shopify.dev/docs/api/admin-graphql/latest/enums/CountPrecision), [Int](https://shopify.dev/docs/api/admin-graphql/latest/scalars/Int).

The broker also preserves the existing active app/shop/scope consent generation when another verified recipient joins, while a first grant, revocation or scope change starts a new generation. Credential versions continue rotating independently. Product consent checks remain unchanged.

All six native targets were rebuilt from the frozen source. Canonical Go tests/race, vet, vulnerability checks, Python privacy/acquisition/MCP checks and provenance passed. All 11 public files were downloaded anonymously and verified byte-for-byte; the public Linux x64 bundle returned the expected catalog. Other targets were cross-compiled, without native macOS or Windows execution. No provider calls or grants were part of this qualification. Independent product adoption remains separate.
