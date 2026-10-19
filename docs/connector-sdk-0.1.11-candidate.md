# Connector SDK 0.1.11 candidate

Not published or qualified yet. The catalog remains 114 official connectors plus Custom MCP; operations, scopes and product defaults are unchanged.

The Python privacy selector recognizes only the compiled Shopify products-list `data.productsCount` object with exactly `count` and `precision`. The count must be a nonnegative GraphQL Int (at most 2^31−1), excluding booleans; precision must be `EXACT` or `AT_LEAST`. This technical fragment retains the host-provided app, shop, grant and tenant lineage. Unknown paths, extra fields and malformed values remain fenced.

Primary contracts: [Count](https://shopify.dev/docs/api/admin-graphql/2026-07/objects/Count), [CountPrecision](https://shopify.dev/docs/api/admin-graphql/latest/enums/CountPrecision), [Int](https://shopify.dev/docs/api/admin-graphql/latest/scalars/Int).

The broker also preserves the existing active app/shop/scope consent generation when another verified recipient joins, while a first grant, revocation or scope change starts a new generation. Credential versions continue rotating independently. Product consent checks remain unchanged.

The release will rebuild all six native targets from its frozen source, avoiding relabelling 0.1.10 binaries. Qualification and independent product adoption remain pending. No provider acceptance follows from the schema fixtures.
