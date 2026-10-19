# OpenAgent Tools

Independent, reusable filesystem, editor, shell, web search, Meta Ads and
device capabilities. Hosts may call them as Python packages, expose them
through the neutral tool protocol or register them as MCP servers where
supported.

Start with [docs/README.md](docs/README.md). The public capability guide is at
[openagent.uno](https://openagent.uno/guide/mcp), and the verified beta artifacts
are published in the repository releases.

## Official connectors

[`packages/connectors`](packages/connectors/README.md) owns the shared Go catalog, adapters, runner and authentication broker. The standalone Python/MCP adapter is `packages/connectors-python`; release bundles and checksums are built with `scripts/build_connectors.py`. [Authentication deployment runbook](deploy/connector-auth/README.md).

The [published SDK/runner **0.1.12**](https://github.com/openagent-uno/openagent-tools/releases/tag/connectors-v0.1.12)
contains **114 official connectors plus Custom MCP**, with **315 read tools and
82 actions**. This release adds authenticated legacy Shopify relay delivery and explicitly negotiated native privacy receipt v2. A delayed redaction uses one uniquely verified prior uninstall cutoff; missing or ambiguous history remains pending. Updating a runner never implicitly claims host support. Catalog operations, schemas and permissions are unchanged. The
[publication and qualification receipt](docs/connector-sdk-0.1.12-qualification.json)
records 11 verified release assets, six cross-platform bundles, anonymous public
downloads, Go Proxy provenance and actual Linux-native runner/acquisition checks.

The 90 manual profiles expose finite API subsets, with two typed reads each;
OneDrive and SharePoint expose 12 read-only operations. These are not complete
ChatGPT app implementations or shared OAuth registrations. Vendor permissions
remain setup guidance; manually supplied credentials do not attest OAuth scopes.
This release qualification performs no provider calls or grants. Product adoption
is separate. See the [coverage and qualification index](docs/chatgpt-app-coverage.md)
and the [native receipt and host-adoption contract](packages/connectors/README.md#authenticated-shopify-receipt-v2).
