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

The [published SDK/runner **0.1.8**](https://github.com/openagent-uno/openagent-tools/releases/tag/connectors-v0.1.8)
contains **114 official connectors plus Custom MCP**, with **315 read tools and
82 actions**. It adds 90 manual-credential profiles (180 typed reads) and
OneDrive/SharePoint (12 read-only operations). The
[publication and qualification receipt](docs/connector-sdk-0.1.8-qualification.json)
records 11 verified release assets, six cross-platform bundles and actual
Linux-native installed-runner/acquisition checks.

The 90 manual profiles implement finite API subsets, not complete ChatGPT app
parity or shared OAuth registrations. Vendor permissions remain setup guidance;
manually supplied credentials do not attest OAuth scopes. No new live-provider
or Google/Microsoft consent acceptance is claimed. Server/CLI **44** and App
**21** remain the public consumers on SDK **0.1.7**; SDK 0.1.8 product adoption is
separate. See the [coverage and qualification index](docs/chatgpt-app-coverage.md).
