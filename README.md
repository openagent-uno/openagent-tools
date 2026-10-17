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

The published SDK/runner is **0.1.7**, with twenty-two official connector entries.
OpenAgent Server/CLI **1.1.0-beta.43** remains pinned to SDK 0.1.6; App **1.1.0-beta.20**
was produced by the normal native release workflow. See the
[coverage and qualification index](docs/chatgpt-app-coverage.md) for the exact
source, artifact, provider-read and product-runtime boundaries.

The [**0.1.7 prerelease**](https://github.com/openagent-uno/openagent-tools/releases/tag/connectors-v0.1.7) adds Google Calendar, Outlook Mail and Outlook
Calendar. Contract, bundle and Linux-native qualification passed; real Google/Microsoft OAuth acceptance and common enrollment remain pending. See the
[operation contract and remaining gates](docs/connector-calendar-mail-0.1.7-candidate.md).
The directory inventory is a backlog; it does not claim that every ChatGPT app
has an implemented or authorized OpenAgent integration.
