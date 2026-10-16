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

The unpublished `0.1.4` source candidate includes 17 GitHub, 8 Notion, 9 Slack
and 9 Atlassian/Jira typed operations. Go test, vet and runner build passed on a
remote worker; this is not real OAuth or native-platform acceptance. Published
connector artifacts and consumer pins remain `0.1.3`. See the
[source and registration checkpoint](deploy/connector-auth/qualification-2026-10-16.md)
and [complete directory coverage inventory](docs/chatgpt-app-coverage.md).
