# OpenAgent repository role

Generic MCP-server scaffold, not a host-specific runtime. Review its selected MCP transport before use; discovery is explicitly owned by the integrating host.

All OpenAgent repositories are agnostic of embedding applications and external
+consumer clients. Do not add their names, domains, deployment assumptions or
+business-specific fixes here. Generalize behavior through upstream public contracts.

| Active repository | Responsibility | Documentation |
| --- | --- | --- |
| `openagent-core` | Kernel, reasoning engine/modules, stores, optional gateway/SDK | [Components](https://github.com/openagent-uno/openagent-core/blob/main/docs/COMPONENTS.md), [usage](https://github.com/openagent-uno/openagent-core/blob/main/docs/USAGE.md) |
| `openagent-tools` | Independent tools, execution backends, sidecars and connector SDK/runner | [Components](https://github.com/openagent-uno/openagent-tools/blob/main/docs/COMPONENTS.md), [usage](https://github.com/openagent-uno/openagent-tools/blob/main/docs/USAGE.md) |
| `openagent` | Standalone App/CLI/server/peer bridge, identity, channels, transport and packaging | [Components](https://github.com/openagent-uno/openagent/blob/main/docs/COMPONENTS.md), [usage](https://github.com/openagent-uno/openagent/blob/main/docs/USAGE.md) |

Read the [generic contribution rule](https://github.com/openagent-uno/openagent/blob/main/docs/site/guide/agnosticism.md).
New runtime capabilities use the same framework and authorization boundary in all
+conforming hosts. The host supplies its own domain data, permissions, credentials
+and lifecycle adapters. A tool process, connector runner and agent Runtime have
+different responsibilities; this repository's historical files do not redefine them.
