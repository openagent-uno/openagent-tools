# OpenAgent MCP scaffold

This starter lives in `openagent-tools/examples/mcp-server`. Read the root
[tool contracts](../../docs/USAGE.md) and [local guidance](AGENTS.md).
Copy this directory for a new server or install it directly with
`pip install ./examples/mcp-server` from the repository root.

This is an independent MCP stdio scaffold. Run `pip install .`, then
`python -m openagent_mcp_example` (or `openagent-mcp-example`). The host owns
stdio, discovery, authentication, authorization and process lifecycle. The
example exposes only `hello`; no shared database, vault, pod or SDK is required.
The container uses the same stdio entry point; attach stdin when invoking it.
`skill.yaml` is optional descriptive metadata and grants no permissions.

For new generic capabilities, start from the independent provider contract in
[OpenAgent Tools](https://github.com/openagent-uno/openagent-tools/blob/main/docs/USAGE.md).
A tool publishes schemas, effect classification and complete results. The host
explicitly selects its function/MCP transport, authenticates and authorizes
callers, registers the source and owns process lifecycle. Installation alone
does not imply discovery, a pod, an orchestrator or an agent runtime.

Generic Runtime and capability-host boundaries are in
[Core components](https://github.com/openagent-uno/openagent-core/blob/main/docs/COMPONENTS.md).
Standalone App/CLI/server/bridge composition is in
[product components](https://github.com/openagent-uno/openagent/blob/main/docs/COMPONENTS.md).

OpenAgent must remain agnostic across every repository: no embedding-project or
external consumer-client references, no consumer-specific defaults, feature
branches or bug fixes. Add reusable public extension contracts upstream when
needed; keep domain adapters, branding and business permissions outside.

The original standalone template Git history is retained by the subtree import;
its refs and release provenance are recorded in the template migration receipt.
