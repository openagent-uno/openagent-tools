# OpenAgent MCP scaffold

Read [OpenAgent architecture and repository role](OPENAGENT-ARCHITECTURE.md)
and [AGENTS.md](AGENTS.md) before using or changing this repository.

This tree preserves an earlier MCP scaffold. Its existing packaging and discovery
metadata include assumptions about a particular host implementation; they are
compatibility debt, not OpenAgent's general integration contract. The previous
host deployment recipe is removed from this maintained README; Git history
preserves the original. This documentation update does not claim the scaffold's
implementation has already been generalized.

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
