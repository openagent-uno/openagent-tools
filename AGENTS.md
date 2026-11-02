# openagent-mcp-template

Read `OPENAGENT-ARCHITECTURE.md` and the repository README when present.
Generic MCP-server scaffold, not a host-specific runtime. Review its selected MCP transport before use; discovery is explicitly owned by the integrating host.

OpenAgent is agnostic in every repository: no references to embedding projects
+or external consuming clients, no consumer-specific features, fixes, defaults,
+prompts or identity branches. Use neutral fixtures and generic public contracts.
+Agent changes belong in the owning active OpenAgent component, including when
+its architecture needs correction; consumers inherit versioned capabilities
+without local patches/overrides. Keep domain data/policy outside OpenAgent.
+Preserve historical release assets and exact evidence; update current contracts
+in the canonical active repository rather than forking them here.
+