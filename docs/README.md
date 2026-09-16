# Independent OpenAgent tools

Each package can run as an MCP server or be called as a Python capability without
installing the agent engine. Filesystem, editor and shell import only the neutral
`openagent-tool-protocol`; native sidecars are owned here. The optional generic
`openagent-capability-host` is owned by core and depends on the neutral protocol;
the protocol has no dependency on that host or engine. The standalone product
composes these packages through its `openagent-host-tools` compatibility facade.

See [extraction provenance](provenance.json). MCP names and result envelopes,
shell completion events, sidecar sources and signing identifiers are preserved.

See [verification](verification.md) for package installation checks and the
explicit limits of native/platform qualification. Build wheels with
`python packaging/build.py --out /absolute/artifact-directory`.
