# Independent OpenAgent tools

The public capability guide is at
[openagent.uno](https://openagent.uno/guide/mcp); this repository remains the
canonical source for package contracts, provenance and verification evidence.

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

`openagent-execution` supplies process execution when a host explicitly enables
code execution. It depends on `openagent-shell`, not the core. The core defines
its structural `CodeExecutor` protocol and accepts an instance from the product.
No package chooses local, Docker or SSH from process-global environment variables.
The host supplies environment, interpreter, transport and isolation policy and
closes the instance it owns. Remote PTC requires an explicit filesystem bridge;
SSH process support alone does not enable PTC over SSH.

Use a dedicated empty output directory for tool artifacts. A product image must
select the required tool wheels explicitly and obtain `openagent-core`, modules,
capability-host and standalone composition packages from their own release
manifests. Do not mix earlier integration wheelhouses that contain packages with
the same beta version but different builds.

For this migration, the qualified independent Python wheel set is recorded in
`../.migration/openagent-v1/artifacts/tools-final-2/manifest.json` relative to this
repository. It contains exactly six wheels (protocol, filesystem, editor, shell,
device-tools and execution), with SHA-256, byte size and the implementation commit
`c348e6c` (editor workspace bounds); five unchanged wheels retain the hashes
from `tools-final`. Earlier `artifacts/tools` files remain diagnostic evidence and include
obsolete core/product builds; they are not a release wheelhouse. The separate web
search archive remains in the earlier evidence directory with its own package
version and verification results.
