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

Device-tools `1.0.0b2` adds `computer_list_windows` and
`computer_capture_window` to the local computer-control sidecar. The first
returns current window ID, process ID, app/title, bounds and focus state; the
second re-resolves that exact ID/process pair and returns a downsampled PNG or
a stale-target error. They require the same verified client registration and
OS screen-capture permission as the existing computer tool. The package still
does not provide an accessibility tree or element-targeted native actions.
Device-tools `1.0.0b3` also adds `computer_list_displays`. The `computer` tool
accepts an exact `display_id` for pointer coordinates, cursor position and
screenshots; call `computer_list_displays` first. Coordinates are relative to
that display and changed or undiscovered IDs fail.
Keyboard focus and screen recording cannot be bound to a display, so the tool
rejects `display_id` for those actions. The default remains the primary display.

`openagent-execution` supplies process execution when a host explicitly enables
code execution. It depends on `openagent-shell`, not the core. The core defines
its structural `CodeExecutor` protocol and accepts an instance from the product.

Filesystem manifest 1.0.1 and Editor manifest 1.1.0 name the registered
destination accurately in both client and server composition. Editor also adds
`apply_patch`: unified-diff hunks against one
existing UTF-8 file, with every context line checked before an atomic replace.
Shell manifest 1.1.0 adds read-only `shell_processes` with optional PID/name
filters and a bounded result. It omits process arguments and environment values.
Both tools travel through the existing editor/shell registrations, so an App or
CLI connection exposes the verified local destination and the standalone server
exposes only its own configured workspace destination.
No package chooses local, Docker or SSH from process-global environment variables.
The host supplies environment, interpreter, transport and isolation policy and
closes the instance it owns. Remote PTC requires an explicit filesystem bridge;
SSH process support alone does not enable PTC over SSH.

`@openagent-uno/meta-ads-mcp-server` is an independently runnable MCP server,
derived from the MIT-licensed `hashcott/meta-ads-mcp-server` 1.5.1. It preserves
the upstream catalog and adds `meta_ads_upload_ad_video`. Public Google Drive
sharing links are converted to direct downloads before Meta fetches the video.
The tool remains gated by `META_ADS_ENABLE_WRITE_TOOLS=true`; installing the
archive does not register it in a runtime.

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

Release `v1.0.0-beta.2` adds the independently installable Meta Ads archive.
Its manifest covers the six Python wheels and both npm archives from the same
source snapshot.

The next repository release is `v1.0.0-beta.3`. Its three updated Python wheels
(filesystem, editor and shell) are `1.0.0b2`; the neutral protocol, device and
execution wheels stay at their existing pinned versions.
