# Extraction verification

The migration retains the full `openagent-host-tools` history and imports the
web-search path history without squashing it. Tags are namespaced under
`legacy/host-tools/`. [provenance.json](provenance.json) records the source commits.

Verified on macOS arm64 with Python 3.12 and Node 22:

| Check | Result |
| --- | --- |
| Existing product host-tools suite against extracted implementations | 87 passed; 2 skipped |
| Explicit generic capability host, ownership and overlapping keys | 4 passed |
| Independent Python tool and official MCP stdio clients | 6 passed; 1 Windows-only skip |
| Noneditable wheel installation outside all repositories | 35 passed; 1 Windows-only skip |
| Web-search build and search-engine regression | 2 passed |
| Meta Ads video URL normalization and MCP discovery | 6 tests; 55-tool write-enabled handshake |
| Native computer-control tests (`cargo test --locked`) | 37 passed; 2 real-display tests intentionally ignored |

The noneditable installation contains `openagent-capability-host`, the neutral
protocol, concrete tools and the standalone compatibility facade, all at
`1.0.0b1`. Module paths were checked to resolve inside its `site-packages`, not to
an editable checkout. Filesystem, editor and shell were started as independent
MCP stdio subprocesses using the official MCP client. Two shell instances receive
separate environment snapshots. Reusing a principal and idempotency key in two
capability hosts does not share state; closing one leaves the other functional.

`packaging/build.py --out DIR` builds six Python tool wheels plus the web-search
and Meta Ads npm archives from one temporary source snapshot. It rejects a
nonempty output directory and writes `manifest.json` with the exact commit,
dirty flag, source digest and SHA-256/size of every artifact. Native source inclusion uses an explicit file list so generated
`target`, `node_modules` and `__pycache__` trees cannot enter the device wheel.
The product owns host-tools installers, signing and updater scripts; they consume
native sources through the installed device package's `sidecar_source()` API.

No production data or old source checkout was modified. No package was published,
and signed cross-platform bundles, updater chains, real display capture/control,
and provider-backed web search have not been qualified by these checks. The
inherited web-search lockfile reports 10 npm audit findings (1 low, 3 moderate,
6 high); no dependency upgrade was mixed into this source-preserving extraction.

The independent `openagent-execution` wheel adds explicit local/Docker/SSH process
backends without global factories or engine imports. Three installed-wheel tests
exercise independent environment snapshots, real cancellation preventing a later
filesystem effect, and rejection of unsupported remote RPC routing. Five core
interop tests execute real Python through Unix and file RPC, verifying opaque
tool references, full results, current authorization, dry-run, call budgets,
missing-executor/isolation refusal, timeout and per-run cleanup. File transport
was qualified using a local fixture, not a running Docker container. Real Docker
and SSH execution and native Windows process behavior remain unqualified.
