# Browser process and transport contract

Device-tools b9 owns browser launch, CDP pipes and target readiness. An explicit
`OPENAGENT_CHROME_BINARY` is authoritative and fails closed when unavailable;
there is no fallback to another installed browser. `OPENAGENT_CHROME_HEADLESS`
selects headless mode. `OPENAGENT_CHROME_TRANSPORT=pipe` uses inherited CDP pipes
instead of a TCP debugger, including an AppContainer-local Windows bridge.

The trusted host may set absolute `OPENAGENT_CHROME_ENVIRONMENT_ADAPTER` (ES module
exporting `linuxBrowserEnvironment(profile, environment, directory)`) and
`OPENAGENT_CHROME_WINDOWS_ADAPTER` (Python module exporting
`verify_browser_confinement(binary)` and `spawn_private_browser(...)`). These
ports bind an already provisioned sandbox/desktop and its packaged environment;
they never select tools, commands or CDP semantics. A required adapter failure
fails the launch. `OPENAGENT_CHROME_PYTHON` selects the bridge interpreter.
Only an explicitly inherited sandbox may set
`OPENAGENT_CHROME_INHERITED_SANDBOX=1` for macOS nested-sandbox compatibility.
Configuration is supplied by the authenticated host, never model tool arguments.
Consumers distribute the exact public sidecar and its dependency lock; no source
rewrite, browser dependency profile or node_modules transformation is required.
Windows/macOS installed GUI acceptance remains separate from transport tests.

Device-tools b10 also closes a pipe-backed browser by its owned child lifecycle,
without probing an unrelated TCP port. An owned Chromium regression exercises
launch, CDP version, target creation and shutdown on that transport.

The Playwright semantic layer currently requires a WebSocket CDP endpoint. A
pipe-backed browser advertises those operations as unavailable and returns an
explicit unsupported-transport outcome, without switching browser or exposing a
TCP debugger. Basic CDP tools remain supported on the pipe transport.
