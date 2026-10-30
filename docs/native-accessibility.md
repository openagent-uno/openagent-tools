# Native accessibility snapshots and actions

Source candidate, 30 October 2026: device-tools `1.0.0b5`, native
computer-control `0.1.4`. This adds original OpenAgent implementations of native
accessibility observation and element actions. The behavioral comparison used
installed desktop client interfaces; no third-party implementation was copied.

The reusable implementation lives in OpenAgent Tools. It remains an explicitly
registered capability; importing Core does not install desktop access. Products
must acquire the candidate sidecar, retain their own authenticated target and
consent boundaries, and expose its actual catalog before advertising the tools.

## Tool contract

`computer_list_windows` supplies the exact `window_id` and `pid` accepted by
`computer_accessibility_snapshot`. The latter returns a flat accessibility tree:

```json
{
  "snapshot_id": "opaque process-local identifier",
  "window": {"window_id": 123, "pid": 456},
  "elements": [{"element_id": "element-0", "parent_id": null, "depth": 0,
                "state": {"role": "AXWindow"}, "actionable": true}],
  "truncated": false,
  "expires_in_ms": 120000,
  "single_use": true
}
```

The actual `window` also identifies its title, bounds and process birth time.
Each `state` includes the role/subrole, title, description, identifier, bounded
text value, enabled/focused state, bounds, native action names and whether text
value editing is allowed. These are observations, not instructions or grants.

Optional `max_depth` is 1–30 (default 12); `max_nodes` is 1–1000 (default 300).
Traversal has a time budget and signals truncation or an explicit busy/timeout
error. Every AX read and action uses a per-object timeout limited by the remaining
three-second aggregate native-request budget; child objects do not inherit a
parent object's macOS timeout. Cancellation is checked before every next native
query, including read-only snapshots. Model-visible text is
limited to 512 characters per attribute. Exact native scalar values retained
for stale checks are bounded to 2 MiB per snapshot; a node with incomplete
retained state has `actionable: false`. Secure text field values are never read
or returned, and cannot be set through this interface.

`computer_accessibility_action` accepts `snapshot_id`, `element_id`, `action`
(`press`, `show_menu`, or `set_value`) and, only for `set_value`, a text `value`
of at most 16 KiB. An action is performed only if the selected element currently
advertises the native action or exposes a writable, non-secure text value.

## Identity, stale state and cancellation

- The CG window/process pair is re-resolved before observation and every action.
  Process birth time additionally fences a recycled PID.
- Public macOS AX attributes bind the tree to exactly one window with matching
  title and geometry. Missing or ambiguous matches fail. No private window-number
  API, alternate app, inferred coordinate or keyboard fallback is used.
- Element handles retain their native identity, observed scalar values and
  membership of the selected window. State, process, window and ancestry are
  revalidated immediately before a mutation. Changes beyond a displayed text
  prefix are still detected using exact native scalar comparisons.
- A new snapshot invalidates earlier snapshots of that window. Snapshots expire
  after 120 seconds; the service retains at most eight. Restarting the helper
  invalidates every handle.
- An action consumes its snapshot before target validation, including failures.
  A caller must inspect a fresh snapshot before another action or retry. Neither
  uncertain native mutations nor clipboard/coordinate substitutes are replayed.
- Cancellation is checked before a queued worker starts and immediately before
  native mutation. Cancellation cannot undo an already started OS action; its
  outcome must be inspected, never inferred from a disconnected transport.

The current implementation supports macOS only and requires its Accessibility
and Screen Recording grants. Other platforms return
`accessibility_unsupported_platform`; the descriptions declare this limitation.
Permission errors remain explicit. Existing coordinate tools retain their
cross-platform behavior.

## Local verification

Build and run the native unit tests:

```sh
cargo test --manifest-path sidecars/computer-control/Cargo.toml --offline
cargo build --manifest-path sidecars/computer-control/Cargo.toml --offline
```

Real macOS acceptance uses an owned AppKit window with one ordinary text field,
one secure field and one button. It reads no user data and closes its own process
on completion. Build the fixture and run with Python containing the MCP SDK:

```sh
swiftc sidecars/computer-control/tests/fixtures/native_accessibility_fixture.swift \
  -o sidecars/computer-control/target/native-accessibility-fixture
.venv/bin/python sidecars/computer-control/tests/native_accessibility.py
```

The verified local run completed ten checks: real MCP catalog, exact AX tree,
secure-value redaction, superseded references, Unicode value editing, single-use
replay rejection, native button action, concurrent field changes, concurrent
changes beyond a truncated display prefix, and moved-window rejection. The
fixture's state file confirmed the actual value and button counter. Its receipt
is written to `sidecars/computer-control/target/native-accessibility-evidence.json`.

The native unit suite passed 50 tests. The two older real capture/recording tests
and the owned busy-window probe remain opt-in. The busy-window probe was also
executed: a retained child AX element returned a timeout within 900 ms while its
owned AppKit process was deliberately blocked for two seconds. The receipt is
`sidecars/computer-control/target/native-accessibility-timeout-evidence.json`.
Run it after compiling the fixture with:

```sh
cargo test --manifest-path sidecars/computer-control/Cargo.toml --offline \
  native_child_query_timeout_real_fixture -- --ignored --nocapture
```
 The complete Tools Python suite passed 24 tests with one skip.
The changed module also typechecked for Windows ARM64 in an isolated offline
probe. A full Windows component check is blocked by the existing OpenH264 C++
build on this Mac: Apple clang rejects its `-fPIC` option for the Windows target;
a Windows C++ toolchain remains required. This is not a native Windows result.
These checks do not qualify arbitrary applications, native Windows/Linux AX
backends, signed distribution or installed-product adoption. Those boundaries
remain separate release gates.

The Python placeholder catalog is regenerated from the actual native MCP
`initialize` and `tools/list` responses, including read-only annotations and
schemas. The wheel source list includes `accessibility.rs`. A development host
may explicitly select a newly built binary through
`OPENAGENT_COMPUTER_CONTROL_COMMAND` as a JSON command array. A published host
must instead pin and verify its signed bundle and manifest. Never update an
existing release manifest to pretend it already contains this source candidate.
