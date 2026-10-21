# X11 text input after a keyboard-map reset

The reusable native computer-control source is owned by OpenAgent Tools, under
`sidecars/computer-control`. The historical host-tools and standalone product
copies are not the development source for this fix.

Enigo 0.5 keeps additional X11 keycode bindings for characters unavailable at
level zero of the active layout. If another X11 client reloads the keyboard map,
those bindings can disappear while the MCP process remains alive. Reusing the
cached keycode then silently omits that character. This dependency behavior is
also documented in [Enigo PR 555](https://github.com/enigo-rs/enigo/pull/555).

Linux `type` now uses a dedicated text connection rebuilt before each text
transaction through Enigo's public API. The previous connection is dropped
**before** capturing the replacement keymap, because its destructor releases its
temporary bindings. A failed replacement does not reuse the stale connection.
The current connection is kept alive until the next transaction or shutdown.
Pointer/chord behavior and non-Linux text input retain their existing paths.
The independently versioned native component is prepared as `0.1.3`; this
qualification targets Linux x64 only, with no rebuilt Mac/Windows assets.
No clipboard, shell command, keyboard-layout command or host-specific fallback
is introduced by the tool. Explicit host-selected display settings remain in
force.

## Reproducible native regression

`sidecars/computer-control/tests/x11_typing.py` is an opt-in Linux integration
probe. Run it in a disposable private-network/private-tmp user service, with
explicit read-only installed Xvfb, Chrome, computer-control and dependency paths.
It refuses an inherited display and always starts its own authenticated Xvfb,
Chrome profile and loopback fixture. The test actions use the MCP tool; CDP only
sets up pages and reads the oracle. It does not touch a user or agent display,
clipboard or model provider.

The `--reset-keymap` case first types a colon through the sidecar, then removes
only the extra first-level colon binding on this newly owned X server. This
models a keyboard-map reload. It does not modify the physical semicolon/colon
key or the host keyboard configuration. Both cold/warm address-bar navigation
and textarea values plus HTTP submissions are checked for URLs, `:`, `/:@`,
uppercase/punctuation and Italian text including the euro symbol.

Debug qualification on 21 October 2026:

- Public SDK 0.1.2, SHA `b9852ed2b90fae14da798260faa48e510dfae817c97d1b42732b3e934e5598c4`:
  seven ordinary cases passed, including controller initialization before Chrome.
- After removal of extra colon binding 93, that same public SDK passed only two
  of seven cases. A URL became `http//127.0.0.1<port>/` and `:` became empty.
- The corrected production `input.rs` and `keys.rs`, cross-compiled into a
  minimal Linux debug harness using unchanged Enigo 0.5, passed all seven cases
  with the same binding-reset fixture. This is **source qualification**, not a
  released/full SDK qualification; the probe's `--input-harness` flag records
  that distinction explicitly.
- Six pure input tests passed, including destruction-before-refresh and
  replacement-failure-without-stale-fallback. No macOS input or TCC operation
  was invoked by those tests.

The original ICS QA screenshot showed the same missing-colon symptom, but the
historical keyboard-map body was not retained. A historical reset in that exact
run is therefore an inference, not a directly observed fact. The controlled
regression proves the dependency-cache failure and the correction independently.
A new full native component build, normal MCP test and public checksum-verified
release remain required before adopting a replacement SDK in any host.
