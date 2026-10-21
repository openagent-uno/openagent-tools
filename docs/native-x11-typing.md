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
The source checkpoint above preceded the complete component qualification below.

## Published Linux x64 component0.1.3

[Computer control0.1.3](https://github.com/openagent-uno/openagent-tools/releases/tag/computer-control-v0.1.3)
is published from source `8652aae1d0839caafc2ae4f0be4b8e25b21e08fa`. This is the
independently versioned Linux x64 component, not a rebuilt six-platform SDK.
Existing SDK0.1.2 releases and other target assets are preserved.

The complete component passed **7/7 actual MCP cases** on an owned authenticated
Xvfb after the same spare-colon-binding reset, then passed all seven again from
the anonymously downloaded public archive. MCP reports version0.1.3. Both cold
and warm address-bar navigation and textarea values submitted through real HTTP
were checked. No user/agent display, model/provider or clipboard was used.
The transient private-network/private-tmp service exited successfully; production
services remained unchanged.

The normal locked/offline Cargo release profile retains LTO, strip, panic-abort
and one codegen unit. Rust1.94.1 and Zig0.15.2 target Linux glibc2.39; existing
Apple libclang17 generated the cross-target bindings. Signed Debian headers/link
inputs were staged privately without package scripts or system installation.
Final LTO eliminates EGL/PipeWire references, so no associated runtime libraries
are included. Final ELF dependencies are gbm, Wayland-client, xcb, m, libc and the
Linux loader, with maximum GLIBC symbol2.39. The binary records relative
`$ORIGIN/lib` RUNPATH; this release contains no library payloads.

- Archive `openagent-computer-control-0.1.3-linux-x64.tar.gz`: 3,120,551 bytes,
  SHA256 `1dfb5dfe17156568edc492dfba2f69b1cb6cb7611138caba3ed10685baea942d`.
- Component manifest SHA256:
  `568420a39ab432abd5ec9a44c73dc6e527ae364011b09795e59baaf0bfb69928`.
- Actual binary: 8,115,624 bytes,
  SHA256 `8cf303db06425df8f5c4cd7cc6eec5269865e4a107c20720a04121806debe5ff`.

The release includes immutable `component-manifest.json`,
`native-qualification.json`, `release-manifest.json` and `SHA256SUMS`. All five
assets passed anonymous HTTPS/full-SHA verification. This is Linux x64 X11
qualification only: Wayland execution, clipboard and new Mac/Windows/arm64 builds
are not claimed. Hosts must adopt the exact public component through their
normal trusted asset/namespace admission; publishing this release does not
implicitly replace any product's active runtime.
