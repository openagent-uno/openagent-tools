# Advanced native controls

The optional `computer-control` sidecar implements these public macOS APIs independently of a model/provider. Native source version is `0.1.5`; the device-tools development candidate (versioned in `packages/device-tools/pyproject.toml`) includes its source and exact MCP catalog. This candidate is not a published or signed desktop release.

| Tool | Contract |
| --- | --- |
| `computer_list_apps` | Enumerates running app bundles first, then standard Applications directories (depth 2, maximum 1000). `truncated` reports the three-second deadline/cap. Every result receives a fresh opaque `app_ref` valid for at most ten minutes. |
| `computer_launch_app` | Consumes an observed `app_ref`, verifies its canonical bundle/executable identity, submits one exact NSWorkspace launch and returns a fresh reference plus confirmed PID. An uncertain launch is never repeated automatically. |
| `computer_app_policy` | Reports current Accessibility/Screen Recording grant observations, implemented platform/backend features and the requirement for host authorization. Does not create a persistent app allowlist or claim OpenAI service approval. |
| `computer_window_input` | Consumes a fresh AX snapshot; supports explicit focus, physical key chords, Unicode text, window-relative click/drag and pixel scroll. Exact PID/process identity and focused window are checked before input. Coordinates must fit the observed window. Optional element targeting also verifies focused element/value. |
| `computer_select_text` | Selects one exact UTF-16 range or a unique text match, optionally disambiguated with adjacent prefix/suffix. Supports selecting text or positioning the caret before/after it. Rejects ambiguous matches and split surrogate pairs. |
| `computer_perform_action` | Executes only an AX action advertised on the observed exact element. No invented action mapping or coordinate fallback. |
| `computer_paste` | One clipboard transaction on a fresh exact element; accepts explicit base64 `text/plain`, `text/html`, `text/rtf`, `image/png` representations, at most 8 MiB. Saves every existing clipboard item/type privately, submits paste, and restores originals if the clipboard still contains the transaction's content. |
| `computer_audio_start` | Captures system output on macOS 13+ using ScreenCaptureKit. Requires `source: "system_output"` and exactly one observed `app_ref` or explicit `all_system_output: true`. Never captures the microphone. Returns an owned opaque `recording_id`, source/PID provenance, duration limit and format. |
| `computer_audio_stop` | Stops/consumes one owned recording and returns a 24 kHz stereo WAV as MCP audio plus metadata/private artifact path. `return_audio: false` stops/releases for host cleanup without returning audio. Missing samples, denied grants and failed backends are explicit errors. |

Existing snapshot/action contracts in [native-accessibility.md](native-accessibility.md) still apply: exact CG window/PID, process birth identity, retained AX objects, secure-value redaction, bounded tree traversal, state/ancestry validation, single-use snapshot TTL and aggregate three-second request deadline. Snapshots must be taken again after every attempted mutation, including uncertain outcomes.

## Authorization and resources

The host must bind returned `app_ref`, `snapshot_id` and `recording_id` resources to its authenticated account/device/interaction scope. The canonical host facade provides this binding, expiry checks, idempotency/replay receipts, and stop-without-audio cleanup on scope release. A model argument cannot grant operating-system access or widen host audio consent. Products may additionally gate system output with a local owner-controlled permission; an absent app target never falls back to all-system recording.

Native calls check cancellation/deadline before starting further work. Already submitted OS events/launches may have taken effect; inspect current state before a new call. ScreenCaptureKit initialization alone has an eight-second budget inside the host call deadline; AX/input calls retain their three-second limit. A cancelled pending start retains the exact stream until its late completion can stop it. Recording automatically stops at its explicit bounded duration measured after confirmed start (default 60 seconds, maximum 300 seconds). Artifacts are created in private temporary directories and retained for the caller; this API does not delete saved user artifacts.

Temporary paste requires one unique enabled advertised AX menu command; an app without that command receives an explicit unconfirmed result and no raw Cmd+V event is queued. A queued key could otherwise execute after clipboard restoration.

Clipboard transactions hold a per-user OS advisory lock across scoped helper processes and check pasteboard change counts. External clipboard changes are preserved and reported instead of overwritten. A helper crash cannot guarantee clipboard rollback. No clipboard read API or original clipboard payload is returned by this feature.

## Platform and build boundaries

These advanced native controls and AX trees are implemented on macOS. Windows/Linux return an explicit unsupported result for these APIs; the pre-existing portable screenshot/input/window/display tools retain their platform support. macOS builds need the Xcode command-line SDK/compiler to compile the bundled Objective-C bridge; ScreenCaptureKit is weak-linked and only used on macOS 13+. The compiler and static archiver both resolve through `/usr/bin/xcrun --sdk macosx`, independent of GNU binutils earlier on `PATH`. The selected Apple `libclang_rt.osx.a` is linked explicitly for Objective-C availability checks because Rust release linking omits Clang default runtime libraries. The standalone builder gives Cargo and its C/C++ dependencies a macOS deployment floor of 12.0, preserving higher caller targets. The build recreates its own generated archive rather than retaining a previously incompatible archive index. Qualify distribution changes with a fresh release build from the wheel; a cached debug build can hide toolchain selection defects. The bridge uses public Foundation/AppKit, ApplicationServices, CoreGraphics, CoreMedia, AVFAudio and ScreenCaptureKit APIs; no installed proprietary native implementation is linked or copied.

Public references: [NSWorkspace exact app launch](https://developer.apple.com/documentation/appkit/nsworkspace/openapplication(at:configuration:completionhandler:)), [AXUIElement](https://developer.apple.com/documentation/applicationservices/axuielement), [NSPasteboard](https://developer.apple.com/documentation/appkit/nspasteboard), [ScreenCaptureKit](https://developer.apple.com/documentation/screencapturekit), [SCStreamConfiguration capturesAudio](https://developer.apple.com/documentation/screencapturekit/scstreamconfiguration/capturesaudio).

## Acceptance

`tests/native_advanced.py` creates a disposable owned AppKit bundle, discovers/cold-launches that exact app, and checks real AX selection, Unicode input, native actions, rich paste/clipboard restoration and app-filtered loopback using only its generated tone. It writes `target/native-advanced-evidence.json` and an owned synthetic WAV only after a successful capture. OS grant/backend denials are recorded explicitly; denied audio does not count as captured-audio acceptance. The fixture reads no personal app contents and never records arbitrary user audio.

Run from the Tools root:

```sh
MACOSX_DEPLOYMENT_TARGET=12.0 CARGO_BUILD_JOBS=1 cargo build --offline --manifest-path sidecars/computer-control/Cargo.toml
swiftc sidecars/computer-control/tests/fixtures/native_accessibility_fixture.swift -o sidecars/computer-control/target/native-accessibility-fixture
.venv/bin/python sidecars/computer-control/tests/native_advanced.py
MACOSX_DEPLOYMENT_TARGET=12.0 CARGO_BUILD_JOBS=1 cargo test --offline --manifest-path sidecars/computer-control/Cargo.toml
.venv/bin/python -m pytest tests/test_device_tools.py
```

### Current candidate qualification boundary

Owned real-Mac acceptance confirmed catalog discovery, exact cold launch/ref refresh/replay denial, UTF-16 prefix/suffix selection, Unicode PID-targeted typing, unique observed AX menu shortcut invocation, coordinate click, RTF paste with actual bold text, private clipboard restoration, and 24 kHz stereo WAV capture containing the owned fixture's synthetic tone. These 17 checks passed through the compiled OpenAgent App LocalHostBridge and two embedding-host ComputerExecutor scoped capability paths, all using the canonical facade and the real shared native sidecar. This is local source/adopter proof; installed/signed product distributions and public releases are separate gates.

PID-targeted Quartz events bypass normal WindowServer hit-testing and AppKit menu routing. Coordinate events explicitly preserve the observed Cocoa window number and use its relative coordinates; command shortcuts resolve one unique enabled advertised AX menu equivalent. Ambiguity or an attempted native command error never triggers another delivery path. The fixture additionally exercised window-bound drag and pixel scroll on an owned AppKit view. Those individual effect oracles passed before a later stale-window/focus guard refused unrelated input; this interrupted run is not a combined 19-check pass. The three complete adopter receipts contain 17 checks each. The final input-only acceptance completed all four oracles in 5.05 seconds on the rebuilt `0.1.5` runtime: coordinate click, exact drag endpoint, pixel scroll, and missing-menu paste denial with no raw key delivery, unchanged target text and private clipboard restoration. This is a separate four-check receipt, not a combined 19-check run. No repeated focus loop or new audio capture was used.

The test transport shim under the task's `work/native-adopter-mcp-proxy.mjs` forwards every operation through the actual compiled adopter; it implements no native effect. Each test uses an isolated host home and retires that home's verified broker before removing the scratch directory. User app helpers/brokers are preserved. No microphone or arbitrary user audio is recorded.

The final short run used `OPENAGENT_NATIVE_QA_PASTE_DENIAL=1 .venv/bin/python sidecars/computer-control/tests/native_input.py`. Its recorded receipt is the task work artifact `native-input-mini-slot1.json`; the runtime and owned Swift fixture were compiled serially immediately before this run. Further distribution packaging/publication is a separate step.

Release toolchain qualification: a serial source `--release --offline --locked` build with `MACOSX_DEPLOYMENT_TARGET=12.0` completed successfully, then the rebuilt binary initialized and advertised all 15 tools without invoking native UI/audio actions. Mach-O load commands reported `minos 12.0`. This source-build receipt (`native-source-release-runtime-fix.json`) is distinct from final wheel/bundle qualification.
