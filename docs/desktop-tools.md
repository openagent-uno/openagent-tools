# Desktop execution and live media

`@openagent/desktop-tools` is an optional engine-free TypeScript SDK. It owns
file/shell execution, owned native process lifecycle, scoped MCP/browser/native
bridges, provider catalog/resource validation and continuous desktop media.
Hosts inject verified process commands, principals and consent/grant policy.
Importing the SDK starts no process, enrolls no device and grants no access.

The canonical `sidecars/computer-control` binary supports three separate entry
points: ordinary MCP, `--desktop-stdio` (`openagent-desktop/1`) and
`--desktop-stream` (`openagent-video/1`). Input/capture use the same owning native
implementation. Desktop stdio is bounded NDJSON. The live protocol accepts
`display_id` (optional exact display), `fps` (1–30) and
`max_duration_seconds` (1–300). Explicit invalid/missing displays never fall back.
Stdin close/stop and host cancellation retire the owned encoder. Raw RGBA capture
feeds OpenH264 directly; it does not poll an MCP screenshot or write a recording.
Encoded dimensions are even; input dimensions retain canonical coordinate space.
Geometry change fails closed and requires reopening the view.

Video consists of one AVC Annex-B configuration followed by ordered key/delta
frames. The browser-only `/video` entry exposes `VideoCanvasDecoder`, checks codec
support and sequence/queue bounds, closes each decoded frame and resets only on
a new encoder configuration from the same source. Annex-B configuration and key
frame semantics follow the [W3C AVC registration](https://www.w3.org/TR/webcodecs-avc-codec-registration/).
No video is persisted. Permission or encoder errors are returned to the host.

Optional `/electron-video`, `/video-preload` and `/livekit-publisher` entries
compose an isolated sandboxed publisher and LiveKit track. The host supplies and
renews exact transport grants. Leases expire after 20 seconds, sender/frame and
URL are checked, and stop/expiry closes the owned processes/window/track. Encoder
cycles renew on the same source while the lease remains current. The root entry
does not import Electron or LiveKit; `/video` has no Node dependency.

Python `openagent_device_tools.media.NativeDesktopMedia` implements Core's
optional media executor contract without depending on Core. Hosts pass a trusted
command and call `qualify()` before advertising it. `stream_options` and
`video_packet` enforce the shared bounds. `native_desktop_command()` selects
only a packaged artifact qualified for the current platform and verifies its
SHA-256. It returns no command when that platform is absent.

## Artifacts and qualification

`packages/desktop-tools/native/manifest.json` is the canonical version/hash
inventory. Python and TypeScript distributions carry the same bytes and native
third-party notices. In the repository, run `npm run build:native` in
`packages/desktop-tools` on each target machine, then build/test/pack the SDK.
`nativeHelper` and `verifyNativeHelper` verify the complete bundle inventory,
including its application identity and signatures. They never compile a host-local
fork or accept old product helpers. Missing architectures fail explicitly.
Electron hosts must unpack `node_modules/@openagent/desktop-tools/native/**`
from ASAR and preserve the already signed native bundles during outer signing.

The manifest protocol is `openagent-native-artifacts/2`. Explicit control/view
roles select the same qualified native source. On macOS both roles retain the
established `com.openagent.computer-control` application bundle; control supports
macOS 12, while continuous ScreenCaptureKit media requires 12.3. Never extract the
Mach-O executable from its bundle: that loses the OS application identity and
breaks simultaneous MCP capture and live viewing. Rehash the full bundle with
`stage-native.cjs --refresh-manifest` after signing, notarization and stapling.

The release cohort is `@openagent/desktop-tools@0.1.0`, device tools `1.0.0b18`,
and native helper `0.1.7`. Public artifacts must carry all six qualified target
entries with immutable upstream source revisions. Windows builds statically link
the CRT; runtime discovery must not depend on a build machine’s installed
redistributable. Each target must pass an actual native protocol launch. Local qualification, signed release
artifacts and physical remote-device acceptance remain separate evidence.
