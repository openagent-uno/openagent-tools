# Desktop tools

Optional, engine-free desktop execution, exact scoped native/browser/MCP bridges
and process cancellation. Hosts inject verified process launch configurations and
authenticated principals. Importing this package starts no process and grants no
access. It defines no account, enrollment, UI or sharing policy.

Native desktop requests use the versioned `openagent-desktop/1` adapter of the
canonical computer-control sidecar (`--desktop-stdio`). File and shell execution
and native/browser resource ownership are implemented here, never copied into
hosts. `stop` retires only owned processes; uncertain mutations are not replayed.

Live screen capture uses an owned H.264 encoder process and a browser-only
`/video` decoder. Optional `/electron-video`, `/video-preload` and
`/livekit-publisher` entries accept host-authorized expiring transport grants.
Native artifacts and third-party notices ship under `native/`; selection and
staging verify their manifest SHA-256. Missing platforms fail explicitly.
Electron applications must unpack `native/**` from ASAR. Python device tools
carry the same manifest and artifact bytes. Full contracts and source build
instructions are in the repository's `docs/desktop-tools.md`.

Hosts can supply optional `prepareGrant` / `configureSession` transport ports and
`beforeConnect` publisher setup. The SDK owns stream/window lifetime and URL
validation; product-specific routing and transport hints remain host-owned.
