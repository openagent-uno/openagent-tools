# agent-in-chrome

The built-in browser capability. Drives a **dedicated** Chrome/Chromium/Brave/Edge
purely over the **Chrome DevTools Protocol (CDP)** — no browser extension, no
native-messaging host, no HTTP bridge. One WebSocket to the browser, one
flattened CDP session per tab.

## Why CDP instead of an extension

The previous design shipped a Chrome extension and reached it through native
messaging *or* an HTTP-polling bridge. That stack was fragile: MV3 service
workers suspend, `chrome.alarms` clamps polling to ~30 s, native-messaging
manifests broke when their `path` drifted, Google Chrome blocks
`--load-extension`, and the browser was launched eagerly at every server start.

Since the pool spawns exactly **one** shared `mcp-server.js` process and we own a
dedicated browser, none of that is needed. CDP gives us navigation, input,
screenshots, DOM/accessibility, console, network, and JS eval directly — the
same surface the extension wrapped, minus every failure mode above.

## Design guarantees

A trusted host without a usable GPU can set `OPENAGENT_CHROME_RENDERER=software`.
The default preserves Chromium's normal rendering selection. Software mode uses
SwiftShader/CPU rendering explicitly; it does not retry a failed browser, expose
a TCP debugger or change the host's confinement policy. Unknown values fail.
The macOS boundary qualification checks real DOM, screenshots, private pipes
and denial of a file outside the host-owned fixture.

- **Lazy** — the browser launches on the *first browser tool call*, never at
  server startup. Nothing pops up until the agent decides to use it.
- **Owned reuse** — reconnect only when Chrome's `DevToolsActivePort` marker in
  this exact dedicated profile matches both the port and browser WebSocket path.
  An unrelated CDP service on the same port is never adopted.
- **Isolated + persistent profile** — a dedicated `user-data-dir` that never
  touches the user's real browser, and keeps cookies/logins so "log in to X"
  happens once.
- **No runtime browser download** — use `OPENAGENT_CHROME_BINARY` or an
  OS-installed Chrome/Chromium/Brave/Edge. Browser binaries must come from the
  user's normal signed package/software-update channel; mutable Chromium
  snapshots such as `LAST_CHANGE` are never fetched or executed.
- **No explicit WebDriver flag** — we launch the browser ourselves without
  `--enable-automation`. This does not make a CDP-controlled browser
  indistinguishable from a human-operated browser, and sites may still require
  interactive verification.
- **Clean shutdown** — the process that launched the browser terminates it on
  exit; a reused browser is left alone.

## Files (`host/`)

| file             | role                                                                 |
|------------------|----------------------------------------------------------------------|
| `mcp-server.js`  | MCP stdio server; tab/session management + all tool handlers.        |
| `browser.js`     | binary resolution, lazy launch, owned-CDP discovery, signed CRX3 verification. |
| `cdp.js`         | minimal CDP-over-`ws` client (flattened sessions, id/event routing). |
| `page-script.js` | in-page helpers (a11y tree, find, form_input, page text, ref map).   |

## Config (env)

- `OPENAGENT_CHROME_BINARY` — explicit browser executable path.
- `OPENAGENT_CHROME_CDP_PORT` — CDP remote-debugging port (default `18800`).
- `OPENAGENT_BROWSER_LOCATION=server` — describe this sidecar as a server-host
  browser when a product explicitly registers it as a durable host capability.
  Omitted for the normal App/CLI device capability. The flag changes only MCP
  instructions; it does not alter profile ownership or grant remote access.
- `OPENAGENT_CHROME_PROFILE_EXCLUSIVE=1` — the embedding host guarantees a single
  writer for this profile (for example one container at a time on a mounted
  volume). A Chromium `SingletonLock` naming another host is then stale and is
  removed before launch, instead of leaving the profile "in use by another
  computer" forever. Without it, locks are left to Chromium.
- `OPENAGENT_CHROME_CLOSE_GRACE_MS` (default 10000) — after `Browser.close`, how
  long a launched browser may take to flush cookies and release its profile lock
  before its process group is killed.
- `OPENAGENT_BROWSER_EXTERNAL=1` — when the server attaches to an independently
  supervised Chrome using a verified profile marker, disconnect the MCP without
  closing that browser. The normal sidecar-owned browser still closes on exit.
- `OPENAGENT_CHROME_PROXY` — egress proxy for page traffic: `http://`, `https://`
  or `socks5://` URL. Loopback is always bypassed and WebRTC is limited to
  proxied UDP so it cannot reveal the host address. Credentials in the URL
  (`http://user:pass@host:port`, `socks5://user:pass@host:port`) are supported:
  Chromium accepts none on `--proxy-server` (and cannot authenticate to SOCKS5),
  so the sidecar starts a loopback relay (`proxy-relay.js`) that opens every
  tunnel through the upstream with those credentials. Chrome only sees
  `http://127.0.0.1:<cdp port + 1>`; credentials stay out of its command line
  and logs. A proxy/VPN *extension* (see below) remains an alternative for
  providers that only ship one.

Chrome, Chromium, Brave, or Edge must already be installed on every supported
OS/architecture unless `OPENAGENT_CHROME_BINARY` points at another trusted
Chromium-compatible executable. This includes Linux/Windows ARM64: Agent in
Chrome never substitutes an x64 snapshot or downloads a mutable fallback.

## Interactive session and live view

`openagent-browser-session` (device-tools console script, `host/browser-session.js`)
opens the same dedicated browser without a model — same profile, flags and egress
proxy — for a person to sign in, pass a site verification or configure the profile
once. It serves a WebSocket live view at `/live` (and `GET /health`):

- Authentication: `Authorization: Bearer $OPENAGENT_BROWSER_LIVE_TOKEN` (required,
  ≥ 32 characters). The host that started the session proxies its own users to it.
- Out: each frame is a **binary** WebSocket message (JPEG bytes); text messages are
  `{"type":"viewport","width","height"}`, `{"type":"page","url"}`, `{"type":"ready"}`,
  `{"type":"error"}`, `{"type":"closed","status"}`.
- Flow control: after showing a frame the viewer sends `{"type":"frame_ack"}`; at most
  `--frames-in-flight` (1–4, default 2) frames are unacknowledged and newer frames
  replace the pending one, so a slow link never queues frames (a viewer silent for
  5 s is resumed). `--quality` (20–95,
  default 60) and `--max-width` (320–2560, default 1280) size the stream.
- In: `mouse` (`press|release|move`, `x`/`y` normalized 0–1), `wheel` (`dx`, `dy`),
  `text` (inserted text), `key` (Enter, Backspace, Tab, Escape, Delete, arrows,
  Home/End/PageUp/PageDown with modifiers), `navigate` (http/https), `back`, `done`.
- `done`, `--timeout` (30–86400 s) or SIGTERM close the browser cleanly so cookies
  are flushed; stdout ends with `{"status": ...}`. The view follows popups (OAuth).

```sh
OPENAGENT_BROWSER_LIVE_TOKEN=... OPENAGENT_CHROME_PROFILE_DIR=/profiles/chrome \
  openagent-browser-session --url https://example.com/login --listen 0.0.0.0:9300
```

Credentials typed by the person go to the site only; the session neither reads nor
stores them, and the agent never receives the live-view token.

## Extensions

The agent's browser always loads the builtin cosmetic tab-group extension, plus
any extensions the agent installs, from a persistent managed dir
(`~/.openagent/chrome-extensions/<id>/`). Tools: `install_extension` (Chrome Web
Store id or an unpacked path), `remove_extension`, `list_extensions`. Installing
a VPN/proxy *extension* (e.g. NordVPN) is the clean way to route the browser
through a chosen country: it handles its own proxy auth and persists its login
in the profile — no system VPN, no shim. Builtins can't be removed.

Web Store installs accept CRX3 only. Before extraction, Agent in Chrome checks
that the signed CRX id and the SHA-256-derived public-key id both equal the
requested store id, then verifies the RSA/ECDSA signature over the signed header
and complete ZIP payload. CRX2, an id mismatch, or any tampering is rejected.
An unpacked local directory remains an explicit local install and is not
represented as Web Store-authenticated content.

Web Store CRX3 packages are unpacked in-process by the standalone sidecar using
only the bundled Node runtime. The runtime does not require `unzip` or `tar`
from the host OS. Extraction rejects absolute/traversal paths, aliases,
duplicate paths, symlinks, special files, ZIP64/multi-disk archives, and
archives outside conservative entry/size limits before writing into an atomic
staging directory.

## Tools

`tabs_context_mcp`, `tabs_create_mcp`, `navigate`, `computer` (click/type/key/
scroll/screenshot/drag/hover/zoom), `find`, `read_page`, `get_page_text`,
`form_input`, `javascript_tool`, `read_console_messages`,
`read_network_requests`, `resize_window`, `upload_image`,
`install_extension`, `remove_extension`, `list_extensions`.

Token discipline: prefer `find` + `read_page` + `get_page_text` (structured,
cheap) to locate and read; take a `computer` screenshot only when you need to
see pixels.

## Site verification

A site's CAPTCHA or bot challenge is an access decision made by that site, not
an MCP connectivity failure. Let a person complete any required verification
in the same dedicated browser profile, then retry the requested tool action.
Do not claim that disabling the WebDriver flag guarantees access, impersonate
another browser through client-hint or hardware overrides, or move clearance
cookies between devices. Automated challenge completion is not a supported
browser capability.
