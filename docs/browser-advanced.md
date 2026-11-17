# Advanced browser controls

Source candidate: Agent-in-Chrome 3.0.0, 30 October 2026. These APIs are implemented
by the shared OpenAgent Tools sidecar and travel through each product's existing
authenticated capability host. They do not require an OpenAI account or remote
OpenAI service. The machine-readable catalog is
`sidecars/agent-in-chrome/host/browser-advanced-tools.json`.

The runtime uses the exact installed Chrome/Chromium CDP endpoint and the official
`playwright-core` 1.62.1 library. It never installs or downloads a browser. CDP
attachment supports Chromium-family browsers; Safari/WebKit and Firefox are
reported as unsupported rather than silently substituted. See the official
[CDP connection contract](https://playwright.dev/docs/api/class-browsertype#browser-type-connect-over-cdp),
[locators](https://playwright.dev/docs/locators) and
[frames](https://playwright.dev/docs/frames).

## Catalog and targeting

| Tool | Behavior |
| --- | --- |
| `browser_capabilities` | Lists configured browser IDs, implemented features, resource limits and actual connected/not-probed state |
| `browser_control` | Explicit attach/detach, inventory, pending decisions, recovery guidance and human takeover/resume |
| `browser_frames` | Current tab/frame/document handles, including separate-site cross-origin frames |
| `browser_locate` | Role/name, label, text, placeholder, test ID or CSS matching with bounded waits |
| `browser_action` | Exact-element click/fill/check/uncheck/select/press/hover/focus/scroll |
| `browser_upload` | Bounded inline files or host-authorized local file paths |
| `browser_downloads` | Tab-bound inventory/status, chunked reads, cancellation and explicit release |
| `browser_file_chooser` | Observe/wait for a real chooser and set/cancel its exact handle |
| `browser_permissions` | Actual permission queries, pending requests and host-approved grant/revoke |

Every advanced tab operation accepts an explicit `browser_id` (default:
`dedicated`) and `tabId`. `browser_frames` returns opaque `frame_ref` and
`document_id`; navigation/detach invalidates them. Locator results contain
short-lived `element_ref` handles bound to that exact browser, tab, frame and
document. Mutations pin one actual element; they never choose the first
ambiguous match or re-resolve a mutation into a new document. Waits are bounded
at 30 seconds, element references at 512 and two minutes. Cancellation
disconnects only the automation transport to stop pending waits/actions;
already dispatched external effects cannot be undone or automatically replayed.

`browser_control` with `action: attach` and no tab ID lists tabs after connecting
the selected backend. Legacy tools remain bound to the dedicated profile; an
advanced selection does not silently change their destination.

Operator configuration may add up to eight slots via
`OPENAGENT_BROWSER_TARGETS`, an array of `{id,label,profile_dir,cdp_port,
allow_downloads?}`. Profile paths must be absolute and the exact profile's
DevTools marker must match the endpoint. Tools cannot supply an endpoint or
search/attach another user's normal browser. Additional slots are host-granted
capabilities; hosts must scope their configuration to the authenticated client.
External slots default to downloads disabled and retain their normal browser
settings. Sidecar shutdown never closes a configured external browser.

## Files

Uploads accept at most ten files and 32 MiB total. Inline payloads use
`{name,mime_type?,data_base64}`; paths require explicit absolute roots in
`OPENAGENT_BROWSER_UPLOAD_ROOTS`. Canonical paths outside those roots, non-regular
files, growth during reads, invalid names/base64 and oversized content fail.
File chooser handles are document-bound, expire after two minutes and are used
once. See the official [file chooser API](https://playwright.dev/docs/api/class-filechooser).

Downloads retain at most 32 records, with 32 MiB per file. Events from observed
frames cancel transfers exceeding that limit; a completed file is also checked
before being exposed. Data is read in chunks of at most 1 MiB through an opaque
ID; no browser host path is exposed or accepted. `release` drains a transfer
before removing its owned temporary artifact. Cleanup touches only the runtime's
own temporary directories, and supervision/consent revocation closes the owned
transport. The official [download API](https://playwright.dev/docs/api/class-download)
defines the underlying browser lifecycle. Receiving hosts may export authorized
bytes into their own durable artifact store before release.

## Human control and permissions

`request_takeover` pauses both legacy and advanced automation for that browser.
A human completes login, CAPTCHA, consent or another interactive step in the same
profile. Recovery guidance does not inspect stored credentials or attempt to
bypass a site's decision. A takeover does not auto-resume; its pending decision
remains inspectable through inventory. Permission requests are bound to the exact
current origin/tab and expire on navigation.

Resume and permission grant/revoke require signed trusted-host metadata; approval
proof is not part of tool arguments. The broker supplies a private ephemeral
`OPENAGENT_BROWSER_CONTROL_SECRET` to each account-scoped browser process.
A host decision is `_meta["openagent/browser-approval"] = {payload,signature}`.
The signature is lowercase HMAC-SHA256 over UTF-8 canonical JSON (object keys
sorted, compact separators, Unicode literal). The payload is exactly:

```json
{"version":1,"action":"resume","browser_id":"dedicated","tab_id":1,"request_id":"request_...","nonce":"fresh-random-host-nonce","expires_at_ms":1790000000000,"origin":null,"permissions":[]}
```

For permissions, action is `grant` or `revoke`, origin is the exact canonical
origin and permissions are sorted. Proofs expire within 60 seconds, are
single-use, and must match a current pending request. A missing/forged/replayed
proof fails. The receiving product's dedicated user-confirmation control path
signs them; ordinary model calls never receive the secret or mint approvals.
The control plane assumes its local main-process/shim is trusted, consistent
with the existing unrestricted local-tools consent boundary; it is not an OS
sandbox against other fully authorized code running as the same OS user.

## Verification and dependency qualification

```console
node --test --test-concurrency=1 browser-advanced.test.mjs browser-reliability.test.mjs browser-external.test.mjs
```

From the host directory this passed **16 tests, zero failures/skips** on the
installed Chrome using only owned temporary headless profiles and HTTP fixtures.
Coverage includes actual MCP discovery, semantic strictness/delayed readiness,
separate-site iframe actions, upload paths and inline bytes, real chooser and
download lifecycle, wrong-target refusal, two explicitly configured browsers,
unsigned/replayed/origin-mismatched approval refusal, actual permission changes,
legacy pause, cancellation, navigation races, stale references, interception and
supervised-browser preservation. Native/installed-product acceptance is separate.

SDK 1.32.2, ws 8.22.0, Zod 4.6.7 and patched compatible Hono/qs dependencies are
locked. A deliberate Zod 4 migration was checked against its
[official migration guide](https://zod.dev/v4/changelog), because the
[collection-validation advisory](https://github.com/advisories/GHSA-mrhx-c7xc-m3w5)
has no patched Zod 3 release. Actual catalog, schema and browser/approval tests
pass with the new versions. `npm audit` reports **zero vulnerabilities** for
this source tree. This does not constitute a signed native release or deployment
of OpenAgent App or any embedding host; each adopter must rebuild verified inputs
and exercise its own authenticated UI/control path.

## Product operator path and qualification

The canonical product's authenticated local control protocol adds
`provider_control` as a **main-process control request**, absent from the model
MCP catalog. It only permits browser resume/grant/revoke with an exact current
principal. The broker generates a process-owned secret per browser instance;
ordinary tool calls carry no approval metadata. Core's public MCP transport has
an optional keyword-only `metadata` argument for this dispatch. An interrupted
operator mutation is indeterminate and is never automatically replayed.

OpenAgent Desktop's computer settings and a conforming host's computer-sharing
panel expose pending decisions. The renderer provides only a pending request ID
and the desired decision. Electron main re-reads the host inventory, shows a
native confirmation containing the exact browser, tab, origin and permission
list, and checks the inventory again before signing. Account ownership is checked
against the requesting renderer's certified loopback in OpenAgent. Computers v2
looks up opaque scope hashes in its main-process entry table; workspace, actor,
session, computer and generation never come from decision arguments.

Scoped Computer entries also pass a trusted `browser_scope` hash into the local
principal. Browser profiles and signing keys include that scope. This prevents
one actor's other sessions/generations from inheriting its browser references or
pending approvals. Ordinary desktop/CLI account profile reuse remains unchanged.

The source qualification receipt
`outputs/openagent-codex-port/browser-adopter-advanced-e2e.json` in the comparison
workspace records an actual compiled bridge → facade → per-principal MCP →
headless Chrome run for OpenAgent and two independent embedding-host adapters. It observed navigation,
Unicode semantic fill, takeover, refusal of unsigned resume, signed operator
resume, click, and permission grant/revoke. Its confirmation callback is injected
for the owned test; **a real native confirmation dialog was not clicked** in that
run. This receipt does not assert installation, signed application release,
production authentication or unrelated platform acceptance.
