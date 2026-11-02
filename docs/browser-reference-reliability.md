# Browser reference and transport reliability

Unreleased source work, 30 October 2026. This is a behavioral comparison against
local client code, not a claim of complete Codex/browser-service parity.

The inspected local Codex browser client is
`/Applications/ChatGPT.app/Contents/Resources/cua_node/lib/node_modules/@oai/browser-desktop/scripts/browser-client.mjs`.
It exposes tab-scoped browser operations and distinguishes locator failure cases
such as `multiple_matches`, `intercepted` and `no_visible_match`. It also contains
API/transport boundaries for frame targeting and credential recovery. Those
client boundaries do not provide the implementation of its remote browser
service. No proprietary implementation was copied into OpenAgent.

## Gaps and source changes

| Area | Observed OpenAgent gap | Implemented behavior |
| --- | --- | --- |
| Element identity | Every document/tab restarted the same `ref_1` counter, allowing an old or other-tab ref to select a different element | Random document-scoped refs; current-document/connected-node checks; prototype-like strings cannot access inherited objects |
| Element lifetime | A detached or adopted DOM node could still resolve through its WeakRef | Reject disconnected nodes and nodes moved into another frame/document |
| Pointer target | Ref coordinates could point behind an overlay or to a disabled element | Scroll current element into view, validate dimensions and effective disabled state, hit-test through open shadow roots and reject interception |
| Form target | A container silently selected the first nested input, non-fields accepted invented `.value` properties, and unknown select values reported success | Require one editable target, reject ambiguous/disabled/read-only/unsupported targets and missing/ambiguous/disabled select options; boolean checkbox/radio validation |
| Discovery | Matching ancestor containers could fill all 20 results before the actionable control | Rank interactive and exact-name matches before matching containers while retaining the bounded output; reject blank queries |
| Browser/session lifetime | Concurrent calls could attach the same target repeatedly; retired connection/session listeners could affect current state | One pending attachment per target; exact connection/session checks, detach disposal, and old-connection close isolation |
| CDP responses | Session identity was not checked; close left calls and event waits pending | Bind replies to the requested session, reject only detached-session work, settle owned waiters on close, clean up timeout/abort listeners |
| Cancellation | MCP cancellation was not passed to browser commands or waits | Per-invocation AbortSignal propagation; ignore late responses without replay; attempt key/mouse release after interrupted input sequences |
| Result accuracy | Invalid refs and failed navigation/viewport operations could report successful tool results; zero-duration waits became one second | Explicit ref/navigation/viewport failures, positive integer tab IDs and bounded dimensions/counts, explicit zero-duration waits |
| Screenshot identity | Timestamp-based IDs could collide during concurrent captures | Random unique screenshot IDs retain exact captured bytes |

The tool names and existing persistent browser/profile identity remain unchanged.
The independently supervised-browser shutdown rule remains in place. New refs
are opaque strings and must be acquired through `find`/`read_page` in the current
document. They are not persistent selectors and cannot be imported from another
tab or a restored document.

Cancellation stops local waiting and subsequent dispatched work; CDP cannot undo
an operation already accepted by Chrome. No mutation is automatically retried.
Pointer/key release is cleanup against the same still-attached session, not a
fallback to another browser or tab. Arbitrary JavaScript, browser navigation and
coordinate actions retain their existing explicit capability/consent boundary.

## Verification

Command from the repository root:

```console
node --test sidecars/agent-in-chrome/host/browser-reliability.test.mjs sidecars/agent-in-chrome/host/browser-external.test.mjs
```

Result on this Mac: **11 passed, 0 failed, 0 skipped**, 8.59 seconds. Five tests
use a loopback WebSocket fixture for close, reply/session binding, cancellation
and late responses, detached sessions and timeout/event cleanup. Five tests run
the installed Google Chrome in isolated temporary headless profiles: tab and
new-document refs, adopted iframe nodes, form ambiguity/validation, actionable
find ranking, actual MCP stdio cancellation and stale-ref errors, interception
and disabled targets. The existing external-browser shutdown regression is
included. The fixture owns only its temporary profiles/processes and does not
attach to a user's normal browser profile.

`node --check` passed for `cdp.js`, `page-script.js` and `mcp-server.js`;
`git diff --check -- sidecars/agent-in-chrome/host` passed.

Tests discover an installed Chromium binary (or
`OPENAGENT_TEST_CHROME_BINARY`). On a machine without one, the real-browser
cases explicitly skip; such a run does not reproduce this Mac's qualification.
No browser is downloaded by the test or sidecar.

## Receiving products and remaining boundaries

The shared Agent-in-Chrome source is the upstream implementation consumed by
OpenAgent's host-tools facade. OpenAgent App and embedding hosts must acquire
and verify a newly built device-tools/host-tools bundle through their existing
capability adapters. These source tests do not modify an installed or published
bundle, forge release hashes or qualify any deployed consumer.

This work does not implement Codex's complete Playwright API, cloud/browser
selection service, user-browser pairing, credential handoff/recovery, protected
browser policy service, downloads/file-chooser integration, cross-origin iframe
locator API or MCP Apps rendering. Existing OpenAgent structured DOM helpers
operate in their selected document and open shadow roots; a frame-targeting
service is a separate feature. Page load waiting is bounded and is not proof
that a site's asynchronous application has finished loading. Real provider
login/CAPTCHA flows, native Windows/Linux UI, installed desktop applications,
and release packaging still require their own acceptance.
