# Bounded DOM reads without a model

`openagent-browser-read --request-file request.json` reads an explicitly selected
set of web pages using Agent in Chrome. The writable JSON file is consumed before
Chromium starts. The command needs Node and the packaged sidecar's locked npm
dependencies. `deploy/browser-reader/Dockerfile` builds an independent container
from verified published device-tools and protocol wheels, without an agent server,
model configuration or an inference credential.

```json
{
  "pages": [{"url":"https://example.com/catalog/","selector":"a.product","targets":["/product/123/"]}],
  "stopPathPrefixes": ["/login/", "/challenge/"],
  "stopSelectors": ["input[type=password]"],
  "pageTimeoutMs": 20000,
  "settleMs": 1000,
  "maxScrolls": 4,
  "maxRows": 500
}
```

The only page operations are navigation, a fixed DOM read and bounded vertical
scrolling. It never evaluates caller-provided scripts, clicks controls, reads
form values or signs in. Each row contains the selected element's `href` and
rendered `innerText`. Invisible elements are omitted. Targets are literal href
substrings used only to decide when all requested rows are present; the caller
must verify exact identifiers and interpret the text. Conflicting rows are kept
so callers can reject ambiguous observations. Limits are 20 pages, 100 targets
per page, 1000 rows, 20 scrolls and 60 seconds per page; defaults are smaller.

The reader waits for matching DOM content to settle, not for the browser's load
event or network-idle. Media streams therefore do not hold an otherwise complete
read open. Each result includes requested URL, status, observedAt, durationMs,
scrolls and rows. `incomplete` can contain verified partial rows. A URL change
outside the exact requested URL is `redirected`; a configured path or visible
stop selector is `blocked`. Both stop the entire batch and discard that page's
rows. A page-level failure is explicit and missing data is never replaced by zero.

Existing `OPENAGENT_CHROME_PROFILE_DIR`, `OPENAGENT_CHROME_PROFILE_EXCLUSIVE`
and `OPENAGENT_CHROME_PROXY` settings retain their meaning. The host must own
authorization, one-writer profile admission, allowed destinations, network policy,
rate budgets and persistence of results. A stored profile does not authorize new
accounts or login actions. The reader closes its owned browser on completion,
deadline or termination so profile cookies can flush. Diagnostic output contains
no page source, credential material or model transcript.

## Source qualification

Device-tools b19 candidate: 13 Node tests passed, including real Chromium DOM
reading with an unfinished page load, checkpoint stop, live-session profile reuse
and local-file navigation rejection. The installed wheel passed seven device
manifest/package tests; two optional native MCP bundle probes were not selected.
The historical test expectation for the already published computer-control 0.1.7
manifest was corrected from 0.1.5. No native helper was rebuilt.

The wheel retains all 14 native artifact files byte-for-byte from published
device-tools b18 (wheel SHA-256
`b061071fe0098e2c0160cbc0ee13775baf6e2d7d87a50c441dfea783b6fa8f20`).
Existing native signatures, manifest hashes and version 0.1.7 are preserved.
These tests do not qualify any live provider account or external site's availability.
