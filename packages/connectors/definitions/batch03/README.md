# Batch03 official read API definitions

Thirty additional source candidates with two finite reads each, disjoint from batch01, batch02 and the OneDrive/SharePoint work. Source-only; no shared runtime, catalog, OAuth or consumer file is modified. No provider calls, registrations, builds or tests were executed.

The manifest uses existing Go Manifest/OperationManifest field names. Authentication is manual_token with a single compiled header/scheme; no secret in query/body, arbitrary request or caller-selected origin is provided. Schema validation precedes Preview and Invoke. Fixed revision headers, leaf output projection, pagination and application-error checks must be enforced by the shared consumer. Unknown envelope/schema shapes fail closed.

Productive was replaced with Tally because the former needs a second variable tenant header; Teamtailor was replaced with Lucid to avoid a parameterized auth header. Lemlist and Ashby explicitly require an owner-prepared base64 HTTP Basic credential (documented in authentication.permissions); raw API keys are not bearer tokens, no automatic encoder/fallback is added here. OAuth-only providers accept an already-authorized access token; common OAuth registration, refresh and live lifecycle remain unqualified.

All reads are one attempt and at most four MiB. Numeric/URL pagination is deliberately first-page-only; opaque cursors are connection/operation/query bound by the normal consumer. Returned links and media URLs are never followed. Public vendor documentation supports the request definitions; actual provider output and lifecycle acceptance remain separate gates. No full ChatGPT parity claim is made.
