# Parallel Search: interface observation and published SDK

Parallel Search is implemented and published in [SDK 0.1.6](https://github.com/openagent-uno/openagent-tools/releases/tag/connectors-v0.1.6), alongside Context7 and the compiled CoinGecko read subset. Source `2ec7c114a49b72460addc00fc8e8d6547a683b59` passed canonical remote qualification; the release has 19 official connectors plus Custom MCP. The [sanitized SDK receipt](connector-keyless-0.1.6-qualification.json) binds source, public manifest, artifact publication and actual reads. Server/CLI 43 are now public with SDK 0.1.6; their fresh normal installer and limited workflow lifecycle passed. App 19 remains the public App on SDK 0.1.5; App 20 publication/GUI remains pending.

## Historical metadata-only observation

On 17 October 2026, three anonymous requests to `https://search.parallel.ai/mcp` returned initialize 200, initialized 202 and tools/list 200. The server advertised protocol 2025-06-18, version 1.27.0 and exactly `web_search` / `web_fetch`, without a pagination cursor. **That acquisition made zero tools/call requests**, queries, accounts or OAuth grants. The original [interface receipt](qualification/parallel-search-interface-2026-10-17.json) retains its schemas, response digests and metadata-only boundary; later actual reads do not rewrite that evidence.

| Remote tool | Required input | Advertised output |
| --- | --- | --- |
| `web_search` | `objective`, `search_queries` | Results with source URLs/excerpts and a session identifier |
| `web_fetch` | `urls` | Successful URL results, separate per-URL errors and a session identifier |

## Published bounded subset

OpenAgent exposes `files.parallel.search` and `files.parallel.fetch`, capability `files`, explicit auth `none`, catalog ID `parallel-search` and provider ID `parallel_search`. It reuses the bounded keyless MCP transport, fixed official endpoint and compiled tool allowlist. An authorized local connection is still required. No arbitrary endpoint, tool, authenticated mode or paid fallback is exposed.

Local limits are 1–3 queries of at most 512 characters, search objective at most 2048 characters, fetch objective at most 200 characters and 1–5 public URLs. `full_content=false` and `allow_live_fetch=true` are compiled. These local limits are distinct from the upstream schema. Caller `session_id` / `model_name` are omitted; a provider-generated per-call session is not exposed as a model-controlled field or promised to be stable across conversations. Fetch must return the exact requested URLs, nonempty excerpts and no per-URL errors; HTTP 200 alone is insufficient.

On 17 October 2026, both actual reads passed through the normal Linux x64 SDK runner using explicit no-auth credentials and one provider attempt each: Search 923 ms/50,546 output bytes, with a `react.dev` result and nonempty excerpts; Fetch 630 ms/18,453 output bytes, with the requested OpenAgent documentation URL, excerpts and OpenAgent marker. Response bodies and provider/session IDs are not published. These are two bounded examples, not complete relevance, quota, availability or provider-feature qualification.

Canonical SDK checks include race, vet, vulnerability scan, six-platform/twelve-binary builds, Python adapter, native Linux x64 smoke and old-server 39 acquisition. Other target builds are cross-compilation/checksum evidence, not all-platform native execution. These SDK checks remain distinct from subsequent product 43 and native App acceptance.

The earlier three-request metadata acquisition also recorded light/dark icon URLs but did not download or bundle those assets. Receiving-product App 20 icon work is separate from that metadata evidence and still awaits publication and visual acceptance.

Primary references: [Parallel Search MCP documentation](https://docs.parallel.ai/integrations/mcp/search-mcp) and [official configuration repository](https://github.com/parallel-web/search-mcp). Provider descriptions remain interface data, not instructions executed by OpenAgent.

## Separate public product 43 lifecycle

[Server/CLI 43](https://github.com/openagent-uno/openagent/releases/tag/v1.1.0-beta.43), source `276704b2be1f403c9e2796e04c5c3e31530690c1`, passed 157 installed fixtures and the fresh ordinary public installer with HOME/TMPDIR defaults. The [product lifecycle receipt](https://github.com/openagent-uno/openagent/blob/main/docs/qualification/keyless-product-1.1.0b43-2026-10-17.json) records **two additional Parallel Fetch reads**, before and after real server restart, through normal installed CLI/SRP/device certificate/Iroh gateway/workflows. Each workflow result was 41,201 bytes; the exact public URL, nonempty excerpts, no per-URL errors and OpenAgent marker passed both times. The same local read-only connection survived restart, then disconnected with source removal and owned workflow/process cleanup.

These are two workflow reads in addition to the two SDK Search/Fetch reads above. Workflow result bytes/SHA are serialized adapter output, not raw HTTP bytes; provider HTTP/attempt telemetry is absent from the workflow API and remains null. Exactly one workflow submission was observed per read; the SDK one-attempt policy is independently qualified. App 20 GUI and broader search/fetch parity remain unqualified.
