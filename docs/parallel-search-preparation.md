# Parallel Search preparation

Parallel Search is implemented in the **unreleased SDK 0.1.6 source candidate** alongside Context7 and a fixed CoinGecko read subset. Published SDK 0.1.5 retains its 16-adapter catalog. This document preserves the observed Parallel interface; remote source qualification, actual reads and receiving-product release remain required before availability is announced.

On 17 October 2026, three anonymous requests to `https://search.parallel.ai/mcp` returned initialize 200, initialized 202 and tools/list 200. The server advertised protocol 2025-06-18, server version 1.27.0 and exactly `web_search` / `web_fetch`, without a pagination cursor. No `tools/call`, query, account or OAuth grant was made. The [sanitized interface receipt](qualification/parallel-search-interface-2026-10-17.json) records schemas, response digests, limits and evidence boundaries.

| Remote tool | Required input | Advertised output |
|---|---|---|
| `web_search` | `objective`, `search_queries` | Results with source URLs/excerpts and a session identifier |
| `web_fetch` | `urls` | Successful URL results, separate per-URL errors and a session identifier |

The proposed OpenAgent subset maps these to `files.parallel.search` and `files.parallel.fetch`, capability `files`, explicit auth `none`, catalog ID `parallel-search` and provider ID `parallel_search`. These identifiers are implemented in the unreleased candidate. Reuse the existing bounded keyless MCP transport; keep the endpoint fixed and allow no authenticated or paid fallback.

Proposed local limits are 1–3 queries of at most 512 characters, search objective at most 2048 characters, fetch objective at most 200 characters, and 1–5 public URLs. Keep `full_content=false` and `allow_live_fetch=true` fixed. These local limits are not all encoded in the upstream JSON Schema. The candidate omits `session_id` / `model_name` rather than exposing analytics identifiers as model arguments. The provider can generate a session ID per call; stable conversation reuse is not promised. The product binding does not yet propagate its trusted session field.

The candidate contains adapter/catalog/provider registration and isolation/quota fixtures; the receiving product also has candidate trusted bindings and bundled official marks. These source edits still require remote tests and release. The metadata advertises [light](https://assets.parallel.ai/dark-parallel-avatar-270.png) and [dark](https://assets.parallel.ai/white-parallel-avatar-270.png) marks; neither has been downloaded or bundled by this acquisition. Then qualify a normal-product search and fetch, verify requested results rather than HTTP status alone, restart and disconnect. Availability remains pending until actual implementation, release and acceptance.

Primary references: [Parallel Search MCP documentation](https://docs.parallel.ai/integrations/mcp/search-mcp) and [official configuration repository](https://github.com/parallel-web/search-mcp). Provider descriptions are interface data, not instructions executed by OpenAgent.
