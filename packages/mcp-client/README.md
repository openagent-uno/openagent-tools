# OpenAgent MCP client

`openagent-mcp-client==0.1.0b1` is an independent, engine-free **source candidate**.
It uses the official MCP Python SDK for protocol negotiation, sessions, catalog
pagination and tool envelopes. Installing it starts no listener, agent or model.
Publication and receiving-host qualification are separate from source tests.

```python
from openagent_mcp_client import request, MCPClientError

try:
    result = await request(
        "http://127.0.0.1:9100/mcp",
        operation="call", name="inventory", arguments={},
        headers=host_authorized_headers,
    )
except MCPClientError:
    # Optional availability only: no grant and no retry of uncertain effects.
    availability = "unavailable"
```

The host supplies endpoint, authentication and domain authorization. The default
HTTP client ignores process proxy configuration and follows no redirects. A host
may supply an explicit `http_client_factory`; no credentials or principals are
inferred. Each operation owns and closes a fresh SDK session.

`operation="list"` returns unique catalog entries containing `name`,
`description` and `input_schema`. Defaults bound the catalog to 64 pages and
4096 tools; repeated cursors, duplicate names and exceeded bounds fail closed.
`operation="call"` preserves the official SDK `CallToolResult` dictionary. A
well-formed result with `isError=true` remains a result, not a transport failure.

## Error contract

- `MCPRemoteError` contains the JSON-RPC `code` and `remote_message`. Its default
  text excludes the potentially private remote message.
- `MCPTransportError` represents an expected HTTP/network failure and exposes
  `http_status` when available, without headers, URLs or credential material.
- `MCPSessionError` contains multiple expected session failures.
- `MCPProtocolError` represents an inconsistent or oversized remote catalog.

These derive from `MCPClientError`. They do not establish whether a mutating
operation took effect. No application operation is retried automatically.

An operation rejection is caught **inside** SDK contexts and raised only after
normal context teardown, so SDK-owned task groups cannot obscure the error.
Lifecycle groups are normalized only when every leaf is an expected remote,
HTTP or network error. Cancellation, process-control exceptions, programming
errors and mixed groups propagate. The overall deadline retains `TimeoutError`.

## Qualification and independent distribution

Run `PYTHONPATH=packages/mcp-client/src python -m unittest discover -s tests -p
test_mcp_client.py -v` in a prepared Python 3.11+ environment with MCP 1.27+ and
httpx 0.28+. Focused tests use the real SDK against HTTP mocks, no providers or
personal credentials. Host adoption and production acceptance remain separate.

Build only this package with `uv build --wheel packages/mcp-client --out-dir
/absolute/empty/output`. Publish an immutable wheel and checksum before hosts
pin it; do not copy or overlay the implementation into a receiving application.
