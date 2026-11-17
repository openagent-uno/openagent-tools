"""Engine-free, operation-scoped transport using the official MCP Python SDK."""
from __future__ import annotations

import asyncio
from collections.abc import Callable, Mapping
import math
from typing import Any
from urllib.parse import urlsplit

import httpx
from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client
from mcp.shared.exceptions import McpError

__version__ = "0.1.0b1"


class MCPClientError(Exception):
    """Expected remote/protocol/transport failure, never a programming error.

    Hosts may treat this as unavailable optional context. The failure does not
    grant authority or establish whether an interrupted mutation took effect.
    No request is retried by this client.
    """


class MCPRemoteError(MCPClientError):
    def __init__(self, code: int, message: str):
        self.code = code
        self.remote_message = message
        # Diagnostic messages can contain private server data. Keep the default
        # exception text safe; hosts choose whether/how to display the field.
        super().__init__(f"MCP remote request rejected (code {code})")


class MCPProtocolError(MCPClientError):
    """A bounded remote catalog is malformed or inconsistent."""


class MCPTransportError(MCPClientError):
    def __init__(self, *, http_status: int | None = None):
        self.http_status = http_status
        super().__init__("MCP transport failed" + (f" (HTTP {http_status})" if http_status else ""))


class MCPSessionError(MCPClientError):
    def __init__(self, failures: tuple[MCPClientError, ...]):
        self.failures = failures
        super().__init__("MCP session failed with expected remote/transport errors")


def _expected(error: BaseException) -> MCPClientError | None:
    if isinstance(error, MCPClientError):
        return error
    if isinstance(error, McpError):
        return MCPRemoteError(error.error.code, error.error.message)
    if isinstance(error, httpx.HTTPStatusError):
        return MCPTransportError(http_status=error.response.status_code)
    if isinstance(error, httpx.TransportError):
        return MCPTransportError()
    if isinstance(error, BaseExceptionGroup):
        failures = tuple(_expected(child) for child in error.exceptions)
        # A mixed group may contain a cancellation or a programming bug. Never
        # turn either into an ordinary optional-capability availability error.
        if all(failure is not None for failure in failures):
            admitted = tuple(failure for failure in failures if failure is not None)
            return admitted[0] if len(admitted) == 1 else MCPSessionError(admitted)
    return None


def _http_client(headers=None, timeout=None, auth=None):
    return httpx.AsyncClient(headers=headers, timeout=timeout or httpx.Timeout(30),
                             auth=auth, trust_env=False, follow_redirects=False)


async def request(url: str, *, operation: str, headers: Mapping[str, str] | None = None,
                  name: str | None = None, arguments: Mapping[str, Any] | None = None,
                  timeout: float = 35, http_client_factory: Callable | None = None,
                  max_catalog_pages: int = 64, max_catalog_tools: int = 4096) -> Any:
    """Perform exactly one operation with fresh SDK session lifecycle.

    A well-formed JSON-RPC rejection is raised as ``MCPRemoteError`` only AFTER
    SDK async contexts close normally. This prevents anyio TaskGroups from
    obscuring it inside an ExceptionGroup. Expected transport-only groups are
    normalized too; cancellation and programming errors propagate unchanged.
    ``TimeoutError`` remains the ordinary asyncio deadline contract.

    Call results preserve the official SDK envelope. ``list`` returns bounded,
    unique name/description/input_schema entries across all catalog pages.
    The host supplies authentication and authorizes the operation independently.
    """
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
        raise ValueError("An explicit MCP endpoint without userinfo or fragment is required")
    if operation not in {"list", "call"} or operation == "call" and not name:
        raise ValueError("Select list, or call with an explicit tool name")
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not math.isfinite(timeout) or timeout <= 0:
        raise ValueError("A finite positive request deadline is required")
    if type(max_catalog_pages) is not int or not 1 <= max_catalog_pages <= 1024 or type(max_catalog_tools) is not int or not 1 <= max_catalog_tools <= 100000:
        raise ValueError("Finite positive catalog limits are required")
    if arguments is not None and not isinstance(arguments, Mapping):
        raise TypeError("Tool arguments must be a mapping")
    deferred = None
    output = None
    try:
        async with asyncio.timeout(timeout):
            async with streamablehttp_client(url, headers=dict(headers or {}),
                    httpx_client_factory=http_client_factory or _http_client) as transport:
                async with ClientSession(transport[0], transport[1]) as session:
                    try:
                        await session.initialize()
                        if operation == "call":
                            result = await session.call_tool(name, dict(arguments or {}))
                            output = result.model_dump(mode="json", exclude_none=True)
                        else:
                            tools, names, cursors, cursor = [], set(), set(), None
                            for _ in range(max_catalog_pages):
                                page = await session.list_tools(cursor=cursor)
                                for item in page.tools:
                                    if item.name in names or len(tools) >= max_catalog_tools:
                                        raise MCPProtocolError("MCP catalog is ambiguous or exceeds limits")
                                    names.add(item.name)
                                    tools.append({"name": item.name, "description": item.description or "", "input_schema": item.inputSchema})
                                cursor = page.nextCursor
                                if not cursor:
                                    output = tools
                                    break
                                if cursor in cursors:
                                    raise MCPProtocolError("MCP catalog repeated a cursor")
                                cursors.add(cursor)
                            else:
                                raise MCPProtocolError("MCP catalog exceeds pagination limit")
                    except (MCPClientError, McpError, httpx.HTTPStatusError, httpx.TransportError) as error:
                        # Do not throw an operation rejection through SDK-owned
                        # TaskGroup exits. They must observe a normal body exit.
                        deferred = _expected(error)
    except (McpError, httpx.HTTPStatusError, httpx.TransportError, BaseExceptionGroup) as error:
        normalized = _expected(error)
        if normalized is None:
            raise
        # The original HTTP/SDK traceback can contain credential-bearing URLs.
        # Typed fields are the public diagnostic contract for expected failures.
        raise normalized from None
    if deferred is not None:
        raise deferred from None
    return output


__all__ = ["request", "MCPClientError", "MCPRemoteError", "MCPProtocolError", "MCPTransportError", "MCPSessionError"]
