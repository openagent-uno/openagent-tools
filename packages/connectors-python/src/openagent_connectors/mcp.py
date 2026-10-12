"""Official MCP transport for a host-supplied connector capability.

The host capability must resolve and authorize its current credential binding
on every call. This transport does not read ambient tokens or choose identities.
"""
from openagent_tool_protocol.mcp import serve


async def serve_connector(factory):
    await serve(factory)
