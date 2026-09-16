"""FilesystemServer: independent function and MCP stdio server."""
from .server import FilesystemServer

def main():
    import asyncio
    from pathlib import Path
    from openagent_tool_protocol.mcp import serve
    asyncio.run(serve(lambda sink: FilesystemServer(Path.cwd()), completion_events=False))
