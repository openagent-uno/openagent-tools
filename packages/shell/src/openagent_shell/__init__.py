"""ShellServer: independent function and MCP stdio server."""
from .server import ShellServer

def main():
    import asyncio
    from pathlib import Path
    from openagent_tool_protocol.mcp import serve
    asyncio.run(serve(lambda sink: ShellServer(Path.cwd(), event_sink=sink), completion_events=True))
