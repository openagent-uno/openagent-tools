"""Neutral example tool; no database, orchestrator or shared state is assumed."""
from mcp.server.fastmcp import FastMCP


def register_tools(app: FastMCP) -> None:
    @app.tool()
    async def hello(name: str = 'world') -> str:
        """Return a greeting without external effects."""
        return f'Hello, {name}!'
