import os
from pathlib import Path
import sys
import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


@pytest.mark.asyncio
async def test_installed_entry_point_exposes_neutral_tool():
    root = Path(__file__).resolve().parents[1]
    params = StdioServerParameters(command=sys.executable,
        args=['-m', 'openagent_mcp_example'],
        env={**os.environ, 'PYTHONPATH': str(root / 'src')})
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            tools = await session.list_tools()
            assert [tool.name for tool in tools.tools] == ['hello']
            result = await session.call_tool('hello', {'name': 'fixture'})
            assert not result.isError
            assert result.content[0].text == 'Hello, fixture!'
