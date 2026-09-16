import json
import os
import sys
from pathlib import Path

import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from openagent_shell import ShellServer


@pytest.mark.asyncio
@pytest.mark.parametrize("module,tool,args", [
    ("openagent_filesystem", "list_directory", {"path": "."}),
    ("openagent_editor", "glob", {"pattern": "*.txt"}),
    ("openagent_shell", "shell_exec", {"command": "printf independent", "timeout": 1000}),
])
async def test_standalone_mcp_without_product_or_engine(tmp_path, module, tool, args):
    (tmp_path / "fixture.txt").write_text("fixture")
    server = StdioServerParameters(command=sys.executable, args=["-m", module], cwd=str(tmp_path))
    async with stdio_client(server) as (read, write):
        async with ClientSession(read, write) as session:
            initialized = await session.initialize()
            names = {entry.name for entry in (await session.list_tools()).tools}
            assert tool in names
            result = await session.call_tool(tool, args)
            assert not result.isError
            assert result.content
            assert initialized.serverInfo.name


@pytest.mark.asyncio
async def test_shell_environments_are_captured_per_instance(tmp_path, monkeypatch):
    a = ShellServer(tmp_path, environment={"TOOL_TEST_ID": "left", "PATH": os.defpath})
    b = ShellServer(tmp_path, environment={"TOOL_TEST_ID": "right", "PATH": os.defpath})
    monkeypatch.setenv("TOOL_TEST_ID", "global-change")
    try:
        for server, value in ((a, "left"), (b, "right")):
            result = await server.call("shell_exec", {"command": 'printf "$TOOL_TEST_ID"'})
            assert result.structured_content["stdout"] == value
    finally:
        await a.close()
        await b.close()
