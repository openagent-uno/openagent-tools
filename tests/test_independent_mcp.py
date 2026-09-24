import json
import os
import sys
from pathlib import Path

import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from openagent_shell import ShellServer
from openagent_editor import EditorServer
from openagent_filesystem import FilesystemServer


def test_file_capability_manifests_describe_both_registration_destinations():
    for server in (EditorServer, FilesystemServer):
        instructions = server.manifest.instructions
        assert "client registration" in instructions
        assert "server registration" in instructions
        assert "Paths cannot select another destination" in instructions


@pytest.mark.asyncio
@pytest.mark.parametrize("module,tool,args", [
    ("openagent_filesystem", "list_directory", {"path": "."}),
    ("openagent_editor", "glob", {"pattern": "*.txt"}),
    ("openagent_editor", "apply_patch", {"file_path": "fixture.txt", "patch": "@@ -1 +1 @@\n-fixture\n+changed\n"}),
    ("openagent_shell", "shell_exec", {"command": "printf independent", "timeout": 1000}),
    ("openagent_shell", "shell_processes", {"pid": os.getpid()}),
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
        which = await a.call("shell_which", {"command": "not-on-this-path"})
        assert which.structured_content["available"] is False
    finally:
        await a.close()
        await b.close()


@pytest.mark.asyncio
async def test_shell_processes_inspects_current_host_without_command_lines(tmp_path):
    server = ShellServer(tmp_path)
    try:
        result = await server.call("shell_processes", {"pid": os.getpid()})
        processes = result.structured_content["processes"]
        assert len(processes) == 1
        assert processes[0]["pid"] == os.getpid()
        assert processes[0]["name"]
        assert "command" not in processes[0]
    finally:
        await server.close()


@pytest.mark.asyncio
async def test_shell_processes_rejects_invalid_filter(tmp_path):
    from openagent_tool_protocol.types import HostError

    server = ShellServer(tmp_path)
    try:
        with pytest.raises(HostError):
            await server.call("shell_processes", {"pid": "1"})
    finally:
        await server.close()


@pytest.mark.skipif(os.name == "nt", reason="POSIX executable-path fixture")
@pytest.mark.asyncio
async def test_shell_discovery_uses_instance_path_not_global_path(tmp_path, monkeypatch):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    executable = bin_dir / "instance-only-tool"
    executable.write_text("#!/bin/sh\nexit 0\n")
    executable.chmod(0o755)
    server = ShellServer(tmp_path, environment={"PATH": str(bin_dir)})
    monkeypatch.setenv("PATH", os.defpath)
    try:
        which = await server.call("shell_which", {"command": executable.name})
        assert which.structured_content == {"available": True, "path": str(executable)}
    finally:
        await server.close()
