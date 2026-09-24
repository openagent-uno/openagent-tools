from __future__ import annotations

import pytest

from openagent_editor import EditorServer
from openagent_tool_protocol.types import HostError


@pytest.mark.asyncio
async def test_apply_patch_checks_multiple_hunks_and_preserves_newlines(tmp_path):
    file = tmp_path / "example.txt"
    file.write_bytes(b"first\r\nsecond\r\nthird\r\nfourth\r\n")
    server = EditorServer(tmp_path, allowed_roots=[tmp_path])
    try:
        result = await server.call("apply_patch", {
            "file_path": "example.txt",
            "patch": "@@ -1,2 +1,2 @@\n first\n-second\n+two\n@@ -3,2 +3,2 @@\n third\n-fourth\n+four\n",
        })
        assert result.structured_content["hunks"] == 2
        assert file.read_bytes() == b"first\r\ntwo\r\nthird\r\nfour\r\n"
    finally:
        await server.close()


@pytest.mark.asyncio
async def test_apply_patch_conflict_does_not_write(tmp_path):
    file = tmp_path / "example.txt"
    file.write_text("actual\n")
    server = EditorServer(tmp_path, allowed_roots=[tmp_path])
    try:
        with pytest.raises(HostError) as error:
            await server.call("apply_patch", {
                "file_path": "example.txt",
                "patch": "@@ -1 +1 @@\n-expected\n+changed\n",
            })
        assert error.value.code == "patch_conflict"
        assert file.read_text() == "actual\n"
    finally:
        await server.close()


@pytest.mark.asyncio
async def test_apply_patch_cannot_write_outside_allowed_roots(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    target = tmp_path / "outside.txt"
    target.write_text("old\n")
    server = EditorServer(root, allowed_roots=[root])
    try:
        with pytest.raises(HostError) as error:
            await server.call("apply_patch", {
                "file_path": str(target),
                "patch": "@@ -1 +1 @@\n-old\n+new\n",
            })
        assert error.value.code == "path_not_allowed"
        assert target.read_text() == "old\n"
    finally:
        await server.close()
