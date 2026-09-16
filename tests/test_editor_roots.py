import json
import pytest
from openagent_editor import EditorServer
from openagent_tool_protocol.types import HostError


@pytest.mark.asyncio
async def test_configured_editor_roots_reject_escape_and_filter_symlinks(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    outside = tmp_path / "private.txt"
    outside.write_text("private sentinel")
    (workspace / "public.txt").write_text("public sentinel")
    (workspace / "link.txt").symlink_to(outside)
    editor = EditorServer(workspace, allowed_roots=[workspace])
    try:
        for path in (str(outside), "../private.txt", "link.txt"):
            with pytest.raises(HostError, match="configured roots"):
                await editor.call("edit", {"file_path":path, "old_string":"private", "new_string":"changed"})
        for tool, args in (("grep", {"pattern":"sentinel"}), ("glob", {"pattern":"*.txt"})):
            result = await editor.call(tool, args)
            data = json.dumps(result.to_wire())
            assert "public.txt" in data
            assert "private.txt" not in data
            assert "private sentinel" not in data
            assert "link.txt" not in data
        result = await editor.call("edit", {"file_path":"public.txt", "old_string":"public", "new_string":"shared"})
        assert not result.is_error
        assert (workspace / "public.txt").read_text() == "shared sentinel"
        assert outside.read_text() == "private sentinel"
    finally:
        await editor.close()


@pytest.mark.asyncio
async def test_empty_roots_deny_all_without_changing_default_device_behavior(tmp_path):
    path = tmp_path / "note.txt"
    path.write_text("one")
    denied = EditorServer(tmp_path, allowed_roots=[])
    default = EditorServer(tmp_path)
    try:
        with pytest.raises(HostError):
            await denied.call("edit", {"file_path":str(path), "old_string":"one", "new_string":"two"})
        result = await default.call("edit", {"file_path":str(path), "old_string":"one", "new_string":"two"})
        assert not result.is_error
    finally:
        await denied.close()
        await default.close()
