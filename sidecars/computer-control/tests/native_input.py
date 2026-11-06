"""Short opt-in owned click/drag/scroll acceptance; no clipboard/audio or focus loop.

Optional OPENAGENT_NATIVE_QA_PASTE_DENIAL=1 also checks that a missing advertised
AX paste command never sends a raw key and restores the clipboard privately.
Run only while the Mac foreground is reserved for this owned fixture. A changed
focus/window is a safety denial and stops the run; mutations are never replayed.
"""
from __future__ import annotations

import asyncio
import base64
import json
import os
import subprocess
import tempfile
import time
import uuid
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from native_advanced import ROOT, state_until, unpack


def describe_error(error):
    nested = getattr(error, "exceptions", None)
    return "; ".join(describe_error(item) for item in nested) if nested else str(error) or type(error).__name__


async def main():
    checks = []
    result = {"fixture_only": True, "completed": False, "checks": checks}
    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix="openagent-owned-native-input-") as temporary:
        directory = Path(temporary)
        state = directory / "state.json"
        control = directory / "control.txt"
        title = "OpenAgent input fixture " + uuid.uuid4().hex[:8]
        fixture = subprocess.Popen([str(ROOT / "target/native-accessibility-fixture"), title, str(state), str(control)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            ready = await state_until(state, lambda value: value["title"] == title)
            command = json.loads(os.environ.get("OPENAGENT_NATIVE_QA_MCP_COMMAND", json.dumps([str(ROOT / "target/debug/openagent-computer-control")])))
            async with stdio_client(StdioServerParameters(command=command[0], args=command[1:])) as (read, write):
                async with ClientSession(read, write) as session:
                    initialized = await session.initialize()
                    result["sidecar_version"] = initialized.serverInfo.version
                    async def call(name, arguments):
                        value = unpack(await session.call_tool(name, arguments))
                        if "error" in value:
                            raise AssertionError(value["error"])
                        return value
                    async def snapshot():
                        windows = await call("computer_list_windows", {})
                        target = [row for row in windows["windows"] if row["pid"] == ready["pid"] and row["title"] == title]
                        assert len(target) == 1, "owned fixture window must be unique"
                        return await call("computer_accessibility_snapshot", {"window_id": target[0]["window_id"], "pid": ready["pid"]})
                    def coordinate(tree, identifier, dx, dy):
                        matches = [row for row in tree["elements"] if row["state"]["identifier"] == identifier]
                        assert len(matches) == 1, "owned fixture element must be unique"
                        bounds = matches[0]["state"]["bounds"]
                        return [bounds[0] + dx - tree["window"]["x"], bounds[1] + dy - tree["window"]["y"]]
                    tree = await snapshot()
                    await call("computer_window_input", {"snapshot_id": tree["snapshot_id"], "input": {"action": "focus"}})
                    await asyncio.sleep(.15)
                    tree = await snapshot()
                    point = coordinate(tree, "oa-fixture-apply", 90, 15)
                    await call("computer_window_input", {"snapshot_id": tree["snapshot_id"], "input": {"action": "click", "coordinate": point}})
                    await state_until(state, lambda value: value["clicks"] == 1, attempts=80)
                    checks.append("window-bound coordinate click effect observed")
                    tree = await snapshot()
                    start = coordinate(tree, "oa-fixture-input-surface", 20, 20)
                    await call("computer_window_input", {"snapshot_id": tree["snapshot_id"], "input": {"action": "drag", "coordinate": start, "to_coordinate": [start[0] + 80, start[1] + 10]}})
                    await state_until(state, lambda value: value["drag_count"] >= 1 and abs(value["last_drag"][0]-100) < 1 and abs(value["last_drag"][1]-30) < 1, attempts=80)
                    checks.append("window-bound drag endpoint observed at owned view coordinates")
                    tree = await snapshot()
                    start = coordinate(tree, "oa-fixture-input-surface", 20, 20)
                    await call("computer_window_input", {"snapshot_id": tree["snapshot_id"], "input": {"action": "scroll", "coordinate": start, "direction": "down", "amount": 120}})
                    await state_until(state, lambda value: value["scroll_count"] >= 1 and value["last_scroll"][1] < 0, attempts=80)
                    checks.append("window-bound pixel scroll effect observed")
                    if os.environ.get("OPENAGENT_NATIVE_QA_PASTE_DENIAL") == "1":
                        control.write_text("hide-paste")
                        before = await state_until(state, lambda value: value["paste_available"] is False)
                        tree = await snapshot()
                        fields = [row for row in tree["elements"] if row["state"]["identifier"] == "oa-fixture-rich"]
                        assert len(fields) == 1
                        denied = unpack(await session.call_tool("computer_paste", {"snapshot_id": tree["snapshot_id"], "element_id": fields[0]["element_id"], "items": [{"mime_type": "text/plain", "data_base64": base64.b64encode(b"must never be submitted").decode()}]}))
                        assert "paste_not_confirmed" in denied.get("error", ""), denied
                        await asyncio.sleep(.25)
                        control.write_text("clipboard-digest-after")
                        await asyncio.sleep(.15)
                        after = json.loads(state.read_text())
                        assert after["key_event_count"] == before["key_event_count"], "missing AX command must never enqueue a raw paste key"
                        assert after["rich_text"] == before["rich_text"], "denied paste must not change the target"
                        assert after["clipboard_digest"] == before["clipboard_digest"], "original clipboard representations must be restored"
                        checks.append("missing AX paste command refuses raw key delivery and restores clipboard privately")
                    result["completed"] = True
        except BaseException as error:
            result["error"] = describe_error(error)
            raise
        finally:
            control.write_text("quit")
            try:
                fixture.wait(timeout=2)
            except subprocess.TimeoutExpired:
                fixture.terminate()
                fixture.wait(timeout=2)
            result["passed"] = len(checks)
            result["elapsed_seconds"] = round(time.monotonic()-started, 3)
            destination = Path(os.environ.get("OPENAGENT_NATIVE_QA_RECEIPT", str(ROOT / "target/native-input-evidence.json")))
            destination.write_text(json.dumps(result, indent=2) + "\n")
            print(json.dumps(result, indent=2))


async def bounded_main():
    await asyncio.wait_for(main(), timeout=20)


if __name__ == "__main__":
    asyncio.run(bounded_main())
