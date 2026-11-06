"""Opt-in real macOS AX acceptance against an owned AppKit fixture.

Build the sidecar and fixture first (see docs/native-accessibility.md), then
run this file with Python containing the MCP SDK. No user application is edited.
"""
from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import uuid

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

ROOT = Path(__file__).resolve().parents[1]


def unpack(result):
    text = "\n".join(item.text for item in result.content if hasattr(item, "text"))
    if result.isError:
        return {"error": text}
    return json.loads(text)


async def wait_state(path, predicate):
    for _ in range(100):
        try:
            state = json.loads(path.read_text())
            if predicate(state):
                return state
        except (OSError, ValueError):
            pass
        await asyncio.sleep(0.05)
    raise AssertionError("owned fixture state did not reach expected value")


async def main():
    assert os.uname().sysname == "Darwin", "macOS-only acceptance"
    binary = ROOT / "target/debug/openagent-computer-control"
    fixture = ROOT / "target/native-accessibility-fixture"
    assert binary.is_file() and fixture.is_file(), "build sidecar and fixture first"
    started = time.monotonic()
    checks = []
    with tempfile.TemporaryDirectory(prefix="openagent-owned-ax-") as directory:
        directory = Path(directory)
        state = directory / "state.json"
        control = directory / "control.txt"
        title = f"OpenAgent AX Fixture {uuid.uuid4().hex[:10]}"
        process = subprocess.Popen([str(fixture), title, str(state), str(control)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            ready = await wait_state(state, lambda value: value["title"] == title)
            async with stdio_client(StdioServerParameters(command=str(binary), args=[])) as (read, write):
                async with ClientSession(read, write) as session:
                    initialization = await session.initialize()
                    catalog = (await session.list_tools()).tools
                    names = {tool.name for tool in catalog}
                    assert {"computer_accessibility_snapshot", "computer_accessibility_action"} <= names
                    checks.append("real MCP discovery")
                    windows = unpack(await session.call_tool("computer_list_windows", {}))
                    assert "error" not in windows, windows
                    selected = [row for row in windows["windows"] if row["pid"] == ready["pid"] and row["title"] == title]
                    assert len(selected) == 1, selected
                    target = {"window_id": selected[0]["window_id"], "pid": selected[0]["pid"]}
                    async def snapshot():
                        value = unpack(await session.call_tool("computer_accessibility_snapshot", target))
                        assert "error" not in value, value
                        assert not value["truncated"], value
                        return value
                    def element(tree, identifier):
                        matches = [row for row in tree["elements"] if row["state"]["identifier"] == identifier]
                        assert len(matches) == 1, (identifier, tree)
                        return matches[0]
                    async def action(tree, row, verb, value=None):
                        arguments = {"snapshot_id": tree["snapshot_id"], "element_id": row["element_id"], "action": verb}
                        if value is not None:
                            arguments["value"] = value
                        return unpack(await session.call_tool("computer_accessibility_action", arguments))
                    first = await snapshot()
                    plain = element(first, "oa-fixture-text")
                    secure = element(first, "oa-fixture-secure")
                    assert plain["state"]["value"] == "initial fixture text"
                    assert secure["state"]["value"] is None and secure["state"]["value_settable"] is False
                    assert "fixture-secret-must-not-appear" not in json.dumps(first)
                    checks.extend(["real AX tree exact window/process", "secure-field value redacted"])
                    current = await snapshot()
                    superseded = await action(first, plain, "set_value", "must-not-apply")
                    assert "stale_accessibility_snapshot" in superseded.get("error", ""), superseded
                    checks.append("superseded snapshot rejected")
                    edit = await action(current, element(current, "oa-fixture-text"), "set_value", "Ciao, è già così 🌞")
                    assert edit.get("ok") is True, edit
                    await wait_state(state, lambda value: value["text"] == "Ciao, è già così 🌞")
                    repeated = await action(current, element(current, "oa-fixture-text"), "set_value", "must-not-repeat")
                    assert "stale_accessibility_snapshot" in repeated.get("error", ""), repeated
                    checks.extend(["native AXValue Unicode mutation", "single-use mutation rejects replay"])
                    current = await snapshot()
                    pressed = await action(current, element(current, "oa-fixture-apply"), "press")
                    assert pressed.get("ok") is True, pressed
                    await wait_state(state, lambda value: value["clicks"] == 1)
                    checks.append("native AXPress delivered to fixture button")
                    current = await snapshot()
                    control.write_text("external-change")
                    await wait_state(state, lambda value: value["text"] == "fixture external edit")
                    changed = await action(current, element(current, "oa-fixture-text"), "set_value", "must-not-overwrite")
                    assert "stale_accessibility_element" in changed.get("error", ""), changed
                    await wait_state(state, lambda value: value["text"] == "fixture external edit")
                    checks.append("changed element rejects stale mutation")
                    control.write_text("long-initial")
                    await wait_state(state, lambda value: value["text"].endswith("original"))
                    current = await snapshot()
                    assert len(element(current, "oa-fixture-text")["state"]["value"]) == 512
                    control.write_text("long-change")
                    await wait_state(state, lambda value: value["text"].endswith("external"))
                    hidden_change = await action(current, element(current, "oa-fixture-text"), "set_value", "must-not-overwrite-hidden-edit")
                    assert "stale_accessibility_element" in hidden_change.get("error", ""), hidden_change
                    checks.append("edit beyond truncated display prefix rejects stale mutation")
                    current = await snapshot()
                    control.write_text("move")
                    await asyncio.sleep(0.3)
                    moved = await action(current, element(current, "oa-fixture-apply"), "press")
                    assert "stale_accessibility_window" in moved.get("error", ""), moved
                    await wait_state(state, lambda value: value["clicks"] == 1)
                    checks.append("moved window rejects stale mutation")
                    result = {"platform": "macos", "sidecar_version": initialization.serverInfo.version, "checks": checks, "passed": len(checks), "elapsed_seconds": round(time.monotonic()-started, 3), "fixture_only": True}
                    (ROOT / "target/native-accessibility-evidence.json").write_text(json.dumps(result, indent=2)+"\n")
                    print(json.dumps(result, indent=2))
        finally:
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)


if __name__ == "__main__":
    asyncio.run(main())
