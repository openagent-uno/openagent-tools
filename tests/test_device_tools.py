from __future__ import annotations

import json

from openagent_device_tools import (
    AGENT_IN_CHROME_MANIFEST,
    COMPUTER_CONTROL_MANIFEST,
    discover_sidecars,
    sidecar_source,
)


def test_agent_in_chrome_sources_and_manifest_ship_with_device_tools() -> None:
    source = sidecar_source("agent-in-chrome")
    assert (source / "host" / "mcp-server.js").is_file()
    assert (source / "host" / "browser.js").is_file()
    assert (source / "tab-group-extension" / "manifest.json").is_file()
    assert AGENT_IN_CHROME_MANIFEST.name == "agent-in-chrome"
    assert {tool.name for tool in AGENT_IN_CHROME_MANIFEST.tools} >= {
        "tabs_context_mcp",
        "navigate",
        "read_page",
    }
    assert COMPUTER_CONTROL_MANIFEST.name == "computer-control"
    window_tools = {tool.name: tool for tool in COMPUTER_CONTROL_MANIFEST.tools}
    assert {"computer_list_displays", "computer_list_windows", "computer_capture_window"} <= window_tools.keys()
    assert window_tools["computer_list_displays"].classification.value == "read_only"
    assert window_tools["computer_list_windows"].classification.value == "read_only"
    assert window_tools["computer_capture_window"].classification.value == "read_only"
    assert set(window_tools["computer_capture_window"].input_schema["required"]) == {"window_id", "pid"}
    assert "display_id" in window_tools["computer"].input_schema["properties"]
    assert COMPUTER_CONTROL_MANIFEST.version == "0.1.5"


def test_agent_in_chrome_lock_excludes_known_moderate_advisories() -> None:
    lock = json.loads(
        (sidecar_source("agent-in-chrome") / "host" / "package-lock.json").read_text()
    )
    packages = lock["packages"]
    assert packages["node_modules/@hono/node-server"]["version"] == "2.1.5"
    assert packages["node_modules/hono"]["version"] == "4.13.14"
    assert packages["node_modules/qs"]["version"] == "6.17.1"


def test_agent_in_chrome_discovery_honors_explicit_client_command(monkeypatch) -> None:
    command = ["/verified/node", "/verified/agent-in-chrome/mcp-server.js"]
    monkeypatch.setenv("OPENAGENT_AGENT_IN_CHROME_COMMAND", json.dumps(command))
    candidates = {candidate.name: candidate for candidate in discover_sidecars()}
    assert candidates["agent-in-chrome"].command == tuple(command)
    assert candidates["agent-in-chrome"].placeholder is AGENT_IN_CHROME_MANIFEST


def test_native_accessibility_tools_have_explicit_target_and_mutation_contracts():
    tools = {tool.name: tool for tool in COMPUTER_CONTROL_MANIFEST.tools}
    snapshot = tools["computer_accessibility_snapshot"]
    action = tools["computer_accessibility_action"]
    assert snapshot.classification.value == "read_only"
    assert action.classification.value == "mutating"
    assert set(snapshot.input_schema["required"]) == {"window_id", "pid"}
    assert set(action.input_schema["required"]) == {"snapshot_id", "element_id", "action"}
    assert action.input_schema["$defs"]["ElementAction"]["enum"] == ["press", "show_menu", "set_value"]
    assert "macOS only" in snapshot.description
    assert "automatically retried" in action.description
    assert "single-use" in snapshot.description
    assert (sidecar_source("computer-control") / "src" / "accessibility.rs").is_file()


def test_advanced_sidecar_catalog_preserves_argument_classification():
    browser = {tool.name: tool for tool in AGENT_IN_CHROME_MANIFEST.tools}
    assert AGENT_IN_CHROME_MANIFEST.version == "3.0.0"
    assert browser["browser_control"].classification_for({"action": "inventory"}).value == "read_only"
    assert browser["browser_control"].classification_for({"action": "request_takeover"}).value == "mutating"
    assert browser["browser_downloads"].classification_for({"action": "read"}).value == "read_only"
    source = sidecar_source("agent-in-chrome") / "host"
    assert (source / "browser-advanced.js").is_file()
    assert (source / "browser-advanced-tools.json").is_file()
    lock = json.loads((source / "package-lock.json").read_text())["packages"]
    for name, version in {"@modelcontextprotocol/sdk": "1.32.2", "ws": "8.22.0", "zod": "4.6.7", "playwright-core": "1.62.1"}.items():
        assert lock["node_modules/" + name]["version"] == version


def test_advanced_native_catalog_is_explicit_and_ships_sources():
    tools = {tool.name: tool for tool in COMPUTER_CONTROL_MANIFEST.tools}
    assert {"computer_list_apps", "computer_launch_app", "computer_app_policy", "computer_window_input", "computer_select_text", "computer_perform_action", "computer_paste", "computer_audio_start", "computer_audio_stop"} <= tools.keys()
    assert tools["computer_list_apps"].classification.value == "read_only"
    assert tools["computer_app_policy"].classification.value == "read_only"
    for name in ["computer_window_input", "computer_paste", "computer_select_text", "computer_perform_action"]:
        assert "snapshot_id" in tools[name].input_schema["required"]
        assert tools[name].classification.value == "mutating"
    assert "source" in tools["computer_audio_start"].input_schema["required"]
    assert "all_system_output" in tools["computer_audio_start"].input_schema["properties"]
    source = sidecar_source("computer-control")
    assert (source / "build.rs").is_file()
    assert (source / "src" / "advanced.rs").is_file()
    assert (source / "src" / "native_advanced.m").is_file()
