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


def test_agent_in_chrome_lock_excludes_known_moderate_advisories() -> None:
    lock = json.loads(
        (sidecar_source("agent-in-chrome") / "host" / "package-lock.json").read_text()
    )
    packages = lock["packages"]
    assert packages["node_modules/@hono/node-server"]["version"] == "2.1.1"
    assert packages["node_modules/hono"]["version"] == "4.13.8"
    assert packages["node_modules/qs"]["version"] == "6.16.0"


def test_agent_in_chrome_discovery_honors_explicit_client_command(monkeypatch) -> None:
    command = ["/verified/node", "/verified/agent-in-chrome/mcp-server.js"]
    monkeypatch.setenv("OPENAGENT_AGENT_IN_CHROME_COMMAND", json.dumps(command))
    candidates = {candidate.name: candidate for candidate in discover_sidecars()}
    assert candidates["agent-in-chrome"].command == tuple(command)
    assert candidates["agent-in-chrome"].placeholder is AGENT_IN_CHROME_MANIFEST
