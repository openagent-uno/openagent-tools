"""Explicitly enabled direct-human capabilities for an isolated Linux guest."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import html
from html.parser import HTMLParser
import http.client
import json
from pathlib import Path
import re
import socket
import threading
import sys

from openagent_tool_protocol.context import current_principal
from openagent_tool_protocol.types import HostError, ToolClassification, ToolManifest
from openagent_tool_protocol.util import json_result

MAX_PREVIEW = 512 * 1024
ALLOWED_TAGS = frozenset(("html body main article section header footer div span p pre code b strong i em small "
                          "h1 h2 h3 h4 h5 h6 br hr ul ol li table thead tbody tr th td blockquote").split())


class StaticPreview(HTMLParser):
    def __init__(self):
        super().__init__()
        self.fragments = []
        self.hidden = None

    def handle_starttag(self, tag, attrs):
        if self.hidden:
            return
        if tag in {"script", "style", "title", "textarea"}:
            self.hidden = tag
        elif tag in ALLOWED_TAGS:
            self.fragments.append("<" + tag + ">")

    def handle_endtag(self, tag):
        if self.hidden:
            if tag == self.hidden:
                self.hidden = None
        elif tag in ALLOWED_TAGS:
            self.fragments.append("</" + tag + ">")

    def handle_data(self, data):
        if not self.hidden:
            self.fragments.append(html.escape(data))


def origin(value):
    if not isinstance(value, str):
        raise ValueError("Invalid preview configuration")
    match = re.fullmatch(r"([1-9][0-9]{0,4}):(/[a-zA-Z0-9/_~.-]{0,256})", value)
    if not match or not 1024 <= int(match[1]) <= 65535 or match[2].startswith("//") or ".." in match[2].split("/"):
        raise ValueError("Invalid guest preview endpoint")
    return int(match[1]), match[2]


def preview(endpoint):
    port, path = endpoint
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
    sock = None
    def interrupt():
        if sock is not None:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

    conn.connect()
    sock = conn.sock
    deadline = threading.Timer(5, interrupt)
    deadline.daemon = True
    deadline.start()
    try:
        conn.request("GET", path, headers={"Accept": "image/png,text/html", "Accept-Encoding": "identity"})
        res = conn.getresponse()
        if res.status != 200 or res.getheader("Content-Encoding", "identity") != "identity":
            raise ValueError("Guest preview unavailable")
        mime = res.getheader("Content-Type", "").split(";")[0].strip().lower()
        data = res.read(MAX_PREVIEW+1)
    finally:
        deadline.cancel()
        conn.close()
    if len(data) > MAX_PREVIEW:
        raise ValueError("Guest preview too large")
    if mime == "text/html":
        parser = StaticPreview()
        parser.feed(data.decode("utf-8", "replace"))
        parser.close()
        policy = '<meta http-equiv="Content-Security-Policy" content="default-src &#39;none&#39;; form-action &#39;none&#39;; base-uri &#39;none&#39;">'
        data = ("<!doctype html>" + policy + "".join(parser.fragments)).encode()
    elif mime != "image/png" or not data.startswith(b"\x89PNG\r\n\x1a\n"):
        raise ValueError("Unsupported guest preview")
    if len(data) > MAX_PREVIEW:
        raise ValueError("Guest preview too large")
    return {"mime": mime, "data": base64.b64encode(data).decode()}


def manifest(terminal, preview_enabled):
    tools = []
    ops = []
    if terminal:
        ops.extend(("open", "attach", "read", "input"))
    if preview_enabled:
        ops.append("preview")
    for op in ops:
        props = {}
        if op in {"read", "input"}:
            props["terminal_id"] = {"type": "string", "format": "uuid"}
        if op == "read":
            props["cursor"] = {"type": "integer", "minimum": 0}
        if op == "input":
            props.update(text={"type": "string", "minLength": 1, "maxLength": 4096},
                         request_id={"type": "string", "format": "uuid"})
        if op == "preview":
            props["endpoint"] = {"type": "string"}
        tools.append(ToolManifest("task_surface_" + op, "Access the current task computer: " + op,
                     {"type": "object", "additionalProperties": False, "properties": props, "required": list(props)},
                     ToolClassification.MUTATING if op in {"open", "input"} else ToolClassification.READ_ONLY,
                     metadata={"ui": {"visibility": ["app"]}, "openagent/task-surface": "1"}))
    return tuple(tools)


class GuestSurfaces:
    def __init__(self, workspace, endpoint):
        if sys.platform != "linux" or not workspace.is_absolute() or not workspace.is_dir():
            raise ValueError("Task surfaces require a dedicated Linux workspace")
        self.cwd = workspace.resolve()
        self.endpoint = origin(endpoint) if endpoint else None
        self.tools = manifest(True, bool(self.endpoint))

    async def call(self, name, args):
        try:
            principal = json.loads(current_principal.get() or "null")
            if not isinstance(principal, dict) or principal.get("kind") != "user":
                raise ValueError("Current enrolled task user required")
            keys = [principal.get(k) for k in ("network_id", "account_id", "device_id", "browser_scope")]
            if not all(isinstance(key, str) and key for key in keys) or not re.fullmatch(r"[0-9a-f]{64}", keys[-1]):
                raise ValueError("Certified task computer scope required")
            metadata = next((tool for tool in self.tools if tool.name == name), None)
            if not metadata or set(args) != set(metadata.input_schema["properties"]):
                raise ValueError("Invalid task surface operation")
            op = name.removeprefix("task_surface_")
            if op == "preview":
                if self.endpoint is None or origin(args["endpoint"]) != self.endpoint:
                    raise ValueError("Unknown preview on this computer")
                result = await asyncio.to_thread(preview, self.endpoint)
            else:
                from .task_terminal import terminal
                ident = hashlib.sha256(json.dumps(keys, separators=(",", ":")).encode()).hexdigest()
                directory = Path.home() / ".local" / "state" / "openagent" / "terminals" / ident
                result = await asyncio.to_thread(terminal, directory, self.cwd, {**args, "op": op})
            return json_result(result)
        except (OSError, ValueError, TypeError, KeyError, http.client.HTTPException) as exc:
            raise HostError("task_surface_unavailable", str(exc)) from None
