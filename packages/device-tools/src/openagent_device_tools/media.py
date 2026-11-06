"""Optional continuous desktop media; hosts supply a trusted sidecar command.

No identity, transport, sharing or storage policy is implemented here. The
caller must keep authorizing the viewer and close the iterator on disconnect.
"""
import asyncio
import base64
import json
import re
from collections.abc import Mapping


def stream_options(value):
    if not isinstance(value, Mapping) or set(value) - {"display_id", "fps", "max_duration_seconds"}:
        raise ValueError("Invalid desktop media options")
    result = {"fps": 20, "max_duration_seconds": 300, **value}
    for key, minimum, maximum in (("display_id", 0, 2**32-1), ("fps", 1, 30), ("max_duration_seconds", 1, 300)):
        if key in result and (type(result[key]) is not int or not minimum <= result[key] <= maximum):
            raise ValueError("Invalid desktop media options")
    return result


def video_packet(value):
    if not isinstance(value, dict):
        raise ValueError("Invalid media packet")
    if value.get("type") == "config":
        if value.get("protocol") != "openagent-video/1" or not re.fullmatch(r"avc1\.[A-Fa-f0-9]{6}", str(value.get("codec", ""))):
            raise ValueError("Invalid media configuration")
        for key in ("width", "height", "input_width", "input_height", "fps"):
            maximum = 30 if key == "fps" else 32768
            minimum = 1 if key == "fps" else 2
            if type(value.get(key)) is not int or not minimum <= value[key] <= maximum:
                raise ValueError("Invalid media dimensions")
    elif value.get("type") == "frame":
        if any(type(value.get(key)) is not int or value[key] < 0 or value[key] > 2**53-1 for key in ("seq", "timestamp_us")) or type(value.get("key")) is not bool:
            raise ValueError("Invalid media frame")
        data = value.get("data")
        if not isinstance(data, str) or not data or len(data) > 1400000:
            raise ValueError("Invalid media payload")
        base64.b64decode(data, validate=True)
    else:
        raise ValueError("Invalid media packet")
    return value


def native_desktop_command(role="control"):
    """Select an exact qualified artifact; a macOS executable keeps its bundle."""
    import hashlib
    import os
    import platform
    import stat
    import sys
    from pathlib import Path
    root=Path(__file__).resolve().parent/"native"
    if not (root/"manifest.json").is_file():return None
    manifest=json.loads((root/"manifest.json").read_text())
    if manifest.get("protocol")!="openagent-native-artifacts/2":raise ValueError("Invalid native artifact manifest")
    machine={"aarch64":"arm64","arm64":"arm64","amd64":"x64","x86_64":"x64"}.get(platform.machine().lower(),platform.machine().lower())
    artifact=manifest.get("artifacts",{}).get(f"{sys.platform}-{machine}")
    selected=artifact.get("roles",{}).get(role) if artifact else None
    if selected is None:return None
    def relative(value):return isinstance(value,str) and re.fullmatch(r"[A-Za-z0-9_./-]+",value) and all(part not in {"", ".", ".."} for part in value.split("/"))
    if not relative(selected.get("root")) or not relative(selected.get("executable")):raise ValueError("Invalid native artifact path")
    bundle=(root/selected["root"]).resolve()
    if not bundle.is_relative_to(root):raise ValueError("Invalid native artifact root")
    if sys.platform=="darwin" and selected.get("minimumSystemVersion"):
        current=tuple(map(int,platform.mac_ver()[0].split(".")))
        minimum=tuple(map(int,selected["minimumSystemVersion"].split(".")))
        if current+((0,)*(3-len(current)))<minimum+((0,)*(3-len(minimum))):return None
    expected=selected.get("files")
    if not isinstance(expected,dict) or not 1<=len(expected)<=256 or selected["executable"] not in expected:raise ValueError("Invalid native artifact inventory")
    actual={p.relative_to(bundle).as_posix() for p in bundle.rglob("*") if p.is_file()}
    if actual!=set(expected):raise ValueError("Native artifact inventory mismatch")
    for relative_path,digest in expected.items():
        if not relative(relative_path) or not re.fullmatch(r"[a-f0-9]{64}",str(digest)):raise ValueError("Invalid native artifact digest")
        file=bundle/relative_path
        if file.is_symlink() or not stat.S_ISREG(file.lstat().st_mode) or hashlib.sha256(file.read_bytes()).hexdigest()!=digest:raise ValueError("Native artifact digest mismatch")
    binary=bundle/selected["executable"]
    if sys.platform!="win32" and not os.access(binary,os.X_OK):raise PermissionError("Native artifact is not executable")
    return (str(binary),)


class NativeDesktopMedia:
    """Media executor for Core's public optional pool adapter.

    Each viewer owns one encoder. Subprocess pipes provide backpressure;
    cancellation closes stdin and reaps only this owned encoder.
    """
    def __init__(self, command, *, environment=None, cwd=None, tool_names=("computer", "computer_control_computer")):
        if not isinstance(command, (tuple, list)) or not command or any(not isinstance(v, str) or not v for v in command):
            raise ValueError("Explicit trusted encoder command required")
        self.command, self.environment, self.cwd = tuple(command), environment, cwd
        control=native_desktop_command("control")
        if control and self.command==control:self.command=native_desktop_command("view")
        self.tool_names = frozenset(tool_names)

    async def qualify(self):
        """Probe the engine-free protocol before advertising media support."""
        if self.command is None:return False
        process = await asyncio.create_subprocess_exec(*self.command, "--desktop-stdio",
            stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL, env=self.environment, cwd=self.cwd, limit=8192)
        try:
            output, _ = await asyncio.wait_for(process.communicate(b'{"id":1,"action":"hello"}\n'), timeout=5)
            if len(output) > 8192 or process.returncode:
                return False
            response = json.loads(output)
            return response.get("ok") is True and response.get("result", {}).get("protocol") == "openagent-desktop/1"
        except (ValueError, asyncio.TimeoutError):
            return False
        finally:
            if process.returncode is None:
                process.kill()
                await process.wait()

    def metadata(self, name):
        return {"openagent/liveMedia": "openagent-video/1"} if name in self.tool_names else {}

    async def stream_tool(self, name, options, context):
        if self.command is None or name not in self.tool_names:
            raise LookupError("Exact desktop media tool unavailable")
        options = stream_options(options)
        # Restart only the same explicit source after a bounded encoder cycle.
        while True:
            process = await asyncio.create_subprocess_exec(*self.command, "--desktop-stream",
                stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL, env=self.environment, cwd=self.cwd, limit=2*1024*1024)
            try:
                process.stdin.write((json.dumps(options)+"\n").encode())
                await process.stdin.drain()
                configured, sequence = False, 0
                while True:
                    line = await asyncio.wait_for(process.stdout.readline(), timeout=20)
                    if not line:
                        break
                    if len(line) > 2*1024*1024:
                        raise ValueError("Media packet exceeds its bound")
                    packet = video_packet(json.loads(line))
                    if packet["type"] == "config":
                        if configured:
                            raise ValueError("Duplicate media configuration")
                        configured = True
                    else:
                        if not configured or packet["seq"] != sequence or sequence == 0 and not packet["key"]:
                            raise ValueError("Media sequence interrupted")
                        sequence += 1
                    yield packet
                code = await process.wait()
                if code or not configured or not sequence:
                    raise RuntimeError("Desktop encoder unavailable; check screen recording permission")
            finally:
                process.stdin.close()
                if process.returncode is None:
                    try:
                        process.terminate()
                    except ProcessLookupError:
                        pass
                    try:
                        await asyncio.wait_for(process.wait(), timeout=2)
                    except asyncio.TimeoutError:
                        process.kill()
                        await process.wait()
