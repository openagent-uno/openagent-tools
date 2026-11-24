"""One reconnectable Linux PTY per authenticated, dedicated task computer."""

from __future__ import annotations

import base64
import collections
import errno
import fcntl
import hashlib
import json
import os
from pathlib import Path
import pty
import selectors
import socket
import struct
import subprocess
import sys
import tempfile
import termios
import threading
import time
import uuid

WINDOW = 256 * 1024
CHUNK = 32 * 1024
MAX_INPUT = 4096


def write_state(path, value):
    with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as out:
        out.write(json.dumps(value).encode())
        out.flush()
        os.fsync(out.fileno())
    os.replace(out.name, path)


def snapshot(state, data, cursor):
    if type(cursor) is not int or cursor < 0 or cursor > state["end"]:
        raise ValueError("Invalid terminal cursor")
    base = state["end"] - len(data)
    start = max(base, cursor)
    block = data[start-base:start-base+CHUNK]
    return {**state, "offset": start, "next_cursor": start + len(block), "truncated": cursor < base,
            "output": block.decode("utf-8", "replace"), "output_base64": base64.b64encode(block).decode()}


def frame(conn):
    buf = bytearray()
    while len(buf) < 65536:
        chunk = conn.recv(8192)
        if not chunk:
            break
        buf.extend(chunk)
        if b"\n" in chunk:
            break
    if len(buf) >= 65536 or not buf.endswith(b"\n"):
        raise ValueError("Invalid terminal request")
    return json.loads(buf)


def socket_name(state):
    # Linux abstract sockets do not depend on the length of a home directory.
    return "\0oa-pty-" + hashlib.sha256(os.fsencode(state)).hexdigest()


def serve(directory, cwd):
    os.umask(0o077)
    path = directory / "session.json"
    state = json.loads(path.read_bytes())
    tail = bytearray()
    with socket.socket(socket.AF_UNIX) as listener, selectors.DefaultSelector() as events:
        listener.bind(socket_name(directory))
        listener.listen(8)
        events.register(listener, selectors.EVENT_READ)
        child, master = pty.fork()
        if child == 0:
            os.chdir(cwd)
            import pwd
            account = pwd.getpwuid(os.getuid())
            shell = account.pw_shell or "/bin/sh"
            os.execve(shell, [shell, "-i"], {"HOME": account.pw_dir, "USER": account.pw_name,
                      "SHELL": shell, "TERM": "xterm-256color", "LANG": "C.UTF-8",
                      "PATH": "/usr/local/bin:/usr/bin:/bin"})
        fcntl.ioctl(master, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 100, 0, 0))
        os.set_blocking(master, False)
        events.register(master, selectors.EVENT_READ)
        seen = {}
        pending = collections.deque()
        state["status"] = "running"
        write_state(path, state)
        while True:
            for key, mask in events.select():
                if key.fileobj == master:
                    if mask & selectors.EVENT_READ:
                        try:
                            data = os.read(master, CHUNK)
                        except OSError as exc:
                            if exc.errno != errno.EIO:
                                raise
                            data = b""
                        if not data:
                            events.unregister(master)
                            os.close(master)
                            _, status = os.waitpid(child, 0)
                            state.update(status="exited", exit_code=os.waitstatus_to_exitcode(status))
                            write_state(directory / "scrollback.json", base64.b64encode(tail).decode())
                            write_state(path, state)
                            return
                        tail.extend(data)
                        del tail[:max(0, len(tail)-WINDOW)]
                        state["end"] += len(data)
                    if mask & selectors.EVENT_WRITE and pending:
                        try:
                            sent = os.write(master, pending[0])
                        except BlockingIOError:
                            continue
                        pending[0] = pending[0][sent:]
                        if not pending[0]:
                            pending.popleft()
                        if not pending:
                            events.modify(master, selectors.EVENT_READ)
                    continue
                with listener.accept()[0] as conn:
                    conn.settimeout(2)
                    try:
                        _, uid, _ = struct.unpack("3i", conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
                        if uid != os.getuid():
                            continue
                        req = frame(conn)
                        if req.get("terminal_id") != state["terminal_id"]:
                            raise ValueError("Unknown terminal")
                        if req["op"] == "input":
                            ident = str(uuid.UUID(req["request_id"]))
                            data = req["text"].encode()
                            if not 0 < len(data) <= MAX_INPUT:
                                raise ValueError("Invalid terminal input")
                            digest = hashlib.sha256(data).digest()
                            if ident in seen and seen[ident] != digest:
                                raise ValueError("Conflicting terminal input receipt")
                            if ident not in seen:
                                if len(seen) >= 100_000 or len(pending) >= 64:
                                    raise ValueError("Terminal input capacity reached")
                                seen[ident] = digest
                                pending.append(data)
                                events.modify(master, selectors.EVENT_READ | selectors.EVENT_WRITE)
                        elif req["op"] != "read":
                            raise ValueError("Unexpected terminal operation")
                        result = snapshot(state, tail, req.get("cursor", state["end"]))
                    except (ValueError, KeyError, AttributeError, TypeError, TimeoutError) as exc:
                        result = {"error": str(exc)}
                    try:
                        conn.sendall(json.dumps(result).encode() + b"\n")
                    except OSError:
                        pass


def terminal(directory, cwd, args):
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    path = directory / "session.json"
    op = args["op"]
    with (directory / "opening.lock").open("a+b") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if not path.exists():
            if op != "open":
                raise ValueError("There is no terminal on this computer")
            state = {"terminal_id": str(uuid.uuid4()), "status": "starting", "cwd": str(cwd), "exit_code": None, "end": 0}
            write_state(path, state)
            # A guest service outlives its capability channel and web clients.
            proc = subprocess.Popen([sys.executable, "-m", __name__, str(directory), str(cwd)],
                                    cwd=cwd, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                    stderr=subprocess.DEVNULL, start_new_session=True)
            threading.Thread(target=proc.wait, daemon=True).start()
            for _ in range(150):
                if json.loads(path.read_bytes())["status"] != "starting" or proc.poll() is not None:
                    break
                time.sleep(.02)
        state = json.loads(path.read_bytes())
    ident = state["terminal_id"]
    if op in {"open", "attach"}:
        args = {"op": "read", "terminal_id": ident, "cursor": 0}
    if args.get("terminal_id") != ident:
        raise ValueError("Unknown terminal")
    with socket.socket(socket.AF_UNIX) as conn:
        conn.settimeout(4)
        try:
            conn.connect(socket_name(directory))
        except (ConnectionRefusedError, FileNotFoundError):
            state = json.loads(path.read_bytes())
            if args["op"] == "input":
                raise ValueError("The terminal is no longer running") from None
            if state["status"] != "exited":
                state.update(status="unknown", end=0)
                return {**snapshot(state, b"", 0), "truncated": True}
            tail = base64.b64decode(json.loads((directory / "scrollback.json").read_bytes()))
            return snapshot(state, tail, args.get("cursor", 0))
        conn.sendall(json.dumps(args).encode() + b"\n")
        with conn.makefile("rb") as response:
            raw = response.readline(512 * 1024)
        if not raw.endswith(b"\n"):
            raise ValueError("Terminal response interrupted")
        result = json.loads(raw)
        if "error" in result:
            raise ValueError(result["error"])
        return result


if __name__ == "__main__":
    serve(Path(sys.argv[1]), Path(sys.argv[2]))
