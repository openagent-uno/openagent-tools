"""Shared low-level shell process core used by server and client hosts.

Policy, authorization, MCP envelopes and server ShellHub integration live in
their adapters. Process spawning, bounded stream accounting, stdin, signals,
timeouts and finalisation live here once.
"""

from __future__ import annotations

import asyncio
import os
import platform
import signal as signal_module
import subprocess
import time
from dataclasses import dataclass
from typing import Literal

MAX_STREAM_BYTES = 1_000_000
DEFAULT_KILL_GRACE = 5.0
FINALISE_TIMEOUT = 5.0
SignalName = Literal["TERM", "INT", "KILL"]


def pick_shell(environment: dict[str, str] | None = None) -> tuple[str, str]:
    environment = os.environ if environment is None else environment
    system = platform.system().lower()
    if system == "windows":
        return (environment.get("COMSPEC", "cmd.exe"), "/c")
    if system == "darwin":
        return (environment.get("SHELL", "/bin/zsh"), "-c")
    return (environment.get("SHELL", "/bin/bash"), "-c")


_LOGIN_PATH_START = "__OPENAGENT_LOGIN_PATH_START__"
_LOGIN_PATH_END = "__OPENAGENT_LOGIN_PATH_END__"
_LOGIN_PATH_TIMEOUT = 5.0
_MACOS_WELL_KNOWN_PATHS = ("/opt/homebrew/bin", "/opt/homebrew/sbin", "/usr/local/bin")
_login_path_cache: dict[tuple[str, str, str], str | None] = {}


def _probe_login_path(environment: dict[str, str]) -> str | None:
    """Return ``PATH`` as the user's interactive login shell defines it.

    A macOS app started from Finder, the Dock or launchd inherits only the
    launchd default ``/usr/bin:/bin:/usr/sbin:/sbin``. Commands that work in
    the user's terminal (Homebrew, SDKs, version managers configured in
    ``.zprofile``/``.zshrc``) are then missing. The interactive login shell is
    asked once, with stdin closed and a short timeout; output outside the
    markers (banners, prompts) is ignored. Any failure returns ``None``.
    """
    shell, _flag = pick_shell(environment)
    key = (shell, environment.get("PATH", ""), environment.get("HOME", ""))
    if key in _login_path_cache:
        return _login_path_cache[key]
    script = f"printf '%s%s%s' '{_LOGIN_PATH_START}' \"$PATH\" '{_LOGIN_PATH_END}'"
    resolved: str | None = None
    try:
        completed = subprocess.run(
            [shell, "-ilc", script],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env=dict(environment),
            timeout=_LOGIN_PATH_TIMEOUT,
            start_new_session=True,
            check=False,
        )
        output = completed.stdout.decode("utf-8", "replace")
        start = output.rfind(_LOGIN_PATH_START)
        end = output.rfind(_LOGIN_PATH_END)
        if start != -1 and end > start:
            value = output[start + len(_LOGIN_PATH_START):end].strip()
            resolved = value or None
    except (OSError, subprocess.SubprocessError, ValueError):
        resolved = None
    _login_path_cache[key] = resolved
    return resolved


def user_environment(environment: dict[str, str] | None = None) -> dict[str, str]:
    """Return ``environment`` with the user's login-shell ``PATH`` on macOS.

    Entries already present keep working; the login-shell entries come first
    so the shell resolves programs as the user's terminal does. When the probe
    fails, the standard Homebrew/``/usr/local`` directories that exist are
    appended instead. Set ``OPENAGENT_SHELL_LOGIN_PATH=0`` to disable it.
    Other platforms and other variables are returned unchanged.
    """
    result = dict(os.environ if environment is None else environment)
    if platform.system().lower() != "darwin":
        return result
    if result.get("OPENAGENT_SHELL_LOGIN_PATH", "1").strip().lower() in {"0", "false", "no", "off"}:
        return result
    current = [entry for entry in result.get("PATH", "").split(os.pathsep) if entry]
    login = _probe_login_path(result)
    if login:
        preferred = [entry for entry in login.split(os.pathsep) if entry]
    else:
        preferred = [entry for entry in _MACOS_WELL_KNOWN_PATHS if os.path.isdir(entry)]
        preferred = current + preferred
    merged: list[str] = []
    for entry in [*preferred, *current]:
        if entry not in merged:
            merged.append(entry)
    if merged:
        result["PATH"] = os.pathsep.join(merged)
    return result


@dataclass
class ForegroundResult:
    exit_code: int | None
    signal: str | None
    stdout: str
    stderr: str
    duration_ms: int
    timed_out: bool
    stdout_dropped: int
    stderr_dropped: int


class BackgroundShell:
    """One subprocess with bounded stdout/stderr buffers and lifecycle APIs."""

    def __init__(
        self,
        *,
        shell_id: str,
        command: str,
        cwd: str | None,
        env: dict[str, str] | None,
        base_environment: dict[str, str] | None = None,
    ) -> None:
        self.shell_id = shell_id
        self.command = command
        self.cwd = cwd
        self.env = {**(os.environ if base_environment is None else base_environment), **(env or {})}
        self._proc: asyncio.subprocess.Process | None = None
        self._stdout_buf = bytearray()
        self._stderr_buf = bytearray()
        self._stdout_total = 0
        self._stderr_total = 0
        self._stdout_dropped = 0
        self._stderr_dropped = 0
        self._stdout_task: asyncio.Task | None = None
        self._stderr_task: asyncio.Task | None = None
        self._started_at: float | None = None
        self._completed_at: float | None = None
        self._exit_code: int | None = None
        self._signal: str | None = None

    async def _spawn_process(self) -> asyncio.subprocess.Process:
        common = {
            "stdin": asyncio.subprocess.PIPE,
            "stdout": asyncio.subprocess.PIPE,
            "stderr": asyncio.subprocess.PIPE,
            "cwd": self.cwd,
            "env": dict(self.env),
        }
        if platform.system().lower() == "windows":
            # ``cmd.exe`` is not a Microsoft C-runtime argv consumer. Passing
            # the complete command as the third argv element of
            # ``create_subprocess_exec(cmd, "/c", command)`` makes Python run
            # ``list2cmdline`` over it, escaping embedded quotes with
            # backslashes. ``cmd.exe`` does not interpret those backslashes as
            # quote escapes, so a command such as ``python -c "..."`` is
            # reparsed incorrectly. The shell API accepts the command as an
            # already-formed command line and applies cmd.exe's outer quoting.
            # Let CPython resolve its hardened COMSPEC default itself:
            # explicitly forwarding ``executable`` through the Proactor
            # transport is not equivalent across supported Windows builds.
            return await asyncio.create_subprocess_shell(
                self.command,
                **common,
            )
        shell, flag = pick_shell(self.env)
        return await asyncio.create_subprocess_exec(
            shell,
            flag,
            self.command,
            start_new_session=True,
            **common,
        )

    def _event(self, name: str, **fields) -> None:
        del name, fields

    async def start(self) -> None:
        self._proc = await self._spawn_process()
        self._started_at = time.time()
        self._stdout_task = asyncio.create_task(
            self._drain(self._proc.stdout, is_stderr=False)
        )
        self._stderr_task = asyncio.create_task(
            self._drain(self._proc.stderr, is_stderr=True)
        )

    async def _drain(
        self, stream: asyncio.StreamReader | None, *, is_stderr: bool
    ) -> None:
        if stream is None:
            return
        while chunk := await stream.read(4096):
            self._append(chunk, is_stderr=is_stderr)

    def _append(self, chunk: bytes, *, is_stderr: bool) -> None:
        buffer = self._stderr_buf if is_stderr else self._stdout_buf
        buffer.extend(chunk)
        if is_stderr:
            self._stderr_total += len(chunk)
        else:
            self._stdout_total += len(chunk)
        if len(buffer) > MAX_STREAM_BYTES:
            dropped = len(buffer) - MAX_STREAM_BYTES
            del buffer[:dropped]
            if is_stderr:
                self._stderr_dropped += dropped
            else:
                self._stdout_dropped += dropped

    def read(self, *, since_stdout: int, since_stderr: int) -> tuple[str, str]:
        return (
            self._slice(
                self._stdout_buf,
                since_stdout,
                self._stdout_total,
                self._stdout_dropped,
            ),
            self._slice(
                self._stderr_buf,
                since_stderr,
                self._stderr_total,
                self._stderr_dropped,
            ),
        )

    @staticmethod
    def _slice(buffer: bytearray, since: int, total: int, dropped: int) -> str:
        if since >= total:
            return ""
        start = max(0, since - dropped)
        return bytes(buffer[start:]).decode("utf-8", errors="replace")

    @property
    def process(self) -> asyncio.subprocess.Process | None:
        return self._proc

    @property
    def is_running(self) -> bool:
        return self._proc is not None and self._proc.returncode is None

    @property
    def exit_code(self) -> int | None:
        return self._exit_code if not self.is_running else None

    @property
    def signal(self) -> str | None:
        return self._signal

    @property
    def stdout_bytes_total(self) -> int:
        return self._stdout_total

    @property
    def stderr_bytes_total(self) -> int:
        return self._stderr_total

    @property
    def started_at(self) -> float | None:
        return self._started_at

    @property
    def completed_at(self) -> float | None:
        return self._completed_at

    @property
    def stdout_dropped(self) -> int:
        return self._stdout_dropped

    @property
    def stderr_dropped(self) -> int:
        return self._stderr_dropped

    async def _wait_with_timeout(self) -> int | None:
        assert self._proc is not None
        try:
            return await asyncio.wait_for(self._proc.wait(), timeout=FINALISE_TIMEOUT)
        except asyncio.TimeoutError:
            self._event("wait_stuck", shell_id=self.shell_id)
            transport = getattr(self._proc, "_transport", None)
            if transport is not None:
                try:
                    transport.close()
                except Exception:
                    pass
            try:
                return await asyncio.wait_for(
                    self._proc.wait(), timeout=FINALISE_TIMEOUT
                )
            except asyncio.TimeoutError:
                return self._proc.returncode

    async def _await_drain(self, task: asyncio.Task | None, name: str) -> None:
        if task is None:
            return
        if task.done():
            try:
                task.result()
            except Exception as exc:
                self._event("drain_error", shell_id=self.shell_id, stream=name, error=str(exc))
            return
        try:
            await asyncio.wait_for(asyncio.shield(task), timeout=FINALISE_TIMEOUT)
        except asyncio.TimeoutError:
            self._event("drain_stuck", shell_id=self.shell_id, stream=name)
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
        except Exception as exc:
            self._event("drain_error", shell_id=self.shell_id, stream=name, error=str(exc))

    async def finalise(self) -> None:
        if self._proc is None:
            return
        rc = await self._wait_with_timeout()
        await self._await_drain(self._stdout_task, "stdout")
        await self._await_drain(self._stderr_task, "stderr")
        self._event("finalise_done", shell_id=self.shell_id, rc=rc)
        if rc is not None and rc < 0:
            try:
                self._signal = signal_module.Signals(-rc).name.removeprefix("SIG")
            except ValueError:
                self._signal = str(-rc)
            self._exit_code = None
        else:
            self._exit_code = rc
        self._completed_at = time.time()

    async def write_stdin(self, text: str, *, press_enter: bool = True) -> int:
        if self._proc is None or self._proc.stdin is None:
            raise RuntimeError(f"shell {self.shell_id} has no stdin (not started?)")
        if self._proc.returncode is not None:
            raise RuntimeError(f"shell {self.shell_id} has exited")
        payload = text + "\n" if press_enter and not text.endswith("\n") else text
        data = payload.encode("utf-8")
        self._proc.stdin.write(data)
        await self._proc.stdin.drain()
        return len(data)

    async def kill(
        self,
        *,
        signal_name: SignalName = "TERM",
        grace_seconds: float = DEFAULT_KILL_GRACE,
    ) -> None:
        if self._proc is None or self._proc.returncode is not None:
            return
        if os.name == "nt":
            if signal_name == "KILL":
                self._proc.kill()
            else:
                self._proc.terminate()
            if signal_name != "KILL" and grace_seconds > 0:
                try:
                    await asyncio.wait_for(self._proc.wait(), timeout=grace_seconds)
                except asyncio.TimeoutError:
                    self._proc.kill()
            return
        try:
            process_group = os.getpgid(self._proc.pid)
        except ProcessLookupError:
            return
        first = {
            "TERM": signal_module.SIGTERM,
            "INT": signal_module.SIGINT,
            "KILL": signal_module.SIGKILL,
        }[signal_name]
        try:
            os.killpg(process_group, first)
        except ProcessLookupError:
            return
        if first == signal_module.SIGKILL or grace_seconds <= 0:
            return
        try:
            await asyncio.wait_for(self._proc.wait(), timeout=grace_seconds)
        except asyncio.TimeoutError:
            try:
                os.killpg(process_group, signal_module.SIGKILL)
            except ProcessLookupError:
                pass

    async def run_with_timeout(
        self, *, timeout_seconds: float, stdin_data: str | None = None
    ) -> ForegroundResult:
        await self.start()
        timed_out = False
        try:
            if stdin_data:
                await self.write_stdin(stdin_data, press_enter=False)
                if self._proc is not None and self._proc.stdin is not None:
                    self._proc.stdin.close()
            assert self._proc is not None
            try:
                await asyncio.wait_for(self._proc.wait(), timeout=timeout_seconds)
            except asyncio.TimeoutError:
                timed_out = True
                self._event(
                    "timeout", shell_id=self.shell_id, timeout_s=timeout_seconds
                )
                await self.kill(signal_name="TERM", grace_seconds=DEFAULT_KILL_GRACE)
                self._event("kill_returned", shell_id=self.shell_id)
        except asyncio.CancelledError:
            await self.kill(signal_name="KILL", grace_seconds=0)
            raise
        finally:
            await self.finalise()
        stdout, stderr = self.read(since_stdout=0, since_stderr=0)
        started = self._started_at or 0.0
        completed = self._completed_at or started
        return ForegroundResult(
            exit_code=self._exit_code,
            signal=self._signal,
            stdout=stdout,
            stderr=stderr,
            duration_ms=int((completed - started) * 1000),
            timed_out=timed_out,
            stdout_dropped=self._stdout_dropped,
            stderr_dropped=self._stderr_dropped,
        )
