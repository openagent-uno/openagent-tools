from __future__ import annotations

import os
import subprocess
import sys

import pytest

from openagent_shell import shell_core
from openagent_shell.shell_core import BackgroundShell


@pytest.mark.skipif(os.name != "nt", reason="real Windows COMSPEC regression")
@pytest.mark.asyncio
async def test_windows_shell_runs_quoted_command_without_comspec(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    monkeypatch.delenv("COMSPEC", raising=False)
    command = subprocess.list2cmdline(
        [
            sys.executable,
            "-c",
            "import sys; sys.stdout.buffer.write(b'quoted value\\n')",
        ]
    )
    shell = BackgroundShell(
        shell_id="windows-real-quoted",
        command=command,
        cwd=str(tmp_path),
        env=None,
    )

    result = await shell.run_with_timeout(timeout_seconds=10)

    assert result.exit_code == 0
    assert result.stderr == ""
    assert result.stdout == "quoted value\n"


@pytest.mark.asyncio
async def test_windows_shell_command_is_not_requoted_as_an_argv_element(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    command = '\"C:\\Program Files\\Python\\python.exe\" -c \"print(\'quoted value\')\"'
    sentinel = object()
    captured: dict[str, object] = {}

    async def fake_create_subprocess_shell(value: str, **kwargs):
        captured["command"] = value
        captured.update(kwargs)
        return sentinel

    async def reject_create_subprocess_exec(*_args, **_kwargs):
        raise AssertionError("Windows commands must not pass through argv quoting")

    monkeypatch.setattr(shell_core.platform, "system", lambda: "Windows")
    monkeypatch.setattr(
        shell_core.asyncio,
        "create_subprocess_shell",
        fake_create_subprocess_shell,
    )
    monkeypatch.setattr(
        shell_core.asyncio,
        "create_subprocess_exec",
        reject_create_subprocess_exec,
    )

    shell = BackgroundShell(
        shell_id="windows-quoted",
        command=command,
        cwd="C:\\work tree",
        env={"OPENAGENT_TEST": "1"},
    )
    process = await shell._spawn_process()

    assert process is sentinel
    assert captured["command"] == command
    assert "executable" not in captured
    assert captured["cwd"] == "C:\\work tree"
    assert captured["env"]["OPENAGENT_TEST"] == "1"
    assert "start_new_session" not in captured


@pytest.mark.asyncio
async def test_posix_shell_keeps_exec_argv_contract(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    command = "printf '%s\\n' 'quoted value'"
    sentinel = object()
    captured: dict[str, object] = {}

    async def fake_create_subprocess_exec(*argv, **kwargs):
        captured["argv"] = argv
        captured.update(kwargs)
        return sentinel

    async def reject_create_subprocess_shell(*_args, **_kwargs):
        raise AssertionError("POSIX keeps the explicit shell argv contract")

    monkeypatch.setattr(shell_core.platform, "system", lambda: "Linux")
    monkeypatch.setenv("SHELL", "/bin/test-shell")
    monkeypatch.setattr(
        shell_core.asyncio,
        "create_subprocess_exec",
        fake_create_subprocess_exec,
    )
    monkeypatch.setattr(
        shell_core.asyncio,
        "create_subprocess_shell",
        reject_create_subprocess_shell,
    )

    shell = BackgroundShell(
        shell_id="posix-quoted",
        command=command,
        cwd="/work tree",
        env=None,
    )
    process = await shell._spawn_process()

    assert process is sentinel
    assert captured["argv"] == ("/bin/test-shell", "-c", command)
    assert captured["cwd"] == "/work tree"
    assert captured["start_new_session"] is True


def _clear_login_cache() -> None:
    shell_core._login_path_cache.clear()


def test_user_environment_prefers_login_shell_path_on_macos(monkeypatch: pytest.MonkeyPatch) -> None:
    _clear_login_cache()
    monkeypatch.setattr(shell_core.platform, "system", lambda: "Darwin")
    calls: list[list[str]] = []

    def fake_run(argv, **kwargs):
        calls.append(argv)
        assert kwargs["stdin"] is subprocess.DEVNULL
        out = (
            "banner noise\n"
            + shell_core._LOGIN_PATH_START
            + "/opt/homebrew/bin:/usr/bin:/bin"
            + shell_core._LOGIN_PATH_END
        )
        return subprocess.CompletedProcess(argv, 0, stdout=out.encode())

    monkeypatch.setattr(shell_core.subprocess, "run", fake_run)
    env = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "SHELL": "/bin/zsh", "HOME": "/h", "KEEP": "1"}

    result = shell_core.user_environment(env)

    assert result["PATH"] == "/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin"
    assert result["KEEP"] == "1"
    assert env["PATH"] == "/usr/bin:/bin:/usr/sbin:/sbin"
    assert calls and calls[0][:2] == ["/bin/zsh", "-ilc"]
    shell_core.user_environment(env)
    assert len(calls) == 1, "the login shell is probed once per environment"


def test_user_environment_falls_back_to_well_known_dirs(monkeypatch: pytest.MonkeyPatch) -> None:
    _clear_login_cache()
    monkeypatch.setattr(shell_core.platform, "system", lambda: "Darwin")

    def failing_run(argv, **kwargs):
        raise subprocess.TimeoutExpired(argv, 5)

    monkeypatch.setattr(shell_core.subprocess, "run", failing_run)
    monkeypatch.setattr(shell_core.os.path, "isdir", lambda p: p == "/opt/homebrew/bin")

    result = shell_core.user_environment({"PATH": "/usr/bin:/bin", "SHELL": "/bin/zsh"})

    assert result["PATH"] == "/usr/bin:/bin:/opt/homebrew/bin"


def test_user_environment_unchanged_off_macos_or_when_disabled(monkeypatch: pytest.MonkeyPatch) -> None:
    _clear_login_cache()

    def unexpected_run(*_args, **_kwargs):
        raise AssertionError("must not probe")

    monkeypatch.setattr(shell_core.subprocess, "run", unexpected_run)
    env = {"PATH": "/usr/bin:/bin", "SHELL": "/bin/zsh"}
    monkeypatch.setattr(shell_core.platform, "system", lambda: "Linux")
    assert shell_core.user_environment(env) == env
    monkeypatch.setattr(shell_core.platform, "system", lambda: "Darwin")
    disabled = {**env, "OPENAGENT_SHELL_LOGIN_PATH": "0"}
    assert shell_core.user_environment(disabled) == disabled


def test_shell_server_keeps_explicit_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    from openagent_shell.server import ShellServer

    monkeypatch.setattr(
        shell_core.subprocess, "run",
        lambda *_a, **_k: (_ for _ in ()).throw(AssertionError("must not probe")),
    )
    server = ShellServer(environment={"PATH": "/x"})
    assert server.environment == {"PATH": "/x"}
