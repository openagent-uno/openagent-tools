from __future__ import annotations

import asyncio
import json
from pathlib import Path
import uuid


class ConnectorError(RuntimeError):
    """A bounded, credential-free runner error."""


class ConnectorRunner:
    def __init__(self, executable: str | Path, *, identity_file: str | Path,
                 product: str, name: str, broker: str = "https://auth.openagent.uno", oauth_providers: str | Path | None = None):
        self.command = (str(executable), "--identity-file", str(identity_file),
                        "--product", product, "--name", name, "--broker", broker)
        if oauth_providers:
            self.command += ("--oauth-providers", str(oauth_providers))
        self.process = None
        self.lock = asyncio.Lock()

    async def _close(self):
        process, self.process = self.process, None
        if process is not None and process.returncode is None:
            process.kill()
            await process.wait()

    async def close(self):
        async with self.lock:
            await self._close()

    async def call(self, method: str, params=None, *, timeout=100):
        # Only the trusted host can populate binding/credential fields. Tool
        # arguments are always nested and cannot become runner configuration.
        request_id = uuid.uuid4().hex
        data = (json.dumps({"id": request_id, "method": method, "params": params or {}},
                           separators=(",", ":")) + "\n").encode()
        if len(data) > 32 << 20:
            raise ConnectorError("request_too_large")
        async with self.lock:
            try:
                async with asyncio.timeout(timeout):
                    if self.process is None or self.process.returncode is not None:
                        self.process = await asyncio.create_subprocess_exec(
                            *self.command, stdin=asyncio.subprocess.PIPE,
                            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL,
                            limit=40 << 20)
                    self.process.stdin.write(data)
                    await self.process.stdin.drain()
                    line = await self.process.stdout.readline()
                    reply = json.loads(line)
                    if reply.get("id") != request_id:
                        await self._close()
                        raise ConnectorError("runner_response_mismatch")
                    if reply.get("error"):
                        allowed = {"provider_not_configured", "authorization_not_ready",
                                   "credential_recovery_required", "rotation_in_progress",
                                   "oauth_app_mismatch", "rate_limited", "provider_exchange_failed",
                                   "provider_refresh_failed", "authorization_expired"}
                        code = reply["error"]
                        raise ConnectorError(code if code in allowed else "connector_request_failed")
                    return reply.get("result")
            except ConnectorError:
                raise
            except BaseException as exc:
                await self._close()
                if isinstance(exc, asyncio.CancelledError):
                    raise
                raise ConnectorError("runner_unavailable") from None
