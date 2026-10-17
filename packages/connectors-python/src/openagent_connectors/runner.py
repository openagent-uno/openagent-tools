from __future__ import annotations

import asyncio
import json
from pathlib import Path
import uuid


class ConnectorError(RuntimeError):
    """A bounded, credential-free runner error."""

    def __init__(self, code: str, *, provider_status: int | None = None):
        if provider_status is not None and not _provider_status_allowed(code, provider_status):
            code, provider_status = "connector_request_failed", None
        self.code = code
        self.provider_status = provider_status
        super().__init__(code)


def _provider_status_allowed(code, status):
    # bool is an int subclass, but is never an HTTP status on the wire.
    if type(status) is not int or not 100 <= status <= 599:
        return False
    if code in {"sync_reset_required", "resource_gone"}:
        return status == 410
    if code == "version_conflict":
        return status == 412
    if code == "rate_limited":
        return status == 429
    if code == "provider_permission":
        return status in {401, 403}
    return code in {"invalid_response", "provider_error"}


def _reply_error(reply):
    allowed = {"provider_not_configured", "authorization_not_ready",
               "credential_recovery_required", "rotation_in_progress",
               "oauth_app_mismatch", "rate_limited", "provider_exchange_failed",
               "provider_refresh_failed", "authorization_expired",
               "token_grant_revoked", "qa_installation_not_admitted",
               "qa_shop_not_admitted", "sync_reset_required", "resource_gone",
               "version_conflict", "provider_permission", "network_error",
               "invalid_response", "provider_error"}
    code = reply["error"]
    if not isinstance(code, str) or code not in allowed:
        return ConnectorError("connector_request_failed")
    if "provider_status" in reply:
        status = reply["provider_status"]
        if not _provider_status_allowed(code, status):
            return ConnectorError("connector_request_failed")
        return ConnectorError(code, provider_status=status)
    return ConnectorError(code)


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
                    if "error" in reply:
                        raise _reply_error(reply)
                    return reply.get("result")
            except ConnectorError:
                raise
            except BaseException as exc:
                await self._close()
                if isinstance(exc, asyncio.CancelledError):
                    raise
                raise ConnectorError("runner_unavailable") from None
