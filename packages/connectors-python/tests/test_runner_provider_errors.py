import json
import unittest
from unittest.mock import AsyncMock, patch

from openagent_connectors.runner import ConnectorError, ConnectorRunner


class _Input:
    def __init__(self):
        self.request = None
        self.writes = 0

    def write(self, value):
        self.request = json.loads(value)
        self.writes += 1

    async def drain(self):
        pass


class _Output:
    def __init__(self, stdin, reply):
        self.stdin, self.reply = stdin, reply

    async def readline(self):
        return (json.dumps({"id": self.stdin.request["id"], **self.reply}) + "\n").encode()


class _Process:
    def __init__(self, reply):
        self.stdin = _Input()
        self.stdout = _Output(self.stdin, reply)
        self.returncode = None

    def kill(self):
        self.returncode = -9

    async def wait(self):
        return self.returncode


class RunnerProviderErrors(unittest.IsolatedAsyncioTestCase):
    async def call_error(self, reply):
        process = _Process(reply)
        runner = ConnectorRunner("unused-runner", identity_file="unused-identity", product="openagent", name="fixture")
        try:
            with patch("openagent_connectors.runner.asyncio.create_subprocess_exec", new=AsyncMock(return_value=process)) as spawn:
                with self.assertRaises(ConnectorError) as caught:
                    await runner.call("invoke", {"fixture": True})
                self.assertEqual(spawn.await_count, 1)
                self.assertEqual(process.stdin.writes, 1)
            self.assertIsInstance(caught.exception, RuntimeError)
            return caught.exception
        finally:
            await runner.close()

    async def test_runtime_wire_signals_are_catchable_without_error_text_changes(self):
        for code, status in (("sync_reset_required", 410), ("resource_gone", 410),
                             ("version_conflict", 412), ("rate_limited", 429),
                             ("provider_permission", 401), ("provider_permission", 403),
                             ("invalid_response", 200), ("provider_error", 503)):
            with self.subTest(code=code, status=status):
                error = await self.call_error({"error": code, "provider_status": status})
                self.assertEqual(error.code, code)
                self.assertEqual(error.provider_status, status)
                self.assertEqual(str(error), code)
        network = await self.call_error({"error": "network_error"})
        self.assertEqual(network.code, "network_error")
        self.assertIsNone(network.provider_status)

    async def test_unknown_or_mismatched_status_is_generic_and_has_no_raw_payload(self):
        cases = [
            {"error": "PRIVATE token-secret", "provider_status": 410},
            {"error": {"PRIVATE": "token-secret"}}, {"error": ["token-secret"]},
            {"error": False}, {"error": 0}, {"error": ""},
            *({"error": "sync_reset_required", "provider_status": status}
              for status in (True, False, "410", 410.0, None, 99, 600, 412)),
            {"error": "network_error", "provider_status": 200},
            {"error": "provider_permission", "provider_status": 500},
            {"error": "authorization_expired", "provider_status": 401},
        ]
        for reply in cases:
            with self.subTest(reply=reply):
                error = await self.call_error({**reply, "result": {"PRIVATE": "token-secret"}})
                self.assertEqual(error.code, "connector_request_failed")
                self.assertIsNone(error.provider_status)
                self.assertEqual(str(error), "connector_request_failed")
                self.assertNotIn("token-secret", repr(error))

    async def test_legacy_authentication_codes_and_success_contract_stay_compatible(self):
        for code in ("authorization_expired", "credential_recovery_required", "rate_limited"):
            error = await self.call_error({"error": code})
            self.assertEqual(str(error), code)
            self.assertEqual(error.code, code)
            self.assertIsNone(error.provider_status)
        runner = ConnectorRunner("unused-runner", identity_file="unused-identity", product="openagent", name="fixture")
        process = _Process({"result": {"ok": True}})
        try:
            with patch("openagent_connectors.runner.asyncio.create_subprocess_exec", new=AsyncMock(return_value=process)):
                self.assertEqual(await runner.call("catalog"), {"ok": True})
        finally:
            await runner.close()

    def test_direct_connector_error_keeps_runtime_error_string_and_validates_status(self):
        error = ConnectorError("runner_unavailable")
        self.assertEqual(str(error), "runner_unavailable")
        self.assertEqual(error.code, "runner_unavailable")
        self.assertIsNone(error.provider_status)
        invalid = ConnectorError("sync_reset_required", provider_status=True)
        self.assertEqual(invalid.code, "connector_request_failed")
        self.assertIsNone(invalid.provider_status)


if __name__ == "__main__":
    unittest.main()
