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




class ReceiptVersionNegotiation(unittest.IsolatedAsyncioTestCase):
    async def exchange(self, method, params, reply):
        process = _Process(reply)
        runner = ConnectorRunner("unused", identity_file="unused", product="fixture", name="receipt")
        try:
            with patch("openagent_connectors.runner.asyncio.create_subprocess_exec", new=AsyncMock(return_value=process)):
                result = await runner.call(method, params)
            return process.stdin.request, result
        finally:
            await runner.close()

    async def test_default_stays_v1_explicit_v2_preserves_cutoff_and_pair(self):
        request, _ = await self.exchange("events", None, {"result": []})
        self.assertEqual(request["params"], {})
        receipt = {"receipt_version": 2, "occurred_at": "2026-10-19T10:00:00Z",
                   "authorization_cutoff_at": "2026-10-17T10:00:00Z", "uninstall_event_id": "a" * 64}
        request, result = await self.exchange("events", {"receipt_version": 2}, {"result": [receipt]})
        self.assertEqual(request["params"], {"receipt_version": 2})
        self.assertEqual(result, [receipt])
        for params in ({"provider": "shopify"}, {"provider": "shopify", "receipt_version": 2}):
            request, _ = await self.exchange("auth.start", params, {"result": {}})
            self.assertEqual(request["params"], params)

    async def test_invalid_capability_rejected_before_subprocess(self):
        for method in ("events", "auth.start"):
            for value in (True, False, 2.0, "2", None, 0, 3):
                runner = ConnectorRunner("unused", identity_file="unused", product="fixture", name="receipt")
                params = {"receipt_version": value}
                if method == "auth.start":
                    params["provider"] = "shopify"
                try:
                    with patch("openagent_connectors.runner.asyncio.create_subprocess_exec", new=AsyncMock()) as spawn:
                        with self.assertRaises(ConnectorError) as error:
                            await runner.call(method, params)
                        self.assertEqual(error.exception.code, "unsupported_receipt_version")
                        spawn.assert_not_awaited()
                finally:
                    await runner.close()
        for params in ([2], {"receipt_version": 2, "other": True}):
            runner = ConnectorRunner("unused", identity_file="unused", product="fixture", name="receipt")
            try:
                with patch("openagent_connectors.runner.asyncio.create_subprocess_exec", new=AsyncMock()) as spawn:
                    with self.assertRaises(ConnectorError):
                        await runner.call("events", params)
                    spawn.assert_not_awaited()
            finally:
                await runner.close()

    async def test_version_error_is_safe_and_has_no_provider_status(self):
        runner = ConnectorRunner("unused", identity_file="unused", product="fixture", name="receipt")
        process = _Process({"error": "unsupported_receipt_version", "result": {"private": "discard"}})
        try:
            with patch("openagent_connectors.runner.asyncio.create_subprocess_exec", new=AsyncMock(return_value=process)):
                with self.assertRaises(ConnectorError) as error:
                    await runner.call("events")
            self.assertEqual(error.exception.code, "unsupported_receipt_version")
            self.assertIsNone(error.exception.provider_status)
            self.assertEqual(str(error.exception), "unsupported_receipt_version")
        finally:
            await runner.close()


if __name__ == "__main__":
    unittest.main()
