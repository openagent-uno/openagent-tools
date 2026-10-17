"""Receipt-binding regressions, not real artifact or native qualification.

Source, payload and log verification are mocked ONLY to isolate receipt binding.
The synthetic archive has no executable; no provider or subprocess is invoked.
"""
import importlib.util
import io
import json
import copy
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch


SPEC = importlib.util.spec_from_file_location(
    "connector_qualification", Path(__file__).resolve().parents[1] / "qualify_connectors.py"
)
QUALIFIER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(QUALIFIER)
REMOTE_SPEC = importlib.util.spec_from_file_location(
    "connector_remote_qualification", Path(__file__).resolve().parents[1] / "qualify_connectors_remote.py"
)
REMOTE = importlib.util.module_from_spec(REMOTE_SPEC)
REMOTE_SPEC.loader.exec_module(REMOTE)


class ReceiptBindingTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="connector-receipt-fixture-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        catalog = [
            {"id": "synthetic", "available": True},
            {"id": "custom-mcp", "available": True, "nativeKind": "custom_mcp"},
        ]
        catalog_bytes = self.write("catalog.json", catalog)
        manifest = {
            "format": 1, "version": "0.1.4", "source_commit": "1" * 40,
            "source_sha256": "2" * 64, "go_toolchain": "go1.26.9",
            "dirty_snapshot": False, "release_status": "development-unqualified",
            "files": {"catalog.json": {"bytes": len(catalog_bytes), "sha256": QUALIFIER.digest(catalog_bytes)}},
        }
        self.original_manifest = self.write("manifest.json", manifest)
        # This fake archive exercises only the exact manifest receipt binding.
        bundle_manifest = b'{"fixture":"not an executable bundle"}\n'
        with tarfile.open(self.root / "openagent-connectors-0.1.4-linux-x64.tar.gz", "w:gz") as archive:
            entry = tarfile.TarInfo("manifest.json")
            entry.size = len(bundle_manifest)
            archive.addfile(entry, io.BytesIO(bundle_manifest))
        self.write("artifacts.json", {
            "source_commit": manifest["source_commit"], "source_sha256": manifest["source_sha256"],
            "go_toolchain": manifest["go_toolchain"], "dirty_snapshot": False,
            "archives": sorted(QUALIFIER.PLATFORMS), "verified_binaries": 12,
        })
        self.consumer = {
            "source_commit": manifest["source_commit"], "adapter": manifest["version"],
            "native_runner_toolchain": manifest["go_toolchain"], "native": "linux-x64",
            "native_catalog": 2, "python_catalog": 1, "available_connectors": 1,
            "mcp_surface_import": True, "broker_network_calls": 0,
            "catalog_sha256": QUALIFIER.digest(catalog_bytes),
            "bundle_manifest_sha256": QUALIFIER.digest(bundle_manifest),
        }
        self.write("consumer.json", self.consumer)
        self.broker = {
            "source_commit": manifest["source_commit"], "native": "linux-x64",
            "health": 200, "readiness": 503, "enrollment": "qa", "unsigned_start": 401,
            "real_provider_grants": 0, "production_secret_reads": 0,
        }
        self.write("broker.json", self.broker)

    def write(self, name, value):
        data = (json.dumps(value) + "\n").encode()
        (self.root / name).write_bytes(data)
        return data

    def assert_rejected(self, reason):
        with patch.object(QUALIFIER, "verify_source"), \
             patch.object(QUALIFIER, "verify_payloads"), \
             patch.object(QUALIFIER, "verify_logs", return_value={}):
            with self.assertRaisesRegex(ValueError, reason):
                QUALIFIER.qualify(
                    self.root, self.root / "race.log", self.root / "vet.log", self.root / "vulnerability.log",
                    self.root / "artifacts.json", self.root / "consumer.json", self.root / "broker.json",
                )
        self.assertFalse((self.root / "qualification.json").exists())
        self.assertFalse((self.root / "SHA256SUMS").exists())
        self.assertEqual((self.root / "manifest.json").read_bytes(), self.original_manifest)

    def test_rejects_broker_receipt_for_another_native_target(self):
        self.broker["native"] = "darwin-arm64"
        self.write("broker.json", self.broker)
        self.assert_rejected("native broker receipt incomplete")

    def test_rejects_substituted_catalog_digest_even_when_counts_match(self):
        self.consumer["catalog_sha256"] = "3" * 64
        self.write("consumer.json", self.consumer)
        self.assert_rejected("consumer catalog identity mismatch")

    def test_rejects_substituted_native_bundle_manifest(self):
        self.consumer["bundle_manifest_sha256"] = "4" * 64
        self.write("consumer.json", self.consumer)
        self.assert_rejected("native consumer bundle identity mismatch")


class CalendarMailMetadataTests(unittest.TestCase):
    def google_tools(self):
        rows = []
        for operation, scope, risk in (
                ("calendars.list", "calendar.calendarlist.readonly", "read"),
                ("calendars.get", "calendar.calendarlist.readonly", "read"),
                ("events.list", "calendar.events", "read"),
                ("events.get", "calendar.events", "read"),
                ("events.create", "calendar.events", "write"),
                ("events.update", "calendar.events", "write"),
                ("events.delete", "calendar.events", "destructive")):
            properties = {"connection_id": {"type": "string"}, "provider": {"enum": ["google_calendar"]}}
            required = []
            if operation.endswith((".update", ".delete")):
                properties["etag"] = {"type": "string"}
                required.append("etag")
            if operation.endswith((".create", ".update")):
                properties["body"] = {"type": "object", "additionalProperties": False}
                required.append("body")
            rows.append({"name": "files.google_calendar." + operation, "provider": "google_calendar",
                "capability": "files", "mode": "typed", "risk": risk,
                "required_scopes": ["https://www.googleapis.com/auth/" + scope], "retry": {"max_attempts": 1},
                "inputSchema": {"type": "object", "additionalProperties": False,
                                "properties": properties, "required": required}})
        return rows

    def mail_tools(self):
        rows = []
        for operation, scope, risk in (
                ("folders.list", "Mail.ReadBasic", "read"), ("folders.get", "Mail.ReadBasic", "read"),
                ("messages.list", "Mail.Read", "read"), ("messages.get", "Mail.Read", "read"),
                ("attachments.list", "Mail.Read", "read"), ("attachments.get", "Mail.Read", "read"),
                ("drafts.create", "Mail.ReadWrite", "draft"), ("drafts.update", "Mail.ReadWrite", "draft"),
                ("messages.send", "Mail.Send", "publish")):
            properties = {"connection_id": {"type": "string"}, "provider": {"const": "outlook_mail"}}
            required = []
            if operation == "drafts.update":
                properties["etag"] = {"type": "string"}
                required.append("etag")
            if operation.startswith("drafts."):
                properties["body"] = {"type": "object", "additionalProperties": False}
                required.append("body")
            rows.append({"name": "outreach.outlook_mail." + operation, "provider": "outlook_mail",
                "capability": "outreach", "mode": "typed", "risk": risk,
                "required_scopes": [scope], "retry": {"max_attempts": 1},
                "inputSchema": {"type": "object", "additionalProperties": False,
                                "properties": properties, "required": required}})
        return rows

    def test_closed_calendar_schema_scope_and_conflict_guards_are_required(self):
        self.assertEqual(REMOTE.verify_calendar_mail_tools("google-calendar", self.google_tools())["operations"], 7)
        for mutation in ("scope", "raw", "retry", "open", "etag", "body"):
            with self.subTest(mutation=mutation):
                rows = self.google_tools()
                update = next(row for row in rows if row["name"].endswith("events.update"))
                if mutation == "scope":
                    update["required_scopes"] = ["https://www.googleapis.com/auth/calendar"]
                elif mutation == "raw":
                    update["mode"] = "raw"
                elif mutation == "retry":
                    update["retry"]["max_attempts"] = 2
                elif mutation == "open":
                    update["inputSchema"]["additionalProperties"] = True
                elif mutation == "etag":
                    update["inputSchema"]["required"].remove("etag")
                elif mutation == "body":
                    update["inputSchema"]["properties"]["body"]["additionalProperties"] = True
                with self.assertRaises(ValueError):
                    REMOTE.verify_calendar_mail_tools("google-calendar", rows)

    def test_default_mail_scope_does_not_authorize_send_or_allow_scope_substitution(self):
        rows = self.mail_tools()
        default = [row for row in rows if not row["name"].endswith("messages.send")]
        self.assertEqual(REMOTE.verify_calendar_mail_tools("outlook-mail", default)["operations"], 8)
        self.assertEqual(REMOTE.verify_calendar_mail_tools("outlook-mail", rows, send_authorized=True)["operations"], 9)
        with self.assertRaises(ValueError):
            REMOTE.verify_calendar_mail_tools("outlook-mail", rows)
        with self.assertRaises(ValueError):
            REMOTE.verify_calendar_mail_tools("outlook-mail", default, send_authorized=True)
        rows[-1]["required_scopes"] = ["Mail.ReadWrite"]
        with self.assertRaises(ValueError):
            REMOTE.verify_calendar_mail_tools("outlook-mail", rows, send_authorized=True)


class ReleaseCohortTests(unittest.TestCase):
    """Pure catalog/source fixtures; no build, provider or package installation."""

    def catalog(self, version="0.1.6"):
        rows = [{"id": name, "available": True} for name in sorted(REMOTE.SDK15_OFFICIAL_IDS)]
        rows.append({"id": "custom-mcp", "available": True, "nativeKind": "custom_mcp"})
        if version in {"0.1.6", "0.1.7"}:
            for identifier, (provider, tools) in REMOTE.SDK16_KEYLESS.items():
                rows.append({"id": identifier, "provider": provider, "auth": "none", "capability": "files",
                             "available": True, "agentTools": [], "readTools": sorted(tools)})
        if version == "0.1.7":
            for identifier, (provider, capability, prefix, reads, writes, _) in REMOTE.SDK17_OAUTH.items():
                rows.append({"id": identifier, "provider": provider, "auth": "oauth", "capability": capability,
                             "available": True, "readTools": sorted(prefix + op for op in reads),
                             "agentTools": sorted(prefix + op for op in writes)})
        return rows

    def test_sdk17_binds_twenty_two_identities_and_exact_seven_nine_seven_operations(self):
        cohort = REMOTE.verify_catalog_cohort("0.1.7", self.catalog("0.1.7"))
        self.assertEqual(cohort["official_count"], 22)
        self.assertTrue(cohort["exact_version_cohort"])
        for identifier, count in (("google-calendar", 7), ("outlook-mail", 9), ("outlook-calendar", 7)):
            row = next(row for row in self.catalog("0.1.7") if row["id"] == identifier)
            self.assertEqual(len(row["readTools"]) + len(row["agentTools"]), count)

    def test_sdk17_rejects_substitution_auth_tool_duplicates_and_retains_keyless_guards(self):
        for identifier, field, value in (
                ("google-calendar", "id", "unreviewed-calendar"),
                ("google-calendar", "provider", "another-account-provider"),
                ("outlook-mail", "auth", "none"),
                ("outlook-mail", "capability", "files"),
                ("outlook-calendar", "available", False),
                ("outlook-calendar", "agentTools", ["files.outlook_calendar.raw"]),
                ("google-calendar", "readTools", ["files.google_calendar.events.get"] * 4),
                ("coingecko", "auth", "oauth")):
            with self.subTest(identifier=identifier, field=field):
                rows = self.catalog("0.1.7")
                next(row for row in rows if row["id"] == identifier)[field] = value
                with self.assertRaises(ValueError):
                    REMOTE.verify_catalog_cohort("0.1.7", rows)

    def test_sdk17_source_fallback_must_match_all_new_entries(self):
        with tempfile.TemporaryDirectory(prefix="connector-source17-fixture-") as temporary:
            root = Path(temporary)
            path = root / "packages/connectors-python/src/openagent_connectors/catalog.json"
            path.parent.mkdir(parents=True)
            catalog = self.catalog("0.1.7")
            path.write_text(json.dumps({"version": "0.1.7", "connectors": catalog}))
            REMOTE.verify_source_python_catalog(root, "0.1.7", catalog)
            path.write_text(json.dumps({"version": "0.1.7", "connectors": self.catalog("0.1.6")}))
            with self.assertRaisesRegex(ValueError, "Source Python fallback"):
                REMOTE.verify_source_python_catalog(root, "0.1.7", catalog)

    def test_sdk16_binds_nineteen_identities_and_one_custom_entry(self):
        cohort = REMOTE.verify_catalog_cohort("0.1.6", self.catalog())
        self.assertEqual(cohort["official_count"], 19)
        self.assertEqual(set(cohort["official_ids"]), REMOTE.SDK15_OFFICIAL_IDS | set(REMOTE.SDK16_KEYLESS))
        self.assertEqual(cohort["custom_ids"], ["custom-mcp"])
        self.assertTrue(cohort["exact_version_cohort"])

    def test_same_count_cannot_substitute_an_unreviewed_provider(self):
        rows = self.catalog()
        next(row for row in rows if row["id"] == "context7")["id"] = "context7-other"
        with self.assertRaisesRegex(ValueError, "identities differ"):
            REMOTE.verify_catalog_cohort("0.1.6", rows)

    def test_duplicate_or_misclassified_custom_identity_is_rejected(self):
        rows = self.catalog()
        rows.append(copy.deepcopy(rows[0]))
        with self.assertRaisesRegex(ValueError, "duplicate"):
            REMOTE.verify_catalog_cohort("0.1.6", rows)
        rows = self.catalog()
        next(row for row in rows if row["id"] == "custom-mcp")["nativeKind"] = "other"
        with self.assertRaisesRegex(ValueError, "custom MCP"):
            REMOTE.verify_catalog_cohort("0.1.6", rows)

    def test_new_keyless_contract_cannot_change_auth_scope_or_tools(self):
        for field, value in (("provider", "another-source"), ("auth", "oauth"),
                             ("capability", "ads"), ("available", False),
                             ("agentTools", ["files.coingecko.write"]),
                             ("readTools", ["files.coingecko.price", "files.coingecko.raw"]),
                             ("readTools", ["files.coingecko.price", "files.coingecko.price"])):
            with self.subTest(field=field, value=value):
                rows = self.catalog()
                next(row for row in rows if row["id"] == "coingecko")[field] = value
                with self.assertRaisesRegex(ValueError, "keyless connector contract"):
                    REMOTE.verify_catalog_cohort("0.1.6", rows)

    def test_historical_sdk15_keeps_its_exact_sixteen_identity_cohort(self):
        cohort = REMOTE.verify_catalog_cohort("0.1.5", self.catalog("0.1.5"))
        self.assertEqual(cohort["official_count"], 16)
        with self.assertRaisesRegex(ValueError, "identities differ"):
            REMOTE.verify_catalog_cohort("0.1.5", self.catalog())

    def test_older_content_bound_catalog_fixtures_remain_supported(self):
        cohort = REMOTE.verify_catalog_cohort("0.1.4", [
            {"id": "synthetic", "available": True},
            {"id": "custom-mcp", "nativeKind": "custom_mcp", "available": True}])
        self.assertFalse(cohort["exact_version_cohort"])
        self.assertEqual(cohort["official_count"], 1)

    def test_source_version_mismatch_is_rejected_before_any_build(self):
        with tempfile.TemporaryDirectory(prefix="connector-version-fixture-") as temporary:
            root = Path(temporary)
            go = root / "packages/connectors/catalog.go"
            python = root / "packages/connectors-python/pyproject.toml"
            go.parent.mkdir(parents=True)
            python.parent.mkdir(parents=True)
            go.write_text('const Version = "0.1.6"\n')
            python.write_text('version = "0.1.6"\n')
            self.assertEqual(REMOTE.source_sdk_version(root, "0.1.6"), "0.1.6")
            with self.assertRaisesRegex(ValueError, "source version differs"):
                REMOTE.source_sdk_version(root, "0.1.5")
            python.write_text('version = "0.1.5"\n')
            with self.assertRaisesRegex(ValueError, "source version differs"):
                REMOTE.source_sdk_version(root, "0.1.6")

    def test_sdk16_source_fallback_cannot_be_silently_repaired_by_build_snapshot(self):
        with tempfile.TemporaryDirectory(prefix="connector-source-catalog-fixture-") as temporary:
            root = Path(temporary)
            path = root / "packages/connectors-python/src/openagent_connectors/catalog.json"
            path.parent.mkdir(parents=True)
            catalog = self.catalog()
            path.write_text(json.dumps({"version": "0.1.6", "connectors": catalog}))
            REMOTE.verify_source_python_catalog(root, "0.1.6", catalog)
            stale = [row for row in catalog if row["id"] != "coingecko"]
            path.write_text(json.dumps({"version": "0.1.6", "connectors": stale}))
            with self.assertRaisesRegex(ValueError, "Source Python fallback catalog differs"):
                REMOTE.verify_source_python_catalog(root, "0.1.6", catalog)
            path.unlink()
            # Historical SDK15 does not acquire this new source requirement.
            REMOTE.verify_source_python_catalog(root, "0.1.5", self.catalog("0.1.5"))


if __name__ == "__main__":
    unittest.main()
