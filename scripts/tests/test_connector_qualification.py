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


class ReleaseCohortTests(unittest.TestCase):
    """Pure catalog/source fixtures; no build, provider or package installation."""

    def catalog(self, version="0.1.6"):
        rows = [{"id": name, "available": True} for name in sorted(REMOTE.SDK15_OFFICIAL_IDS)]
        rows.append({"id": "custom-mcp", "available": True, "nativeKind": "custom_mcp"})
        if version == "0.1.6":
            for identifier, (provider, tools) in REMOTE.SDK16_KEYLESS.items():
                rows.append({"id": identifier, "provider": provider, "auth": "none", "capability": "files",
                             "available": True, "agentTools": [], "readTools": sorted(tools)})
        return rows

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
