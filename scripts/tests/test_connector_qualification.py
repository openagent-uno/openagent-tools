"""Receipt-binding regressions, not real artifact or native qualification.

Source, payload and log verification are mocked ONLY to isolate receipt binding.
The synthetic archive has no executable; no provider or subprocess is invoked.
"""
import importlib.util
import io
import json
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


if __name__ == "__main__":
    unittest.main()
