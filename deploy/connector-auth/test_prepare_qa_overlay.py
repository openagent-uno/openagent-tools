import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("qa_overlay", Path(__file__).with_name("prepare-qa-overlay.py"))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class PrepareQAOverlayTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.output = Path(self.temp.name) / "overlay"
        self.image = "localhost:5000/openagent-connector-auth@sha256:" + "a" * 64

    def test_clickup_only_pins_original_registration_and_recipient(self):
        module.prepare("clickup", ["b" * 64], [], self.image, self.output)
        provider = json.loads((self.output / "providers.json").read_text())
        self.assertEqual(len(provider), 1)
        self.assertEqual(provider[0]["client_id"], "UD5K7XJRRR6Z8BV2SIXSDUPI19P4G9HM")
        self.assertEqual(json.loads((self.output / "qa-enrollment.json").read_text()), {"installations": ["b" * 64]})
        resources = (self.output / "resources.yaml").read_text()
        self.assertIn("--qa-enrollment=/config/qa-enrollment.json", resources)
        self.assertIn("type: Recreate", resources)
        self.assertNotIn("--legacy-shopify-webhooks", resources)

    def test_missing_or_unreviewed_shop_never_writes_output(self):
        for shops in [[], ["example.myshopify.com/redirect"], ["-bad.myshopify.com"]]:
            with self.assertRaises(ValueError):
                module.prepare("shopify", ["b" * 64], shops, self.image, self.output)
            self.assertFalse(self.output.exists())

    def test_non_immutable_image_and_untrusted_identity_rejected(self):
        for image, identities in [("broker:latest", ["b" * 64]), (self.image, ["z" * 64]), (self.image, ["b" * 64] * 2)]:
            with self.assertRaises(ValueError):
                module.prepare("clickup", identities, [], image, self.output)
            self.assertFalse(self.output.exists())

    def test_existing_output_is_preserved(self):
        self.output.mkdir()
        marker = self.output / "existing"
        marker.write_text("keep")
        with self.assertRaises(FileExistsError):
            module.prepare("clickup", ["b" * 64], [], self.image, self.output)
        self.assertEqual(marker.read_text(), "keep")


if __name__ == "__main__":
    unittest.main()
