import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

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

    def test_github_and_notion_select_only_registered_app_and_exact_callback(self):
        expected = {
            "github": ("Iv23lis9sNxlYnR2B6lZ", True, "https://github.com/login/oauth/access_token"),
            "notion": ("3fbd872b-594c-8157-8fb9-0037e6a6efb2", False, "https://api.notion.com/v1/oauth/token"),
        }
        for provider, (client_id, pkce, token_url) in expected.items():
            with self.subTest(provider=provider):
                output = Path(self.temp.name) / provider
                module.prepare(provider, ["b" * 64], [], self.image, output)
                rows = json.loads((output / "providers.json").read_text())
                self.assertEqual(len(rows), 1)
                self.assertEqual(rows[0]["id"], provider)
                self.assertEqual(rows[0]["client_id"], client_id)
                self.assertEqual(rows[0]["app_id"], provider + ":" + client_id)
                self.assertEqual(rows[0]["pkce"], pkce)
                self.assertEqual(rows[0]["scopes"], [])
                self.assertEqual(rows[0]["token_url"], token_url)
                self.assertEqual(rows[0]["secret_file"], "/secrets/" + provider + "-client-secret")
                self.assertEqual(rows[0]["redirect_uri"], "https://auth.openagent.uno/v1/oauth/" + provider + "/callback")
                self.assertEqual(json.loads((output / "qa-enrollment.json").read_text()), {"installations": ["b" * 64]})
                self.assertNotIn("--legacy-shopify-webhooks", (output / "resources.yaml").read_text())

    def test_pending_atlassian_and_unknown_cannot_be_selected_even_programmatically(self):
        for provider in ("atlassian", "arbitrary"):
            with self.subTest(provider=provider):
                with self.assertRaises(ValueError):
                    module.prepare(provider, ["b" * 64], [], self.image, self.output)
                self.assertFalse(self.output.exists())

    def test_slack_uses_only_existing_registration_and_single_reviewed_recipient(self):
        module.prepare("slack_import", [module.SLACK_QA_INSTALLATION], [], self.image, self.output)
        rows = json.loads((self.output / "providers.json").read_text())
        registration = json.loads((module.BASE / "registrations/slack.json").read_text())
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["id"], "slack_import")
        self.assertEqual(rows[0]["client_id"], "12333069497846.12337417629937")
        self.assertEqual(rows[0]["app_id"], "slack_import:" + registration["client_id"])
        self.assertEqual(rows[0]["authorization_url"], "https://slack.com/oauth/v2/authorize")
        self.assertEqual(rows[0]["token_url"], "https://slack.com/api/oauth.v2.access")
        self.assertEqual(rows[0]["secret_file"], "/secrets/slack-client-secret")
        self.assertEqual(rows[0]["scopes"], registration["configured_user_scopes"])
        self.assertEqual(json.loads((self.output / "qa-enrollment.json").read_text()),
                         {"installations": [module.SLACK_QA_INSTALLATION]})
        resources = (self.output / "resources.yaml").read_text()
        self.assertIn("type: Recreate", resources)
        self.assertNotIn("--legacy-shopify-webhooks", resources)

    def test_slack_other_or_additional_recipients_never_write_output(self):
        for identities in (["b" * 64], [module.SLACK_QA_INSTALLATION, "b" * 64], []):
            with self.subTest(identities=identities):
                with self.assertRaises(ValueError):
                    module.prepare("slack_import", identities, [], self.image, self.output)
                self.assertFalse(self.output.exists())

    def test_slack_registration_or_user_token_contract_drift_never_writes_output(self):
        for change in ("client", "callback", "scope", "bot", "rotation", "custody"):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as directory:
                base = Path(directory)
                (base / "registrations").mkdir()
                rows = json.loads((module.BASE / "providers-reviewed.json").read_text())
                registration = json.loads((module.BASE / "registrations/slack.json").read_text())
                slack = next(row for row in rows if row["id"] == "slack_import")
                if change == "client":
                    slack["client_id"] = "different-client"
                elif change == "callback":
                    registration["callback_url"] = "https://example.invalid/callback"
                elif change == "scope":
                    slack["scopes"] = slack["scopes"] + ["admin"]
                elif change == "bot":
                    registration["configured_bot_scopes"] = ["chat:write"]
                elif change == "rotation":
                    registration["token_rotation_enabled"] = False
                else:
                    registration["production_secret_configured"] = False
                (base / "providers-reviewed.json").write_text(json.dumps(rows))
                (base / "registrations/slack.json").write_text(json.dumps(registration))
                with patch.object(module, "BASE", base):
                    with self.assertRaises(ValueError):
                        module.prepare("slack_import", [module.SLACK_QA_INSTALLATION], [], self.image, self.output)
                self.assertFalse(self.output.exists())

    def test_candidate_metadata_does_not_activate_bootstrap_or_jira(self):
        self.assertIn("'providers.json=[]'", (module.BASE / "kustomization.yaml").read_text())
        rows = json.loads((module.BASE / "providers-reviewed.json").read_text())
        for provider in ("atlassian",):
            row = next(item for item in rows if item["id"] == provider)
            self.assertEqual(row["client_id"], "")
            self.assertEqual(row["app_id"], provider + ":registration-pending")
            self.assertFalse(row["pkce"])
            self.assertNotIn("revocation_url", row)
        slack = json.loads((module.BASE / "registrations/slack.json").read_text())
        self.assertFalse(slack["broker_enabled"])
        self.assertFalse(slack["common_enrollment_enabled"])


if __name__ == "__main__":
    unittest.main()
