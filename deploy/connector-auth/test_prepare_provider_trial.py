"""File-only trial preparation; fixture metadata never attests a real app."""
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("provider_trial", Path(__file__).with_name("prepare-provider-trial.py"))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class PrepareProviderTrialTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.base = self.root / "reviewed"
        (self.base / "registrations").mkdir(parents=True)
        self.rows = json.loads((module.BASE / "providers-reviewed.json").read_text())
        self.registration = json.loads((module.BASE / "registrations/google.json").read_text())
        self.current = [copy.deepcopy(row) for row in self.rows if row["id"] in module.PUBLIC]
        self.baseline = self.root / "current-providers.json"
        self.baseline.write_text(json.dumps(self.current))
        self.output = self.root / "output"

    def write_metadata(self, ready=False):
        registration = copy.deepcopy(self.registration)
        if ready:
            calendar = next(row for row in self.rows if row["id"] == "google_calendar")
            registration["enabled_apis"].append("calendar-json.googleapis.com")
            registration["declared_scopes"].extend(calendar["scopes"])
            registration["calendar_preparation"].update(api_enabled=True, calendar_scopes_declared=True)
        (self.base / "providers-reviewed.json").write_text(json.dumps(self.rows))
        (self.base / "registrations/google.json").write_text(json.dumps(registration))

    def prepare(self, provider="google_calendar"):
        with patch.object(module, "BASE", self.base):
            module.prepare(provider, self.baseline, self.output)

    def test_calendar_trial_appends_without_global_qa_or_public_row_changes(self):
        self.write_metadata(ready=True)
        before = self.baseline.read_bytes()
        self.prepare()
        result = json.loads((self.output / "providers.json").read_text())
        self.assertEqual(self.current, result[:-1])
        self.assertEqual("google_calendar", result[-1]["id"])
        self.assertEqual(before, self.baseline.read_bytes())
        self.assertEqual({"providers.json", "trial-metadata.json"}, {p.name for p in self.output.iterdir()})
        metadata = json.loads((self.output / "trial-metadata.json").read_text())
        self.assertFalse(metadata["global_qa_enrollment_added"])
        self.assertFalse(metadata["provider_review_attested"])
        self.assertEqual(0, metadata["new_grants"])

    def test_pending_calendar_metadata_cannot_prepare_output(self):
        self.write_metadata()
        with self.assertRaises(ValueError):
            self.prepare()
        self.assertFalse(self.output.exists())

    def test_missing_or_changed_public_provider_cannot_prepare_output(self):
        self.write_metadata(ready=True)
        for changed in (self.current[:-1], [{**row, "client_id": "different"} for row in self.current], self.current + [self.current[0]]):
            self.baseline.write_text(json.dumps(changed))
            with self.assertRaises(ValueError):
                self.prepare()
            self.assertFalse(self.output.exists())

    def test_registration_callback_or_secret_reference_drift_is_rejected(self):
        for field in ("redirect_uris", "secret_reference"):
            self.write_metadata(ready=True)
            p = self.base / "registrations/google.json"
            registration = json.loads(p.read_text())
            registration[field] = [] if field == "redirect_uris" else {"mount_path": "/secrets/different"}
            p.write_text(json.dumps(registration))
            with self.assertRaises(ValueError):
                self.prepare()
            self.assertFalse(self.output.exists())

    def test_microsoft_cannot_be_invented_from_absent_registration_or_row(self):
        self.write_metadata()
        for provider in ("outlook_mail", "outlook_calendar"):
            with self.assertRaises(ValueError):
                self.prepare(provider)
            self.assertFalse(self.output.exists())

    def test_microsoft_fixture_preserves_audience_and_requires_explicit_send_scope(self):
        client = "00000000-0000-4000-8000-000000000001"
        scopes = ["offline_access", module.GRAPH + "User.Read", module.GRAPH + "Mail.ReadWrite"]
        row = {"id": "outlook_mail", "app_id": "microsoft:" + client, "client_id": client,
               "secret_file": "/secrets/microsoft-client-secret",
               "authorization_url": "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
               "token_url": "https://login.microsoftonline.com/common/oauth2/v2.0/token",
               "redirect_uri": "https://auth.openagent.uno/v1/oauth/outlook_mail/callback",
               "scopes": scopes, "pkce": True}
        self.rows.append(row)
        self.write_metadata()
        registration = {"client_id": client, "cloud": "global", "account_audience": "fixture-existing-audience",
                        "oauth_settings_verified": True, "production_secret_configured": True,
                        "redirect_uris": [row["redirect_uri"]], "declared_scopes": scopes,
                        "secret_reference": {"namespace": "openagent-connectors", "name": "connector-auth-secrets",
                                             "key": "microsoft-client-secret", "mount_path": row["secret_file"]}}
        p = self.base / "registrations/microsoft.json"
        p.write_text(json.dumps(registration))
        original = p.read_bytes()
        self.prepare("outlook_mail")
        self.assertEqual(original, p.read_bytes(), "audience is never rewritten")
        selected = json.loads((self.output / "providers.json").read_text())[-1]
        self.assertEqual(scopes, selected["scopes"])
        self.assertNotIn(module.GRAPH + "Mail.Send", selected["scopes"])
        for field, changed in (("cloud", "other-cloud"), ("oauth_settings_verified", False),
                               ("production_secret_configured", False), ("account_audience", "")):
            registration[field] = changed
            p.write_text(json.dumps(registration))
            with patch.object(module, "BASE", self.base), self.assertRaises(ValueError):
                module.reviewed_registration(row)
            registration = json.loads(original)

    def test_existing_output_and_existing_provider_are_never_replaced(self):
        self.write_metadata(ready=True)
        self.output.mkdir()
        marker = self.output / "keep"
        marker.write_text("unchanged")
        with self.assertRaises(FileExistsError):
            self.prepare()
        self.assertEqual("unchanged", marker.read_text())
        self.baseline.write_text(json.dumps(self.current + [next(row for row in self.rows if row["id"] == "google_calendar")]))
        with self.assertRaises(ValueError):
            self.prepare()
        self.assertEqual({"keep"}, {p.name for p in self.output.iterdir()})


if __name__ == "__main__":
    unittest.main()
