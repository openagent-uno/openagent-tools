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
        registration_path = self.base / "registrations/google.json"
        registration = json.loads(registration_path.read_text())
        registration["calendar_preparation"].update(api_enabled=False, calendar_scopes_declared=False)
        registration_path.write_text(json.dumps(registration))
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


class MicrosoftFamilyTests(unittest.TestCase):
    setUp = PrepareProviderTrialTests.setUp
    write_metadata = PrepareProviderTrialTests.write_metadata
    prepare = PrepareProviderTrialTests.prepare

    def write_families(self):
        # Designed file-only fixtures, never evidence of live registration/consent.
        self.write_metadata(ready=True)
        for i, provider in enumerate(sorted(module.MICROSOFT), 1):
            filename, key, audience = module.MICROSOFT_REGISTRATIONS[provider]
            row = next(row for row in self.rows if row["id"] == provider)
            client = ("c245634c-3535-44fd-a7ef-0fdd8040dc93" if provider == "outlook_calendar"
                      else "00000000-0000-4000-8000-%012d" % i)
            row.update(client_id=client, app_id="microsoft:" + client, secret_file="/secrets/" + key)
            registration = {"provider_family": "microsoft", "provider": provider, "client_id": client,
                            "cloud": "global", "account_audience": audience, "sign_in_audience": audience,
                            "oauth_settings_verified": True, "production_secret_stored": True,
                            "production_secret_mounted": False, "production_secret_configured": False,
                            "secret_custody_checkpoint": {"immutable": True},
                            "redirect_uris": [row["redirect_uri"]],
                            "configured_delegated_scopes": [s.removeprefix(module.GRAPH) for s in row["scopes"]],
                            "secret_reference": {"namespace": "openagent-connectors", "name": "fixture-" + provider.replace("_", "-"),
                                                 "key": key, "mount_path": row["secret_file"]}}
            (self.base / "registrations" / filename).write_text(json.dumps(registration))
        (self.base / "providers-reviewed.json").write_text(json.dumps(self.rows))

    def registration_file(self, provider):
        return self.base / "registrations" / module.MICROSOFT_REGISTRATIONS[provider][0]

    def validate(self, provider, row=None):
        with patch.object(module, "BASE", self.base):
            module.reviewed_registration(row or next(r for r in self.rows if r["id"] == provider))

    def test_four_fixed_families_prepare_with_exact_reference_and_no_live_claim(self):
        self.write_families()
        before = {p.name: p.read_bytes() for p in (self.base / "registrations").iterdir()}
        for provider in sorted(module.MICROSOFT):
            with self.subTest(provider=provider):
                self.output = self.root / provider
                self.prepare(provider)
                meta = json.loads((self.output / "trial-metadata.json").read_text())
                self.assertEqual(json.loads(self.registration_file(provider).read_text())["secret_reference"], meta["required_secret_reference"])
                self.assertFalse(meta["secret_mount_attested"])
                self.assertFalse(meta["broker_apply_authorized"])
                self.assertEqual(0, meta["new_grants"])
        self.assertEqual(before, {p.name: p.read_bytes() for p in (self.base / "registrations").iterdir()})

    def test_missing_family_never_falls_back_to_original_shared_registration(self):
        self.write_families()
        for provider in ("outlook_mail", "onedrive", "sharepoint"):
            path = self.registration_file(provider);raw = path.read_bytes();path.unlink()
            with self.assertRaises(FileNotFoundError): self.prepare(provider)
            self.assertFalse(self.output.exists());path.write_bytes(raw)

    def test_family_reference_issuer_and_custody_drift_are_rejected(self):
        self.write_families()
        for provider in sorted(module.MICROSOFT):
            path = self.registration_file(provider);original = json.loads(path.read_text());row = next(r for r in self.rows if r["id"] == provider)
            for field, value in (("client_id", "another-client"), ("cloud", "other-cloud"),
                                 ("oauth_settings_verified", False), ("production_secret_stored", False),
                                 ("secret_custody_checkpoint", {"immutable": False}), ("redirect_uris", [])):
                path.write_text(json.dumps({**original, field: value}))
                with self.subTest(provider=provider, field=field), self.assertRaises(ValueError): self.validate(provider)
            for field, value in (("key", "event-key"), ("namespace", "other"), ("name", "../other"),
                                 ("mount_path", "/secrets/other")):
                path.write_text(json.dumps({**original, "secret_reference": {**original["secret_reference"], field: value}}))
                with self.subTest(provider=provider, reference=field), self.assertRaises(ValueError): self.validate(provider)
            if provider != "outlook_calendar":
                path.write_text(json.dumps({**original, "provider": "outlook_calendar"}))
                with self.assertRaises(ValueError): self.validate(provider)
            path.write_text(json.dumps(original))
            for changed in ({**row, "app_id": "microsoft:other"}, {**row, "secret_file": "/secrets/microsoft-client-secret-other"}):
                with self.assertRaises(ValueError): self.validate(provider, changed)

    def test_sharepoint_requires_organizations_and_other_families_personal_compatible_audience(self):
        self.write_families()
        for provider in sorted(module.MICROSOFT):
            self.validate(provider)
            path = self.registration_file(provider);d = json.loads(path.read_text())
            wrong = "AzureADandPersonalMicrosoftAccount" if provider == "sharepoint" else "AzureADMultipleOrgs"
            d.update(account_audience=wrong, sign_in_audience=wrong);path.write_text(json.dumps(d))
            with self.assertRaises(ValueError): self.validate(provider)

    def test_cross_surface_and_broader_permissions_still_reject_no_send_is_inferred(self):
        self.write_families()
        for provider in sorted(module.MICROSOFT):
            row = next(r for r in self.rows if r["id"] == provider)
            foreign = "Files.Read" if provider == "sharepoint" else "Sites.Read.All"
            for scope in (foreign, "Directory.Read.All", "Files.ReadWrite.All"):
                with self.assertRaises(ValueError): self.validate(provider, {**row, "scopes": row["scopes"] + [module.GRAPH + scope]})
        row = next(r for r in self.rows if r["id"] == "outlook_mail")
        row["scopes"].remove(module.GRAPH + "Mail.Send")
        (self.base / "providers-reviewed.json").write_text(json.dumps(self.rows))
        self.prepare("outlook_mail")
        self.assertNotIn(module.GRAPH + "Mail.Send", json.loads((self.output / "providers.json").read_text())[-1]["scopes"])

    def old_eleven_baseline(self):
        calendar = next(r for r in self.rows if r["id"] == "outlook_calendar")
        result = [copy.deepcopy(r) for r in self.rows if r["id"] in module.PUBLIC | set(module.TRIAL)]
        for row in result:
            if row["id"] in {"outlook_mail", "onedrive", "sharepoint"}:
                row.update(client_id=calendar["client_id"], app_id=calendar["app_id"], secret_file=calendar["secret_file"])
        self.baseline.write_text(json.dumps(result))
        return result

    def switch(self):
        with patch.object(module, "BASE", self.base):
            module.prepare_microsoft_family_switch(self.baseline, self.output)

    def test_family_switch_preserves_calendar_and_seven_other_rows_and_never_rewrites_tokens(self):
        self.write_families();before = self.old_eleven_baseline();raw = self.baseline.read_bytes()
        calendar_before = self.registration_file("outlook_calendar").read_bytes()
        self.switch();after = json.loads((self.output / "providers.json").read_text())
        self.assertEqual(11, len(after));self.assertEqual([r["id"] for r in before], [r["id"] for r in after])
        for old, new in zip(before, after):
            if old["id"] not in {"outlook_mail", "onedrive", "sharepoint"}:self.assertEqual(old, new)
            else:self.assertNotEqual(old["app_id"], new["app_id"])
        self.assertEqual(raw, self.baseline.read_bytes());self.assertEqual(calendar_before, self.registration_file("outlook_calendar").read_bytes())
        meta = json.loads((self.output / "trial-metadata.json").read_text())
        self.assertFalse(meta["existing_credential_records_or_issuers_rewritten"])
        self.assertFalse(meta["old_issuer_refresh_compatibility_claimed"])
        self.assertFalse(meta["broker_apply_authorized"])
        self.assertFalse(meta["secret_mount_attested"])

    def test_pending_registration_secret_or_oauth_configuration_blocks_family_switch(self):
        self.write_families();self.old_eleven_baseline();path = self.registration_file("onedrive");original = json.loads(path.read_text())
        for field, value in (("client_id", None), ("production_secret_stored", False), ("oauth_settings_verified", False)):
            path.write_text(json.dumps({**original, field: value}))
            with self.assertRaises(ValueError):self.switch()
            self.assertFalse(self.output.exists())
        path.write_text(json.dumps(original))

    def test_family_switch_rejects_reused_clients_and_any_unexpected_baseline_change(self):
        self.write_families();original = self.old_eleven_baseline()
        for changed in (original[:-1], original + [original[0]],
                        [{**r, "client_id": "drift"} if r["id"] == "clickup" else r for r in original],
                        [{**r, "app_id": "microsoft:another-issuer"} if r["id"] == "outlook_mail" else r for r in original]):
            self.baseline.write_text(json.dumps(changed))
            with self.assertRaises(ValueError):self.switch()
            self.assertFalse(self.output.exists())
        self.baseline.write_text(json.dumps(original))
        mail = next(r for r in self.rows if r["id"] == "outlook_mail");drive = next(r for r in self.rows if r["id"] == "onedrive")
        drive.update(client_id=mail["client_id"], app_id=mail["app_id"])
        path = self.registration_file("onedrive");registration = json.loads(path.read_text());registration["client_id"] = mail["client_id"];path.write_text(json.dumps(registration))
        (self.base / "providers-reviewed.json").write_text(json.dumps(self.rows))
        with self.assertRaises(ValueError):self.switch()
        self.assertFalse(self.output.exists())


if __name__ == "__main__":
    unittest.main()
