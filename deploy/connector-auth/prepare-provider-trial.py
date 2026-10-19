#!/usr/bin/env python3
"""Prepare an additive provider trial config; never read secrets or apply it."""
import argparse
import hashlib
import json
from pathlib import Path
import re

BASE = Path(__file__).resolve().parent
PUBLIC = {"clickup", "github", "notion"}
MICROSOFT = {"outlook_mail", "outlook_calendar", "onedrive", "sharepoint"}
TRIAL = ("gmail", "google_drive", "google_analytics", "google_calendar", "outlook_mail", "outlook_calendar", "onedrive", "sharepoint")
GRAPH = "https://graph.microsoft.com/"
MICROSOFT_REGISTRATIONS = {
    "outlook_calendar": ("microsoft.json", "microsoft-client-secret", "AzureADandPersonalMicrosoftAccount"),
    "outlook_mail": ("microsoft-mail.json", "microsoft-mail-client-secret", "AzureADandPersonalMicrosoftAccount"),
    "onedrive": ("microsoft-onedrive.json", "microsoft-onedrive-client-secret", "AzureADandPersonalMicrosoftAccount"),
    "sharepoint": ("microsoft-sharepoint.json", "microsoft-sharepoint-client-secret", "AzureADMultipleOrgs"),
}


def registration_path(provider):
    if provider not in TRIAL:
        raise ValueError("provider is outside this finite trial")
    filename = MICROSOFT_REGISTRATIONS[provider][0] if provider in MICROSOFT else "google.json"
    return BASE / "registrations" / filename


def reviewed_registration(row):
    provider = row["id"]
    if provider not in TRIAL:
        raise ValueError("provider is outside this finite trial")
    microsoft = provider in MICROSOFT
    registration = json.loads(registration_path(provider).read_text())
    expected_key = MICROSOFT_REGISTRATIONS[provider][1] if microsoft else "google-client-secret"
    if microsoft and provider != "outlook_calendar" and registration.get("provider") != provider:
        raise ValueError("Microsoft registration must belong to the exact provider family")
    reference = registration.get("secret_reference") or {}
    # The name comes only from the reviewed registration, never a CLI argument
    # or provider row. Namespace, key and destination remain family-bound.
    if (not isinstance(reference, dict)
            or set(reference) != {"namespace", "name", "key", "mount_path"}
            or not isinstance(reference.get("name"), str)
            or not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", reference["name"])):
        raise ValueError("an explicit reviewed namespace-local Secret reference is required")
    if (not row.get("client_id") or "registration-pending" in row.get("app_id", "")
            or row["client_id"] != registration.get("client_id")
            or row["app_id"] != ("microsoft:" if microsoft else "google:") + row["client_id"]
            or row["redirect_uri"] != "https://auth.openagent.uno/v1/oauth/" + provider + "/callback"
            or row["redirect_uri"] not in registration.get("redirect_uris", [])
            or row["secret_file"] != reference.get("mount_path")
            or reference.get("namespace") != "openagent-connectors"
            or reference.get("key") != expected_key
            or row["secret_file"] != "/secrets/" + str(reference.get("key", ""))
            or row["pkce"] is not True):
        raise ValueError("provider must match the existing reviewed registration and secret reference")
    scopes = row["scopes"]
    if (not isinstance(scopes, list) or not scopes or not all(isinstance(scope, str) for scope in scopes)
            or len(scopes) != len(set(scopes))):
        raise ValueError("distinct reviewed scopes are required")
    if microsoft:
        allowed = {"outlook_mail": {"Mail.ReadBasic", "Mail.Read", "Mail.ReadWrite", "Mail.Send"},
                   "outlook_calendar": {"Calendars.ReadBasic", "Calendars.Read", "Calendars.ReadWrite"},
                   "onedrive": {"Files.Read"}, "sharepoint": {"Sites.Read.All"}}[provider]
        canonical = [scope[len(GRAPH):] if scope.startswith(GRAPH) else scope for scope in scopes]
        if (registration.get("cloud") != "global"
                or registration.get("account_audience") != MICROSOFT_REGISTRATIONS[provider][2]
                or registration.get("sign_in_audience") != registration.get("account_audience")
                or registration.get("oauth_settings_verified") is not True
                or registration.get("production_secret_stored") is not True
                or (registration.get("secret_custody_checkpoint") or {}).get("immutable") is not True
                or row["authorization_url"] != "https://login.microsoftonline.com/common/oauth2/v2.0/authorize"
                or row["token_url"] != "https://login.microsoftonline.com/common/oauth2/v2.0/token"
                or row.get("revocation_url")
                or len(canonical) != len(set(canonical))
                or GRAPH + "offline_access" in scopes
                or not {"offline_access", "User.Read"} <= set(canonical)
                or not (set(canonical) & (allowed - {"Mail.Send"}))
                or not set(canonical) <= allowed | {"offline_access", "User.Read"}
                or any(scope != "offline_access" and not scope.startswith(GRAPH) for scope in scopes)):
            raise ValueError("Microsoft trial requires verified global-cloud app metadata and exact Graph scopes")
        if not set(canonical) <= set(registration.get("configured_delegated_scopes", [])):
            raise ValueError("Microsoft scopes are not recorded on the existing app")
    else:
        services = {"gmail": {"gmail.googleapis.com"}, "google_drive": {"drive.googleapis.com"},
                    "google_analytics": {"analyticsdata.googleapis.com", "analyticsadmin.googleapis.com"},
                    "google_calendar": {"calendar-json.googleapis.com"}}[provider]
        if (registration.get("publication_status") != "testing" or not registration.get("test_users")
                or row["authorization_url"] != "https://accounts.google.com/o/oauth2/v2/auth"
                or row["token_url"] != "https://oauth2.googleapis.com/token"
                or row.get("revocation_url") != "https://oauth2.googleapis.com/revoke"
                or not services <= set(registration.get("enabled_apis", []))
                or not set(scopes) <= set(registration.get("declared_scopes", []))):
            raise ValueError("Google trial requires recorded Testing users, enabled API and declared scopes")
        if provider == "google_calendar":
            calendar = registration.get("calendar_preparation") or {}
            expected = {"https://www.googleapis.com/auth/calendar.calendarlist.readonly",
                        "https://www.googleapis.com/auth/calendar.events"}
            if (set(scopes) != expected or calendar.get("api_enabled") is not True
                    or calendar.get("calendar_scopes_declared") is not True):
                raise ValueError("Calendar API and scope preparation remains incomplete")


def prepare(provider, baseline, output):
    if provider not in TRIAL:
        raise ValueError("provider is outside this finite trial")
    reviewed = json.loads((BASE / "providers-reviewed.json").read_text())
    known = {row["id"]: row for row in reviewed}
    if len(known) != len(reviewed):
        raise ValueError("reviewed provider identifiers must be unique")
    raw = Path(baseline).read_bytes()
    current = json.loads(raw)
    if not isinstance(current, list) or any(not isinstance(row, dict) for row in current):
        raise ValueError("baseline must be the current provider array")
    ids = [row.get("id") for row in current]
    if (len(ids) != len(set(ids)) or not PUBLIC <= set(ids) or provider in ids
            or not set(ids) <= PUBLIC | set(TRIAL)
            or any(row != known.get(row.get("id")) for row in current)):
        raise ValueError("preserve the reviewed public providers and every existing row without replacement")
    selected = known.get(provider)
    if selected is None:
        raise ValueError("existing app registration and reviewed provider row are not available")
    reviewed_registration(selected)
    # No global QA flag, resource manifests, provider calls or app mutations.
    output = Path(output)
    output.mkdir(parents=True, exist_ok=False)
    (output / "providers.json").write_text(json.dumps(current + [selected], indent=2) + "\n")
    (output / "trial-metadata.json").write_text(json.dumps({
        "status": "prepared-not-applied-or-provider-qualified", "added_provider": provider,
        "preserved_provider_ids": ids, "baseline_sha256": hashlib.sha256(raw).hexdigest(),
        "global_qa_enrollment_added": False, "new_grants": 0,
        "google_trial_requires_recorded_testing_users": provider not in MICROSOFT,
        "required_secret_reference": json.loads(registration_path(provider).read_text())["secret_reference"],
        "secret_mount_attested": False,
        "broker_apply_authorized": False,
        "provider_review_attested": False,
    }, indent=2) + "\n")


def prepare_microsoft_family_switch(baseline, output):
    """Replace only three reviewed issuer rows; never migrate credentials."""
    replaced = {"outlook_mail", "onedrive", "sharepoint"}
    reviewed = json.loads((BASE / "providers-reviewed.json").read_text())
    known = {row["id"]: row for row in reviewed}
    if len(known) != len(reviewed):
        raise ValueError("reviewed provider identifiers must be unique")
    raw = Path(baseline).read_bytes()
    current = json.loads(raw)
    if not isinstance(current, list) or any(not isinstance(row, dict) for row in current):
        raise ValueError("baseline must be the current eleven-provider array")
    ids = [row.get("id") for row in current]
    if len(ids) != len(set(ids)) or set(ids) != PUBLIC | set(TRIAL):
        raise ValueError("the exact current eleven-provider cohort is required")
    calendar_registration = json.loads(registration_path("outlook_calendar").read_text())
    previous_client = calendar_registration["client_id"]
    previous_app = "microsoft:" + previous_client
    previous_secret = calendar_registration["secret_reference"]["mount_path"]
    clients = {previous_client}
    for provider in replaced:
        selected = known[provider]
        reviewed_registration(selected)
        if selected["client_id"] in clients:
            raise ValueError("each new Microsoft family requires a distinct registration")
        clients.add(selected["client_id"])
    result = []
    for row in current:
        provider = row["id"]
        selected = known[provider]
        if provider in replaced:
            previous = {**selected, "client_id": previous_client,
                        "app_id": previous_app, "secret_file": previous_secret}
            if row != previous:
                raise ValueError("the old issuer row changed; review the actual baseline")
            result.append(selected)
        else:
            if row != selected:
                raise ValueError("preserve every other reviewed row without replacement")
            result.append(row)
    output = Path(output)
    output.mkdir(parents=True, exist_ok=False)
    (output / "providers.json").write_text(json.dumps(result, indent=2) + "\n")
    (output / "trial-metadata.json").write_text(json.dumps({
        "status": "prepared-microsoft-family-switch-not-applied-or-provider-qualified",
        "replaced_provider_ids": sorted(replaced), "preserved_provider_ids": [p for p in ids if p not in replaced],
        "baseline_sha256": hashlib.sha256(raw).hexdigest(), "new_grants": 0,
        "required_secret_references": {p: json.loads(registration_path(p).read_text())["secret_reference"]
                                       for p in sorted(MICROSOFT)},
        "original_calendar_issuer_preserved": True,
        "existing_credential_records_or_issuers_rewritten": False,
        "old_issuer_refresh_compatibility_claimed": False,
        "secret_mount_attested": False, "broker_apply_authorized": False,
        "provider_review_attested": False,
    }, indent=2) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--provider", choices=TRIAL)
    mode.add_argument("--microsoft-family-switch", action="store_true")
    parser.add_argument("--baseline-providers", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.microsoft_family_switch:
            prepare_microsoft_family_switch(args.baseline_providers, args.output)
        else:
            prepare(args.provider, args.baseline_providers, args.output)
    except (ValueError, OSError, KeyError, TypeError):
        parser.error("trial preparation refused; review current baseline and verified registration metadata")
    print("Prepared provider file only; image compatibility, CAS rollout and actual consent remain separate.")


if __name__ == "__main__":
    main()
