#!/usr/bin/env python3
"""Render a single-writer, allowlisted QA overlay without reading any secrets.

This prepares files only. It never builds, applies Kubernetes objects or changes
provider registrations. The output directory must not already exist.
"""
import argparse
import json
from pathlib import Path
import re


BASE = Path(__file__).resolve().parent
QA_PROVIDERS = ("clickup", "gmail", "google_drive", "google_analytics", "shopify", "github", "notion", "slack_import")
SLACK_QA_CLIENT_ID = "12333069497846.12337417629937"
SLACK_QA_INSTALLATION = "2339c00b5f5bc1d0b78606920323613c1894172e4af172701d8c6adcd7ba0da6"


def prepare(provider, installations, shops, image, output):
    if provider not in QA_PROVIDERS:
        raise ValueError("provider is not admitted to the reviewed QA overlay")
    if not re.fullmatch(r"localhost:5000/openagent-connector-auth@sha256:[0-9a-f]{64}", image):
        raise ValueError("a pinned broker image digest is required")
    if not 1 <= len(installations) <= 50 or len(set(installations)) != len(installations):
        raise ValueError("one to fifty distinct installation fingerprints are required")
    if any(not re.fullmatch(r"[0-9a-f]{64}", value) for value in installations):
        raise ValueError("installation fingerprints must be lowercase SHA-256 hex")
    if provider == "slack_import" and installations != [SLACK_QA_INSTALLATION]:
        raise ValueError("Slack QA is limited to the reviewed installation")
    if len(shops) > 10 or len(set(shops)) != len(shops):
        raise ValueError("at most ten distinct dedicated QA shops are allowed")
    if any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.myshopify\.com", value) for value in shops):
        raise ValueError("dedicated QA Shopify domains are required")
    if bool(shops) != (provider == "shopify"):
        raise ValueError("Shopify QA requires explicit shops; other providers do not")
    rows = json.loads((BASE / "providers-reviewed.json").read_text())
    selected = [row for row in rows if row["id"] == provider]
    if len(selected) != 1:
        raise ValueError("select one reviewed provider")
    if not selected[0].get("client_id") or not selected[0].get("app_id") or "registration-pending" in selected[0]["app_id"]:
        raise ValueError("provider registration must be complete before QA")
    if provider == "slack_import":
        registration = json.loads((BASE / "registrations/slack.json").read_text())
        row = selected[0]
        if (row["client_id"] != SLACK_QA_CLIENT_ID or row["app_id"] != "slack_import:" + SLACK_QA_CLIENT_ID
                or registration.get("client_id") != SLACK_QA_CLIENT_ID or registration.get("provider") != provider
                or row["redirect_uri"] != "https://auth.openagent.uno/v1/oauth/slack_import/callback"
                or registration.get("callback_url") != row["redirect_uri"]
                or row["scopes"] != registration.get("configured_user_scopes")
                or registration.get("configured_bot_scopes") != [] or row["pkce"] is not False
                or registration.get("pkce") is not False or registration.get("token_rotation_enabled") is not True
                or registration.get("oauth_settings_verified") is not True
                or registration.get("production_secret_configured") is not True):
            raise ValueError("Slack QA must match the reviewed existing user-token app registration")
    # A previous immutable bootstrap image does not implement QA admission.
    digest = image.split("@sha256:")[1]
    if digest == "f5cb0256ef28919ccf2f3e27a47bdb5c87931a27d7e3197f870fb1a1a81f2777":
        raise ValueError("the bootstrap image lacks QA admission; build the reviewed commit first")
    resources = (BASE / "resources.yaml").read_text()
    marker = "            - --event-key=/secrets/event-key\n"
    if resources.count(marker) != 1:
        raise ValueError("base deployment arguments changed; review the overlay generator")
    resources = resources.replace(marker, marker + "            - --qa-enrollment=/config/qa-enrollment.json\n")
    config = {"installations": sorted(installations)}
    if shops:
        config["shopify_stores"] = sorted(shops)
    output = Path(output)
    output.mkdir(parents=True, exist_ok=False)
    (output / "providers.json").write_text(json.dumps(selected, indent=2) + "\n")
    (output / "qa-enrollment.json").write_text(json.dumps(config, indent=2) + "\n")
    (output / "resources.yaml").write_text(resources)
    (output / "kustomization.yaml").write_text(
        "apiVersion: kustomize.config.k8s.io/v1beta1\n"
        "kind: Kustomization\nnamespace: openagent-connectors\n"
        "resources: [resources.yaml]\n"
        "configMapGenerator:\n  - name: connector-auth-config\n"
        "    files: [providers.json, qa-enrollment.json]\n"
        "images:\n  - name: openagent-connector-auth\n"
        "    newName: localhost:5000/openagent-connector-auth\n"
        f"    digest: sha256:{digest}\n"
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--provider", required=True, choices=QA_PROVIDERS)
    parser.add_argument("--installation", action="append", required=True)
    parser.add_argument("--shop", action="append", default=[])
    parser.add_argument("--image", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        prepare(args.provider, args.installation, args.shop, args.image, args.output)
    except (ValueError, FileExistsError) as error:
        parser.error(str(error))
    print("Prepared QA overlay; review/dry-run/apply and rollback remain operator actions.")


if __name__ == "__main__":
    main()
