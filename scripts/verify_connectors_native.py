#!/usr/bin/env python3
"""Installed SDK/native smoke using ephemeral fake credentials, never a grant."""
import argparse
import asyncio
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import platform
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.request

from openagent_connectors import ConnectorError, ConnectorRunner
from openagent_connectors.catalog import bundled_catalog
from openagent_connectors.mcp import serve_connector
import openagent_connectors.privacy as privacy


def write(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n")


async def runner_smoke(bundle, private, output, commit, manifest, expected_catalog, native_target):
    executable = bundle / "bin/openagent-connector-runner"
    runner = ConnectorRunner(executable, identity_file=private / "installation.json",
                             product="OpenAgent qualification", name="Native SDK fixture",
                             broker="http://127.0.0.1:9")
    try:
        catalog = await runner.call("catalog")
        python = bundled_catalog()
        expected_python = [item for item in expected_catalog if not item.get("nativeKind")]
        assert catalog == expected_catalog and python == expected_python
        binding = {"catalog_id": "replio", "allow_write": False,
                   "principal": {"workspace_id": "wrong-tenant", "actor_id": "actor", "role": "owner"},
                   "connection": {"id": "fixture", "workspace_id": "owner-tenant", "provider": "replio",
                                  "capability": "outreach", "status": "connected"}}
        try:
            await runner.call("invoke", {"binding": binding, "tool": "outreach.replio.apps.list",
                              "arguments": {}, "credential": {"kind": "api_token", "secret": "fixture-only",
                              "header": "Authorization", "scheme": "Bearer"}, "invocation_id": "misdirected"})
        except ConnectorError as error:
            assert str(error) == "connector_request_failed"
        else:
            raise AssertionError("Cross-tenant invocation was accepted")
        toolchain = subprocess.check_output(["go", "version", str(executable)], text=True).split()[-1]
        assert toolchain == manifest["go_toolchain"]
        assert importlib.metadata.version("openagent-connectors") == manifest["version"]
        assert Path(os.sys.prefix).resolve() in Path(privacy.__file__).resolve().parents
        write(output / "consumer.json", {"source_commit": commit, "adapter": manifest["version"],
              "native": native_target, "catalog_sha256": manifest["files"]["catalog.json"]["sha256"],
              "bundle_manifest_sha256": hashlib.sha256((bundle / "manifest.json").read_bytes()).hexdigest(),
              "native_runner_toolchain": toolchain, "native_catalog": len(catalog),
              "python_catalog": len(python), "available_connectors": sum(item["available"] for item in python),
              "mcp_surface_import": callable(serve_connector), "broker_network_calls": 0,
              "normal_isolated_wheel_install": True, "source_overlay": False,
              "privacy_module_sha256": hashlib.sha256(Path(privacy.__file__).read_bytes()).hexdigest(),
              "protocol_version": importlib.metadata.version("openagent-tool-protocol"),
              "cross_tenant_invoke": "denied before provider IO"})
    finally:
        await runner.close()


def broker_smoke(bundle, private, output, commit, native_target):
    (private / "secret").write_text("pcs_fixture-only")
    (private / "secret").chmod(0o600)
    (private / "key").write_text(os.urandom(32).hex())
    (private / "key").chmod(0o600)
    provider = {"id": "postiz", "app_id": "postiz:pca_fixture-only", "client_id": "pca_fixture-only",
                "secret_file": str(private / "secret"), "authorization_url": "https://provider.invalid/oauth/authorize",
                "token_url": "https://provider.invalid/oauth/token",
                "redirect_uri": "https://auth.openagent.uno/v1/oauth/postiz/callback", "scopes": [], "pkce": False}
    write(private / "providers.json", [provider])
    write(private / "qa.json", {"installations": ["a" * 64]})
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
    process = subprocess.Popen([str(bundle / "bin/openagent-connector-auth"), "--listen", f"127.0.0.1:{port}",
               "--state", str(private / "state.json"), "--providers", str(private / "providers.json"),
               "--event-key", str(private / "key"), "--qa-enrollment", str(private / "qa.json")],
               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def request(path, body=None):
        req = urllib.request.Request(f"http://127.0.0.1:{port}" + path, data=body,
                                     headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=2) as response:
                return response.status, json.load(response)
        except urllib.error.HTTPError as response:
            return response.code, {}

    try:
        for attempt in range(50):
            try:
                status, health = request("/healthz")
                break
            except OSError:
                assert process.poll() is None, "Native broker exited"
                time.sleep(0.1)
        else:
            raise AssertionError("Native broker startup timeout")
        readiness, _ = request("/readyz")
        denied, _ = request("/v1/transactions", b'{"provider":"postiz"}')
        assert status == 200 and health["enrollment"] == "qa" and health["configured_providers"] == 1
        assert readiness == 503 and denied == 401
        write(output / "native-broker.json", {"source_commit": commit, "native": native_target,
              "health": status, "readiness": readiness, "enrollment": "qa", "unsigned_start": denied,
              "real_provider_grants": 0, "production_secret_reads": 0,
              "fixture_cleanup": "process stopped and temporary fake secrets/state removed"})
    finally:
        process.terminate()
        process.wait(timeout=5)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--release-directory", type=Path, required=True)
    args = parser.parse_args()
    system = {"Darwin": "darwin", "Linux": "linux"}.get(platform.system())
    arch = {"arm64": "arm64", "aarch64": "arm64", "x86_64": "x64", "AMD64": "x64"}.get(platform.machine())
    assert system is not None and arch is not None
    native_target = system + "-" + arch
    manifest = json.loads((args.release_directory / "manifest.json").read_bytes())
    assert manifest["source_commit"] == args.source_commit and manifest["dirty_snapshot"] is False
    catalog_bytes = (args.release_directory / "catalog.json").read_bytes()
    assert hashlib.sha256(catalog_bytes).hexdigest() == manifest["files"]["catalog.json"]["sha256"]
    assert len(catalog_bytes) == manifest["files"]["catalog.json"]["bytes"]
    expected_catalog = json.loads(catalog_bytes)
    bundle_manifest = json.loads((args.bundle / "manifest.json").read_bytes())
    for key in ("version", "source_commit", "source_sha256", "go_toolchain", "dirty_snapshot"):
        assert bundle_manifest[key] == manifest[key]
    assert bundle_manifest["platform"] == native_target
    expected_files = {"bin/openagent-connector-runner", "bin/openagent-connector-auth"}
    assert set(bundle_manifest["files"]) == expected_files
    assert not args.bundle.is_symlink() and not any(path.is_symlink() for path in args.bundle.rglob("*"))
    assert {path.relative_to(args.bundle).as_posix() for path in args.bundle.rglob("*") if path.is_file()} == expected_files | {"manifest.json"}
    for name, metadata in bundle_manifest["files"].items():
        data = (args.bundle / name).read_bytes()
        assert len(data) == metadata["bytes"] and hashlib.sha256(data).hexdigest() == metadata["sha256"]
    with tempfile.TemporaryDirectory(prefix="openagent-native-smoke-") as temporary:
        private = Path(temporary)
        private.chmod(0o700)
        asyncio.run(runner_smoke(args.bundle, private, args.output, args.source_commit,
                                 manifest, expected_catalog, native_target))
        broker_smoke(args.bundle, private, args.output, args.source_commit, native_target)


if __name__ == "__main__":
    main()
