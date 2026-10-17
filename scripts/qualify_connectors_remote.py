#!/usr/bin/env python3
"""Sequential POSIX-worker qualification; never creates tags or releases."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import tarfile
import urllib.request

PUBLIC_BASELINES = (
    ("openagent", "v1.1.0-beta.39", "772b455753fe99fd97165134ab9739d0d40ac1650f73c20018b1ac561a335c97"),
    ("openagent-core", "v1.1.0-beta.22", "291be9e298c1035ae88079b849620e9a8a04e03f43dd9180f86ebe6e79f4876d"),
    ("openagent-tools", "v1.0.0-beta.4", None),
    ("openagent-tools", "connectors-v0.1.3", "03684b84d9738ea7c14073a43110a4fc46744af6bd7ba3438c3059e682af127f"),
)
HOST_TOOLS_INDEX = "a0f85b84e6d98f525c466126df7a5de9437d9628127607517a94f1b61b1889e0"
PROTOCOL = "openagent_tool_protocol-1.0.0b1-py3-none-any.whl"
PROTOCOL_SHA = "3d4c266eb8e51552408c70448ad7c466a6cb8fa7263939412ce4069c8b73cef2"
SDK15_OFFICIAL_IDS = frozenset({
    "atlassian", "billingbear", "clickup", "exa", "firecrawl", "github", "gmail",
    "google-analytics", "google-drive", "imap_smtp", "notion", "pipeboard", "postiz",
    "replio", "shopify", "slack-import",
})
SDK16_KEYLESS = {
    "parallel-search": ("parallel_search", {"files.parallel.search", "files.parallel.fetch"}),
    "context7": ("context7", {"files.context7.resolve_library", "files.context7.query_docs"}),
    "coingecko": ("coingecko", {"files.coingecko.price", "files.coingecko.global"}),
}
SDK17_OAUTH = {
    "google-calendar": ("google_calendar", "files", "files.google_calendar.",
        {"calendars.list", "calendars.get", "events.list", "events.get"},
        {"events.create", "events.update", "events.delete"},
        ["https://www.googleapis.com/auth/calendar.calendarlist.readonly", "https://www.googleapis.com/auth/calendar.events"]),
    "outlook-mail": ("outlook_mail", "outreach", "outreach.outlook_mail.",
        {"folders.list", "folders.get", "messages.list", "messages.get", "attachments.list", "attachments.get"},
        {"drafts.create", "drafts.update", "messages.send"},
        ["offline_access", "User.Read", "Mail.ReadWrite"]),
    "outlook-calendar": ("outlook_calendar", "files", "files.outlook_calendar.",
        {"calendars.list", "calendars.get", "events.list", "events.get"},
        {"events.create", "events.update", "events.delete"},
        ["offline_access", "User.Read", "Calendars.ReadWrite"]),
}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def write(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n")


def verify_catalog_cohort(version, catalog):
    """Bind the new cohort by identities/contracts, never just its cardinality.

    Older immutable releases retain their content-bound catalog checks in the
    artifact/native qualifiers; this does not rewrite their existing receipts.
    """
    if not isinstance(catalog, list) or any(not isinstance(row, dict) for row in catalog):
        raise ValueError("invalid release catalog")
    ids = [row.get("id") for row in catalog]
    if any(not isinstance(value, str) or not value for value in ids) or len(ids) != len(set(ids)):
        raise ValueError("invalid or duplicate catalog identifiers")
    custom = [row for row in catalog if row.get("nativeKind")]
    if len(custom) != 1 or custom[0].get("id") != "custom-mcp" or custom[0]["nativeKind"] != "custom_mcp":
        raise ValueError("custom MCP catalog contract mismatch")
    official = {row["id"]: row for row in catalog if not row.get("nativeKind")}
    expected = {"0.1.5": SDK15_OFFICIAL_IDS,
                "0.1.6": SDK15_OFFICIAL_IDS | set(SDK16_KEYLESS),
                "0.1.7": SDK15_OFFICIAL_IDS | set(SDK16_KEYLESS) | set(SDK17_OAUTH)}.get(version)
    if expected is not None and set(official) != expected:
        raise ValueError("release catalog identities differ from the reviewed cohort")
    if version in {"0.1.6", "0.1.7"}:
        for identifier, (provider, tools) in SDK16_KEYLESS.items():
            row = official[identifier]
            reads = row.get("readTools")
            if (row.get("provider") != provider or row.get("auth") != "none"
                    or row.get("capability") != "files" or row.get("available") is not True
                    or row.get("agentTools") != [] or not isinstance(reads, list)
                    or any(not isinstance(tool, str) for tool in reads)
                    or len(reads) != len(tools) or set(reads) != tools):
                raise ValueError("new keyless connector contract differs from the reviewed cohort")
    if version == "0.1.7":
        for identifier, (provider, capability, prefix, reads, writes, _) in SDK17_OAUTH.items():
            row = official[identifier]
            if (row.get("provider") != provider or row.get("auth") != "oauth"
                    or row.get("capability") != capability or row.get("available") is not True
                    or row.get("nativeKind") or row.get("readTools") is None or row.get("agentTools") is None):
                raise ValueError("new OAuth connector contract differs from the reviewed cohort")
            for field, operations in (("readTools", reads), ("agentTools", writes)):
                values = row[field]
                if (not isinstance(values, list) or any(not isinstance(value, str) for value in values)
                        or len(values) != len(operations) or set(values) != {prefix + op for op in operations}):
                    raise ValueError("new OAuth connector tools differ from the reviewed cohort")
    return {"sdk_version": version, "official_ids": sorted(official), "official_count": len(official),
            "custom_ids": ["custom-mcp"], "exact_version_cohort": expected is not None}


def source_sdk_version(source, expected=None):
    go = re.search(r'const Version = "(\d+\.\d+\.\d+)"',
                   (source / "packages/connectors/catalog.go").read_text())
    python = re.search(r'^version = "(\d+\.\d+\.\d+)"',
                       (source / "packages/connectors-python/pyproject.toml").read_text(), re.MULTILINE)
    if not go or not python or go[1] != python[1] or expected is not None and go[1] != expected:
        raise ValueError("SDK source version differs from the reviewed release")
    return go[1]


def verify_source_python_catalog(source, version, catalog):
    """SDK16's offline source fallback must not be repaired only in the build snapshot."""
    if version not in {"0.1.6", "0.1.7"}:
        return
    path = source / "packages/connectors-python/src/openagent_connectors/catalog.json"
    if json.loads(path.read_bytes()) != {"version": version, "connectors": catalog}:
        raise ValueError("Source Python fallback catalog differs from the generated SDK catalog")


def verify_calendar_mail_tools(identifier, tools, *, send_authorized=False):
    """Check installed runner metadata; this never invokes a provider operation."""
    provider, capability, prefix, reads, writes, _ = SDK17_OAUTH[identifier]
    expected = {prefix + operation for operation in reads | writes}
    if identifier == "outlook-mail" and not send_authorized:
        expected.remove(prefix + "messages.send")
    if (not isinstance(tools, list) or any(not isinstance(tool, dict) for tool in tools)
            or len(tools) != len(expected) or {tool.get("name") for tool in tools} != expected):
        raise ValueError("Calendar/mail operation identities or separate send grant differ")
    for tool in tools:
        operation = tool["name"][len(prefix):]
        if identifier == "google-calendar":
            scope = SDK17_OAUTH[identifier][5][0 if operation.startswith("calendars.") else 1]
        elif operation.startswith("calendars."):
            scope = "Calendars.ReadBasic"
        elif identifier == "outlook-calendar":
            scope = "Calendars.Read" if operation in reads else "Calendars.ReadWrite"
        elif operation.startswith("folders."):
            scope = "Mail.ReadBasic"
        elif operation == "messages.send":
            scope = "Mail.Send"
        else:
            scope = "Mail.Read" if operation in reads else "Mail.ReadWrite"
        risk = "read" if operation in reads else ("publish" if operation == "messages.send" else
                "draft" if operation.startswith("drafts.") else "destructive" if operation.endswith(".delete") else "write")
        schema = tool.get("inputSchema")
        if (tool.get("provider") != provider or tool.get("capability") != capability
                or tool.get("mode") != "typed" or tool.get("risk") != risk
                or tool.get("required_scopes") != [scope] or tool.get("retry", {}).get("max_attempts") != 1
                or not isinstance(schema, dict) or schema.get("type") != "object"
                or schema.get("additionalProperties") is not False or not isinstance(schema.get("properties"), dict)):
            raise ValueError("Calendar/mail typed schema, scope or retry contract differs")
        properties = schema["properties"]
        provider_schema = properties.get("provider", {})
        if ("connection_id" not in properties
                or not (provider_schema.get("const") == provider or provider_schema.get("enum") == [provider])):
            raise ValueError("Calendar/mail schema connection binding differs")
        if operation.endswith((".update", ".delete")):
            if "etag" not in schema.get("required", []) or properties.get("etag", {}).get("type") != "string":
                raise ValueError("Calendar/mail write version precondition differs")
        if "body" in properties:
            body = properties["body"]
            if ("body" not in schema.get("required", []) or body.get("type") != "object"
                    or body.get("additionalProperties") is not False):
                raise ValueError("Calendar/mail write body must remain a closed typed object")
    return {"operations": len(tools), "schemas_sha256": sha(json.dumps(tools, sort_keys=True, separators=(",", ":")).encode()),
            "send_authorized": send_authorized, "provider_calls": 0}


def calendar_mail_native_metadata(executable):
    requests, contracts = [], []
    for identifier, (provider, capability, _, _, _, scopes) in SDK17_OAUTH.items():
        for send in ([False, True] if identifier == "outlook-mail" else [False]):
            binding = {"catalog_id": identifier, "allow_write": True,
                "principal": {"workspace_id": "metadata-fixture", "actor_id": "owner"},
                "connection": {"id": "metadata-connection", "workspace_id": "metadata-fixture", "provider": provider,
                    "capability": capability, "enabled": True, "external_id": "metadata-account",
                    "scopes": scopes + (["Mail.Send"] if send else []), "config": {}}}
            requests.append(json.dumps({"id": str(len(requests)), "method": "tools", "params": binding}))
            contracts.append((identifier, send))
    process = subprocess.run([str(executable)], input="\n".join(requests) + "\n", text=True,
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=30, check=True)
    if len(process.stdout) > 1 << 20:
        raise ValueError("Calendar/mail metadata exceeds qualification bound")
    replies = process.stdout.splitlines()
    if len(replies) != len(contracts):
        raise ValueError("Calendar/mail metadata response count differs")
    receipt = []
    for index, (line, (identifier, send)) in enumerate(zip(replies, contracts)):
        reply = json.loads(line)
        if reply.get("id") != str(index) or "error" in reply:
            raise ValueError("Calendar/mail metadata binding failed")
        receipt.append({"catalog_id": identifier, **verify_calendar_mail_tools(identifier, reply.get("result"), send_authorized=send)})
    return {"source": "acquired native runner tools metadata", "real_provider_grants": 0, "provider_calls": 0, "contracts": receipt}


def fetch(url, limit=16 << 20):
    request = urllib.request.Request(url, headers={"User-Agent": "openagent-connector-qualification"})
    with urllib.request.urlopen(request, timeout=60) as response:
        value = response.read(limit + 1)
    if len(value) > limit:
        raise ValueError("Public dependency exceeds its bound")
    return value


def public_closure(destination):
    """Keep the published beta39/Core22 host separate from the candidate SDK."""
    destination.mkdir()
    receipts = []
    for repository, tag, pinned_manifest in PUBLIC_BASELINES:
        base = f"https://api.github.com/repos/openagent-uno/{repository}/releases/tags/{tag}"
        release = json.loads(fetch(base))
        assert not release["draft"]
        assets = {item["name"]: item for item in release["assets"]}
        manifest_data = fetch(assets["manifest.json"]["browser_download_url"])
        manifest_sha = sha(manifest_data)
        assert assets["manifest.json"]["digest"] == "sha256:" + manifest_sha
        if pinned_manifest is not None:
            assert manifest_sha == pinned_manifest
        manifest = json.loads(manifest_data)
        if "wheels" in manifest:
            expected = {item["file"]: item["sha256"] for item in manifest["wheels"]}
        elif "artifacts" in manifest:
            expected = {item["path"]: item["sha256"] for item in manifest["artifacts"]}
        else:
            expected = {name: item["sha256"] for name, item in manifest["files"].items()}
        files = {}
        for name, asset in assets.items():
            if not name.endswith(".whl"):
                continue
            assert Path(name).name == name and name in expected
            data = fetch(asset["browser_download_url"])
            assert sha(data) == expected[name] and len(data) == asset["size"]
            assert asset["digest"] == "sha256:" + expected[name]
            target = destination / name
            if target.exists():
                assert sha(target.read_bytes()) == expected[name]
            else:
                target.write_bytes(data)
            files[name] = {"sha256": expected[name], "bytes": len(data)}
        receipts.append({"repository": repository, "tag": tag,
                         "manifest_sha256": manifest_sha, "files": files})
    base = "https://github.com/openagent-uno/openagent/releases/download/v1.0.0b6/"
    index_data = fetch(base + "release-index.json")
    assert sha(index_data) == HOST_TOOLS_INDEX
    index = json.loads(index_data)
    assert index["source_commit"] == "aa8dafb3ef14066dbdaadbbf66bc9b3a00b801e0"
    wheel = index["python_wheel"]
    assert wheel["asset"] == "openagent_host_tools-1.0.0b6-py3-none-any.whl"
    data = fetch(base + wheel["asset"])
    assert sha(data) == wheel["sha256"]
    (destination / wheel["asset"]).write_bytes(data)
    receipts.append({"repository": "openagent", "tag": "v1.0.0b6",
                     "index_sha256": HOST_TOOLS_INDEX,
                     "files": {wheel["asset"]: {"sha256": sha(data), "bytes": len(data)}}})
    assert sha((destination / PROTOCOL).read_bytes()) == PROTOCOL_SHA
    return receipts


def auth_assets(source, bundles, output, evidence, commit, version, native_target):
    """Extract the freshly built Linux binary; do not compile a second image."""
    destination = output / "auth"
    destination.mkdir()
    sdk_version = json.loads((bundles / "manifest.json").read_bytes())["version"]
    with tarfile.open(bundles / f"openagent-connectors-{sdk_version}-linux-x64.tar.gz") as archive:
        binary = archive.extractfile("bin/openagent-connector-auth").read()
    binary_name = "openagent-connector-auth-linux-amd64"
    (destination / binary_name).write_bytes(binary)
    (destination / binary_name).chmod(0o755)
    sources = {}
    names = subprocess.check_output(["git", "ls-files", "packages/connectors"], cwd=source, text=True).splitlines()
    for name in names:
        sources[name] = sha((source / name).read_bytes())
    scope_hash = sha(json.dumps(sources, sort_keys=True, separators=(",", ":")).encode())
    files = {binary_name: {"sha256": sha(binary), "bytes": len(binary)}}
    qualification = {"format": 1, "version": version, "component": "connector-auth",
        "source_commit": commit, "source_sha256": scope_hash, "go_toolchain": "go1.26.9",
        "status": "contract-qualified-prerelease", "binary": files[binary_name],
        "sdk_qualification_sha256": sha((bundles / "qualification.json").read_bytes()),
        "evidence": {path.name: {"sha256": sha(path.read_bytes()), "bytes": path.stat().st_size}
                     for path in (evidence / "race.log", evidence / "vet.log", evidence / "govulncheck.log",
                                  evidence / "native-broker.json")},
        "coverage": {"linux_amd64": "Linux binary artifact; native coverage is listed separately",
                     "native": native_target + " ephemeral broker fixture from the same SDK build"},
        "pending": ["native Linux deployment acceptance", "real provider OAuth",
                    "dual-server Shopify/privacy/capacity qualification", "public enrollment"]}
    write(destination / "qualification.json", qualification)
    manifest = {"format": 1, "component": "connector-auth", "version": version,
        "contract": "openagent-connectors/v1", "connector_module_version": sdk_version,
        "source_repository": "openagent-uno/openagent-tools", "source_ref": "connector-auth-v" + version,
        "source_commit": commit, "source_scope": "packages/connectors", "source_sha256": scope_hash,
        "sources": sources, "dirty_snapshot": False, "go_toolchain": "go1.26.9",
        "platform": "linux-amd64", "build": {"CGO_ENABLED": "0", "GOWORK": "off", "GOOS": "linux",
        "GOARCH": "amd64", "trimpath": True, "ldflags": "-s -w"}, "files": files,
        "qualification": {"file": "qualification.json", "sha256": sha((destination / "qualification.json").read_bytes())}}
    write(destination / "manifest.json", manifest)
    (destination / "SHA256SUMS").write_text("".join(
        f"{sha(path.read_bytes())}  {path.name}\n" for path in sorted(destination.iterdir()) if path.is_file()))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--auth-version", help="Optional independently reviewed Auth candidate version; no Auth assets by default")
    parser.add_argument("--expected-sdk-version", help="Optional operator-reviewed version pin; older invocations remain supported")
    args = parser.parse_args()
    source, output = args.source.resolve(), args.output.resolve()
    system = {"Darwin": "darwin", "Linux": "linux"}.get(platform.system())
    arch = {"arm64": "arm64", "aarch64": "arm64", "x86_64": "x64", "AMD64": "x64"}.get(platform.machine())
    assert system is not None and arch is not None, "Only native Linux/macOS arm64/x64 workers are supported"
    native_target = system + "-" + arch
    assert args.auth_version is None or re.fullmatch(r"\d+\.\d+\.\d+", args.auth_version)
    assert args.expected_sdk_version is None or re.fullmatch(r"\d+\.\d+\.\d+", args.expected_sdk_version)
    sdk_version = source_sdk_version(source, args.expected_sdk_version)
    output.mkdir(exist_ok=False)
    evidence = output / "evidence"
    evidence.mkdir()
    temporary = output.parent / "qualification-private"
    temporary.mkdir(mode=0o700, exist_ok=False)
    env = dict(os.environ, GOMAXPROCS="1", GOMEMLIMIT="1GiB", GOFLAGS="-p=1", GOTOOLCHAIN="local", GOWORK="off",
               UV_CONCURRENT_BUILDS="1", UV_CONCURRENT_DOWNLOADS="1", UV_CONCURRENT_INSTALLS="1")
    assert subprocess.check_output(["go", "env", "GOVERSION"], cwd=source / "packages/connectors", env=env, text=True).strip() == "go1.26.9"

    def run(command, name, cwd=source):
        with (evidence / (name + ".log")).open("w") as log:
            subprocess.run(command, cwd=cwd, env=env, stdout=log, stderr=subprocess.STDOUT, check=True)

    commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=source, text=True).strip()
    assert commit == os.environ["PAYLOAD_SOURCE"]
    assert not subprocess.check_output(["git", "status", "--porcelain"], cwd=source).strip()
    subprocess.run(["git", "merge-base", "--is-ancestor", commit, "origin/main"], cwd=source, check=True)
    write(evidence / "execution.json", {"payload_source_commit": commit,
          "executor_commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=Path(__file__).resolve().parents[1], text=True).strip(),
          "runner": native_target,
          "run_url": (os.environ["GITHUB_SERVER_URL"] + "/" + os.environ["GITHUB_REPOSITORY"] +
                     "/actions/runs/" + os.environ["GITHUB_RUN_ID"]) if os.environ.get("GITHUB_RUN_ID") else None,
          "go_toolchain": "go1.26.9", "sdk_version": sdk_version, "parallel_jobs": 1, "gomaxprocs": 1,
          "publication": False, "real_provider_grants": 0})
    try:
        module = source / "packages/connectors"
        run(["go", "test", "-race", "./..."], "race", module)
        run(["go", "vet", "./..."], "vet", module)
        run(["go", "run", "golang.org/x/vuln/cmd/govulncheck@v1.6.0", "-show", "verbose", "./..."], "govulncheck", module)
        bundles = output / "sdk"
        run(["python", "scripts/build_connectors.py", "--out", str(bundles)], "build")
        spec = importlib.util.spec_from_file_location("qualifier", source / "scripts/qualify_connectors.py")
        qualifier = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(qualifier)
        manifest = json.loads((bundles / "manifest.json").read_text())
        if manifest["version"] != sdk_version:
            raise ValueError("Built SDK version differs from the reviewed source")
        qualifier.verify_source(manifest)
        qualifier.verify_payloads(bundles, manifest)
        catalog_bytes = (bundles / "catalog.json").read_bytes()
        catalog = json.loads(catalog_bytes)
        cohort = verify_catalog_cohort(sdk_version, catalog)
        verify_source_python_catalog(source, sdk_version, catalog)
        cohort["catalog_sha256"] = sha(catalog_bytes)
        write(evidence / "catalog-cohort.json", cohort)
        lock = {"format": 1, "version": manifest["version"],
                "source_repository": "openagent-uno/openagent-tools",
                "source_ref": "connectors-v" + manifest["version"],
                "source_commit": commit, "manifest_sha256": sha((bundles / "manifest.json").read_bytes()),
                "assets": manifest["files"], "platforms": {}}
        for archive in bundles.glob("*.tar.gz"):
            with tarfile.open(archive) as stream:
                body = stream.extractfile("manifest.json").read()
                item = json.loads(body)
                lock["platforms"][item["platform"]] = {"manifest_sha256": sha(body)}
        write(evidence / "acquisition-lock.json", lock)
        write(evidence / "artifacts.json", {"source_commit": commit,
              "source_sha256": manifest["source_sha256"], "go_toolchain": "go1.26.9",
              "dirty_snapshot": False, "archives": sorted(lock["platforms"]), "verified_binaries": 12,
              "catalog_cohort": cohort})
        wheelhouse = temporary / "public-wheelhouse"
        write(evidence / "public-closure.json", public_closure(wheelhouse))
        sdk_env, host_env = temporary / "sdk-env", temporary / "host-env"
        for destination in (sdk_env, host_env):
            run(["uv", "venv", "--python", "3.11", str(destination)], destination.name)
        sdk_python, host_python = sdk_env / "bin/python", host_env / "bin/python"
        wheel = bundles / f"openagent_connectors-{manifest['version']}-py3-none-any.whl"
        run(["uv", "pip", "install", "--python", str(sdk_python), str(wheelhouse / PROTOCOL),
             str(wheel), "mcp>=1,<2"], "sdk-install")
        run(["uv", "pip", "check", "--python", str(sdk_python)], "sdk-check")
        run(["uv", "pip", "install", "--python", str(host_python), "--pre", "--find-links",
             str(wheelhouse), "openagent-framework==1.1.0b39"], "host-install")
        run(["uv", "pip", "check", "--python", str(host_python)], "host-check")
        # The published host stays on SDK0.1.3; acquisition verifies the explicit candidate lock.
        def acquire_code(lock_name, bundle_name):
            return "from pathlib import Path; from openagent_server.connector_acquisition import acquire; " + \
                f"acquire(Path({str(evidence / lock_name)!r}), {native_target!r}, " + \
                f"Path({str(temporary / bundle_name)!r}), Path({str(temporary / 'acquired-wheelhouse')!r}), Path({str(bundles)!r}))"
        run([str(host_python), "-I", "-c", acquire_code("acquisition-lock.json", "bundle")], "public-host-acquisition", temporary)
        if sdk_version == "0.1.7":
            write(evidence / "calendar-mail-metadata.json", calendar_mail_native_metadata(
                temporary / "bundle/bin/openagent-connector-runner"))
        tests = temporary / "tests"
        tests.mkdir()
        shutil.copyfile(source / "packages/connectors-python/tests/test_privacy.py", tests / "test_privacy.py")
        if sdk_version == "0.1.7":
            shutil.copyfile(source / "packages/connectors-python/tests/test_runner_provider_errors.py",
                            tests / "test_runner_provider_errors.py")
        run([str(sdk_python), "-I", "-m", "unittest", "discover", "-s", str(tests), "-v"], "privacy-tests", temporary)
        run([str(sdk_python), "-I", str(source / "scripts/verify_connectors_native.py"),
             "--bundle", str(temporary / "bundle"), "--source-commit", commit,
             "--release-directory", str(bundles),
             "--output", str(evidence)], "native", temporary)
        qualifier.qualify(bundles, evidence / "race.log", evidence / "vet.log", evidence / "govulncheck.log",
                          evidence / "artifacts.json", evidence / "consumer.json", evidence / "native-broker.json")
        # Final manifest acquired again by the unchanged public installed host.
        lock["manifest_sha256"] = sha((bundles / "manifest.json").read_bytes())
        lock["assets"] = json.loads((bundles / "manifest.json").read_text())["files"]
        write(evidence / "acquisition-lock-qualified.json", lock)
        run([str(host_python), "-I", "-c", acquire_code("acquisition-lock-qualified.json", "qualified-bundle")],
            "public-host-acquisition-qualified", temporary)
        if args.auth_version is not None:
            auth_assets(source, bundles, output, evidence, commit, args.auth_version, native_target)
        write(evidence / "status.json", {"source_commit": commit, "qualified": True,
              "sdk_version": sdk_version, "official_ids": cohort["official_ids"],
              "native": [native_target], "other_targets": "cross-compilation only",
              "real_provider_grants": 0, "public_enrollment": False})
    finally:
        shutil.rmtree(temporary)


if __name__ == "__main__":
    main()
