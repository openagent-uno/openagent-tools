#!/usr/bin/env python3
"""Qualify an immutable connector build after its contract/artifact checks.

This does not rebuild payloads or qualify provider activation or product release.
Inputs are operator-owned logs/receipts. Their hashes are retained in the public
attestation; raw logs, tokens, credentials and absolute paths are not published.
"""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import re
import subprocess
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parents[1]
PLATFORMS = {"darwin-arm64", "darwin-x64", "linux-arm64", "linux-x64", "win32-arm64", "win32-x64"}
STATUS = "contract-qualified-prerelease"


def digest(data):
    return hashlib.sha256(data).hexdigest()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def read_receipt(path):
    data = Path(path).read_bytes()
    require(len(data) <= 1 << 20, "receipt exceeds bound")
    return json.loads(data), {"file": Path(path).name, "bytes": len(data), "sha256": digest(data)}


def verify_source(manifest):
    commit = manifest["source_commit"]
    require(bool(re.fullmatch(r"[0-9a-f]{40}", commit)), "invalid source commit")
    archive = subprocess.check_output(["git", "archive", "--format=tar", commit], cwd=ROOT)
    sources = {}
    bodies = {}
    with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
        for member in tar:
            if member.isdir():
                continue
            require(member.isfile(), "source snapshot contains a non-regular file")
            data = tar.extractfile(member).read()
            sources[member.name] = digest(data)
            if member.name in ("packages/connectors/go.mod", "packages/connectors/catalog.go"):
                bodies[member.name] = data.decode()
    source_hash = digest(json.dumps(sources, sort_keys=True, separators=(",", ":")).encode())
    require(source_hash == manifest["source_sha256"], "source digest differs from the immutable commit")
    toolchain = re.search(r"^toolchain (go\d+\.\d+\.\d+)$", bodies["packages/connectors/go.mod"], re.MULTILINE)
    version = re.search(r'const Version = "(\d+\.\d+\.\d+)"', bodies["packages/connectors/catalog.go"])
    require(toolchain is not None and toolchain[1] == manifest["go_toolchain"], "source toolchain mismatch")
    require(version is not None and version[1] == manifest["version"], "source version mismatch")


def verify_payloads(directory, manifest):
    version = manifest["version"]
    expected = {f"openagent-connectors-{version}-{platform}.tar.gz" for platform in PLATFORMS}
    expected |= {f"openagent_connectors-{version}-py3-none-any.whl", "catalog.json"}
    require(set(manifest["files"]) == expected, "unexpected build payload list")
    binaries = 0
    for name, metadata in manifest["files"].items():
        data = (directory / name).read_bytes()
        require(len(data) == metadata["bytes"] and digest(data) == metadata["sha256"], "payload checksum mismatch: " + name)
        if not name.endswith(".tar.gz"):
            continue
        with tarfile.open(fileobj=io.BytesIO(data)) as tar:
            members = tar.getmembers()
            require(all(member.isfile() for member in members), "non-regular archive entry")
            require(len(members) == 3, "unexpected archive members")
            platform_manifest = json.load(tar.extractfile("manifest.json"))
            platform = platform_manifest["platform"]
            require(platform in PLATFORMS and name == f"openagent-connectors-{version}-{platform}.tar.gz", "archive platform mismatch")
            for key in ("version", "source_commit", "source_sha256", "go_toolchain", "dirty_snapshot"):
                require(platform_manifest[key] == manifest[key], "archive provenance mismatch")
            suffix = ".exe" if platform.startswith("win32-") else ""
            files = {"bin/openagent-connector-runner" + suffix, "bin/openagent-connector-auth" + suffix}
            require(set(platform_manifest["files"]) == files, "archive binary list mismatch")
            require({member.name for member in members} == files | {"manifest.json"}, "unsafe archive path")
            for binary_name, binary_metadata in platform_manifest["files"].items():
                binary = tar.extractfile(binary_name).read()
                require(len(binary) == binary_metadata["bytes"] and digest(binary) == binary_metadata["sha256"], "binary checksum mismatch")
                with tempfile.NamedTemporaryFile() as temporary:
                    temporary.write(binary)
                    temporary.flush()
                    actual = subprocess.check_output(["go", "version", temporary.name], text=True).strip().split()[-1]
                require(actual == manifest["go_toolchain"], "compiled binary toolchain mismatch")
                binaries += 1
    require(binaries == 12, "missing compiled binary")
    expected_checksums = dict(line.split("  ", 1)[::-1] for line in (directory / "SHA256SUMS").read_text().splitlines())
    require(set(expected_checksums) == expected | {"manifest.json"}, "build checksum list mismatch")
    for name, checksum in expected_checksums.items():
        require(digest((directory / name).read_bytes()) == checksum, "build checksum mismatch")


def verify_logs(tests, vet, vulnerability, toolchain):
    records = {}
    for kind, path in (("race_tests", tests), ("vet", vet), ("govulncheck", vulnerability)):
        data = Path(path).read_bytes()
        require(len(data) <= 16 << 20, "log exceeds bound")
        value = data.decode()
        if kind == "race_tests":
            require(not re.search(r"(^FAIL|WARNING: DATA RACE|--- FAIL:)", value, re.MULTILINE), "race suite failed")
            for package in ("connectors", "connectors/auth", "connectors/oauth", "connectors/providers", "connectors/domain"):
                require(bool(re.search(r"^ok\s+github.com/openagent-uno/openagent-tools/packages/" + re.escape(package) + r"\s", value, re.MULTILINE)), "missing package race result: " + package)
        elif kind == "vet":
            require(not value.strip(), "vet did not produce a clean log")
        else:
            require("No vulnerabilities found." in value and "=== Module Results ===" not in value and "Vulnerability #" not in value, "vulnerability gate not clean")
            require(toolchain + " standard library" in value, "vulnerability scan toolchain mismatch")
        records[kind] = {"file": Path(path).name, "bytes": len(data), "sha256": digest(data)}
    return records


def atomic_json(path, value):
    atomic_bytes(path, (json.dumps(value, indent=2) + "\n").encode())


def atomic_bytes(path, data):
    with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as temporary:
        name = temporary.name
        temporary.write(data)
        temporary.flush()
        os.fsync(temporary.fileno())
    os.replace(name, path)


def qualify(directory, tests, vet, vulnerability, artifact_receipt, consumer_receipt, broker_receipt):
    directory = Path(directory)
    manifest_path = directory / "manifest.json"
    manifest = json.loads(manifest_path.read_bytes())
    require(manifest["format"] == 1 and manifest["dirty_snapshot"] is False, "dirty/unknown build cannot be qualified")
    require(manifest["release_status"] == "development-unqualified", "build already qualified or unknown status")
    require(not (directory / "qualification.json").exists(), "qualification already exists")
    verify_source(manifest)
    verify_payloads(directory, manifest)
    logs = verify_logs(tests, vet, vulnerability, manifest["go_toolchain"])
    receipts = {}
    for kind, path in (("artifacts", artifact_receipt), ("consumer", consumer_receipt), ("native_broker", broker_receipt)):
        receipt, record = read_receipt(path)
        require(receipt["source_commit"] == manifest["source_commit"], "receipt source mismatch")
        if kind == "artifacts":
            require(receipt["source_sha256"] == manifest["source_sha256"] and receipt["go_toolchain"] == manifest["go_toolchain"] and receipt["dirty_snapshot"] is False, "artifact receipt provenance mismatch")
            require(set(receipt["archives"]) == PLATFORMS and receipt["verified_binaries"] == 12, "artifact receipt incomplete")
        elif kind == "consumer":
            require(receipt["adapter"] == manifest["version"] and receipt["native_runner_toolchain"] == manifest["go_toolchain"], "consumer version mismatch")
            require(receipt["native_catalog"] == 13 and receipt["python_catalog"] == 12 and receipt["available_connectors"] == 10 and receipt["mcp_surface_import"] is True and receipt["broker_network_calls"] == 0, "consumer receipt incomplete")
        else:
            require(receipt["native"] == "darwin-arm64" and receipt["health"] == 200 and receipt["readiness"] == 503 and receipt["enrollment"] == "qa" and receipt["unsigned_start"] == 401, "native broker receipt incomplete")
            require(receipt["real_provider_grants"] == 0 and receipt["production_secret_reads"] == 0, "unexpected real-provider evidence")
        receipts[kind] = record
    payloads = {name: dict(value) for name, value in manifest["files"].items()}
    qualifier_path = Path(__file__).resolve().relative_to(ROOT).as_posix()
    qualifier_commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    qualifier_body = Path(__file__).read_bytes()
    committed_qualifier = subprocess.check_output(["git", "show", qualifier_commit + ":" + qualifier_path], cwd=ROOT)
    require(committed_qualifier == qualifier_body, "qualification tool is not committed")
    require(not subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT).strip(), "qualification tool checkout is not clean")
    attestation = {
        "format": 1, "status": STATUS, "version": manifest["version"],
        "source_commit": manifest["source_commit"], "source_sha256": manifest["source_sha256"],
        "go_toolchain": manifest["go_toolchain"], "payloads": payloads,
        "qualifier_sha256": digest(qualifier_body),
        "qualifier_source_commit": qualifier_commit,
        "qualifier_source_path": qualifier_path,
        "qualifier_source_url": "https://github.com/openagent-uno/openagent-tools/blob/" + qualifier_commit + "/" + qualifier_path,
        "checks": {"platform_bundles": 6, "compiled_binaries": 12, "payload_checksums": "verified", "race_tests": "passed", "vet": "passed", "govulncheck": {"tool": "v1.6.0", "database": "https://vuln.go.dev", "result": "no vulnerabilities found"}},
        "evidence": {"logs": logs, "receipts": receipts},
        "coverage": {"native_runtime": ["darwin-arm64 smoke"], "other_platforms": "cross-compilation and checksum/toolchain verification only", "mcp": "published adapter/protocol import smoke; full host transport acceptance separate"},
        "pending": ["real provider OAuth and dual-server Shopify acceptance", "product-local privacy processing and coordinated product rollout", "Windows/Linux native runtime acceptance", "applicable provider reviews", "production capacity/admission and common app activation"],
        "revocation_fence": "calling installation/provider/app grant only; no Google account correlation across aliases or servers",
    }
    attestation_data = (json.dumps(attestation, indent=2) + "\n").encode()
    manifest["release_status"] = STATUS
    manifest["qualification"] = {"file": "qualification.json", "sha256": digest(attestation_data), "scope": "contract/artifact verification and macOS smoke only"}
    manifest["files"]["qualification.json"] = {"bytes": len(attestation_data), "sha256": digest(attestation_data)}
    manifest_data = (json.dumps(manifest, indent=2) + "\n").encode()
    checksums = {name: metadata["sha256"] for name, metadata in manifest["files"].items()}
    checksums["manifest.json"] = digest(manifest_data)
    sums = "".join(f"{checksum}  {name}\n" for name, checksum in checksums.items()).encode()
    atomic_bytes(directory / "qualification.json", attestation_data)
    atomic_bytes(manifest_path, manifest_data)
    atomic_bytes(directory / "SHA256SUMS", sums)
    # Never report success after a partially written publication set.
    for name, checksum in checksums.items():
        require(digest((directory / name).read_bytes()) == checksum, "qualified release checksum mismatch")
    return {"status": STATUS, "source_commit": manifest["source_commit"], "source_sha256": manifest["source_sha256"], "manifest_sha256": digest(manifest_data), "attestation_sha256": digest(attestation_data)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("directory", "tests", "vet", "vulnerability", "artifact-receipt", "consumer-receipt", "broker-receipt"):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    try:
        result = qualify(args.directory, args.tests, args.vet, args.vulnerability, args.artifact_receipt, args.consumer_receipt, args.broker_receipt)
    except (ValueError, KeyError) as error:
        parser.error(str(error))
    print(json.dumps(result))


if __name__ == "__main__":
    main()
