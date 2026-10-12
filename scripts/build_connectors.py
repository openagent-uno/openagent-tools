#!/usr/bin/env python3
"""Build immutable shared connector binaries, a Python wheel and checksum manifests."""
import argparse
import gzip
import hashlib
import io
import json
import os
import re
import shutil
from pathlib import Path
import subprocess
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parents[1]
MODULE = ROOT / "packages/connectors"
PLATFORMS = {"darwin-arm64": ("darwin", "arm64"), "darwin-x64": ("darwin", "amd64"),
             "linux-arm64": ("linux", "arm64"), "linux-x64": ("linux", "amd64"),
             "win32-arm64": ("windows", "arm64"), "win32-x64": ("windows", "amd64")}


def run(*args, cwd=ROOT, env=None):
    return subprocess.check_output(args, cwd=cwd, env=env, text=True).strip()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--allow-dirty", action="store_true")
    args = parser.parse_args()
    destination = args.out.resolve()
    if destination.exists() and any(destination.iterdir()):
        parser.error("Output directory must be empty")
    dirty = bool(run("git", "status", "--porcelain"))
    if dirty and not args.allow_dirty:
        parser.error("Commit the source snapshot before publishing artifacts")
    destination.mkdir(parents=True, exist_ok=True)
    commit = run("git", "rev-parse", "HEAD")
    version_match = re.search(r'const Version = "(\d+\.\d+\.\d+)"', (MODULE / "catalog.go").read_text())
    python_match = re.search(r'^version = "(\d+\.\d+\.\d+)"', (ROOT / "packages/connectors-python/pyproject.toml").read_text(), re.MULTILINE)
    if not version_match or not python_match or version_match[1] != python_match[1]:
        parser.error("Go and Python connector versions must match")
    version = version_match[1]
    sources = {}
    with tempfile.TemporaryDirectory(prefix="openagent-connectors-build-") as temporary:
        scratch = Path(temporary)
        snapshot = scratch / "source"
        names = subprocess.check_output(["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"], cwd=ROOT).decode().split("\0")
        for name in sorted(set(names) - {""}):
            source = ROOT / name
            if not source.is_file():
                continue
            if source.is_symlink():
                raise ValueError("Source snapshot cannot follow symbolic links: " + name)
            data = source.read_bytes()
            sources[name] = hashlib.sha256(data).hexdigest()
            target = snapshot / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
            shutil.copymode(source, target)
        module = snapshot / "packages/connectors"
        source_digest = hashlib.sha256(json.dumps(sources,sort_keys=True,separators=(",",":")).encode()).hexdigest()
        environment = dict(os.environ, CGO_ENABLED="0", GOWORK="off")
        local = scratch / "catalog-runner"
        subprocess.run(["go", "build", "-trimpath", "-o", str(local), "./cmd/connector-runner"], cwd=module, env=environment, check=True)
        reply = subprocess.check_output([str(local)], input=b'{"id":"catalog","method":"catalog"}\n')
        catalog = json.loads(reply)["result"]
        (destination / "catalog.json").write_text(json.dumps(catalog, indent=2) + "\n")
        (snapshot / "packages/connectors-python/src/openagent_connectors/catalog.json").write_text(
            json.dumps({"version": version, "connectors": catalog}, indent=2) + "\n")
        for platform, (goos, goarch) in PLATFORMS.items():
            files = {}
            for program in ("connector-runner", "connector-auth"):
                filename = f"openagent-{program}" + (".exe" if goos == "windows" else "")
                binary = scratch / f"{platform}-{filename}"
                subprocess.run(["go", "build", "-trimpath", "-ldflags=-s -w", "-o", str(binary), f"./cmd/{program}"],
                               cwd=module, env=dict(environment, GOOS=goos, GOARCH=goarch), check=True)
                files[f"bin/{filename}"] = binary.read_bytes()
            manifest = {"format": 1, "version": version, "platform": platform, "source_commit": commit, "source_sha256": source_digest,
                        "dirty_snapshot": dirty, "files": {name: {"sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)} for name, data in files.items()}}
            files["manifest.json"] = (json.dumps(manifest, indent=2) + "\n").encode()
            name = f"openagent-connectors-{version}-{platform}.tar.gz"
            with (destination / name).open("wb") as stream:
                with gzip.GzipFile(filename="", fileobj=stream, mode="wb", mtime=0) as compressed:
                    with tarfile.open(fileobj=compressed, mode="w") as archive:
                        for filename, data in files.items():
                            entry = tarfile.TarInfo(filename)
                            entry.size, entry.mode, entry.mtime = len(data), 0o755 if filename.startswith("bin/") else 0o644, 0
                            archive.addfile(entry, io.BytesIO(data))

        subprocess.run(["uv", "build", "--wheel", "--out-dir", str(destination), str(snapshot / "packages/connectors-python")], check=True)
    files = {file.name: {"sha256": hashlib.sha256(file.read_bytes()).hexdigest(), "bytes": file.stat().st_size}
             for file in sorted(destination.iterdir()) if file.is_file()}
    (destination / "manifest.json").write_text(json.dumps({"format": 1, "version": version, "source_commit": commit, "source_sha256": source_digest,
        "dirty_snapshot": dirty, "release_status": "development-unqualified", "files": files}, indent=2) + "\n")
    files["manifest.json"] = {"sha256": hashlib.sha256((destination / "manifest.json").read_bytes()).hexdigest()}
    (destination / "SHA256SUMS").write_text("".join(f'{data["sha256"]}  {name}\n' for name, data in files.items()))
    print(f"Built {len(PLATFORMS)} platform bundles and the Python adapter: {destination}")


if __name__ == "__main__":
    main()
