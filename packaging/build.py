"""Build release artifacts from one source snapshot and record their provenance."""
from pathlib import Path
import argparse
import hashlib
import json
import shutil
import subprocess
import tempfile

PYTHON_PACKAGES = ("tool-protocol", "filesystem", "editor", "shell", "device-tools", "execution")
NODE_PACKAGES = ("web-search", "meta-ads-mcp-server")


def command(*args, cwd):
    return subprocess.check_output(args, cwd=cwd, text=True).strip()

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    destination = args.out.resolve()
    destination.mkdir(parents=True, exist_ok=True)
    if any(destination.iterdir()):
        parser.error("Use an empty output directory to avoid mixing source snapshots")
    for executable in ("uv", "npm"):
        if shutil.which(executable) is None:
            parser.error(f"Required build frontend is unavailable: {executable}")

    revision = command("git", "rev-parse", "HEAD", cwd=root)
    dirty = bool(command("git", "status", "--porcelain", cwd=root))
    names = subprocess.check_output(
        ["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"], cwd=root
    ).decode().split("\0")
    sources = {}
    with tempfile.TemporaryDirectory(prefix="openagent-tools-build-") as temporary:
        snapshot = Path(temporary) / "source"
        snapshot.mkdir()
        for name in sorted(set(names) - {""}):
            source = root / name
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
        for name in PYTHON_PACKAGES:
            subprocess.run(
                ["uv", "build", "--wheel", "--out-dir", str(destination)],
                cwd=snapshot / "packages" / name,
                check=True,
            )
        for name in NODE_PACKAGES:
            package = snapshot / "packages" / name
            subprocess.run(["npm", "ci", "--ignore-scripts"], cwd=package, check=True)
            if name == "meta-ads-mcp-server":
                subprocess.run(["npm", "test"], cwd=package, check=True)
            else:
                subprocess.run(["npm", "run", "build"], cwd=package, check=True)
            subprocess.run(["npm", "pack", "--pack-destination", str(destination)], cwd=package, check=True)

    files = {}
    for artifact in sorted(destination.iterdir()):
        if artifact.is_file() and not artifact.name.startswith("."):
            files[artifact.name] = {
                "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
                "size_bytes": artifact.stat().st_size,
            }
    manifest = {
        "format": 1,
        "repository": "openagent-tools",
        "source_commit": revision,
        "version": "1.0.0b3",
        "dirty_snapshot": dirty,
        "source_sha256": hashlib.sha256(
            json.dumps(sources, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest(),
        "sources": sources,
        "files": files,
    }
    (destination / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print("Manifest: " + str(destination / "manifest.json"))

if __name__ == "__main__":
    main()
