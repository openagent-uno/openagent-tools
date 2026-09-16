"""Build Python wheels and the independent web-search npm archive."""
from pathlib import Path
import argparse
import subprocess

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    destination = args.out.resolve()
    destination.mkdir(parents=True, exist_ok=True)
    for name in ("tool-protocol", "filesystem", "editor", "shell", "device-tools"):
        subprocess.run(["uv", "build", "--wheel", "--out-dir", str(destination)], cwd=root / "packages" / name, check=True)
    web = root / "packages/web-search"
    subprocess.run(["npm", "ci", "--ignore-scripts"], cwd=web, check=True)
    subprocess.run(["npm", "run", "build"], cwd=web, check=True)
    subprocess.run(["npm", "pack", "--pack-destination", str(destination)], cwd=web, check=True)

if __name__ == "__main__":
    main()
