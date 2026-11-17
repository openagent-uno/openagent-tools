"""Collect the locked native dependency notices without local filesystem paths."""
from pathlib import Path
import json, subprocess
root=Path(__file__).resolve().parents[1]
crate=root.parents[1]/"sidecars/computer-control"
metadata=json.loads(subprocess.check_output(["cargo","metadata","--locked","--format-version","1"],cwd=crate))
parts=["Native desktop dependencies\n===========================\nGenerated from the locked Cargo dependency graph.\n"]
for package in sorted(metadata["packages"],key=lambda item:(item["name"],item["version"])):
    if not package.get("source"):continue
    directory=Path(package["manifest_path"]).parent
    files=[p for p in directory.iterdir() if p.is_file() and (p.name.upper().startswith("LICENSE") or p.name.upper().startswith("COPYING"))]
    if package["name"]=="openh264-sys2":files.append(directory/"upstream/LICENSE")
    parts.append("\n"+package["name"]+" "+package["version"]+"\n"+str(package.get("license") or "See included notices")+"\n")
    for file in sorted(set(files)):
        parts.append("\n"+file.relative_to(directory).as_posix()+"\n"+file.read_text(errors="replace")+"\n")
(root/"native/THIRD_PARTY_NOTICES.txt").write_text("".join(parts))
