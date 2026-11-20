"""Model-free bounded DOM read using the packaged Agent in Chrome browser."""
from __future__ import annotations
import os
import shutil
import sys
from .sources import sidecar_source


def main() -> None:
    host = sidecar_source("agent-in-chrome") / "host"
    node = os.environ.get("OPENAGENT_NODE_BINARY") or shutil.which("node")
    if node is None or not (host / "node_modules").is_dir():
        raise SystemExit("openagent-browser-read needs Node.js and packaged Agent in Chrome dependencies")
    os.execv(node, [node, str(host / "browser-read.js"), *sys.argv[1:]])


if __name__ == "__main__":
    main()
