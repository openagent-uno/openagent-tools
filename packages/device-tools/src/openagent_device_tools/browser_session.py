"""``openagent-browser-session``: interactive Agent in Chrome session with a live view.

Runs the packaged ``browser-session.js`` with Node.js. Arguments and environment
are passed through unchanged; see that script for the contract.
"""

from __future__ import annotations

import os
import shutil
import sys

from .sources import sidecar_source


def main() -> None:
    host = sidecar_source("agent-in-chrome") / "host"
    script = host / "browser-session.js"
    node = os.environ.get("OPENAGENT_NODE_BINARY") or shutil.which("node")
    if node is None or not script.is_file() or not (host / "node_modules").is_dir():
        sys.stderr.write(
            "openagent-browser-session needs Node.js and the Agent in Chrome dependencies "
            "(npm ci in the packaged agent-in-chrome/host directory)\n"
        )
        raise SystemExit(2)
    os.execv(node, [node, str(script), *sys.argv[1:]])


if __name__ == "__main__":
    main()
