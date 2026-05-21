"""
MCP server entry-point.

Run with:
    python -m virgil_skill_my_skill
    # or via the pyproject.toml script:
    my-skill

The server exposes all @tool-decorated functions in tools.py to the agent pod.
"""
import logging
import os

from mcp.server.fastmcp import FastMCP

from .tools import register_tools

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# App bootstrap
# ---------------------------------------------------------------------------

app = FastMCP(
    name="my-skill",
    # The orchestrator mounts the shared SQLite DB path here.
    # Skills MUST NOT open the DB at a hard-coded path; read from env.
    # db_path=os.environ.get("OPENAGENT_DB_PATH", "/data/openagent.db"),
)

register_tools(app)


def main() -> None:
    """Entry-point called by pyproject.toml script and Dockerfile CMD."""
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s — %(message)s",
    )
    port = int(os.environ.get("MCP_PORT", "9230"))
    logger.info("Starting my-skill MCP server on :%d", port)
    app.run(transport="sse", host="0.0.0.0", port=port)


if __name__ == "__main__":
    main()
