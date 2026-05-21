"""
MCP tool definitions.

Every function decorated with @app.tool() becomes callable by the agent pod.
Keep each tool focused on a single action; compose in the agent, not here.

Naming convention:  <skill_id>_<verb_noun>
Example:            telegram_ingester_list_chats
"""
import os
from mcp.server.fastmcp import FastMCP


def register_tools(app: FastMCP) -> None:
    """Register all tools on the FastMCP app instance."""

    @app.tool()
    async def my_skill_hello(name: str = "world") -> str:
        """
        Say hello — replace this with your first real tool.

        Args:
            name: Who to greet.

        Returns:
            A greeting string.
        """
        return f"Hello, {name}! Replace me with something useful."

    # ---------------------------------------------------------------------------
    # Example: reading from the shared SQLite DB
    # ---------------------------------------------------------------------------
    # @app.tool()
    # async def my_skill_recent_events(limit: int = 10) -> list[dict]:
    #     """Return the N most recent events from the shared events table."""
    #     import sqlite3, json
    #     db_path = os.environ["OPENAGENT_DB_PATH"]
    #     with sqlite3.connect(db_path) as conn:
    #         conn.row_factory = sqlite3.Row
    #         rows = conn.execute(
    #             "SELECT id, source, channel, timestamp, content_summary "
    #             "FROM events ORDER BY timestamp DESC LIMIT ?",
    #             (limit,)
    #         ).fetchall()
    #     return [dict(r) for r in rows]

    # ---------------------------------------------------------------------------
    # Example: writing an insight
    # ---------------------------------------------------------------------------
    # @app.tool()
    # async def my_skill_create_insight(title: str, body: str) -> str:
    #     """Write an insight to the shared insights table."""
    #     import sqlite3, time, secrets
    #     db_path = os.environ["OPENAGENT_DB_PATH"]
    #     ulid = secrets.token_hex(10).upper()
    #     with sqlite3.connect(db_path) as conn:
    #         conn.execute(
    #             "INSERT INTO insights(id, kind, generated_by, title, body, confidence) "
    #             "VALUES (?,?,?,?,?,?)",
    #             (ulid, "custom", "my-skill", title, body, 0.8)
    #         )
    #     return ulid
