# openagent-mcp-template

> Python skeleton for writing **OpenAgent skill** MCP servers.
> Clone this, rename, implement your tools, ship.

Skills are modular MCP servers that run as sidecars in a user's agent pod on the
[Virgil platform](https://heyvirgil.ai) (or any OpenAgent deployment). They speak
the [Model Context Protocol](https://modelcontextprotocol.io) over HTTP/SSE and are
auto-discovered by the main agent pod after install.

---

## Quick start

```bash
# 1. Use this repo as a template
gh repo create my-org/virgil-skill-my-thing \
  --template openagent-uno/openagent-mcp-template --private

cd virgil-skill-my-thing

# 2. Rename everything
./scripts/rename.sh my-thing   # replaces all 'my-skill' occurrences

# 3. Edit skill.yaml — fill id, display_name, description, tier, permissions
# 4. Write your tools in src/virgil_skill_my_thing/tools.py
# 5. Run locally
python -m virgil_skill_my_thing   # listens on :9230

# 6. Talk to it
curl -s http://localhost:9230/mcp \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"tools/list","id":1}' | jq .
```

---

## Directory layout

```
openagent-mcp-template/
├── skill.yaml                    ← marketplace metadata & config schema
├── pyproject.toml                ← deps + entry-point
├── Dockerfile                    ← production image
├── .gitignore
├── README.md
├── src/
│   └── virgil_skill_my_skill/
│       ├── __init__.py
│       ├── server.py             ← FastMCP app + main()
│       ├── tools.py              ← @app.tool() functions
│       └── schema.sql            ← skill-owned SQLite tables (prefixed)
└── tests/
    └── test_tools.py
```

---

## skill.yaml

The single descriptor the Virgil orchestrator reads from the Docker image label
`com.virgil.skill.yaml` (base64-encoded). It drives:

- The **marketplace install card** (display_name, icon, description, tier)
- The **config dialog** (config_schema)
- The **k8s resources** the reconciler renders (Deployment, Service, NetworkPolicy, CronJob)
- The **MCP registration** call to the agent pod (exports)

Key fields:

| Field | Values | Notes |
|---|---|---|
| `category` | `ingester` / `reasoning` / `action` / `utility` | Shown as a badge |
| `tier` | `free` / `starter` / `pro` / `enterprise` | Gated by Kratos identity trait |
| `runtime` | `sidecar` / `central` | `sidecar` = one pod per user; `central` = shared |
| `permissions` | see below | Enforced via NetworkPolicy + Secret RBAC |
| `schedule.ingest` | cron string or `null` | Triggers `python -m … sync` |

Permissions:

| Permission | Meaning |
|---|---|
| `read:events` | SELECT on shared `events` table |
| `write:db` | INSERT/UPDATE on own tables + shared `entities`/`events`/`insights` |
| `write:vault` | Write markdown to the user's vault |
| `network:external` | Egress from the pod (Telegram API, Gmail, …) |

---

## Shared data schema

All skills read/write from the same SQLite database at `$OPENAGENT_DB_PATH`.
Shared tables: `entities`, `events`, `insights`, `relationships`, `entity_overrides`.

**Your skill MUST prefix its own tables** with `<skill_id>_` (e.g. `telegram_ingester_sessions`).
Never `ALTER` a shared table — those migrations go through `openagent-server`.

Full schema: [`architecture/data-model.md`](https://git.spicysparks.com/SpicySparks/Virgil-Server/src/branch/main/docs/architecture/data-model.md)

---

## Writing tools

```python
# src/virgil_skill_my_thing/tools.py
def register_tools(app: FastMCP) -> None:

    @app.tool()
    async def my_thing_search(query: str, limit: int = 20) -> list[dict]:
        """
        Search ingested data for a query.
        Naming: <skill_id>_<verb_noun>  e.g. telegram_ingester_search_messages
        """
        ...
```

Rules:
- **Return JSON-serialisable types** (dict, list, str, int, float, bool, None).
- **Never block the event loop** — use `asyncio` or `run_in_executor` for I/O.
- **One tool, one action.** Composition happens in the agent, not here.
- **Descriptive docstrings** — the agent uses these for tool selection.

---

## Running locally (full stack)

```bash
# Build
docker build -t virgil-skill-my-thing:dev .

# Run (mirrors what the orchestrator does in-cluster)
docker run --rm -p 9230:9230 \
  -e OPENAGENT_DB_PATH=/tmp/test.db \
  -e OPENAGENT_HTTP_TOKEN=test-token \
  -e EXAMPLE_API_KEY=your-key \
  virgil-skill-my-thing:dev

# List tools
curl -s http://localhost:9230/mcp \
  -H "X-OpenAgent-Token: test-token" \
  -d '{"jsonrpc":"2.0","method":"tools/list","id":1}' | jq '.result.tools[].name'
```

For end-to-end cluster testing see the [local dev guide](https://git.spicysparks.com/SpicySparks/Virgil-Server/src/branch/main/docs/guides/local-dev.md).

---

## Publishing

1. Push image to `hub.spicysparks.com/virgil-skill/<name>:<semver>`
2. CI reads `skill.yaml` from the image label and upserts the marketplace registry
3. Users see the skill in the dashboard `/skills` tab

---

## Related

- [Skills runtime contract](https://git.spicysparks.com/SpicySparks/Virgil-Server/src/branch/main/docs/architecture/skills.md)
- [Shared data model](https://git.spicysparks.com/SpicySparks/Virgil-Server/src/branch/main/docs/architecture/data-model.md)
- [Skills catalog](https://git.spicysparks.com/SpicySparks/Virgil-Server/src/branch/main/docs/product/skills-catalog.md)
- [openagent-sdk-python](https://github.com/openagent-uno/openagent-sdk-python) ← coming soon
