-- Skill-owned tables. MUST be prefixed with the skill id (kebab → underscore).
-- These tables are created by the skill on first startup.
-- Do NOT alter shared tables (entities, events, insights, relationships,
-- entity_overrides) — those go through migrations in openagent-server.

CREATE TABLE IF NOT EXISTS my_skill_state (
    id          TEXT PRIMARY KEY,           -- ULID
    key         TEXT NOT NULL UNIQUE,       -- arbitrary state key
    value       TEXT NOT NULL,             -- JSON-encoded value
    updated_at  TIMESTAMP NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS my_skill_log (
    id          TEXT PRIMARY KEY,           -- ULID
    event       TEXT NOT NULL,
    payload     JSON NOT NULL DEFAULT '{}',
    created_at  TIMESTAMP NOT NULL DEFAULT (datetime('now'))
);
