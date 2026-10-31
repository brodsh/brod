-- Nodes and their join tokens, as migrations/0021_nodes.sql.
CREATE TABLE nodes (
  id TEXT PRIMARY KEY, public_key TEXT NOT NULL UNIQUE, name TEXT NOT NULL, status TEXT NOT NULL,
  capabilities TEXT NOT NULL DEFAULT '{}', resources TEXT, version TEXT, address TEXT,
  last_seen_at BIGINT, created_at BIGINT NOT NULL
);
CREATE TABLE node_join_tokens (hash TEXT PRIMARY KEY, created_by TEXT, expires_at BIGINT NOT NULL, used_at BIGINT);
