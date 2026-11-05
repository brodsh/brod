-- Nodes: machines that run workloads for Brod (server/src/nodes.rs). A node holds an Ed25519 key; its id is derived from
-- the public key, so a node that changes address stays the same node. It dials Brod and keeps that connection open.
-- status: joining (joined, never connected), online, draining (no new work), offline (no heartbeat and no connection for
-- 30 s), disabled (refused until enabled). capabilities and resources are JSON from the node's last heartbeat; address is
-- where it last connected from, for people to read, never for identity.
CREATE TABLE nodes (
  id TEXT PRIMARY KEY, public_key TEXT NOT NULL UNIQUE, name TEXT NOT NULL, status TEXT NOT NULL,
  capabilities TEXT NOT NULL DEFAULT '{}', resources TEXT, version TEXT, address TEXT,
  last_seen_at INTEGER, created_at INTEGER NOT NULL
);
-- node_join_tokens: one-time tokens an operator mints to join a node. Only the SHA-256 of the token is kept; it works
-- once, until expires_at.
CREATE TABLE node_join_tokens (hash TEXT PRIMARY KEY, created_by TEXT, expires_at INTEGER NOT NULL, used_at INTEGER);
