-- Agents that sign in with OAuth, as migrations/0004_oauth.sql.

CREATE TABLE oauth_clients (
  id TEXT PRIMARY KEY, name TEXT NOT NULL, redirect_uris TEXT NOT NULL, created_at BIGINT NOT NULL
);

CREATE TABLE oauth_codes (
  hash TEXT PRIMARY KEY, client_id TEXT NOT NULL, user_id TEXT NOT NULL REFERENCES users(id),
  workspace_id TEXT NOT NULL REFERENCES workspaces(id), redirect_uri TEXT NOT NULL, challenge TEXT NOT NULL,
  expires_at BIGINT NOT NULL, used_at BIGINT
);
