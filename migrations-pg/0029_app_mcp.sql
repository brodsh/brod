-- App MCP, as migrations/0029_app_mcp.sql.
ALTER TABLE versions ADD COLUMN mcp TEXT;
ALTER TABLE oauth_codes ADD COLUMN resource TEXT;
CREATE TABLE app_tokens (
  id TEXT PRIMARY KEY, app_id TEXT NOT NULL REFERENCES apps(id), user_id TEXT NOT NULL REFERENCES users(id),
  resource TEXT NOT NULL, name TEXT NOT NULL, client_id TEXT, hash TEXT NOT NULL UNIQUE,
  created_at BIGINT NOT NULL, last_used_at BIGINT, expires_at BIGINT,
  refresh_hash TEXT UNIQUE, prev_refresh_hash TEXT, refresh_expires_at BIGINT, revoked_at BIGINT
);
CREATE INDEX app_tokens_app ON app_tokens(app_id);
CREATE INDEX app_tokens_prev_refresh ON app_tokens(prev_refresh_hash);
