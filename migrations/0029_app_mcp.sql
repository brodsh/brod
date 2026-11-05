-- App MCP (app_mcp.rs): an app names one path of its server code as its MCP endpoint, and MCP clients sign in to it
-- with Brod's OAuth server instead of a secret of the app's own.
--
-- versions.mcp: the path the version's brod.json declares ("mcp": "/api/mcp"), NULL when it declares none. It travels
-- with the version (a rollback or a publish from staging brings its declaration along) and needs no person to approve
-- it: it never lets anyone in who could not open the app already.
ALTER TABLE versions ADD COLUMN mcp TEXT;

-- The resource (RFC 8707) a sign-in asked for: an app's MCP address, or NULL for Brod's own /mcp.
ALTER TABLE oauth_codes ADD COLUMN resource TEXT;

-- Tokens for one app's MCP endpoint, kept apart from tokens (Brod's own connections) so neither kind can ever be read
-- as the other. resource is the exact address the token is for (https://<app host><mcp path>); the gateway takes it
-- only there, and checks on every request that the person may still open the app. A sign-in (client_id set) has an
-- access token that lives an hour and a rotating refresh token, as tokens does; prev_refresh_hash catches a copied one.
CREATE TABLE app_tokens (
  id TEXT PRIMARY KEY, app_id TEXT NOT NULL REFERENCES apps(id), user_id TEXT NOT NULL REFERENCES users(id),
  resource TEXT NOT NULL, name TEXT NOT NULL, client_id TEXT, hash TEXT NOT NULL UNIQUE,
  created_at INTEGER NOT NULL, last_used_at INTEGER, expires_at INTEGER,
  refresh_hash TEXT UNIQUE, prev_refresh_hash TEXT, refresh_expires_at INTEGER, revoked_at INTEGER
);
CREATE INDEX app_tokens_app ON app_tokens(app_id);
CREATE INDEX app_tokens_prev_refresh ON app_tokens(prev_refresh_hash);
