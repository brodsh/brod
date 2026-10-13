-- Agents that sign in with OAuth instead of a pasted token (the MCP authorization flow).

-- MCP clients that registered themselves (RFC 7591). All are public clients: no secret, and every sign-in uses PKCE.
-- redirect_uris: a JSON list.
CREATE TABLE oauth_clients (
  id TEXT PRIMARY KEY, name TEXT NOT NULL, redirect_uris TEXT NOT NULL, created_at INTEGER NOT NULL
);

-- One-time codes from the consent page. The token endpoint swaps one for a connection token in the chosen workspace.
CREATE TABLE oauth_codes (
  hash TEXT PRIMARY KEY, client_id TEXT NOT NULL, user_id TEXT NOT NULL REFERENCES users(id),
  workspace_id TEXT NOT NULL REFERENCES workspaces(id), redirect_uri TEXT NOT NULL, challenge TEXT NOT NULL,
  expires_at INTEGER NOT NULL, used_at INTEGER
);
