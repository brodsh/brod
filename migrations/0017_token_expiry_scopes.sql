-- Agent connections that expire, renew and can be limited to reading.
-- scope: 'manage' (deploy and change things, as before) or 'read' (status, logs and settings only).
-- expires_at: when the access token stops working; NULL never (tokens made before this, or "never" on the connections page).
-- A connection made by OAuth sign-in names its client and holds a refresh token: its access token lives an hour, and the
-- client swaps the refresh token for a new pair before then. refresh_hash is the current refresh token, prev_refresh_hash
-- the one it replaced: a replaced refresh token coming back means it was copied, so the connection is revoked.
ALTER TABLE tokens ADD COLUMN scope TEXT NOT NULL DEFAULT 'manage' CHECK (scope IN ('manage', 'read'));
ALTER TABLE tokens ADD COLUMN expires_at INTEGER;
ALTER TABLE tokens ADD COLUMN client_id TEXT;
ALTER TABLE tokens ADD COLUMN refresh_hash TEXT;
ALTER TABLE tokens ADD COLUMN prev_refresh_hash TEXT;
ALTER TABLE tokens ADD COLUMN refresh_expires_at INTEGER;
CREATE UNIQUE INDEX tokens_refresh ON tokens(refresh_hash);
CREATE INDEX tokens_prev_refresh ON tokens(prev_refresh_hash);

-- The scope the person allowed on the consent page, carried to the token endpoint.
ALTER TABLE oauth_codes ADD COLUMN scope TEXT NOT NULL DEFAULT 'manage';
