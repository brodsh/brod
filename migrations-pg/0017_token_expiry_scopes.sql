-- Agent connections that expire, renew and can be limited to reading, as migrations/0017_token_expiry_scopes.sql.
ALTER TABLE tokens ADD COLUMN scope TEXT NOT NULL DEFAULT 'manage' CHECK (scope IN ('manage', 'read'));
ALTER TABLE tokens ADD COLUMN expires_at BIGINT;
ALTER TABLE tokens ADD COLUMN client_id TEXT;
ALTER TABLE tokens ADD COLUMN refresh_hash TEXT;
ALTER TABLE tokens ADD COLUMN prev_refresh_hash TEXT;
ALTER TABLE tokens ADD COLUMN refresh_expires_at BIGINT;
CREATE UNIQUE INDEX tokens_refresh ON tokens(refresh_hash);
CREATE INDEX tokens_prev_refresh ON tokens(prev_refresh_hash);
ALTER TABLE oauth_codes ADD COLUMN scope TEXT NOT NULL DEFAULT 'manage';
