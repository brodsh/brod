-- Access mode "password": anyone with the app's address and its password can open it, without signing in.
-- password_hash keeps only a salted PBKDF2-SHA256 hash ("pbkdf2$<iterations>$<salt>$<hash>", base64url), and is
-- NULL in every other mode. SQLite cannot change a CHECK constraint, so the table is rebuilt as in
-- 0003_app_slug_per_workspace.sql: ids do not change, and deferring the foreign key check lets the old table go first.
PRAGMA defer_foreign_keys = true;

CREATE TABLE apps_new (
  id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL REFERENCES workspaces(id), owner_id TEXT NOT NULL REFERENCES users(id),
  slug TEXT NOT NULL, name TEXT NOT NULL, title TEXT NOT NULL DEFAULT '', welcome TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT 'live',
  access TEXT NOT NULL DEFAULT 'private' CHECK (access IN ('private', 'people', 'workspace', 'password', 'signed_in', 'public')),
  roles TEXT NOT NULL DEFAULT '["owner","editor","viewer"]', live_version INTEGER, created_at INTEGER NOT NULL,
  secrets_rev INTEGER NOT NULL DEFAULT 0, space_id TEXT, file_bytes INTEGER NOT NULL DEFAULT 0, data_bytes INTEGER NOT NULL DEFAULT 0,
  password_hash TEXT,
  UNIQUE (workspace_id, slug)
);
INSERT INTO apps_new (id, workspace_id, owner_id, slug, name, title, welcome, status, access, roles, live_version, created_at, secrets_rev, space_id, file_bytes, data_bytes)
  SELECT id, workspace_id, owner_id, slug, name, title, welcome, status, access, roles, live_version, created_at, secrets_rev, space_id, file_bytes, data_bytes FROM apps;
DROP TABLE apps;
ALTER TABLE apps_new RENAME TO apps;
