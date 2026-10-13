-- Apps are now served at <app>.<workspace>.<APPS_DOMAIN>, so an app's slug only needs to be unique inside its workspace.
-- SQLite cannot drop a column's UNIQUE constraint, so the table is rebuilt. grants, versions and secrets point at apps(id),
-- which does not change; deferring the foreign key check lets the old table go before the new one takes its name.
PRAGMA defer_foreign_keys = true;

CREATE TABLE apps_new (
  id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL REFERENCES workspaces(id), owner_id TEXT NOT NULL REFERENCES users(id),
  slug TEXT NOT NULL, name TEXT NOT NULL, title TEXT NOT NULL DEFAULT '', welcome TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT 'live',
  access TEXT NOT NULL DEFAULT 'private' CHECK (access IN ('private', 'people', 'workspace', 'signed_in', 'public')),
  roles TEXT NOT NULL DEFAULT '["owner","editor","viewer"]', live_version INTEGER, created_at INTEGER NOT NULL,
  secrets_rev INTEGER NOT NULL DEFAULT 0,
  UNIQUE (workspace_id, slug)
);
INSERT INTO apps_new SELECT id, workspace_id, owner_id, slug, name, title, welcome, status, access, roles, live_version, created_at, secrets_rev FROM apps;
DROP TABLE apps;
ALTER TABLE apps_new RENAME TO apps;
