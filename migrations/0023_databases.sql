-- Managed Postgres for apps (server/src/databases.rs, backups.rs). One database per app at most, in apps-postgres
-- (never Brod's own database): name and role are both app_<hex of the app id>. secret_ref names the Brod-managed secret
-- that holds DATABASE_URL (with the role's password). bytes is the size last measured; drilled_at is when the last
-- restore drill ran.
CREATE TABLE databases (
  id TEXT PRIMARY KEY, app_id TEXT NOT NULL UNIQUE, engine TEXT NOT NULL DEFAULT 'postgres',
  name TEXT NOT NULL, role TEXT NOT NULL, secret_ref TEXT NOT NULL, created_at INTEGER NOT NULL,
  bytes INTEGER, measured_at INTEGER, drilled_at INTEGER
);
-- backups: one encrypted pg_dump in storage at key (backups/<database id>/<timestamp>.dump.enc). state is running,
-- done or failed (error says why). kind is nightly, manual or final (the one taken when the app was deleted, kept
-- until expires_at). row_counts is JSON {"schema.table": rows} counted in the dump's own snapshot, which the restore
-- drill compares against; restored_test_at is when a drill restored this backup and the counts matched.
CREATE TABLE backups (
  id TEXT PRIMARY KEY, database_id TEXT NOT NULL, app_id TEXT, key TEXT NOT NULL, bytes INTEGER,
  state TEXT NOT NULL, kind TEXT NOT NULL DEFAULT 'nightly', error TEXT, row_counts TEXT,
  created_at INTEGER NOT NULL, finished_at INTEGER, restored_test_at INTEGER, drill_error TEXT, expires_at INTEGER
);
CREATE INDEX backups_database ON backups(database_id, created_at);
ALTER TABLE apps ADD COLUMN database_id TEXT;
