-- Managed Postgres for apps and their backups, as migrations/0023_databases.sql.
CREATE TABLE databases (
  id TEXT PRIMARY KEY, app_id TEXT NOT NULL UNIQUE, engine TEXT NOT NULL DEFAULT 'postgres',
  name TEXT NOT NULL, role TEXT NOT NULL, secret_ref TEXT NOT NULL, created_at BIGINT NOT NULL,
  bytes BIGINT, measured_at BIGINT, drilled_at BIGINT
);
CREATE TABLE backups (
  id TEXT PRIMARY KEY, database_id TEXT NOT NULL, app_id TEXT, key TEXT NOT NULL, bytes BIGINT,
  state TEXT NOT NULL, kind TEXT NOT NULL DEFAULT 'nightly', error TEXT, row_counts TEXT,
  created_at BIGINT NOT NULL, finished_at BIGINT, restored_test_at BIGINT, drill_error TEXT, expires_at BIGINT
);
CREATE INDEX backups_database ON backups(database_id, created_at);
ALTER TABLE apps ADD COLUMN database_id TEXT;
