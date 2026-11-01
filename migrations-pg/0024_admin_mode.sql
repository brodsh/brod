-- Admin mode, as migrations/0024_admin_mode.sql.
ALTER TABLE users ADD COLUMN operator_at BIGINT;
CREATE TABLE instance_settings (
  key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_by TEXT, updated_at BIGINT NOT NULL
);
CREATE TABLE workspace_limits (
  workspace_id TEXT PRIMARY KEY REFERENCES workspaces(id),
  max_running_apps BIGINT, max_members BIGINT, max_storage_mb BIGINT, analytics_days BIGINT,
  note TEXT NOT NULL DEFAULT '', updated_by TEXT, updated_at BIGINT NOT NULL
);
