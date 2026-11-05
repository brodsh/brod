-- Admin mode (docs/plans/admin-mode.md). An operator runs the whole Brod server, which is a different job from a
-- workspace admin. users.operator_at is set when someone becomes an operator and NULL otherwise. BROD_ADMIN_EMAIL is
-- made an operator at boot (operator.rs).
ALTER TABLE users ADD COLUMN operator_at INTEGER;
-- instance_settings: settings an operator changes at runtime (instance.rs). value is JSON. A setting whose environment
-- variable is set is locked to that value, and its row here is ignored.
CREATE TABLE instance_settings (
  key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_by TEXT, updated_at INTEGER NOT NULL
);
-- workspace_limits: an operator's per-workspace override. It beats the workspace's plan in hosted mode and the
-- instance defaults when self-hosted. A NULL column inherits; -1 means unlimited.
CREATE TABLE workspace_limits (
  workspace_id TEXT PRIMARY KEY REFERENCES workspaces(id),
  max_running_apps INTEGER, max_members INTEGER, max_storage_mb INTEGER, analytics_days INTEGER,
  note TEXT NOT NULL DEFAULT '', updated_by TEXT, updated_at INTEGER NOT NULL
);
