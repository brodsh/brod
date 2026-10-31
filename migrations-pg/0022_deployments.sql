-- Container apps and their deployments, as migrations/0022_deployments.sql.
ALTER TABLE versions ADD COLUMN runtime TEXT NOT NULL DEFAULT 'auto';
ALTER TABLE versions ADD COLUMN spec TEXT;
CREATE TABLE deployments (
  id TEXT PRIMARY KEY, app_id TEXT NOT NULL, version BIGINT NOT NULL, environment TEXT NOT NULL,
  node_id TEXT, state TEXT NOT NULL, error TEXT, error_code TEXT, container_ref TEXT, log TEXT NOT NULL DEFAULT '',
  cpu DOUBLE PRECISION NOT NULL DEFAULT 0.5, memory_mb BIGINT NOT NULL DEFAULT 512, built BIGINT NOT NULL DEFAULT 0,
  actor TEXT NOT NULL DEFAULT '', created_at BIGINT NOT NULL, updated_at BIGINT NOT NULL,
  ready_at BIGINT, stopped_at BIGINT, removed_at BIGINT
);
CREATE INDEX deployments_app ON deployments(app_id, version, state);
CREATE INDEX deployments_state ON deployments(state);
