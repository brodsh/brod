-- Container apps (server/src/deployments.rs). A version records what runs it: runtime is 'auto' for the bundles Brod
-- has always served (static files, or server code on workerd, told apart by versions.server) and 'container' for a
-- source bundle with a Dockerfile. spec is JSON for a container version: port, health path, cpu, memory_mb, and once
-- built the image's manifest digest, its image id (config digest) and platform.
ALTER TABLE versions ADD COLUMN runtime TEXT NOT NULL DEFAULT 'auto';
ALTER TABLE versions ADD COLUMN spec TEXT;
-- deployments: one container version run on one node for one environment (live or staging). state follows
-- scheduled -> building -> pulling -> starting -> healthy -> serving -> draining -> stopped, or failed at any step
-- (error says why). A version is served only through a deployment in state serving. container_ref is the container's
-- name on the node; log keeps the deployment's own lines (build output, steps, failures), newest last. log_cursor is
-- where reading the container's output into app_logs got to.
CREATE TABLE deployments (
  id TEXT PRIMARY KEY, app_id TEXT NOT NULL, version INTEGER NOT NULL, environment TEXT NOT NULL,
  node_id TEXT, state TEXT NOT NULL, error TEXT, error_code TEXT, container_ref TEXT, log TEXT NOT NULL DEFAULT '',
  cpu REAL NOT NULL DEFAULT 0.5, memory_mb INTEGER NOT NULL DEFAULT 512, built INTEGER NOT NULL DEFAULT 0,
  actor TEXT NOT NULL DEFAULT '', created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL,
  ready_at INTEGER, stopped_at INTEGER, removed_at INTEGER, log_cursor TEXT
);
CREATE INDEX deployments_app ON deployments(app_id, version, state);
CREATE INDEX deployments_state ON deployments(state);
-- The container settings deploy_app was given with a one-time upload address (port, health, cpu, memory_mb), as JSON.
ALTER TABLE uploads ADD COLUMN options TEXT;
