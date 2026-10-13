-- Custom domains, as migrations/0007_custom_domains.sql.
CREATE TABLE domains (
  id TEXT PRIMARY KEY,
  hostname TEXT COLLATE "C" NOT NULL,
  workspace_id TEXT NOT NULL REFERENCES workspaces(id),
  app_id TEXT REFERENCES apps(id),
  token TEXT NOT NULL,
  verified_at BIGINT,
  created_by TEXT NOT NULL,
  created_at BIGINT NOT NULL,
  UNIQUE (hostname, workspace_id)
);
CREATE UNIQUE INDEX domains_verified ON domains(hostname) WHERE verified_at IS NOT NULL;
CREATE INDEX domains_workspace ON domains(workspace_id);
CREATE INDEX domains_app ON domains(app_id);
