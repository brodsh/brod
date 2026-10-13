-- Custom domains. A workspace claims a hostname, then proves it owns it with a TXT record at _brod.<hostname>.
-- With app_id set, the hostname serves that one app (shop.example.com). With app_id NULL it is a wildcard for the
-- whole workspace: <app>.<hostname> serves that app, and <hostname> itself opens the workspace home page.
-- Several workspaces may claim the same hostname while it is unproven (so nobody can squat on a name), but only one
-- may prove it: the partial unique index below. Only proven rows are served.
CREATE TABLE domains (
  id TEXT PRIMARY KEY,
  hostname TEXT NOT NULL,
  workspace_id TEXT NOT NULL REFERENCES workspaces(id),
  app_id TEXT REFERENCES apps(id),
  token TEXT NOT NULL,
  verified_at INTEGER,
  created_by TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  UNIQUE (hostname, workspace_id)
);
CREATE UNIQUE INDEX domains_verified ON domains(hostname) WHERE verified_at IS NOT NULL;
CREATE INDEX domains_workspace ON domains(workspace_id);
CREATE INDEX domains_app ON domains(app_id);
