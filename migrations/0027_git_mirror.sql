-- Git mirror and two-way sync (server/src/git_mirror.rs). One row per app that mirrors to a remote repository.
-- token_sealed: the push credential, sealed with the secrets key like an app secret but kept out of the app's secrets so
-- the app's code never sees it; it is never returned by any API and never exported.
-- token_secret: instead of a token, the name of one of the app's secrets to read at push time.
-- branches: JSON {"main": "<remote branch for live>", "staging": "<remote branch for staging>"}.
CREATE TABLE git_mirrors (
  app_id TEXT PRIMARY KEY, url TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 1,
  branches TEXT NOT NULL DEFAULT '{"main":"main","staging":"staging"}', push_tags INTEGER NOT NULL DEFAULT 1,
  token_sealed TEXT, token_secret TEXT,
  sync_inbound INTEGER NOT NULL DEFAULT 0, inbound_branch TEXT NOT NULL DEFAULT 'main', webhook_secret TEXT,
  last_webhook_at INTEGER, last_poll_at INTEGER, last_inbound_oid TEXT,
  last_push_at INTEGER, last_status TEXT NOT NULL DEFAULT 'idle', last_error TEXT,
  inbound_status TEXT, inbound_error TEXT, inbound_conflicts TEXT,
  created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, updated_by TEXT
);
-- git_mirror_refs: what the remote held for each ref after the last push or check. remote_oid is the commit Brod last
-- saw or wrote there; it is both the base of the next fast-forward check and how Brod recognises its own commits.
CREATE TABLE git_mirror_refs (
  app_id TEXT NOT NULL, ref_name TEXT NOT NULL, remote_oid TEXT, tree_oid TEXT, version INTEGER,
  status TEXT NOT NULL DEFAULT 'idle', message TEXT, pushed_at INTEGER,
  PRIMARY KEY (app_id, ref_name)
);
-- git_sync_events: one row per inbound event (webhook or poll) and what became of it.
CREATE TABLE git_sync_events (
  id TEXT PRIMARY KEY, app_id TEXT NOT NULL, at INTEGER NOT NULL, source TEXT NOT NULL,
  remote_oid TEXT, branch TEXT, result TEXT NOT NULL, version INTEGER, detail TEXT
);
CREATE INDEX git_sync_events_app ON git_sync_events(app_id, at);
