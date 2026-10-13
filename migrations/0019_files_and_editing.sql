-- Getting an app's files back, and seeing who else is working on it.
-- downloads: a short-lived address for a version's files as a tar.gz, for bundles too large to return inline. The id is
-- its own credential, like an upload address; it works until it expires.
CREATE TABLE downloads (
  id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL, app_id TEXT NOT NULL REFERENCES apps(id), version INTEGER NOT NULL,
  user_id TEXT NOT NULL, expires_at INTEGER NOT NULL
);
-- editing: who has been working on an app lately, one row per app and person. Getting an app's files or deploying it
-- sets last_at; others are warned for a while after (never blocked). actor is the agent connection or the person's email.
CREATE TABLE editing (
  app_id TEXT NOT NULL REFERENCES apps(id), user_id TEXT NOT NULL, email TEXT NOT NULL, actor TEXT NOT NULL,
  base_version INTEGER, since INTEGER NOT NULL, last_at INTEGER NOT NULL, PRIMARY KEY (app_id, user_id)
);
