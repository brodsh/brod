-- Getting an app's files back, and seeing who else is working on it, as migrations/0019_files_and_editing.sql.
CREATE TABLE downloads (
  id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL, app_id TEXT NOT NULL REFERENCES apps(id), version BIGINT NOT NULL,
  user_id TEXT NOT NULL, expires_at BIGINT NOT NULL
);
CREATE TABLE editing (
  app_id TEXT NOT NULL REFERENCES apps(id), user_id TEXT NOT NULL, email TEXT NOT NULL, actor TEXT NOT NULL,
  base_version BIGINT, since BIGINT NOT NULL, last_at BIGINT NOT NULL, PRIMARY KEY (app_id, user_id)
);
