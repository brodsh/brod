-- Step 3: server apps. Server code per version, encrypted secrets per app, and request logs.

-- The server code of a version: {"main":"_worker.js","modules":["_worker.js", ...]}, or NULL for a static version.
ALTER TABLE versions ADD COLUMN server TEXT;

-- Bumped on every secret change, so the next request loads the app with its new secrets.
ALTER TABLE apps ADD COLUMN secrets_rev INTEGER NOT NULL DEFAULT 0;

-- Secret values are AES-GCM encrypted with a key derived from SECRETS_KEY. They are never returned by the API.
CREATE TABLE secrets (
  app_id TEXT NOT NULL REFERENCES apps(id), name TEXT NOT NULL, value TEXT NOT NULL,
  updated_at INTEGER NOT NULL, updated_by TEXT NOT NULL, PRIMARY KEY (app_id, name)
);

-- One row per request a server app handled: its console output and exceptions. Kept 7 days.
CREATE TABLE app_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT, app_id TEXT NOT NULL, at INTEGER NOT NULL, version INTEGER,
  method TEXT NOT NULL, path TEXT NOT NULL, status INTEGER, outcome TEXT NOT NULL, logs TEXT NOT NULL, exceptions TEXT NOT NULL
);
CREATE INDEX app_logs_app ON app_logs(app_id, at);
