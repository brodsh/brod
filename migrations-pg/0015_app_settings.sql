-- App settings, as migrations/0015_app_settings.sql.
ALTER TABLE versions ADD COLUMN settings TEXT;
ALTER TABLE releases ADD COLUMN settings TEXT;
CREATE TABLE app_settings (
  app_id TEXT NOT NULL REFERENCES apps(id), key TEXT NOT NULL, value TEXT NOT NULL, content_type TEXT,
  bytes BIGINT NOT NULL DEFAULT 0, updated_at BIGINT NOT NULL, updated_by TEXT NOT NULL,
  PRIMARY KEY (app_id, key)
);
