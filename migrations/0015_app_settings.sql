-- App settings: values a workspace sets on its copy of an app (its name, logo, colours, wording) without changing its
-- code. Brod imposes none: an app declares the settings it reads in a brod.json file in its bundle, and versions.settings
-- keeps that declaration (JSON, NULL when there is none). A release keeps the declaration of the version it came from,
-- so the marketplace can show what an installer can customise before they install.
ALTER TABLE versions ADD COLUMN settings TEXT;
ALTER TABLE releases ADD COLUMN settings TEXT;

-- The values set on one app, as JSON. An image is a file under "<app id>/_settings/<key>" with its sniffed type in
-- content_type and its size in bytes (counted in apps.file_bytes); its value is a token that changes with each upload.
-- A setting without a row here has the default its app declares.
CREATE TABLE app_settings (
  app_id TEXT NOT NULL REFERENCES apps(id), key TEXT NOT NULL, value TEXT NOT NULL, content_type TEXT,
  bytes INTEGER NOT NULL DEFAULT 0, updated_at INTEGER NOT NULL, updated_by TEXT NOT NULL,
  PRIMARY KEY (app_id, key)
);
