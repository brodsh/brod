-- Outside addresses, as migrations/0016_network.sql.
ALTER TABLE versions ADD COLUMN network TEXT;
ALTER TABLE releases ADD COLUMN network TEXT;
CREATE TABLE network_reports (
  app_id TEXT NOT NULL REFERENCES apps(id), host TEXT NOT NULL, source TEXT NOT NULL CHECK (source IN ('server', 'browser')),
  version BIGINT, count BIGINT NOT NULL, blocked BIGINT NOT NULL DEFAULT 0, first_at BIGINT NOT NULL, last_at BIGINT NOT NULL,
  PRIMARY KEY (app_id, host, source)
);
