-- Several people working on one app, as migrations/0018_version_history.sql.
ALTER TABLE apps ADD COLUMN last_version BIGINT;
UPDATE apps SET last_version = (SELECT MAX(n) FROM versions WHERE versions.app_id = apps.id);
ALTER TABLE versions ADD COLUMN based_on BIGINT;
ALTER TABLE uploads ADD COLUMN base_version BIGINT;
