-- Staging, as migrations/0013_staging.sql.
ALTER TABLE apps ADD COLUMN staging_version BIGINT;
ALTER TABLE uploads ADD COLUMN environment TEXT;
