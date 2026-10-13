-- Bytes a server app keeps in its database and key-value store, as migrations/0006_app_data_bytes.sql.
ALTER TABLE apps ADD COLUMN data_bytes BIGINT NOT NULL DEFAULT 0;
