-- Bytes a server app keeps in its database and key-value store (one SQLite Durable Object in the runtime).
-- The runtime reports it after writes and Brod refreshes it every 10 minutes; it counts toward the workspace's storage.
ALTER TABLE apps ADD COLUMN data_bytes INTEGER NOT NULL DEFAULT 0;
