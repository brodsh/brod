-- Content-addressed versions, as migrations/0025_content_addressed_versions.sql.
CREATE TABLE blobs (
  sha256 TEXT PRIMARY KEY, size BIGINT NOT NULL, created_at BIGINT NOT NULL
);
CREATE INDEX blobs_created ON blobs(created_at);
-- version_manifests: one row per version that has a manifest: its parent version (the version it was built on, if any),
-- the user who deployed it (null for a version converted from the old layout), its note and its totals.
CREATE TABLE version_manifests (
  app_id TEXT NOT NULL, version BIGINT NOT NULL, parent BIGINT, author TEXT, note TEXT NOT NULL DEFAULT '',
  created_at BIGINT NOT NULL, file_count BIGINT NOT NULL DEFAULT 0, bytes BIGINT NOT NULL DEFAULT 0,
  PRIMARY KEY (app_id, version)
);
-- manifest_entries: the primary key (app_id, version, path) lists one version's files in path order with one range
-- scan; the index on sha256 answers "is this blob referenced" and "which app already has this content".
CREATE TABLE manifest_entries (
  app_id TEXT NOT NULL, version BIGINT NOT NULL, path TEXT NOT NULL, sha256 TEXT NOT NULL, size BIGINT NOT NULL,
  mode BIGINT NOT NULL DEFAULT 420,
  PRIMARY KEY (app_id, version, path)
);
CREATE INDEX manifest_entries_sha ON manifest_entries(sha256);
