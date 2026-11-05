-- Content-addressed versions (server/src/versions.rs). A version's files are no longer stored under "<app>/<n>/<path>":
-- each distinct content is stored once at the object key "blobs/<sha256>", and a version is a manifest, a sorted list of
-- (path, sha256, size, mode) kept here. A patch deploy that changes one file therefore stores one new blob and one new
-- manifest, and every unchanged file is shared with the version it came from.
--
-- blobs: one row per stored blob. There is no refcount column: "who references this" would have to be kept in step with
-- every deploy, delete and rollback, and a missed update either leaks a blob or loses one. Whether a blob is still used
-- is a lookup in manifest_entries by sha256 (indexed), done only by the garbage collector. created_at is touched
-- whenever a deploy reuses the blob, so the collector's grace period protects a blob an in-progress deploy has just
-- chosen to share.
CREATE TABLE blobs (
  sha256 TEXT PRIMARY KEY, size INTEGER NOT NULL, created_at INTEGER NOT NULL
);
CREATE INDEX blobs_created ON blobs(created_at);
-- version_manifests: one row per version that has a manifest: its parent version (the version it was built on, if any),
-- the user who deployed it (null for a version converted from the old layout), its note and its totals.
CREATE TABLE version_manifests (
  app_id TEXT NOT NULL, version INTEGER NOT NULL, parent INTEGER, author TEXT, note TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL, file_count INTEGER NOT NULL DEFAULT 0, bytes INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (app_id, version)
);
-- manifest_entries: the primary key (app_id, version, path) lists one version's files in path order with one range
-- scan; the index on sha256 answers "is this blob referenced" and "which app already has this content".
CREATE TABLE manifest_entries (
  app_id TEXT NOT NULL, version INTEGER NOT NULL, path TEXT NOT NULL, sha256 TEXT NOT NULL, size INTEGER NOT NULL,
  mode INTEGER NOT NULL DEFAULT 420,
  PRIMARY KEY (app_id, version, path)
);
CREATE INDEX manifest_entries_sha ON manifest_entries(sha256);
