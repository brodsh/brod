-- Git export and import (server/src/git*.rs). Brod maps every version to a git commit that is computed from the
-- version's manifest, never stored as git data: this migration only records the ids, so an imported commit can be
-- recognised and used as the base of a three-way merge.
--
-- blobs.git_oid: the git blob id (sha1 of "blob <len>\0" + content) of a stored blob, filled in lazily the first time the
-- blob is exported, because computing it needs the content.
ALTER TABLE blobs ADD COLUMN git_oid TEXT;
-- version_git_commits: the commit and tree a version exports as. commit_oid is what re-exporting the version produces.
-- source_commit_oid is the id the version had in the repository it was imported from; it is only set for imported
-- versions, and differs from commit_oid because Brod writes its own author, message and parent chain. Both are looked up
-- when a later import brings commits that descend from either.
CREATE TABLE version_git_commits (
  app_id TEXT NOT NULL, version BIGINT NOT NULL, commit_oid TEXT NOT NULL, tree_oid TEXT NOT NULL,
  source_commit_oid TEXT,
  PRIMARY KEY (app_id, version)
);
CREATE INDEX version_git_commits_oid ON version_git_commits(app_id, commit_oid);
CREATE INDEX version_git_commits_source ON version_git_commits(app_id, source_commit_oid);
-- downloads.kind: 'tar' (a version's files as tar.gz) or 'bundle' (the whole app as a git bundle).
ALTER TABLE downloads ADD COLUMN kind TEXT NOT NULL DEFAULT 'tar';
