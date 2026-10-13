-- Abuse protection, as migrations/0009_abuse.sql.

-- An app the platform operator took down. It serves a neutral "taken down" page and its owner cannot bring it back.
ALTER TABLE apps ADD COLUMN taken_down_at BIGINT;
ALTER TABLE apps ADD COLUMN takedown_reason TEXT NOT NULL DEFAULT '';

-- A suspended workspace: none of its apps are served, and it cannot deploy.
ALTER TABLE workspaces ADD COLUMN suspended_at BIGINT;
ALTER TABLE workspaces ADD COLUMN suspended_reason TEXT NOT NULL DEFAULT '';
-- Set by the operator: the workspace may go public before it is a day old.
ALTER TABLE workspaces ADD COLUMN trusted_at BIGINT;

-- The phishing check of a version: NULL until checked, '[]' when nothing was found, else a JSON list of reasons.
-- A flagged version keeps its app private or people-only until the operator clears it (scan_cleared_at).
ALTER TABLE versions ADD COLUMN scan TEXT;
ALTER TABLE versions ADD COLUMN scan_cleared_at BIGINT;

-- Reports from visitors (kind 'visitor') and from the phishing check ('automatic'). status: open, resolved, dismissed.
ALTER TABLE reports ADD COLUMN kind TEXT NOT NULL DEFAULT 'visitor';
ALTER TABLE reports ADD COLUMN resolved_at BIGINT;
ALTER TABLE reports ADD COLUMN note TEXT NOT NULL DEFAULT '';
CREATE INDEX reports_status ON reports(status, created_at);
CREATE INDEX reports_app ON reports(app_id, status);

-- Fixed-window counters for rate limits: key is "<bucket>:<who>:<window number>".
CREATE TABLE rate_limits (key TEXT PRIMARY KEY, n BIGINT NOT NULL, expires_at BIGINT NOT NULL);
CREATE INDEX rate_limits_expires ON rate_limits(expires_at);
