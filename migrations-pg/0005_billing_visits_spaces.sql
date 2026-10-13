-- Step 4: billing through Stripe, visit counts, spaces, and storage accounting, as migrations/0005_billing_visits_spaces.sql.
-- spaces.rs compares and sorts space names with SQLite's COLLATE NOCASE. Postgres folds an unquoted name to lower case,
-- so the same SQL finds this case-insensitive collation (ICU, which ignores case for every letter, not only ASCII).

CREATE COLLATION IF NOT EXISTS nocase (provider = icu, locale = 'und-u-ks-level2', deterministic = false);

ALTER TABLE workspaces ADD COLUMN stripe_customer TEXT;
ALTER TABLE workspaces ADD COLUMN stripe_subscription TEXT;
ALTER TABLE workspaces ADD COLUMN plan_status TEXT NOT NULL DEFAULT '';
ALTER TABLE workspaces ADD COLUMN plan_renews_at BIGINT;
ALTER TABLE workspaces ADD COLUMN plan_cancel_at BIGINT;

CREATE TABLE stripe_events (id TEXT PRIMARY KEY, type TEXT NOT NULL, received_at BIGINT NOT NULL);

CREATE TABLE visits (
  app_id TEXT NOT NULL, day TEXT COLLATE "C" NOT NULL, views BIGINT NOT NULL DEFAULT 0, visitors BIGINT NOT NULL DEFAULT 0,
  PRIMARY KEY (app_id, day)
);
CREATE TABLE visit_visitors (app_id TEXT NOT NULL, day TEXT COLLATE "C" NOT NULL, hash TEXT NOT NULL, PRIMARY KEY (app_id, day, hash));

CREATE TABLE spaces (
  id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL REFERENCES workspaces(id), name TEXT NOT NULL,
  note TEXT NOT NULL DEFAULT '', created_at BIGINT NOT NULL,
  UNIQUE (workspace_id, name)
);
CREATE TABLE space_members (
  space_id TEXT NOT NULL REFERENCES spaces(id), user_id TEXT NOT NULL REFERENCES users(id),
  role TEXT NOT NULL DEFAULT 'viewer', created_at BIGINT NOT NULL,
  PRIMARY KEY (space_id, user_id)
);
CREATE INDEX space_members_user ON space_members(user_id);
ALTER TABLE apps ADD COLUMN space_id TEXT;

ALTER TABLE apps ADD COLUMN file_bytes BIGINT NOT NULL DEFAULT 0;
