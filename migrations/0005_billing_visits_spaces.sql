-- Step 4: billing through Stripe, visit counts, spaces, and storage accounting. The Rust server uses these tables.

-- The Stripe customer and subscription behind a workspace's plan. The plan column stays the source of truth for
-- allowances; Stripe's webhooks move it. plan_status is Stripe's subscription status (active, past_due, canceled, ...).
ALTER TABLE workspaces ADD COLUMN stripe_customer TEXT;
ALTER TABLE workspaces ADD COLUMN stripe_subscription TEXT;
ALTER TABLE workspaces ADD COLUMN plan_status TEXT NOT NULL DEFAULT '';
ALTER TABLE workspaces ADD COLUMN plan_renews_at INTEGER;
ALTER TABLE workspaces ADD COLUMN plan_cancel_at INTEGER;

-- Stripe event ids already applied, so a redelivered webhook changes nothing.
CREATE TABLE stripe_events (id TEXT PRIMARY KEY, type TEXT NOT NULL, received_at INTEGER NOT NULL);

-- Page views per app per UTC day (YYYY-MM-DD), and the distinct visitors behind them as salted hashes.
CREATE TABLE visits (
  app_id TEXT NOT NULL, day TEXT NOT NULL, views INTEGER NOT NULL DEFAULT 0, visitors INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (app_id, day)
);
CREATE TABLE visit_visitors (app_id TEXT NOT NULL, day TEXT NOT NULL, hash TEXT NOT NULL, PRIMARY KEY (app_id, day, hash));

-- A space groups related apps and the people who use them. Everyone in a space gets every app in it, with their
-- space role when the app has that role and the app's lowest role otherwise, wherever named grants count.
CREATE TABLE spaces (
  id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL REFERENCES workspaces(id), name TEXT NOT NULL,
  note TEXT NOT NULL DEFAULT '', created_at INTEGER NOT NULL,
  UNIQUE (workspace_id, name)
);
CREATE TABLE space_members (
  space_id TEXT NOT NULL REFERENCES spaces(id), user_id TEXT NOT NULL REFERENCES users(id),
  role TEXT NOT NULL DEFAULT 'viewer', created_at INTEGER NOT NULL,
  PRIMARY KEY (space_id, user_id)
);
CREATE INDEX space_members_user ON space_members(user_id);
ALTER TABLE apps ADD COLUMN space_id TEXT;

-- Bytes a server app keeps in env.FILES. Bundle bytes are already in versions.bytes.
ALTER TABLE apps ADD COLUMN file_bytes INTEGER NOT NULL DEFAULT 0;
