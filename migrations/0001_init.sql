-- Brod schema: workspaces, people, groups, apps, access grants, versions, sign-in and audit events.

-- A person. One sign-in covers every workspace and app they can reach.
CREATE TABLE users (
  id TEXT PRIMARY KEY, email TEXT NOT NULL UNIQUE, name TEXT NOT NULL DEFAULT '',
  email_verified_at INTEGER, terms_accepted_at INTEGER, created_at INTEGER NOT NULL
);

-- A company, team or solo builder. Plans and allowances belong to the workspace.
CREATE TABLE workspaces (
  id TEXT PRIMARY KEY, slug TEXT NOT NULL UNIQUE, name TEXT NOT NULL, plan TEXT NOT NULL DEFAULT 'free',
  color TEXT NOT NULL DEFAULT '#1f6f4a', icon TEXT NOT NULL DEFAULT '', created_at INTEGER NOT NULL
);

-- admin: people, groups, billing. builder: deploy and manage apps. member: use apps. guest: named apps only.
CREATE TABLE members (
  workspace_id TEXT NOT NULL REFERENCES workspaces(id), user_id TEXT NOT NULL REFERENCES users(id),
  role TEXT NOT NULL CHECK (role IN ('admin', 'builder', 'member', 'guest')), created_at INTEGER NOT NULL,
  PRIMARY KEY (workspace_id, user_id)
);
CREATE INDEX members_user ON members(user_id);

CREATE TABLE groups (
  id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL REFERENCES workspaces(id), name TEXT NOT NULL, created_at INTEGER NOT NULL,
  UNIQUE (workspace_id, name)
);
CREATE TABLE group_members (
  group_id TEXT NOT NULL REFERENCES groups(id), user_id TEXT NOT NULL REFERENCES users(id), PRIMARY KEY (group_id, user_id)
);
CREATE INDEX group_members_user ON group_members(user_id);

-- An emailed, single-use invitation into a workspace, or into one app as a guest.
CREATE TABLE invites (
  id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL REFERENCES workspaces(id), email TEXT NOT NULL, role TEXT NOT NULL,
  app_id TEXT, app_role TEXT, hash TEXT NOT NULL UNIQUE, invited_by TEXT NOT NULL,
  created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, used_at INTEGER, revoked_at INTEGER
);
CREATE INDEX invites_workspace ON invites(workspace_id, created_at);

-- A named, revocable agent connection. It acts with the role of the person who created it.
CREATE TABLE tokens (
  id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL REFERENCES workspaces(id), user_id TEXT NOT NULL REFERENCES users(id),
  name TEXT NOT NULL, hash TEXT NOT NULL UNIQUE, created_at INTEGER NOT NULL, last_used_at INTEGER, revoked_at INTEGER
);

-- access: private (owner only), people (named people and groups), workspace, signed_in (anyone who signs in), public.
-- roles: the app roles this app understands, most powerful first, as a JSON list.
CREATE TABLE apps (
  id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL REFERENCES workspaces(id), owner_id TEXT NOT NULL REFERENCES users(id),
  slug TEXT NOT NULL UNIQUE, name TEXT NOT NULL, title TEXT NOT NULL DEFAULT '', welcome TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT 'live',
  access TEXT NOT NULL DEFAULT 'private' CHECK (access IN ('private', 'people', 'workspace', 'signed_in', 'public')),
  roles TEXT NOT NULL DEFAULT '["owner","editor","viewer"]', live_version INTEGER, created_at INTEGER NOT NULL
);
CREATE INDEX apps_workspace ON apps(workspace_id);

-- Who gets which app role. A subject is a condition: user:<id>, group:<id>, domain:<email domain>, or
-- workspace / signed_in for everyone the access mode lets in. New conditions (installed, paid) fit the same shape.
CREATE TABLE grants (
  app_id TEXT NOT NULL REFERENCES apps(id), subject TEXT NOT NULL, role TEXT NOT NULL, created_at INTEGER NOT NULL,
  PRIMARY KEY (app_id, subject)
);

CREATE TABLE versions (
  app_id TEXT NOT NULL REFERENCES apps(id), n INTEGER NOT NULL, note TEXT NOT NULL, actor TEXT NOT NULL,
  file_count INTEGER NOT NULL, bytes INTEGER NOT NULL, created_at INTEGER NOT NULL, PRIMARY KEY (app_id, n)
);
CREATE TABLE uploads (
  id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL, user_id TEXT NOT NULL, actor TEXT NOT NULL, app_slug TEXT, name TEXT,
  note TEXT NOT NULL, expires_at INTEGER NOT NULL, used_at INTEGER
);

-- Emailed sign-in links. Single use, short-lived, stored only as a hash.
CREATE TABLE login_links (
  hash TEXT PRIMARY KEY, email TEXT NOT NULL, return_to TEXT NOT NULL, created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL, used_at INTEGER
);
CREATE INDEX login_links_email ON login_links(email, created_at);

-- A platform session (app_id NULL, cookie on the API host) and the per-app sessions made from it
-- (cookie on the app's own host). Signing out revokes the platform session, which ends every app session made from it.
CREATE TABLE sessions (
  hash TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id), app_id TEXT, parent TEXT,
  created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, revoked_at INTEGER
);
CREATE INDEX sessions_parent ON sessions(parent);

-- One-time codes that carry a sign-in from the API host to an app's host.
CREATE TABLE app_codes (
  hash TEXT PRIMARY KEY, app_id TEXT NOT NULL, user_id TEXT NOT NULL, parent TEXT NOT NULL, expires_at INTEGER NOT NULL, used_at INTEGER
);

-- Changes an agent asked for that a person must confirm: widening access, inviting people.
CREATE TABLE confirmations (
  id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL, app_id TEXT, kind TEXT NOT NULL, payload TEXT NOT NULL, summary TEXT NOT NULL,
  requested_by TEXT NOT NULL, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, done_at INTEGER, done_by TEXT
);

CREATE TABLE reports (
  id TEXT PRIMARY KEY, app_id TEXT NOT NULL, reporter TEXT NOT NULL, reason TEXT NOT NULL, created_at INTEGER NOT NULL,
  status TEXT NOT NULL DEFAULT 'open'
);

CREATE TABLE events (
  id INTEGER PRIMARY KEY AUTOINCREMENT, workspace_id TEXT NOT NULL, app_id TEXT, at INTEGER NOT NULL,
  actor TEXT NOT NULL, action TEXT NOT NULL, detail TEXT NOT NULL
);
CREATE INDEX events_app ON events(app_id, at);
CREATE INDEX events_workspace ON events(workspace_id, action, at);
