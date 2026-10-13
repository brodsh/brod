-- Step 5: the marketplace, as migrations/0008_marketplace.sql.

CREATE TABLE listings (
  id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL REFERENCES workspaces(id), app_id TEXT,
  slug TEXT NOT NULL UNIQUE, name TEXT NOT NULL, summary TEXT NOT NULL DEFAULT '', description TEXT NOT NULL DEFAULT '',
  price_cents BIGINT NOT NULL DEFAULT 0, currency TEXT NOT NULL DEFAULT 'usd',
  status TEXT NOT NULL DEFAULT 'listed' CHECK (status IN ('listed', 'unlisted')),
  latest_release BIGINT NOT NULL DEFAULT 0, created_at BIGINT NOT NULL, updated_at BIGINT NOT NULL
);
CREATE INDEX listings_workspace ON listings(workspace_id);

CREATE TABLE releases (
  listing_id TEXT NOT NULL REFERENCES listings(id), n BIGINT NOT NULL, from_version BIGINT NOT NULL, note TEXT NOT NULL,
  roles TEXT NOT NULL, secrets TEXT NOT NULL DEFAULT '[]', server TEXT, file_count BIGINT NOT NULL, bytes BIGINT NOT NULL,
  actor TEXT NOT NULL, created_at BIGINT NOT NULL,
  PRIMARY KEY (listing_id, n)
);

CREATE TABLE installs (
  app_id TEXT PRIMARY KEY REFERENCES apps(id), listing_id TEXT NOT NULL REFERENCES listings(id), release_n BIGINT NOT NULL,
  installed_by TEXT NOT NULL, installed_at BIGINT NOT NULL, updated_at BIGINT NOT NULL
);
CREATE INDEX installs_listing ON installs(listing_id);
