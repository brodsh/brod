-- The marketplace. A builder lists one of the workspace's apps; any other workspace can install its own copy
-- and host it there. The Rust server uses these tables.

-- A listing, published from an app. Its slug is unique on the server, since the marketplace is shared by every workspace.
-- app_id is the app it is published from; it is cleared when that app is deleted, and the releases already published stay.
-- price_cents is 0 (free) for every listing for now. A paid listing is a later step, and installs refuse it until then.
CREATE TABLE listings (
  id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL REFERENCES workspaces(id), app_id TEXT,
  slug TEXT NOT NULL UNIQUE, name TEXT NOT NULL, summary TEXT NOT NULL DEFAULT '', description TEXT NOT NULL DEFAULT '',
  price_cents INTEGER NOT NULL DEFAULT 0, currency TEXT NOT NULL DEFAULT 'usd',
  status TEXT NOT NULL DEFAULT 'listed' CHECK (status IN ('listed', 'unlisted')),
  latest_release INTEGER NOT NULL DEFAULT 0, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL
);
CREATE INDEX listings_workspace ON listings(workspace_id);

-- Each publish is a release: a frozen copy of one version's files under "<listing id>/<n>/<path>", so the publisher can
-- keep deploying, roll back and delete versions without changing what installers get. secrets lists the names (never
-- the values) the app's server code reads, so an installer knows what to set.
CREATE TABLE releases (
  listing_id TEXT NOT NULL REFERENCES listings(id), n INTEGER NOT NULL, from_version INTEGER NOT NULL, note TEXT NOT NULL,
  roles TEXT NOT NULL, secrets TEXT NOT NULL DEFAULT '[]', server TEXT, file_count INTEGER NOT NULL, bytes INTEGER NOT NULL,
  actor TEXT NOT NULL, created_at INTEGER NOT NULL,
  PRIMARY KEY (listing_id, n)
);

-- An app installed from a listing stays linked to it. release_n is the release last deployed from the marketplace;
-- a newer release is offered as an update and is deployed only when someone in the installing workspace asks for it.
CREATE TABLE installs (
  app_id TEXT PRIMARY KEY REFERENCES apps(id), listing_id TEXT NOT NULL REFERENCES listings(id), release_n INTEGER NOT NULL,
  installed_by TEXT NOT NULL, installed_at INTEGER NOT NULL, updated_at INTEGER NOT NULL
);
CREATE INDEX installs_listing ON installs(listing_id);
