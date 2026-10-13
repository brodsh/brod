-- Screenshots and screencasts a publisher adds to a marketplace listing, shown before anyone deploys it. Files live under
-- "<listing id>/_media/<id>" (never a release number, so installs never copy them) and count toward the publisher's storage.
CREATE TABLE listing_media (
  id TEXT PRIMARY KEY, listing_id TEXT NOT NULL REFERENCES listings(id), kind TEXT NOT NULL CHECK (kind IN ('image', 'video')),
  content_type TEXT NOT NULL, bytes INTEGER NOT NULL, caption TEXT NOT NULL DEFAULT '', position INTEGER NOT NULL, created_at INTEGER NOT NULL
);
CREATE INDEX listing_media_listing ON listing_media(listing_id, position);
