-- Marketplace listing previews, as migrations/0011_listing_media.sql.

CREATE TABLE listing_media (
  id TEXT PRIMARY KEY, listing_id TEXT NOT NULL REFERENCES listings(id), kind TEXT NOT NULL CHECK (kind IN ('image', 'video')),
  content_type TEXT NOT NULL, bytes BIGINT NOT NULL, caption TEXT NOT NULL DEFAULT '', position BIGINT NOT NULL, created_at BIGINT NOT NULL
);
CREATE INDEX listing_media_listing ON listing_media(listing_id, position);
