-- Marketplace previews Brod takes itself, as migrations/0014_listing_previews.sql.

ALTER TABLE listing_media ADD COLUMN source TEXT NOT NULL DEFAULT 'upload' CHECK (source IN ('upload', 'auto'));
ALTER TABLE listings ADD COLUMN previews_release BIGINT;
