-- Marketplace previews Brod takes itself (preview.rs): a listing's media are either taken by Brod ('auto') or
-- uploaded by the publisher ('upload'), and a listing remembers which release its automatic previews show.
ALTER TABLE listing_media ADD COLUMN source TEXT NOT NULL DEFAULT 'upload' CHECK (source IN ('upload', 'auto'));
ALTER TABLE listings ADD COLUMN previews_release INTEGER;
