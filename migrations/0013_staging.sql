-- Staging: a version an app's builders can try at <slug>--staging.<workspace>.<APPS_DOMAIN> before it goes live.
-- staging_version points at a row in versions like live_version does; NULL when nothing is waiting on staging.
-- uploads.environment remembers where a deploy by upload address goes ('staging' or 'production', NULL for the default).
ALTER TABLE apps ADD COLUMN staging_version INTEGER;
ALTER TABLE uploads ADD COLUMN environment TEXT;
