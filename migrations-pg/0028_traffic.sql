-- Smart traffic, as migrations/0028_traffic.sql.
ALTER TABLE page_views ADD COLUMN traffic TEXT NOT NULL DEFAULT 'human';
ALTER TABLE page_views ADD COLUMN traffic_reason TEXT NOT NULL DEFAULT '';
ALTER TABLE request_stats ADD COLUMN suspicious BIGINT NOT NULL DEFAULT 0;
