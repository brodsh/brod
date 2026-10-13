-- Step 5: analytics, as migrations/0012_analytics.sql.
-- These tables only ever grow at the end (rows arrive in time order) and lose their oldest rows to the retention sweep,
-- so they are packed full (fillfactor 100: rows are never updated in place, except request_stats' counters), vacuumed
-- after a smaller share of dead rows than the default, and indexed for the two ways they are read:
--   * (app_id, at) and (workspace_id, at) B-trees: every dashboard read is one app or one workspace over a time range,
--     so it reads exactly the rows in range, in time order. COLLATE "C" keeps the ids' comparisons byte-wise and cheap.
--   * a BRIN index on at: rows land in time order, so a few hundred bytes of block ranges answer "older than" for the
--     whole table, which the retention sweep and any cross-workspace range read use.

CREATE TABLE page_views (
  workspace_id TEXT COLLATE "C" NOT NULL,
  app_id TEXT COLLATE "C" NOT NULL,
  at BIGINT NOT NULL,
  visitor TEXT COLLATE "C" NOT NULL,
  path TEXT NOT NULL,
  referrer TEXT NOT NULL DEFAULT '',
  utm_source TEXT NOT NULL DEFAULT '',
  utm_medium TEXT NOT NULL DEFAULT '',
  utm_campaign TEXT NOT NULL DEFAULT '',
  country TEXT NOT NULL DEFAULT '',
  lang TEXT NOT NULL DEFAULT '',
  browser TEXT NOT NULL DEFAULT '',
  os TEXT NOT NULL DEFAULT '',
  device TEXT NOT NULL DEFAULT '',
  signed_in BIGINT NOT NULL DEFAULT 0,
  status BIGINT NOT NULL DEFAULT 200,
  ms BIGINT NOT NULL DEFAULT 0
) WITH (fillfactor = 100, autovacuum_vacuum_scale_factor = 0.05, autovacuum_analyze_scale_factor = 0.02);
CREATE INDEX page_views_app_at ON page_views (app_id, at);
CREATE INDEX page_views_ws_at ON page_views (workspace_id, at);
CREATE INDEX page_views_at_brin ON page_views USING brin (at) WITH (pages_per_range = 32);

CREATE TABLE app_events (
  workspace_id TEXT COLLATE "C" NOT NULL,
  app_id TEXT COLLATE "C" NOT NULL,
  at BIGINT NOT NULL,
  visitor TEXT COLLATE "C" NOT NULL,
  path TEXT NOT NULL DEFAULT '',
  kind TEXT COLLATE "C" NOT NULL,
  name TEXT NOT NULL,
  value DOUBLE PRECISION,
  label TEXT NOT NULL DEFAULT ''
) WITH (fillfactor = 100, autovacuum_vacuum_scale_factor = 0.05, autovacuum_analyze_scale_factor = 0.02);
CREATE INDEX app_events_app_at ON app_events (app_id, at);
CREATE INDEX app_events_ws_at ON app_events (workspace_id, at);
CREATE INDEX app_events_at_brin ON app_events USING brin (at) WITH (pages_per_range = 32);

-- Counters updated in place every flush: leave room on each page so the update stays on the page (a HOT update,
-- which touches no index).
CREATE TABLE request_stats (
  app_id TEXT COLLATE "C" NOT NULL,
  hour BIGINT NOT NULL,
  workspace_id TEXT COLLATE "C" NOT NULL,
  requests BIGINT NOT NULL DEFAULT 0,
  bytes BIGINT NOT NULL DEFAULT 0,
  s2xx BIGINT NOT NULL DEFAULT 0,
  s3xx BIGINT NOT NULL DEFAULT 0,
  s4xx BIGINT NOT NULL DEFAULT 0,
  s5xx BIGINT NOT NULL DEFAULT 0,
  bots BIGINT NOT NULL DEFAULT 0,
  ms_total BIGINT NOT NULL DEFAULT 0,
  lat0 BIGINT NOT NULL DEFAULT 0, lat1 BIGINT NOT NULL DEFAULT 0, lat2 BIGINT NOT NULL DEFAULT 0, lat3 BIGINT NOT NULL DEFAULT 0,
  lat4 BIGINT NOT NULL DEFAULT 0, lat5 BIGINT NOT NULL DEFAULT 0, lat6 BIGINT NOT NULL DEFAULT 0, lat7 BIGINT NOT NULL DEFAULT 0,
  PRIMARY KEY (app_id, hour)
) WITH (fillfactor = 70);
CREATE INDEX request_stats_ws_hour ON request_stats (workspace_id, hour);
