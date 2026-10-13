-- Step 5: analytics. The Rust server writes these in batches (analytics.rs) and deletes rows older than the
-- workspace's plan keeps (30 days free, a year solo, two years team).

-- One row per page view: a document request the gateway served, or a navigation inside a single-page app that the
-- insights script reported. The visitor is the same salted, per-app, per-day hash as visit_visitors; the path has no
-- query string; the referrer is only the host of another site. Nothing here identifies a person.
CREATE TABLE page_views (
  workspace_id TEXT NOT NULL,
  app_id TEXT NOT NULL,
  at INTEGER NOT NULL,
  visitor TEXT NOT NULL,
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
  signed_in INTEGER NOT NULL DEFAULT 0,
  status INTEGER NOT NULL DEFAULT 200,
  ms INTEGER NOT NULL DEFAULT 0
);
-- Every read is one app (or one workspace) over a time range, and so is the retention sweep.
CREATE INDEX page_views_app_at ON page_views (app_id, at);
CREATE INDEX page_views_ws_at ON page_views (workspace_id, at);

-- What the insights script reports from the browser: kind is 'vital' (LCP, INP, CLS, FCP, TTFB), 'engage' (seconds
-- on a page), 'screen', 'error', 'outbound' (a click to another site) or 'event' (window.brod.track).
CREATE TABLE app_events (
  workspace_id TEXT NOT NULL,
  app_id TEXT NOT NULL,
  at INTEGER NOT NULL,
  visitor TEXT NOT NULL,
  path TEXT NOT NULL DEFAULT '',
  kind TEXT NOT NULL,
  name TEXT NOT NULL,
  value REAL,
  label TEXT NOT NULL DEFAULT ''
);
CREATE INDEX app_events_app_at ON app_events (app_id, at);
CREATE INDEX app_events_ws_at ON app_events (workspace_id, at);

-- Every request an app answered, per app per UTC hour (hour = the hour's start in ms): status classes, bytes sent,
-- crawlers, and server time as a histogram (lat0 under 10 ms, then 50, 100, 250, 500, 1000, 2500, and lat7 slower).
CREATE TABLE request_stats (
  app_id TEXT NOT NULL,
  hour INTEGER NOT NULL,
  workspace_id TEXT NOT NULL,
  requests INTEGER NOT NULL DEFAULT 0,
  bytes INTEGER NOT NULL DEFAULT 0,
  s2xx INTEGER NOT NULL DEFAULT 0,
  s3xx INTEGER NOT NULL DEFAULT 0,
  s4xx INTEGER NOT NULL DEFAULT 0,
  s5xx INTEGER NOT NULL DEFAULT 0,
  bots INTEGER NOT NULL DEFAULT 0,
  ms_total INTEGER NOT NULL DEFAULT 0,
  lat0 INTEGER NOT NULL DEFAULT 0, lat1 INTEGER NOT NULL DEFAULT 0, lat2 INTEGER NOT NULL DEFAULT 0, lat3 INTEGER NOT NULL DEFAULT 0,
  lat4 INTEGER NOT NULL DEFAULT 0, lat5 INTEGER NOT NULL DEFAULT 0, lat6 INTEGER NOT NULL DEFAULT 0, lat7 INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (app_id, hour)
);
CREATE INDEX request_stats_ws_hour ON request_stats (workspace_id, hour);
