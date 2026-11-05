-- Smart traffic (traffic.rs). Every page view is labelled human, suspicious or bot when it is recorded, from several
-- signals (the user agent, missing or odd headers, probe paths such as /wp-login.php, the address's request rate and
-- share of 4xx answers, and whether the insights script ever ran for the visitor). traffic_reason lists the signals
-- that decided it, comma-separated ("ua", "probe", "no_lang,burst", ...). Analytics shows humans by default.
-- Bots were never recorded as page views before this, so every existing row is a human.
ALTER TABLE page_views ADD COLUMN traffic TEXT NOT NULL DEFAULT 'human';
ALTER TABLE page_views ADD COLUMN traffic_reason TEXT NOT NULL DEFAULT '';
-- request_stats.bots now counts requests labelled bot (before: user agents that said so); suspicious ones are counted
-- apart. Humans are requests - bots - suspicious.
ALTER TABLE request_stats ADD COLUMN suspicious INTEGER NOT NULL DEFAULT 0;
