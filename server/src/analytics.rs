// SPDX-License-Identifier: AGPL-3.0-only
// Analytics: what visitors do in a workspace's apps, kept as long as the workspace's plan allows.
//
// Three kinds of data, all collected off the request path and written in batches (one transaction every few seconds,
// as usage.rs does for daily totals):
//   * page_views: one row per page a person opened, from the gateway (document requests) and from the insights
//     script (navigations inside single-page apps). Path, external referrer host, UTM tags, country, language,
//     browser, OS, device, signed in or not, status and server time. The visitor is the same salted per-app, per-day
//     hash as usage.rs, so nothing stored identifies anyone.
//   * app_events: what the insights script reports from the browser: Core Web Vitals, time on page, screen class,
//     JavaScript errors, clicks to other sites, and custom events (window.brod.track).
//   * request_stats: every request an app answered, folded into per-app hourly counters in memory: status classes,
//     bytes, crawlers, and a server-time histogram.
//
// Reading is one indexed range scan per table, streamed and aggregated here in a single pass, so every number on the
// analytics page comes from the same read: totals, the series, sessions (a visitor's views with no gap over 30 min),
// bounce rate, entry and exit pages, every breakdown, the weekly heatmap, and the comparison with the period before.
use std::collections::{HashMap, HashSet};
use std::sync::Mutex;
use std::time::Instant;

use serde_json::{Value, json};

use crate::config::Config;
use crate::db::{Connection, Sql, Val, params, tx};
use crate::http::Req;
use crate::model::{Caller, plan, plan_named};
use crate::problem::Result;
use crate::state::State;
use crate::util::now;

const MINUTE: i64 = 60_000;
const HOUR: i64 = 3_600_000;
const DAY: i64 = 86_400_000;
/// A visitor's next view more than this long after the last starts a new session.
const SESSION_GAP: i64 = 30 * MINUTE;
/// Rows held in memory between flushes; past this a flood is dropped rather than growing without bound.
const MAX_PENDING: usize = 200_000;
/// Rows per multi-row INSERT (17 columns: well under both databases' parameter limits).
const CHUNK: usize = 50;
/// Entries per breakdown in a report.
const TOP: usize = 50;
/// Upper bounds of the server-time histogram's buckets, in ms; the last bucket is everything slower.
pub const LATENCY_BOUNDS: [i64; 7] = [10, 50, 100, 250, 500, 1000, 2500];

/// The script the gateway adds to every HTML page of a static app (server apps add it themselves).
pub const INSIGHTS_TAG: &str = "<script src=\"/_brod/insights.js\" defer></script>";
pub const INSIGHTS_JS: &str = include_str!("insights.js");

#[derive(Clone, Debug, Default)]
pub struct View {
    pub workspace_id: String,
    pub app_id: String,
    pub at: i64,
    pub visitor: String,
    pub path: String,
    pub referrer: String,
    pub utm_source: String,
    pub utm_medium: String,
    pub utm_campaign: String,
    pub country: String,
    pub lang: String,
    pub browser: String,
    pub os: String,
    pub device: String,
    pub signed_in: bool,
    pub status: i64,
    pub ms: i64,
}

#[derive(Clone, Debug, Default)]
pub struct Event {
    pub workspace_id: String,
    pub app_id: String,
    pub at: i64,
    pub visitor: String,
    pub path: String,
    pub kind: String,
    pub name: String,
    pub value: Option<f64>,
    pub label: String,
}

#[derive(Clone, Debug, Default)]
struct Stat {
    workspace_id: String,
    requests: i64,
    bytes: i64,
    s2xx: i64,
    s3xx: i64,
    s4xx: i64,
    s5xx: i64,
    bots: i64,
    ms_total: i64,
    lat: [i64; 8],
}

#[derive(Default)]
struct Pending {
    views: Vec<View>,
    events: Vec<Event>,
    stats: HashMap<(String, i64), Stat>,
}

#[derive(Default)]
pub struct Analytics {
    pending: Mutex<Pending>,
}

/// One request to an app, from the moment the gateway sees it until its response.
pub struct Hit {
    t0: Instant,
    at: i64,
    pub bot: bool,
    /// The workspace and app it reached, once known; requests that reach no app are not counted.
    pub app: Option<(String, String)>,
    /// The page view it is, if it is one someone may see.
    pub view: Option<View>,
}

impl Hit {
    pub fn new(req: &Req) -> Hit {
        Hit { t0: Instant::now(), at: now(), bot: is_bot(req.header("user-agent").unwrap_or("")), app: None, view: None }
    }
}

impl Analytics {
    /// Count a finished request, and its page view if it was one.
    pub fn finish(&self, hit: Hit, status: u16, bytes: i64) {
        let Some((workspace_id, app_id)) = hit.app else { return };
        let ms = i64::try_from(hit.t0.elapsed().as_millis()).unwrap_or(i64::MAX);
        let Ok(mut p) = self.pending.lock() else { return };
        let s = p.stats.entry((app_id, hit.at - hit.at.rem_euclid(HOUR))).or_default();
        if s.workspace_id.is_empty() {
            s.workspace_id = workspace_id;
        }
        s.requests += 1;
        s.bytes += bytes.max(0);
        match status {
            200..=299 => s.s2xx += 1,
            300..=399 => s.s3xx += 1,
            400..=499 => s.s4xx += 1,
            500..=599 => s.s5xx += 1,
            _ => {}
        }
        s.bots += i64::from(hit.bot);
        s.ms_total += ms;
        s.lat[LATENCY_BOUNDS.iter().position(|b| ms < *b).unwrap_or(7)] += 1;
        if let Some(mut v) = hit.view
            && p.views.len() < MAX_PENDING
        {
            v.status = i64::from(status);
            v.ms = ms;
            p.views.push(v);
        }
    }

    pub fn view(&self, v: View) {
        if let Ok(mut p) = self.pending.lock()
            && p.views.len() < MAX_PENDING
        {
            p.views.push(v);
        }
    }

    pub fn events(&self, list: Vec<Event>) {
        if let Ok(mut p) = self.pending.lock() {
            let room = MAX_PENDING.saturating_sub(p.events.len());
            p.events.extend(list.into_iter().take(room));
        }
    }

    fn take(&self) -> Pending {
        self.pending.lock().map(|mut p| std::mem::take(&mut *p)).unwrap_or_default()
    }
}

// ---------- what a request says about its visitor ----------

/// Crawlers, link previews, uptime checks and command-line clients: counted as requests, never as page views.
pub fn is_bot(ua: &str) -> bool {
    if ua.is_empty() {
        return false;
    }
    let ua = ua.to_ascii_lowercase();
    const MARKS: [&str; 24] = [
        "bot",
        "crawl",
        "spider",
        "slurp",
        "curl/",
        "wget",
        "python-",
        "python/",
        "go-http-client",
        "headless",
        "lighthouse",
        "pingdom",
        "uptime",
        "monitor",
        "facebookexternalhit",
        "preview",
        "scanner",
        "httpclient",
        "java/",
        "okhttp",
        "axios/",
        "libwww",
        "phantomjs",
        "feedfetcher",
    ];
    MARKS.iter().any(|m| ua.contains(m))
}

/// Browser, operating system and device class from a User-Agent.
pub fn parse_ua(ua: &str) -> (&'static str, &'static str, &'static str) {
    let has = |s: &str| ua.contains(s);
    let browser = if has("Edg/") || has("EdgA/") || has("EdgiOS/") || has("Edge/") {
        "Edge"
    } else if has("OPR/") || has("Opera") {
        "Opera"
    } else if has("SamsungBrowser/") {
        "Samsung Internet"
    } else if has("Firefox/") || has("FxiOS/") {
        "Firefox"
    } else if has("CriOS/") || has("Chrome/") || has("Chromium/") {
        "Chrome"
    } else if has("Safari/") || has("AppleWebKit/") {
        "Safari"
    } else if has("MSIE ") || has("Trident/") {
        "Internet Explorer"
    } else {
        "Other"
    };
    let os = if has("Windows") {
        "Windows"
    } else if has("iPad") {
        "iPadOS"
    } else if has("iPhone") || has("iPod") {
        "iOS"
    } else if has("Android") {
        "Android"
    } else if has("CrOS") {
        "ChromeOS"
    } else if has("Macintosh") || has("Mac OS X") {
        "macOS"
    } else if has("Linux") {
        "Linux"
    } else {
        "Other"
    };
    let device = if has("iPad") || has("Tablet") || (has("Android") && !has("Mobile")) {
        "Tablet"
    } else if has("Mobi") || has("iPhone") || has("iPod") || has("Android") {
        "Mobile"
    } else {
        "Desktop"
    };
    (browser, os, device)
}

/// The visitor's country: the code a trusted proxy or CDN put on the request, else the region of their first
/// preferred language (en-GB: GB), which is close enough to tell where an audience is.
pub fn country(cfg: &Config, req: &Req) -> String {
    let valid = |c: &str| c.len() == 2 && c.bytes().all(|b| b.is_ascii_alphabetic()) && c != "XX" && c != "T1";
    if cfg.trust_proxy {
        for h in ["cf-ipcountry", "x-vercel-ip-country", "cloudfront-viewer-country", "x-country-code", "x-geo-country"] {
            if let Some(c) = req.header(h).map(|c| c.trim().to_ascii_uppercase())
                && valid(&c)
            {
                return c;
            }
        }
    }
    let first = req.header("accept-language").and_then(|l| l.split(',').next()).unwrap_or("");
    first
        .split(';')
        .next()
        .unwrap_or("")
        .split(['-', '_'])
        .nth(1)
        .map(|r| r.trim().to_ascii_uppercase())
        .filter(|r| valid(r))
        .unwrap_or_default()
}

/// The primary language the visitor's browser asks for first, like "en".
pub fn language(req: &Req) -> String {
    let first = req.header("accept-language").and_then(|l| l.split(',').next()).unwrap_or("");
    let lang = first.split(';').next().unwrap_or("").split(['-', '_']).next().unwrap_or("").trim().to_ascii_lowercase();
    if (2..=3).contains(&lang.len()) && lang.bytes().all(|b| b.is_ascii_lowercase()) { lang } else { String::new() }
}

/// The host of the site that sent the visitor, or "" when they came from the app itself or from nowhere.
pub fn referrer_host(referer: Option<&str>, own_host: &str) -> String {
    let Some(r) = referer else { return String::new() };
    let rest = r.split_once("://").map_or("", |(_, rest)| rest);
    let host = rest.split(['/', '?', '#']).next().unwrap_or("").rsplit('@').next().unwrap_or("").to_ascii_lowercase();
    let bare = |h: &str| h.split(':').next().unwrap_or("").trim_start_matches("www.").to_string();
    let host = bare(&host);
    if host.is_empty() || host == bare(own_host) { String::new() } else { clip(&host, 120) }
}

fn clip(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].to_string()
}

/// A page view for `req`, without its status and server time, which `Analytics::finish` adds.
pub fn page_view(cfg: &Config, req: &Req, workspace_id: &str, app_id: &str, visitor: String, signed_in: bool, path: &str) -> View {
    let (browser, os, device) = parse_ua(req.header("user-agent").unwrap_or(""));
    let utm = |k: &str| req.param(k).map(|v| clip(v.trim(), 100)).unwrap_or_default();
    View {
        workspace_id: workspace_id.into(),
        app_id: app_id.into(),
        at: now(),
        visitor,
        path: clip(path, 300),
        referrer: referrer_host(req.header("referer"), &req.host),
        utm_source: { if req.param("utm_source").is_some() { utm("utm_source") } else { utm("ref") } },
        utm_medium: utm("utm_medium"),
        utm_campaign: utm("utm_campaign"),
        country: country(cfg, req),
        lang: language(req),
        browser: browser.into(),
        os: os.into(),
        device: device.into(),
        signed_in,
        status: 200,
        ms: 0,
    }
}

/// What the insights script sent (POST /_brod/insights): up to 30 items of {k, n, v, l, p}. Navigations inside a
/// single-page app (k "nav") come back as page views; everything else as events. Unknown kinds are dropped.
pub fn ingest(
    cfg: &Config,
    req: &Req,
    body: &[u8],
    workspace_id: &str,
    app_id: &str,
    visitor: &str,
    signed_in: bool,
) -> (Vec<View>, Vec<Event>) {
    let (mut views, mut events) = (Vec::new(), Vec::new());
    let Ok(Value::Array(items)) = serde_json::from_slice::<Value>(body) else { return (views, events) };
    let at = now();
    let text = |v: &Value, max: usize| v.as_str().map(|s| clip(s, max)).unwrap_or_default();
    for it in items.iter().take(30) {
        let kind = it["k"].as_str().unwrap_or("");
        let path = text(&it["p"], 300);
        let path = if path.starts_with('/') { path } else { "/".to_string() };
        if kind == "nav" {
            let mut v = page_view(cfg, req, workspace_id, app_id, visitor.to_string(), signed_in, &path);
            // A navigation inside the app has no outside referrer; its campaign tags were counted on the first load.
            (v.referrer, v.utm_source, v.utm_medium, v.utm_campaign) = Default::default();
            views.push(v);
            continue;
        }
        if !["vital", "engage", "screen", "error", "outbound", "event"].contains(&kind) {
            continue;
        }
        let name = text(&it["n"], 100);
        if name.is_empty() {
            continue;
        }
        let value = it["v"].as_f64().filter(|f| f.is_finite() && f.abs() < 1e12);
        events.push(Event {
            workspace_id: workspace_id.into(),
            app_id: app_id.into(),
            at,
            visitor: visitor.into(),
            path,
            kind: kind.into(),
            name,
            value,
            label: text(&it["l"], 200),
        });
    }
    (views, events)
}

// ---------- writing ----------

fn insert_rows(conn: &Connection, head: &str, cols: usize, rows: Vec<Vec<Val>>) -> Result<()> {
    let one = format!("({})", vec!["?"; cols].join(","));
    let full = format!("{head} VALUES {}", vec![one.as_str(); CHUNK].join(","));
    let single = format!("{head} VALUES {one}");
    let mut it = rows.into_iter().peekable();
    while it.peek().is_some() {
        let chunk: Vec<Vec<Val>> = it.by_ref().take(CHUNK).collect();
        // The same two statement shapes every time, so both stay prepared.
        if chunk.len() == CHUNK {
            conn.run(&full, chunk.into_iter().flatten().collect::<Vec<Val>>())?;
        } else {
            for r in chunk {
                conn.run(&single, r)?;
            }
        }
    }
    Ok(())
}

fn write(conn: &Connection, p: Pending) -> Result<()> {
    tx(conn, |x| {
        let views = p.views.into_iter().map(|v| {
            vec![
                Val::Text(v.workspace_id),
                Val::Text(v.app_id),
                Val::Int(v.at),
                Val::Text(v.visitor),
                Val::Text(v.path),
                Val::Text(v.referrer),
                Val::Text(v.utm_source),
                Val::Text(v.utm_medium),
                Val::Text(v.utm_campaign),
                Val::Text(v.country),
                Val::Text(v.lang),
                Val::Text(v.browser),
                Val::Text(v.os),
                Val::Text(v.device),
                Val::Int(i64::from(v.signed_in)),
                Val::Int(v.status),
                Val::Int(v.ms),
            ]
        });
        insert_rows(
            x,
            "INSERT INTO page_views (workspace_id, app_id, at, visitor, path, referrer, utm_source, utm_medium, utm_campaign, country, lang, browser, os, device, signed_in, status, ms)",
            17,
            views.collect(),
        )?;
        let events = p.events.into_iter().map(|e| {
            vec![
                Val::Text(e.workspace_id),
                Val::Text(e.app_id),
                Val::Int(e.at),
                Val::Text(e.visitor),
                Val::Text(e.path),
                Val::Text(e.kind),
                Val::Text(e.name),
                e.value.map_or(Val::Null, Val::Real),
                Val::Text(e.label),
            ]
        });
        insert_rows(x, "INSERT INTO app_events (workspace_id, app_id, at, visitor, path, kind, name, value, label)", 9, events.collect())?;
        for ((app, hour), s) in p.stats {
            x.run(
                "INSERT INTO request_stats (app_id, hour, workspace_id, requests, bytes, s2xx, s3xx, s4xx, s5xx, bots, ms_total,
                   lat0, lat1, lat2, lat3, lat4, lat5, lat6, lat7) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                 ON CONFLICT (app_id, hour) DO UPDATE SET requests = request_stats.requests + excluded.requests,
                   bytes = request_stats.bytes + excluded.bytes, s2xx = request_stats.s2xx + excluded.s2xx,
                   s3xx = request_stats.s3xx + excluded.s3xx, s4xx = request_stats.s4xx + excluded.s4xx,
                   s5xx = request_stats.s5xx + excluded.s5xx, bots = request_stats.bots + excluded.bots,
                   ms_total = request_stats.ms_total + excluded.ms_total,
                   lat0 = request_stats.lat0 + excluded.lat0, lat1 = request_stats.lat1 + excluded.lat1,
                   lat2 = request_stats.lat2 + excluded.lat2, lat3 = request_stats.lat3 + excluded.lat3,
                   lat4 = request_stats.lat4 + excluded.lat4, lat5 = request_stats.lat5 + excluded.lat5,
                   lat6 = request_stats.lat6 + excluded.lat6, lat7 = request_stats.lat7 + excluded.lat7",
                params![
                    app,
                    hour,
                    s.workspace_id,
                    s.requests,
                    s.bytes,
                    s.s2xx,
                    s.s3xx,
                    s.s4xx,
                    s.s5xx,
                    s.bots,
                    s.ms_total,
                    s.lat[0],
                    s.lat[1],
                    s.lat[2],
                    s.lat[3],
                    s.lat[4],
                    s.lat[5],
                    s.lat[6],
                    s.lat[7]
                ],
            )?;
        }
        Ok(())
    })
}

/// Write what was collected since the last flush. Called on a timer, before a report is read, and at shutdown.
pub async fn flush(st: &State) -> Result<()> {
    let p = st.analytics.take();
    if p.views.is_empty() && p.events.is_empty() && p.stats.is_empty() {
        return Ok(());
    }
    st.db.call(move |c| write(c, p)).await
}

/// Delete what is older than each workspace's plan keeps. Rows of deleted workspaces go with the shortest plan's.
pub fn purge(conn: &Connection) -> Result<usize> {
    let t = now();
    let mut gone = 0;
    let long = ["solo", "team"];
    for (table, at) in [("page_views", "at"), ("app_events", "at"), ("request_stats", "hour")] {
        for p in long {
            gone += conn.run(
                &format!("DELETE FROM {table} WHERE {at} < ? AND workspace_id IN (SELECT id FROM workspaces WHERE plan = ?)"),
                params![t - plan_named(p).analytics_days * DAY, p],
            )?;
        }
        gone += conn.run(
            &format!("DELETE FROM {table} WHERE {at} < ? AND workspace_id NOT IN (SELECT id FROM workspaces WHERE plan IN (?, ?))"),
            params![t - plan_named("free").analytics_days * DAY, long[0], long[1]],
        )?;
    }
    Ok(gone)
}

/// An app is gone: so is everything counted about it.
pub fn forget_app(conn: &Connection, app_id: &str) -> Result<()> {
    for table in ["page_views", "app_events", "request_stats"] {
        conn.run(&format!("DELETE FROM {table} WHERE app_id = ?"), [app_id])?;
    }
    Ok(())
}

// ---------- reading ----------

/// Counts for one breakdown key: views, and the distinct visitors behind them (as interned ids).
#[derive(Default)]
struct Tally {
    views: i64,
    visitors: HashSet<u32>,
}

#[derive(Default)]
struct Dim(HashMap<String, Tally>);
impl Dim {
    fn add(&mut self, key: &str, visitor: u32) {
        let t = match self.0.get_mut(key) {
            Some(t) => t,
            None => self.0.entry(key.to_string()).or_default(),
        };
        t.views += 1;
        t.visitors.insert(visitor);
    }
    fn top(&self) -> Value {
        let mut v: Vec<(&String, &Tally)> = self.0.iter().collect();
        v.sort_by(|a, b| b.1.views.cmp(&a.1.views).then_with(|| a.0.cmp(b.0)));
        Value::Array(v.into_iter().take(TOP).map(|(k, t)| json!({ "key": k, "views": t.views, "visitors": t.visitors.len() })).collect())
    }
}

/// The period a report covers, cut into buckets (hours for one day, otherwise the viewer's local days).
struct Range {
    from: i64,
    to: i64,
    hourly: bool,
    tz: i64,
    buckets: usize,
}
impl Range {
    fn new(days: i64, tz_minutes: i64, t: i64) -> Range {
        let tz = tz_minutes * MINUTE;
        if days == 1 {
            let this_hour = t - t.rem_euclid(HOUR);
            return Range { from: this_hour - 23 * HOUR, to: t, hourly: true, tz, buckets: 24 };
        }
        let today = (t + tz).div_euclid(DAY);
        Range { from: (today - days + 1) * DAY - tz, to: t, hourly: false, tz, buckets: days as usize }
    }
    fn bucket(&self, at: i64) -> Option<usize> {
        if at < self.from || at >= self.to {
            return None;
        }
        let step = if self.hourly { HOUR } else { DAY };
        usize::try_from((at - self.from) / step).ok().filter(|b| *b < self.buckets)
    }
    fn starts(&self) -> Vec<i64> {
        let step = if self.hourly { HOUR } else { DAY };
        (0..self.buckets as i64).map(|i| self.from + i * step).collect()
    }
}

/// Totals for the period before, to compare with.
#[derive(Default)]
struct Totals {
    views: i64,
    visitors: HashSet<u32>,
    sessions: i64,
    bounces: i64,
    duration: i64,
}
impl Totals {
    fn json(&self) -> Value {
        let s = self.sessions.max(1) as f64;
        json!({
            "views": self.views, "visitors": self.visitors.len(), "sessions": self.sessions,
            "bounce_rate": if self.sessions > 0 { self.bounces as f64 / s } else { 0.0 },
            "avg_session_ms": if self.sessions > 0 { self.duration / self.sessions } else { 0 },
            "views_per_session": if self.sessions > 0 { self.views as f64 / s } else { 0.0 },
        })
    }
}

/// Which rows a report reads: one app, or every app in the workspace.
enum Scope {
    App(String),
    Workspace(String),
}
impl Scope {
    fn sql(&self) -> (&'static str, &str) {
        match self {
            Scope::App(id) => ("app_id", id),
            Scope::Workspace(id) => ("workspace_id", id),
        }
    }
}

/// p-th quantile (0..1) of sorted values.
fn quantile(sorted: &[f64], q: f64) -> Option<f64> {
    if sorted.is_empty() {
        return None;
    }
    let i = ((q * sorted.len() as f64).ceil() as usize).clamp(1, sorted.len()) - 1;
    Some(sorted[i])
}

/// p-th quantile of the server-time histogram, interpolated inside its bucket.
fn latency_quantile(lat: &[i64; 8], q: f64) -> Option<f64> {
    let total: i64 = lat.iter().sum();
    if total == 0 {
        return None;
    }
    let want = q * total as f64;
    let mut seen = 0.0;
    for (i, n) in lat.iter().enumerate() {
        let lo = if i == 0 { 0 } else { LATENCY_BOUNDS[i - 1] } as f64;
        let hi = LATENCY_BOUNDS.get(i).copied().unwrap_or(5000) as f64;
        if *n > 0 && seen + *n as f64 >= want {
            return Some((lo + (hi - lo) * ((want - seen) / *n as f64)).round());
        }
        seen += *n as f64;
    }
    Some(5000.0)
}

/// Good / needs improvement thresholds for each Core Web Vital, as web.dev publishes them.
fn vital_bounds(name: &str) -> Option<(f64, f64)> {
    Some(match name {
        "LCP" => (2500.0, 4000.0),
        "INP" => (200.0, 500.0),
        "CLS" => (0.1, 0.25),
        "FCP" => (1800.0, 3000.0),
        "TTFB" => (800.0, 1800.0),
        _ => return None,
    })
}

/// GET /v1/analytics?days=30&app=<slug>&tz=<minutes east of UTC>: everything the analytics page shows.
pub fn report(conn: &Connection, c: &Caller, app: Option<&str>, days: Option<i64>, tz: Option<i64>) -> Result<Value> {
    crate::people::require_role(c, "builder", "see analytics")?;
    let keep = plan(&c.workspace).analytics_days;
    let days = days.unwrap_or(30).clamp(1, keep);
    let tz = tz.unwrap_or(0).clamp(-14 * 60, 14 * 60);
    let t = now();
    let range = Range::new(days, tz, t);
    let prev_from = range.from - (range.to - range.from);
    let (scope, app_json) = match app.filter(|a| !a.is_empty()) {
        Some(slug) => {
            let a = crate::control::get_app(conn, c, slug)?;
            (Scope::App(a.id.clone()), json!({ "slug": a.slug, "name": a.display_name() }))
        }
        None => (Scope::Workspace(c.workspace.id.clone()), Value::Null),
    };
    let (col, id) = scope.sql();
    let apps: HashMap<String, (String, String)> = conn
        .all("SELECT id, slug, title, name FROM apps WHERE workspace_id = ?", [&c.workspace.id], |r| {
            let (title, name): (String, String) = (r.get(2)?, r.get(3)?);
            Ok((r.get::<_, String>(0)?, (r.get::<_, String>(1)?, if title.is_empty() { name } else { title })))
        })?
        .into_iter()
        .collect();

    // ----- page views: one streamed scan of the current and previous periods -----
    let mut ids: HashMap<String, u32> = HashMap::new();
    let mut paths: Vec<String> = Vec::new();
    let mut path_ids: HashMap<String, u32> = HashMap::new();
    let mut cur = Totals::default();
    let mut prev = Totals::default();
    let mut series_views = vec![0i64; range.buckets];
    let mut series_visitors: Vec<HashSet<u32>> = vec![HashSet::new(); range.buckets];
    let mut series_sessions = vec![0i64; range.buckets];
    let mut heat = [[0i64; 24]; 7];
    let (mut pages, mut referrers, mut sources, mut mediums, mut campaigns) =
        (Dim::default(), Dim::default(), Dim::default(), Dim::default(), Dim::default());
    let (mut countries, mut langs, mut browsers, mut oses, mut devices, mut by_app) =
        (Dim::default(), Dim::default(), Dim::default(), Dim::default(), Dim::default(), Dim::default());
    let mut not_found = Dim::default();
    let (mut signed_in, mut page_ms, mut live) = (0i64, 0i64, HashSet::new());
    // Each visitor's views (time, path), for sessions; previous-period ones only for the comparison.
    let mut trails: HashMap<u32, Vec<(i64, u32)>> = HashMap::new();
    conn.each(
        &format!(
            "SELECT at, visitor, path, referrer, utm_source, utm_medium, utm_campaign, country, lang, browser, os, device, signed_in, status, ms, app_id
             FROM page_views WHERE {col} = ? AND at >= ? AND at < ?"
        ),
        params![id, prev_from, range.to],
        |r| {
            let at: i64 = r.get(0)?;
            let visitor: String = r.get(1)?;
            let n = ids.len() as u32;
            let vid = *ids.entry(visitor).or_insert(n);
            let path: String = r.get(2)?;
            let pid = match path_ids.get(&path) {
                Some(p) => *p,
                None => {
                    let p = paths.len() as u32;
                    paths.push(path.clone());
                    path_ids.insert(path.clone(), p);
                    p
                }
            };
            trails.entry(vid).or_default().push((at, pid));
            let Some(b) = range.bucket(at) else {
                prev.views += 1;
                prev.visitors.insert(vid);
                return Ok(());
            };
            cur.views += 1;
            cur.visitors.insert(vid);
            series_views[b] += 1;
            series_visitors[b].insert(vid);
            let local = at + range.tz;
            let weekday = ((local.div_euclid(DAY) + 3).rem_euclid(7)) as usize; // 0 = Monday
            heat[weekday][(local.rem_euclid(DAY) / HOUR) as usize] += 1;
            pages.add(&path, vid);
            let text = |i: usize| r.get::<_, String>(i);
            referrers.add(&text(3)?, vid);
            sources.add(&text(4)?, vid);
            mediums.add(&text(5)?, vid);
            campaigns.add(&text(6)?, vid);
            countries.add(&text(7)?, vid);
            langs.add(&text(8)?, vid);
            browsers.add(&text(9)?, vid);
            oses.add(&text(10)?, vid);
            devices.add(&text(11)?, vid);
            signed_in += r.get::<_, i64>(12)?;
            if r.get::<_, i64>(13)? == 404 {
                not_found.add(&path, vid);
            }
            page_ms += r.get::<_, i64>(14)?;
            by_app.add(&text(15)?, vid);
            if at >= t - 5 * MINUTE {
                live.insert(vid);
            }
            Ok(())
        },
    )?;

    // ----- sessions, entry and exit pages, bounces -----
    let mut entries: HashMap<u32, i64> = HashMap::new();
    let mut exits: HashMap<u32, i64> = HashMap::new();
    let mut session_lengths = [0i64; 6]; // 1, 2, 3, 4-5, 6-10, 11+ views
    for trail in trails.values_mut() {
        trail.sort_unstable();
        let mut i = 0;
        while i < trail.len() {
            let mut j = i;
            while j + 1 < trail.len() && trail[j + 1].0 - trail[j].0 <= SESSION_GAP {
                j += 1;
            }
            let (start, end, n) = (trail[i].0, trail[j].0, (j - i + 1) as i64);
            let into = if start < range.from { &mut prev } else { &mut cur };
            into.sessions += 1;
            into.duration += end - start;
            into.bounces += i64::from(n == 1);
            if let Some(b) = range.bucket(start) {
                series_sessions[b] += 1;
                *entries.entry(trail[i].1).or_default() += 1;
                *exits.entry(trail[j].1).or_default() += 1;
                session_lengths[match n {
                    1 => 0,
                    2 => 1,
                    3 => 2,
                    4..=5 => 3,
                    6..=10 => 4,
                    _ => 5,
                }] += 1;
            }
            i = j + 1;
        }
    }
    let ranked = |m: &HashMap<u32, i64>| {
        let mut v: Vec<(&String, i64)> = m.iter().map(|(p, n)| (&paths[*p as usize], *n)).collect();
        v.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(b.0)));
        Value::Array(v.into_iter().take(TOP).map(|(k, n)| json!({ "key": k, "sessions": n })).collect())
    };
    let mut top_pages = pages.top();
    for p in top_pages.as_array_mut().into_iter().flatten() {
        let pid = path_ids.get(p["key"].as_str().unwrap_or("")).copied();
        p["entries"] = json!(pid.and_then(|i| entries.get(&i)).copied().unwrap_or(0));
        p["exits"] = json!(pid.and_then(|i| exits.get(&i)).copied().unwrap_or(0));
    }
    let mut apps_top = by_app.top();
    for a in apps_top.as_array_mut().into_iter().flatten() {
        let (slug, name) = apps.get(a["key"].as_str().unwrap_or("")).cloned().unwrap_or_else(|| ("(deleted)".into(), "Deleted app".into()));
        a["key"] = json!(slug);
        a["name"] = json!(name);
    }

    // ----- requests: the hourly counters -----
    let mut req_series = vec![[0i64; 4]; range.buckets]; // requests, 4xx, 5xx, bytes
    let mut req = Stat::default();
    let mut prev_req = 0i64;
    let hour_from = prev_from - prev_from.rem_euclid(HOUR);
    conn.each(
        &format!(
            "SELECT hour, requests, bytes, s2xx, s3xx, s4xx, s5xx, bots, ms_total, lat0, lat1, lat2, lat3, lat4, lat5, lat6, lat7
             FROM request_stats WHERE {col} = ? AND hour >= ? AND hour < ?"
        ),
        params![id, hour_from, range.to],
        |r| {
            let hour: i64 = r.get(0)?;
            let n: i64 = r.get(1)?;
            // An hour counts in the bucket its start falls in (a day's first hour may start just before the range).
            let in_range = if hour + HOUR <= range.from { None } else { range.bucket(hour.max(range.from)) };
            let Some(b) = in_range else {
                prev_req += n;
                return Ok(());
            };
            let g = |i: usize| r.get::<_, i64>(i);
            req.requests += n;
            req.bytes += g(2)?;
            req.s2xx += g(3)?;
            req.s3xx += g(4)?;
            req.s4xx += g(5)?;
            req.s5xx += g(6)?;
            req.bots += g(7)?;
            req.ms_total += g(8)?;
            for (k, l) in req.lat.iter_mut().enumerate() {
                *l += g(9 + k)?;
            }
            req_series[b][0] += n;
            req_series[b][1] += g(5)?;
            req_series[b][2] += g(6)?;
            req_series[b][3] += g(2)?;
            Ok(())
        },
    )?;

    // ----- what the browser reported -----
    let mut vitals: HashMap<String, Vec<f64>> = HashMap::new();
    let (mut engaged, mut engaged_n) = (0.0f64, 0i64);
    let mut engaged_pages: HashMap<String, (f64, i64)> = HashMap::new();
    let (mut screens, mut resolutions, mut outbound, mut custom) = (Dim::default(), Dim::default(), Dim::default(), Dim::default());
    let mut custom_values: HashMap<String, f64> = HashMap::new();
    let mut errors: HashMap<(String, String), (i64, HashSet<u32>, i64)> = HashMap::new();
    conn.each(
        &format!("SELECT at, visitor, path, kind, name, value, label FROM app_events WHERE {col} = ? AND at >= ? AND at < ?"),
        params![id, range.from, range.to],
        |r| {
            let at: i64 = r.get(0)?;
            let visitor: String = r.get(1)?;
            let n = ids.len() as u32;
            let vid = *ids.entry(visitor).or_insert(n);
            let (path, kind, name): (String, String, String) = (r.get(2)?, r.get(3)?, r.get(4)?);
            let value: Option<f64> = r.get(5)?;
            match kind.as_str() {
                "vital" => {
                    if let Some(v) = value
                        && vital_bounds(&name).is_some()
                    {
                        vitals.entry(name).or_default().push(v);
                    }
                }
                "engage" => {
                    if let Some(v) = value.filter(|v| *v >= 0.0 && *v < 4.0 * 3600.0) {
                        engaged += v;
                        engaged_n += 1;
                        let e = engaged_pages.entry(path).or_default();
                        e.0 += v;
                        e.1 += 1;
                    }
                }
                "screen" => {
                    screens.add(&name, vid);
                    resolutions.add(&r.get::<_, String>(6)?, vid);
                }
                "outbound" => outbound.add(&name, vid),
                "event" => {
                    custom.add(&name, vid);
                    if let Some(v) = value {
                        *custom_values.entry(name).or_default() += v;
                    }
                }
                "error" => {
                    let e = errors.entry((name, r.get::<_, String>(6)?)).or_default();
                    e.0 += 1;
                    e.1.insert(vid);
                    e.2 = e.2.max(at);
                }
                _ => {}
            }
            Ok(())
        },
    )?;
    let vitals_json: Vec<Value> = ["LCP", "INP", "CLS", "FCP", "TTFB"]
        .iter()
        .map(|name| {
            let mut v = vitals.remove(*name).unwrap_or_default();
            v.sort_by(f64::total_cmp);
            let (good, poor) = vital_bounds(name).unwrap_or((0.0, 0.0));
            let g = v.iter().filter(|x| **x <= good).count();
            let p = v.iter().filter(|x| **x > poor).count();
            json!({ "name": name, "samples": v.len(), "p75": quantile(&v, 0.75), "p50": quantile(&v, 0.5),
                "good": g, "needs_improvement": v.len() - g - p, "poor": p, "good_max": good, "poor_min": poor })
        })
        .collect();
    let mut eng_pages: Vec<(String, f64, i64)> = engaged_pages.into_iter().map(|(k, (s, n))| (k, s / n as f64, n)).collect();
    eng_pages.sort_by(|a, b| b.2.cmp(&a.2).then_with(|| a.0.cmp(&b.0)));
    let mut custom_top = custom.top();
    for e in custom_top.as_array_mut().into_iter().flatten() {
        e["value"] = json!(custom_values.get(e["key"].as_str().unwrap_or("")).copied());
    }
    let mut errs: Vec<_> = errors.into_iter().collect();
    errs.sort_by(|a, b| b.1.0.cmp(&a.1.0).then_with(|| b.1.2.cmp(&a.1.2)));

    let s = cur.sessions.max(1) as f64;
    let mut app_list: Vec<Value> = apps.values().map(|(s, n)| json!({ "slug": s, "name": n })).collect();
    app_list.sort_by(|a, b| a["slug"].as_str().cmp(&b["slug"].as_str()));
    let mut previous = prev.json();
    previous["requests"] = json!(prev_req);
    let series: Vec<Value> = range
        .starts()
        .iter()
        .enumerate()
        .map(|(i, at)| {
            json!({
                "t": crate::util::iso(*at), "views": series_views[i], "visitors": series_visitors[i].len(), "sessions": series_sessions[i],
                "requests": req_series[i][0], "client_errors": req_series[i][1], "server_errors": req_series[i][2], "bytes": req_series[i][3],
            })
        })
        .collect();
    let latency: Vec<Value> = req.lat.iter().enumerate().map(|(i, n)| json!({ "under_ms": LATENCY_BOUNDS.get(i), "count": n })).collect();
    let requests = json!({
        "total": req.requests, "bytes": req.bytes, "bots": req.bots,
        "status": { "2xx": req.s2xx, "3xx": req.s3xx, "4xx": req.s4xx, "5xx": req.s5xx },
        "error_rate": if req.requests > 0 { req.s5xx as f64 / req.requests as f64 } else { 0.0 },
        "avg_ms": if req.requests > 0 { req.ms_total / req.requests } else { 0 },
        "p50_ms": latency_quantile(&req.lat, 0.5), "p95_ms": latency_quantile(&req.lat, 0.95), "p99_ms": latency_quantile(&req.lat, 0.99),
        "latency": latency,
    });
    let avg_engaged = if engaged_n > 0 { Some(engaged / engaged_n as f64) } else { None };
    let engagement_pages: Vec<Value> =
        eng_pages.into_iter().take(TOP).map(|(k, avg, n)| json!({ "key": k, "avg_seconds": avg, "samples": n })).collect();
    let errors: Vec<Value> = errs
        .into_iter()
        .take(TOP)
        .map(|((msg, src), (n, v, last))| {
            json!({ "message": msg, "source": src, "count": n, "visitors": v.len(), "last": crate::util::iso(last) })
        })
        .collect();
    let totals = json!({
        "views": cur.views, "visitors": cur.visitors.len(), "sessions": cur.sessions,
        "bounce_rate": if cur.sessions > 0 { cur.bounces as f64 / s } else { 0.0 },
        "avg_session_ms": if cur.sessions > 0 { cur.duration / cur.sessions } else { 0 },
        "views_per_session": if cur.sessions > 0 { cur.views as f64 / s } else { 0.0 },
        "signed_in_views": signed_in,
        "avg_page_ms": if cur.views > 0 { page_ms / cur.views } else { 0 },
        "avg_engaged_seconds": avg_engaged,
        "requests": req.requests, "bytes": req.bytes, "bots": req.bots,
    });
    let l = session_lengths;
    let lengths = json!([["1", l[0]], ["2", l[1]], ["3", l[2]], ["4–5", l[3]], ["6–10", l[4]], ["11+", l[5]]]);

    let mut out = serde_json::Map::new();
    let mut put = |k: &str, v: Value| {
        out.insert(k.to_string(), v);
    };
    put("app", app_json);
    put("plan", json!(c.workspace.plan));
    put("retention_days", json!(keep));
    put("days", json!(days));
    put("tz", json!(tz));
    put("from", json!(crate::util::iso(range.from)));
    put("to", json!(crate::util::iso(range.to)));
    put("bucket", json!(if range.hourly { "hour" } else { "day" }));
    put("apps", Value::Array(app_list));
    put("live_visitors", json!(live.len()));
    put("totals", totals);
    put("previous", previous);
    put("series", Value::Array(series));
    put("pages", top_pages);
    put("entry_pages", ranked(&entries));
    put("exit_pages", ranked(&exits));
    put("not_found", not_found.top());
    put("session_lengths", lengths);
    put("referrers", referrers.top());
    put("utm_sources", sources.top());
    put("utm_mediums", mediums.top());
    put("utm_campaigns", campaigns.top());
    put("countries", countries.top());
    put("languages", langs.top());
    put("browsers", browsers.top());
    put("os", oses.top());
    put("devices", devices.top());
    put("by_app", apps_top);
    put("heatmap", json!(heat.to_vec()));
    put("requests", requests);
    put("vitals", Value::Array(vitals_json));
    put("engagement", json!({ "avg_seconds": avg_engaged, "samples": engaged_n, "pages": engagement_pages }));
    put("screens", screens.top());
    put("resolutions", resolutions.top());
    put("outbound", outbound.top());
    put("events", custom_top);
    put("errors", Value::Array(errors));
    Ok(Value::Object(out))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::test_db;
    use crate::model::{User, Workspace};

    fn caller(plan: &str) -> Caller {
        Caller {
            workspace: Workspace {
                id: "ws_a".into(),
                slug: "a".into(),
                name: "A".into(),
                plan: plan.into(),
                color: String::new(),
                icon: String::new(),
                created_at: 1,
            },
            user: User { id: "usr_a".into(), email: "a@a.test".into(), name: String::new(), email_verified_at: None },
            role: "admin".into(),
            actor: "a@a.test".into(),
            agent: false,
            read_only: false,
        }
    }

    fn view(app: &str, at: i64, visitor: &str, path: &str) -> View {
        View {
            workspace_id: "ws_a".into(),
            app_id: app.into(),
            at,
            visitor: visitor.into(),
            path: path.into(),
            browser: "Firefox".into(),
            os: "Linux".into(),
            device: "Desktop".into(),
            country: "NP".into(),
            status: 200,
            ..Default::default()
        }
    }

    #[test]
    fn reads_browsers_devices_and_bots() {
        let iphone = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1";
        assert_eq!(parse_ua(iphone), ("Safari", "iOS", "Mobile"));
        let chrome = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36";
        assert_eq!(parse_ua(chrome), ("Chrome", "Windows", "Desktop"));
        let edge =
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36 Edg/126.0";
        assert_eq!(parse_ua(edge), ("Edge", "macOS", "Desktop"));
        let tab = "Mozilla/5.0 (Linux; Android 13; SM-X700) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36";
        assert_eq!(parse_ua(tab), ("Chrome", "Android", "Tablet"));
        assert_eq!(parse_ua("Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0"), ("Firefox", "Linux", "Desktop"));
        assert!(is_bot("Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"));
        assert!(is_bot("curl/8.4.0") && !is_bot(chrome) && !is_bot("node") && !is_bot(""));
    }

    #[test]
    fn keeps_only_outside_referrers() {
        assert_eq!(referrer_host(Some("https://www.google.com/search?q=x"), "notes.acme.brod.test"), "google.com");
        assert_eq!(referrer_host(Some("https://notes.acme.brod.test/a"), "notes.acme.brod.test"), "");
        assert_eq!(referrer_host(Some("http://localhost:8080/x"), "localhost:8080"), "");
        assert_eq!(referrer_host(None, "x"), "");
        assert_eq!(referrer_host(Some("android-app://com.slack/"), "x"), "com.slack");
    }

    #[test]
    fn quantiles() {
        assert_eq!(quantile(&[1.0, 2.0, 3.0, 4.0], 0.75), Some(3.0));
        assert_eq!(quantile(&[], 0.5), None);
        // 10 requests under 10 ms and 10 between 100 and 250 ms: the median is at the top of the first bucket.
        assert_eq!(latency_quantile(&[10, 0, 0, 10, 0, 0, 0, 0], 0.5), Some(10.0));
        assert_eq!(latency_quantile(&[10, 0, 0, 10, 0, 0, 0, 0], 0.75), Some(175.0));
        assert_eq!(latency_quantile(&[0; 8], 0.5), None);
    }

    #[test]
    fn buckets_by_the_viewers_day() {
        // 2026-01-10 12:00 UTC; a viewer at UTC+5:45 is already at 17:45.
        let t = 1_768_046_400_000;
        let r = Range::new(7, 345, t);
        assert_eq!(r.buckets, 7);
        assert_eq!((r.from + 345 * MINUTE).rem_euclid(DAY), 0);
        assert_eq!(r.bucket(t - 1), Some(6));
        assert_eq!(r.bucket(r.from), Some(0));
        assert_eq!(r.bucket(r.from - 1), None);
        let h = Range::new(1, 0, t + 30 * MINUTE);
        assert_eq!((h.buckets, h.bucket(t + 29 * MINUTE), h.bucket(t - 1), h.bucket(t - 23 * HOUR - 1)), (24, Some(23), Some(22), None));
    }

    #[tokio::test]
    async fn reports_sessions_breakdowns_and_requests() {
        let db = test_db();
        let a = Analytics::default();
        let t = now();
        // Visitor 1: three pages within minutes (one session), then again an hour later (a second, bounced session).
        for (dt, p) in [(0, "/"), (2, "/pricing"), (5, "/signup")] {
            a.view(view("app_1", t - 120 * MINUTE + dt * MINUTE, "v1", p));
        }
        a.view(view("app_1", t - 30 * MINUTE, "v1", "/"));
        // Visitor 2 came from a search engine and saw one page; visitor 3 hit a missing page in the other app.
        let mut v2 = view("app_1", t - 10 * MINUTE, "v2", "/");
        (v2.referrer, v2.browser, v2.device) = ("google.com".into(), "Safari".into(), "Mobile".into());
        a.view(v2);
        let mut v3 = view("app_2", t - 2 * MINUTE, "v3", "/missing");
        v3.status = 404;
        a.view(v3);
        // Last period: one view, to compare against.
        a.view(view("app_1", t - 8 * DAY, "v0", "/"));
        a.events(vec![
            Event {
                workspace_id: "ws_a".into(),
                app_id: "app_1".into(),
                at: t - MINUTE,
                visitor: "v1".into(),
                path: "/".into(),
                kind: "vital".into(),
                name: "LCP".into(),
                value: Some(1200.0),
                label: String::new(),
            },
            Event {
                workspace_id: "ws_a".into(),
                app_id: "app_1".into(),
                at: t - MINUTE,
                visitor: "v2".into(),
                path: "/".into(),
                kind: "vital".into(),
                name: "LCP".into(),
                value: Some(5000.0),
                label: String::new(),
            },
            Event {
                workspace_id: "ws_a".into(),
                app_id: "app_1".into(),
                at: t - MINUTE,
                visitor: "v2".into(),
                path: "/".into(),
                kind: "event".into(),
                name: "signup".into(),
                value: Some(2.0),
                label: String::new(),
            },
            Event {
                workspace_id: "ws_a".into(),
                app_id: "app_1".into(),
                at: t - MINUTE,
                visitor: "v2".into(),
                path: "/".into(),
                kind: "error".into(),
                name: "x is undefined".into(),
                value: None,
                label: "/app.js:3".into(),
            },
            Event {
                workspace_id: "ws_a".into(),
                app_id: "app_1".into(),
                at: t - MINUTE,
                visitor: "v2".into(),
                path: "/".into(),
                kind: "engage".into(),
                name: "time".into(),
                value: Some(30.0),
                label: String::new(),
            },
        ]);
        for (status, bot) in [(200, false), (200, true), (404, false), (500, false)] {
            let mut hit = Hit { t0: Instant::now(), at: t, bot, app: Some(("ws_a".into(), "app_1".into())), view: None };
            hit.at = t - MINUTE;
            a.finish(hit, status, 100);
        }
        let p = a.take();
        let r = db
            .call(move |c| {
                c.run("INSERT INTO workspaces (id, slug, name, created_at) VALUES ('ws_a','a','A',1)", ())?;
                c.run("INSERT INTO users (id, email, created_at) VALUES ('usr_a','a@a.test',1)", ())?;
                for id in ["app_1", "app_2"] {
                    c.run(
                        "INSERT INTO apps (id, workspace_id, owner_id, slug, name, created_at) VALUES (?,'ws_a','usr_a',?,?,1)",
                        params![id, id, id],
                    )?;
                }
                write(c, p)?;
                let all = report(c, &caller("free"), None, Some(7), Some(0))?;
                let one = report(c, &caller("free"), Some("app_1"), Some(1), Some(0))?;
                let long = report(c, &caller("free"), None, Some(400), None)?;
                Ok((all, one, long))
            })
            .await
            .unwrap();
        let (all, one, long) = r;
        assert_eq!(all["totals"]["views"], 6);
        assert_eq!(all["totals"]["visitors"], 3);
        // v1: two sessions, v2: one, v3: one. Three of the four saw one page.
        assert_eq!(all["totals"]["sessions"], 4);
        assert_eq!(all["totals"]["bounce_rate"], 0.75);
        assert_eq!(all["previous"]["views"], 1);
        assert_eq!(all["pages"][0]["key"], "/");
        assert_eq!(all["pages"][0]["views"], 3);
        assert_eq!(all["pages"][0]["entries"], 3);
        assert_eq!(all["exit_pages"].as_array().unwrap().iter().find(|e| e["key"] == "/signup").unwrap()["sessions"], 1);
        assert_eq!(all["referrers"].as_array().unwrap().iter().find(|e| e["key"] == "google.com").unwrap()["views"], 1);
        assert_eq!(all["devices"][0]["key"], "Desktop");
        assert_eq!(all["not_found"][0]["key"], "/missing");
        assert_eq!(all["by_app"][0]["key"], "app_1");
        assert_eq!(all["live_visitors"], 1);
        assert_eq!(all["series"].as_array().unwrap().len(), 7);
        assert_eq!(all["series"].as_array().unwrap().iter().map(|s| s["views"].as_i64().unwrap()).sum::<i64>(), 6);
        assert_eq!(all["requests"]["total"], 4);
        assert_eq!(all["requests"]["bots"], 1);
        assert_eq!(all["requests"]["status"]["5xx"], 1);
        assert_eq!(all["requests"]["error_rate"], 0.25);
        assert_eq!(all["vitals"][0]["name"], "LCP");
        assert_eq!((all["vitals"][0]["good"].as_i64(), all["vitals"][0]["poor"].as_i64()), (Some(1), Some(1)));
        assert_eq!(all["events"][0]["key"], "signup");
        assert_eq!(all["events"][0]["value"], 2.0);
        assert_eq!(all["errors"][0]["message"], "x is undefined");
        assert_eq!(all["engagement"]["avg_seconds"], 30.0);
        assert_eq!(one["bucket"], "hour");
        assert_eq!(one["totals"]["views"], 5);
        assert_eq!(one["app"]["slug"], "app_1");
        // The free plan keeps 30 days, so a longer range is cut to that.
        assert_eq!((long["days"].as_i64(), long["retention_days"].as_i64()), (Some(30), Some(30)));
    }

    #[tokio::test]
    async fn forgets_what_the_plan_does_not_keep() {
        let db = test_db();
        let t = now();
        let left = db
            .call(move |c| {
                for (id, plan) in [("ws_f", "free"), ("ws_s", "solo"), ("ws_t", "team")] {
                    c.run("INSERT INTO workspaces (id, slug, name, plan, created_at) VALUES (?,?,?,?,1)", params![id, id, id, plan])?;
                }
                let a = Analytics::default();
                for ws in ["ws_f", "ws_s", "ws_t", "ws_gone"] {
                    for age in [10, 100, 500, 1000] {
                        let mut v = view("app", t - age * DAY, "v", "/");
                        v.workspace_id = ws.into();
                        a.view(v);
                    }
                }
                write(c, a.take())?;
                purge(c)?;
                c.all("SELECT workspace_id, COUNT(*) FROM page_views GROUP BY workspace_id ORDER BY workspace_id", (), |r| {
                    Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?))
                })
            })
            .await
            .unwrap();
        let left: Vec<(&str, i64)> = left.iter().map(|(w, n)| (w.as_str(), *n)).collect();
        assert_eq!(left, vec![("ws_f", 1), ("ws_gone", 1), ("ws_s", 2), ("ws_t", 3)]);
    }

    #[tokio::test]
    async fn writes_large_batches() {
        let db = test_db();
        let a = Analytics::default();
        let t = now();
        for i in 0..237 {
            a.view(view("app_b", t - i * 1000, &format!("v{}", i % 40), "/"));
        }
        let p = a.take();
        let n = db
            .call(move |c| {
                write(c, p)?;
                c.count("SELECT COUNT(*) FROM page_views WHERE app_id = 'app_b'", ())
            })
            .await
            .unwrap();
        assert_eq!(n, 237);
    }

    #[test]
    fn takes_in_what_the_script_sends() {
        let cfg = Config::for_tests();
        let req = Req::for_tests(
            "GET",
            "/",
            &[("user-agent", "Mozilla/5.0 (X11; Linux x86_64) Firefox/128.0"), ("accept-language", "ne-NP,en;q=0.8")],
        );
        let body = br#"[{"k":"nav","p":"/settings"},{"k":"vital","n":"LCP","v":1234.5},{"k":"event","n":"signup","v":1,"l":"pro"},
            {"k":"nope","n":"x"},{"k":"error","n":""},{"k":"outbound","n":"github.com","p":"no-slash"}]"#;
        let (views, events) = ingest(&cfg, &req, body, "ws", "app", "vh", true);
        assert_eq!(views.len(), 1);
        assert_eq!(
            (views[0].path.as_str(), views[0].browser.as_str(), views[0].lang.as_str(), views[0].country.as_str()),
            ("/settings", "Firefox", "ne", "NP")
        );
        assert!(views[0].signed_in);
        assert_eq!(events.iter().map(|e| e.kind.as_str()).collect::<Vec<_>>(), vec!["vital", "event", "outbound"]);
        assert_eq!(events[2].path, "/");
        assert!(ingest(&cfg, &req, b"not json", "ws", "app", "vh", false).0.is_empty());
    }
}
