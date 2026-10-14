// SPDX-License-Identifier: AGPL-3.0-only
// Usage: page views per app per day, and the storage each app takes.
//
// Page views are counted in memory as the gateway serves them and written to the visits table in one transaction every
// few seconds (and before any usage is read), so a busy app costs one database write per flush, not one per view.
// A visitor is a salted hash of who they are (their user id when signed in, otherwise address and browser) and the
// day, so the same person counts once a day per app and nothing that identifies them is stored.
use std::collections::{HashMap, HashSet};
use std::sync::Mutex;

use crate::db::{Connection, params};
use serde_json::{Value, json};

use crate::config::Config;
use crate::db::{Sql, tx};
use crate::http::Req;
use crate::model::{Caller, Workspace, plan, plan_named};
use crate::problem::{Problem, Result};
use crate::state::State;
use crate::util::{iso, now, sha256_hex};

/// Daily visitor hashes are kept this long, then only the daily totals remain.
const VISITOR_DAYS: i64 = 35;
const DAY_MS: i64 = 86_400_000;

type Batch = HashMap<(String, String), (i64, HashSet<String>)>;

#[derive(Default)]
pub struct Visits {
    pending: Mutex<Batch>,
}

impl Visits {
    pub fn record(&self, app_id: &str, visitor: String) {
        let day = day_of(now());
        if let Ok(mut p) = self.pending.lock() {
            let e = p.entry((app_id.to_string(), day)).or_default();
            e.0 += 1;
            e.1.insert(visitor);
        }
    }
    fn take(&self) -> Batch {
        self.pending.lock().map(|mut p| std::mem::take(&mut *p)).unwrap_or_default()
    }
}

pub fn day_of(ms: i64) -> String {
    iso(ms)[..10].to_string()
}

/// The last `days` UTC days, oldest first, ending today.
pub fn last_days(days: i64) -> Vec<String> {
    let t = now();
    (0..days).rev().map(|i| day_of(t - i * DAY_MS)).collect()
}

/// Is this request someone opening a page (not a script, an image or an API call)?
pub fn is_page_view(req: &Req) -> bool {
    if req.method != axum::http::Method::GET {
        return false;
    }
    if let Some(dest) = req.header("sec-fetch-dest") {
        return dest == "document";
    }
    let last = req.path.rsplit('/').next().unwrap_or("");
    match last.rsplit_once('.') {
        None => true,
        Some((_, ext)) => ext.eq_ignore_ascii_case("html") || ext.eq_ignore_ascii_case("htm"),
    }
}

/// A salted, per-app, per-day hash for the person behind a request.
pub fn visitor_hash(cfg: &Config, req: &Req, app_id: &str, user_id: Option<&str>) -> String {
    let who = match user_id {
        Some(u) => format!("u:{u}"),
        None => {
            let forwarded = cfg
                .trust_proxy
                .then(|| req.header("x-forwarded-for").and_then(|v| v.split(',').next()).map(|v| v.trim().to_string()))
                .flatten();
            let ip = forwarded.or_else(|| req.peer.map(|p| p.to_string())).unwrap_or_default();
            format!("a:{ip}|{}", req.header("user-agent").unwrap_or(""))
        }
    };
    sha256_hex(&format!("{}:visit:{app_id}:{}:{who}", cfg.identity_secret, day_of(now())))[..32].to_string()
}

fn write(conn: &Connection, batch: &Batch) -> Result<()> {
    tx(conn, |x| {
        for ((app, day), (views, visitors)) in batch {
            let mut fresh = 0;
            for h in visitors {
                fresh += x.run("INSERT OR IGNORE INTO visit_visitors (app_id, day, hash) VALUES (?,?,?)", params![app, day, h])?;
            }
            x.run(
                "INSERT INTO visits (app_id, day, views, visitors) VALUES (?,?,?,?)
                 ON CONFLICT (app_id, day) DO UPDATE SET views = visits.views + excluded.views, visitors = visits.visitors + excluded.visitors",
                params![app, day, views, fresh as i64],
            )?;
        }
        x.run("DELETE FROM visit_visitors WHERE day < ?", [day_of(now() - VISITOR_DAYS * DAY_MS)])?;
        Ok(())
    })
}

/// Write the views counted so far. Called on a timer, before usage is read, and at shutdown.
pub async fn flush(st: &State) -> Result<()> {
    let batch = st.visits.take();
    if batch.is_empty() {
        return Ok(());
    }
    st.db.call(move |c| write(c, &batch)).await
}

/// Views and visitors per day for one app, oldest first.
pub fn series(conn: &Connection, app_id: &str, days: &[String]) -> Result<(Vec<i64>, Vec<i64>)> {
    let rows: HashMap<String, (i64, i64)> = conn
        .all(
            "SELECT day, views, visitors FROM visits WHERE app_id = ? AND day >= ?",
            params![app_id, days.first().cloned().unwrap_or_default()],
            |r| Ok((r.get::<_, String>(0)?, (r.get(1)?, r.get(2)?))),
        )?
        .into_iter()
        .collect();
    Ok(days.iter().map(|d| rows.get(d).copied().unwrap_or((0, 0))).unzip())
}

// ---------- storage ----------

pub struct Storage {
    pub bundles: i64,
    pub files: i64,
    /// Server apps' databases and key-value stores, as the runtime last reported them.
    pub data: i64,
}
impl Storage {
    pub fn total(&self) -> i64 {
        self.bundles + self.files + self.data
    }
}

pub fn workspace_storage(conn: &Connection, workspace_id: &str) -> Result<Storage> {
    let bundles = conn.count(
        "SELECT COALESCE(SUM(v.bytes), 0) FROM versions v JOIN apps a ON a.id = v.app_id WHERE a.workspace_id = ?",
        [workspace_id],
    )?;
    // Marketplace releases (copies of a version's files, kept for installers) and listing previews count for the publisher.
    let releases = conn.count(
        "SELECT COALESCE(SUM(r.bytes), 0) FROM releases r JOIN listings l ON l.id = r.listing_id WHERE l.workspace_id = ?",
        [workspace_id],
    )?;
    let media = conn.count(
        "SELECT COALESCE(SUM(m.bytes), 0) FROM listing_media m JOIN listings l ON l.id = m.listing_id WHERE l.workspace_id = ?",
        [workspace_id],
    )?;
    let bundles = bundles + releases + media;
    let files = conn.count("SELECT COALESCE(SUM(file_bytes), 0) FROM apps WHERE workspace_id = ?", [workspace_id])?;
    let data = conn.count("SELECT COALESCE(SUM(data_bytes), 0) FROM apps WHERE workspace_id = ?", [workspace_id])?;
    Ok(Storage { bundles, files, data })
}

pub fn mb(bytes: i64) -> String {
    let m = bytes as f64 / (1024.0 * 1024.0);
    if m >= 1024.0 {
        format!("{:.1} GB", m / 1024.0)
    } else if m >= 10.0 {
        format!("{m:.0} MB")
    } else {
        format!("{m:.1} MB")
    }
}

/// Refuse to store `adding` more bytes when that would go over the plan's storage.
pub fn check_storage(conn: &Connection, cfg: &Config, w: &Workspace, adding: i64) -> Result<()> {
    let used = workspace_storage(conn, &w.id)?.total();
    let limit = plan(w).storage;
    if used + adding > limit {
        return Err(Problem::new(
            402,
            "storage_limit",
            format!(
                "This would use {} of the {} plan's {}. Delete old versions or apps you no longer need, or upgrade the plan.",
                mb(used + adding),
                w.plan,
                mb(limit)
            ),
        )
        .with("storage_bytes", json!(used))
        .with("storage_limit", json!(limit))
        .with("adding_bytes", json!(adding))
        .with("upgrade_url", json!(format!("{}/w/{}/admin#billing", cfg.api_origin, w.slug))));
    }
    Ok(())
}

/// The same check for an app's own files, from the runtime, which knows only the app id.
pub fn check_app_storage(conn: &Connection, app_id: &str, adding: i64) -> Result<()> {
    // A marketplace preview sandbox: it lives for one capture and its files are removed right after (preview.rs).
    if app_id.starts_with("lst_") {
        return Ok(());
    }
    let row: Option<(String, String)> =
        conn.first("SELECT w.id, w.plan FROM apps a JOIN workspaces w ON w.id = a.workspace_id WHERE a.id = ?", [app_id], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })?;
    let Some((wid, plan_name)) = row else { return Err(Problem::new(404, "not_found", "No such app.")) };
    let used = workspace_storage(conn, &wid)?.total();
    let limit = plan_named(&plan_name).storage;
    if adding > 0 && used + adding > limit {
        return Err(Problem::new(507, "storage_limit", format!("The workspace's storage is full ({} of {}).", mb(used), mb(limit))));
    }
    Ok(())
}

pub fn add_file_bytes(conn: &Connection, app_id: &str, delta: i64) -> Result<()> {
    conn.run("UPDATE apps SET file_bytes = MAX(0, file_bytes + ?) WHERE id = ?", params![delta, app_id])?;
    Ok(())
}

/// The runtime reports an app's database size after writes (POST /_runtime/usage). Record it and say whether the
/// workspace is now out of storage, so the runtime refuses writes that would grow it further.
pub fn report_data_bytes(conn: &Connection, app_id: &str, bytes: i64) -> Result<Value> {
    conn.run("UPDATE apps SET data_bytes = ? WHERE id = ?", params![bytes.max(0), app_id])?;
    let row: Option<(String, String)> =
        conn.first("SELECT w.id, w.plan FROM apps a JOIN workspaces w ON w.id = a.workspace_id WHERE a.id = ?", [app_id], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })?;
    // An app deleted meanwhile: nothing to hold back.
    let Some((wid, plan_name)) = row else { return Ok(json!({ "full": false })) };
    let used = workspace_storage(conn, &wid)?.total();
    let limit = plan_named(&plan_name).storage;
    Ok(json!({ "full": used >= limit, "used": used, "limit": limit }))
}

/// Ask the runtime how big every server app's database is now, and record it. Runs every 10 minutes, so sizes are
/// right even for apps that have not written since the last report (or since a restart).
pub async fn sync_data_sizes(st: &State) -> Result<()> {
    let Some(rt) = &st.cfg.runtime else { return Ok(()) };
    let apps: Vec<String> = st
        .db
        .call(|c| {
            c.all("SELECT DISTINCT app_id FROM versions WHERE server IS NOT NULL AND app_id IN (SELECT id FROM apps)", (), |r| r.get(0))
        })
        .await?;
    for chunk in apps.chunks(100) {
        let res = st
            .http
            .post(format!("{}/_runtime/sizes", rt.url))
            .header("x-brod-runtime-secret", &rt.secret)
            .json(&json!({ "apps": chunk }))
            .send()
            .await
            .map_err(|e| Problem::internal(format!("runtime sizes: {e}")))?;
        if !res.status().is_success() {
            return Err(Problem::internal(format!("runtime sizes answered {}", res.status())));
        }
        let body: Value = res.json().await.map_err(Problem::internal)?;
        let sizes: Vec<(String, i64)> = body["sizes"]
            .as_object()
            .map(|m| m.iter().filter_map(|(k, v)| v.as_i64().map(|n| (k.clone(), n))).collect())
            .unwrap_or_default();
        st.db
            .call(move |c| {
                tx(c, |x| {
                    for (app, n) in &sizes {
                        x.run("UPDATE apps SET data_bytes = ? WHERE id = ?", params![n, app])?;
                    }
                    Ok(())
                })
            })
            .await?;
    }
    Ok(())
}

// ---------- what the dashboard reads ----------

fn clamp_days(days: Option<i64>) -> i64 {
    days.unwrap_or(14).clamp(1, 90)
}

/// GET /v1/usage: views per app per day, and storage per app, for the whole workspace.
pub fn workspace_usage(conn: &Connection, c: &Caller, days: Option<i64>) -> Result<Value> {
    crate::people::require_role(c, "builder", "see usage")?;
    let days = last_days(clamp_days(days));
    let apps: Vec<(String, String, i64, i64)> = conn.all(
        "SELECT id, slug, file_bytes, data_bytes FROM apps WHERE workspace_id = ? ORDER BY created_at DESC",
        [&c.workspace.id],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
    )?;
    let bundles: HashMap<String, i64> = conn
        .all(
            "SELECT v.app_id, SUM(v.bytes) FROM versions v JOIN apps a ON a.id = v.app_id WHERE a.workspace_id = ? GROUP BY v.app_id",
            [&c.workspace.id],
            |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)),
        )?
        .into_iter()
        .collect();
    let mut out = Vec::new();
    let (mut views_total, mut visitors_total) = (0, 0);
    for (id, slug, files, data) in apps {
        let (views, visitors) = series(conn, &id, &days)?;
        let (v, u): (i64, i64) = (views.iter().sum(), visitors.iter().sum());
        views_total += v;
        visitors_total += u;
        let b = bundles.get(&id).copied().unwrap_or(0);
        out.push(json!({ "app": slug, "views": views, "visitors": visitors, "total_views": v, "total_visitors": u,
            "storage": { "bundles": b, "files": files, "data": data, "total": b + files + data } }));
    }
    let s = workspace_storage(conn, &c.workspace.id)?;
    Ok(json!({
        "days": days, "apps": out, "total_views": views_total, "total_visitors": visitors_total,
        "storage": { "bundles": s.bundles, "files": s.files, "data": s.data, "total": s.total(), "limit": plan(&c.workspace).storage },
    }))
}

/// GET /v1/apps/<app>/usage: one app's views per day and its storage, version by version.
pub fn app_usage(conn: &Connection, c: &Caller, slug: &str, days: Option<i64>) -> Result<Value> {
    crate::people::require_role(c, "builder", "see usage")?;
    let app = crate::control::get_app(conn, c, slug)?;
    let days = last_days(clamp_days(days));
    let (views, visitors) = series(conn, &app.id, &days)?;
    let bundles = conn.count("SELECT COALESCE(SUM(bytes), 0) FROM versions WHERE app_id = ?", [&app.id])?;
    Ok(json!({
        "app": app.slug, "days": days, "views": views, "visitors": visitors,
        "total_views": views.iter().sum::<i64>(), "total_visitors": visitors.iter().sum::<i64>(),
        "storage": { "bundles": bundles, "files": app.file_bytes, "data": app.data_bytes, "total": bundles + app.file_bytes + app.data_bytes },
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::test_db;

    #[tokio::test]
    async fn counts_views_and_distinct_visitors_per_day() {
        let db = test_db();
        let v = Visits::default();
        for who in ["a", "b", "a", "a"] {
            v.record("app_x", who.into());
        }
        v.record("app_y", "a".into());
        let batch = v.take();
        db.call(move |c| write(c, &batch)).await.unwrap();
        // A second flush with a returning visitor adds views but not visitors.
        v.record("app_x", "b".into());
        let batch = v.take();
        db.call(move |c| write(c, &batch)).await.unwrap();
        let (views, visitors) = db.call(|c| series(c, "app_x", &last_days(2))).await.unwrap();
        assert_eq!((views, visitors), (vec![0, 5], vec![0, 2]));
        assert!(v.take().is_empty());
    }

    #[tokio::test]
    async fn refuses_to_go_over_the_plan_storage() {
        let db = test_db();
        let r = db
            .call(|c| {
                c.run("INSERT INTO workspaces (id, slug, name, created_at) VALUES ('ws_q','q','Q',1)", ())?;
                c.run("INSERT INTO users (id, email, created_at) VALUES ('usr_q','q@q.test',1)", ())?;
                c.run("INSERT INTO apps (id, workspace_id, owner_id, slug, name, created_at, file_bytes) VALUES ('app_q','ws_q','usr_q','a','A',1,?)", [10 * crate::model::MB])?;
                c.run(
                    "INSERT INTO versions (app_id, n, note, actor, file_count, bytes, created_at) VALUES ('app_q',1,'','q',1,?,1)",
                    [200 * crate::model::MB],
                )?;
                let w = Workspace { id: "ws_q".into(), slug: "q".into(), name: "Q".into(), plan: "free".into(), color: String::new(), icon: String::new(), created_at: 1 };
                let cfg = Config::for_tests();
                let fits = check_storage(c, &cfg, &w, 40 * crate::model::MB).is_ok();
                let over = check_storage(c, &cfg, &w, 41 * crate::model::MB).unwrap_err();
                let solo = check_storage(c, &cfg, &Workspace { plan: "solo".into(), ..w }, 41 * crate::model::MB).is_ok();
                let files_full = check_app_storage(c, "app_q", 41 * crate::model::MB).unwrap_err().status;
                let shrink_ok = check_app_storage(c, "app_q", -5).is_ok();
                Ok((fits, over, solo, files_full, shrink_ok))
            })
            .await
            .unwrap();
        assert!(r.0 && r.2 && r.4);
        assert_eq!((r.1.status, r.1.code.as_str(), r.3), (402, "storage_limit", 507));
    }

    #[tokio::test]
    async fn app_databases_count_and_fill_the_plan() {
        let db = test_db();
        let r = db
            .call(|c| {
                c.run("INSERT INTO workspaces (id, slug, name, created_at) VALUES ('ws_d','d','D',1)", ())?;
                c.run("INSERT INTO users (id, email, created_at) VALUES ('usr_d','d@d.test',1)", ())?;
                for a in ["app_d1", "app_d2"] {
                    c.run(
                        "INSERT INTO apps (id, workspace_id, owner_id, slug, name, created_at) VALUES (?,'ws_d','usr_d',?,?,1)",
                        params![a, a, a],
                    )?;
                }
                let some = report_data_bytes(c, "app_d1", 100 * crate::model::MB)?;
                let full = report_data_bytes(c, "app_d2", 150 * crate::model::MB)?;
                let total = workspace_storage(c, "ws_d")?;
                // Deleting data in one app makes room again.
                let freed = report_data_bytes(c, "app_d2", 10 * crate::model::MB)?;
                // A file write counts the databases too.
                let file_refused = check_app_storage(c, "app_d1", 200 * crate::model::MB).is_err();
                let gone = report_data_bytes(c, "app_missing", 1)?;
                Ok((some, full, total.data, freed, file_refused, gone))
            })
            .await
            .unwrap();
        assert_eq!((r.0["full"].as_bool(), r.1["full"].as_bool(), r.3["full"].as_bool()), (Some(false), Some(true), Some(false)));
        assert_eq!(r.2, 250 * crate::model::MB);
        assert!(r.4);
        assert_eq!(r.5["full"], false);
    }

    #[test]
    fn formats_sizes() {
        assert_eq!(mb(250 * 1024 * 1024), "250 MB");
        assert_eq!(mb(5 * 1024 * 1024 * 1024), "5.0 GB");
        assert_eq!(mb(1024 * 1024 / 2), "0.5 MB");
    }
}
