// Abuse protection: takedowns and suspended workspaces, rate limits for anonymous and new users, the guardrail that
// keeps a new workspace's apps inside it for its first day, the flag the deploy-time phishing check (scan.rs) puts on
// a version, and the operator's API under /v1/admin/ (ADMIN_SECRET).
use std::net::IpAddr;

use axum::http::Method;
use axum::response::Response;
use serde_json::{Map, Value, json};

use crate::config::Config;
use crate::db::{Connection, Sql, event, params, tx};
use crate::http::{Req, notice};
use crate::model::{ACCESS, AppRow, Caller};
use crate::problem::{Problem, Result};
use crate::state::State;
use crate::util::{iso, js_slice, js_trim, now, safe_equal};

pub const SIGN_IN_LINKS_PER_IP_HOUR: i64 = 20; // on top of the 5 an hour per email address
pub const OAUTH_CLIENTS_PER_IP_HOUR: i64 = 10;
pub const WORKSPACES_PER_USER_DAY: i64 = 3;
pub const REPORTS_PER_IP_HOUR: i64 = 10;
/// A workspace this young cannot open apps to people outside it (password, signed_in, public).
pub const NEW_WORKSPACE_MS: i64 = 24 * HOUR;
pub const HOUR: i64 = 3_600_000;
pub const DAY: i64 = 24 * HOUR;
/// Who the audit log names for the operator's actions and for the phishing check.
pub const OPERATOR: &str = "Brod operator";
pub const CHECKER: &str = "brod";

// ---------- client addresses and rate limits ----------

/// The visitor's address: the first X-Forwarded-For hop when BROD_TRUST_PROXY=1 (Caddy replaces whatever the visitor
/// sent with the address it saw), else the connection's. IPv6 counts per /64. None when neither is known.
pub fn client_ip(cfg: &Config, req: &Req) -> Option<String> {
    let forwarded = cfg
        .trust_proxy
        .then(|| req.header("x-forwarded-for"))
        .flatten()
        .and_then(|v| v.split(',').next())
        .and_then(|v| v.trim().parse::<IpAddr>().ok());
    forwarded.or(req.peer).map(ip_key)
}

/// An address as a rate-limit key: IPv4 as is (also when mapped into IPv6), IPv6 as its first four groups.
pub fn ip_key(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(a) => a.to_string(),
        IpAddr::V6(a) => match a.to_ipv4_mapped() {
            Some(v4) => v4.to_string(),
            None => {
                let s = a.segments();
                format!("{:x}:{:x}:{:x}:{:x}::/64", s[0], s[1], s[2], s[3])
            }
        },
    }
}

/// Count one more request in a fixed window ("<bucket>:<who>:<window number>" in rate_limits) and refuse with 429
/// once there are more than `limit` in it.
pub fn rate_limit(conn: &Connection, bucket: &str, who: &str, limit: i64, window_ms: i64, message: &str) -> Result<()> {
    let t = now();
    let win = t.div_euclid(window_ms);
    let ends = (win + 1) * window_ms;
    let n: i64 = conn
        .first(
            "INSERT INTO rate_limits (key, n, expires_at) VALUES (?, 1, ?) ON CONFLICT(key) DO UPDATE SET n = rate_limits.n + 1 RETURNING n",
            params![format!("{bucket}:{who}:{win}"), ends],
            |r| r.get(0),
        )?
        .unwrap_or(0);
    conn.run("DELETE FROM rate_limits WHERE expires_at < ?", [t])?;
    if n > limit {
        let retry = (ends - t + 999) / 1000;
        let wait = if retry < 120 { format!("{retry} seconds") } else { format!("{} minutes", (retry + 59) / 60) };
        return Err(Problem::new(429, "rate_limited", format!("{message} Try again in {wait}.")).with("retry_after_seconds", json!(retry)));
    }
    Ok(())
}

// ---------- takedowns and suspensions ----------

pub struct Hold {
    /// "taken_down" or "workspace_suspended", also the error code.
    pub kind: &'static str,
    pub reason: String,
    pub since: i64,
}

/// What keeps an app down, if anything: its own takedown first, then its workspace's suspension.
pub fn hold_of(conn: &Connection, app: &AppRow) -> Result<Option<Hold>> {
    if let Some(since) = app.taken_down_at {
        return Ok(Some(Hold { kind: "taken_down", reason: app.takedown_reason.clone(), since }));
    }
    workspace_hold(conn, &app.workspace_id)
}

pub fn workspace_hold(conn: &Connection, workspace_id: &str) -> Result<Option<Hold>> {
    let w = conn.first("SELECT suspended_at, suspended_reason FROM workspaces WHERE id = ?", [workspace_id], |r| {
        Ok((r.get::<_, Option<i64>>(0)?, r.get::<_, String>(1)?))
    })?;
    Ok(match w {
        Some((Some(since), reason)) => Some(Hold { kind: "workspace_suspended", reason, since }),
        _ => None,
    })
}

pub fn hold_message(h: &Hold, slug: Option<&str>) -> String {
    let why = if h.reason.is_empty() { String::new() } else { format!(" ({})", h.reason) };
    let what = if h.kind == "taken_down" {
        format!("The Brod team took {} down{why}. It shows a \"taken down\" page to everyone", slug.unwrap_or("this app"))
    } else {
        format!("The Brod team suspended this workspace{why}. Its apps are offline and it cannot deploy new ones")
    };
    format!(
        "{what}, and it cannot be resumed, redeployed, rolled back, deleted or shared more widely until the Brod team restores it. \
         If you think this is a mistake, contact the Brod team; there is nothing an agent can change to fix it."
    )
}

fn hold_problem(h: &Hold, slug: Option<&str>) -> Problem {
    Problem::new(403, h.kind, hold_message(h, slug)).with("since", json!(iso(h.since)))
}

/// Refuse a change that would bring an app (back) up while it is taken down or its workspace is suspended.
pub fn check_up(conn: &Connection, app: &AppRow) -> Result<()> {
    match hold_of(conn, app)? {
        Some(h) => Err(hold_problem(&h, Some(&app.slug))),
        None => Ok(()),
    }
}

/// Refuse deploying a new app into a suspended workspace.
pub fn check_workspace_up(conn: &Connection, c: &Caller) -> Result<()> {
    match workspace_hold(conn, &c.workspace.id)? {
        Some(h) => Err(hold_problem(&h, None)),
        None => Ok(()),
    }
}

/// The neutral page a visitor gets instead of an app that is down. It says nothing about why.
pub fn taken_down_page() -> Response {
    notice(410, "This app has been taken down", "This app is no longer available.", "")
}

// ---------- the new-workspace guardrail ----------

/// For its first day, a free workspace that the operator has not trusted keeps its apps to people inside it.
pub fn check_can_open_outside(conn: &Connection, c: &Caller, access: &str) -> Result<()> {
    if !matches!(access, "password" | "signed_in" | "public") {
        return Ok(());
    }
    let opens = c.workspace.created_at + NEW_WORKSPACE_MS;
    if now() >= opens || c.workspace.plan != "free" {
        return Ok(());
    }
    let trusted: Option<i64> = conn.first("SELECT trusted_at FROM workspaces WHERE id = ?", [&c.workspace.id], |r| r.get(0))?.flatten();
    if trusted.is_some() {
        return Ok(());
    }
    let at = iso(opens);
    Err(Problem::new(
        403,
        "workspace_too_new",
        format!(
            "{} is less than a day old, so its apps cannot be opened by people outside it yet (\"{access}\" access). That becomes possible at {at}. \
             Until then, share the app inside the workspace with access \"workspace\", or with named people and groups (\"people\" with \"add\"); \
             or upgrade to a paid plan to lift this now.",
            c.workspace.slug
        ),
    )
    .with("available_at", json!(at)))
}

// ---------- the phishing check's flag ----------

/// The reasons a version was flagged by the phishing check, or None when it was not (or the operator cleared it).
pub fn flag_of(conn: &Connection, app_id: &str, n: Option<i64>) -> Result<Option<Vec<String>>> {
    let Some(n) = n else { return Ok(None) };
    let v = conn.first("SELECT scan, scan_cleared_at FROM versions WHERE app_id = ? AND n = ?", params![app_id, n], |r| {
        Ok((r.get::<_, Option<String>>(0)?, r.get::<_, Option<i64>>(1)?))
    })?;
    Ok(match v {
        Some((Some(scan), None)) => Some(serde_json::from_str::<Vec<String>>(&scan).unwrap_or_default()).filter(|r| !r.is_empty()),
        _ => None,
    })
}

pub fn flag_message(slug: &str, n: i64, reasons: &[String]) -> String {
    format!(
        "The phishing check flagged v{n} of {slug} ({}), so the app stays private or shared with named people until the Brod team reviews it. \
         If the page is legitimate, deploy a version without a password or card form that names another company, or ask the Brod team to clear it.",
        reasons.join("; ")
    )
}

fn rank(access: &str) -> i64 {
    ACCESS.iter().position(|x| *x == access).map(|i| i as i64).unwrap_or(-1)
}

/// A flagged version keeps its app to private or people access: anything wider is narrowed to people. Inside a transaction.
pub fn narrow_if_flagged(conn: &Connection, app: &mut AppRow, n: i64, reasons: Option<&[String]>) -> Result<()> {
    if reasons.is_none() || rank(&app.access) <= rank("people") {
        return Ok(());
    }
    let was = std::mem::replace(&mut app.access, "people".into());
    app.password_hash = None;
    conn.run("UPDATE apps SET access = 'people', password_hash = NULL WHERE id = ?", [&app.id])?;
    event(conn, &app.workspace_id, CHECKER, Some(&app.id), "access", &format!("{was} to people: the phishing check flagged v{n}"))
}

/// Refuse access wider than people while the live version is flagged.
pub fn check_not_flagged(conn: &Connection, app: &AppRow, access: &str) -> Result<()> {
    if rank(access) <= rank("people") {
        return Ok(());
    }
    if let (Some(reasons), Some(n)) = (flag_of(conn, &app.id, app.live_version)?, app.live_version) {
        return Err(Problem::new(403, "flagged", flag_message(&app.slug, n, &reasons)).with("reasons", json!(reasons)));
    }
    Ok(())
}

/// What get_status and list_apps add about an app that is down or flagged.
pub fn add_state(conn: &Connection, app: &AppRow, m: &mut Map<String, Value>) -> Result<()> {
    if let Some(h) = hold_of(conn, app)? {
        m.insert(h.kind.into(), json!({ "reason": h.reason, "since": iso(h.since), "message": hold_message(&h, Some(&app.slug)) }));
    }
    if let (Some(reasons), Some(n)) = (flag_of(conn, &app.id, app.live_version)?, app.live_version) {
        m.insert("flagged".into(), json!({ "message": flag_message(&app.slug, n, &reasons), "reasons": reasons }));
    }
    Ok(())
}

// ---------- the operator's API ----------

fn text(o: &Map<String, Value>, key: &str, max: usize) -> String {
    js_slice(js_trim(&crate::model::field(o, key)), max)
}

/// /v1/admin/... with "Authorization: Bearer <ADMIN_SECRET>":
///   GET  reports?status=open|resolved|dismissed      POST reports/<id> {status: resolved|dismissed, note}
///   POST apps/<workspace>/<app>/takedown {reason}, /restore, /clear (the phishing check's flag)
///   POST workspaces/<workspace>/suspend {reason}, /unsuspend, /trust (may open apps to everyone before it is a day old)
pub async fn serve(st: &State, req: &mut Req, seg: &[String]) -> Result<Response> {
    let given = crate::control::Credentials::of(req).bearer().unwrap_or_default();
    if st.cfg.admin_secret.is_empty() || !safe_equal(&given, &st.cfg.admin_secret) {
        return Err(Problem::new(401, "unauthorized", "The admin API needs the admin secret."));
    }
    let s = |i: usize| seg.get(i).map(String::as_str).filter(|x| !x.is_empty());
    let (what, a, b, action) = (s(1).map(String::from), s(2).map(String::from), s(3).map(String::from), s(4).map(String::from));
    let m = req.method.clone();
    let o: Map<String, Value> = if m == Method::POST {
        // Lenient: a missing or broken body reads as {}.
        match serde_json::from_slice(&req.bytes(64 * 1024, "The request body").await?) {
            Ok(Value::Object(o)) => o,
            _ => Map::new(),
        }
    } else {
        Map::new()
    };
    let status_param = req.param("status").filter(|x| !x.is_empty());
    let path = req.path.clone();
    let out = st
        .db
        .call(move |conn| {
            let t = now();
            match (what.as_deref(), a.as_deref(), b.as_deref(), action.as_deref()) {
                (Some("reports"), None, _, _) if m == Method::GET => {
                    if let Some(sp) = &status_param
                        && !["open", "resolved", "dismissed"].contains(&sp.as_str())
                    {
                        return Err(Problem::new(400, "bad_status", "status is open, resolved or dismissed."));
                    }
                    let reports = conn.rows_json(
                        "SELECT r.id, a.slug AS app, w.slug AS workspace, r.kind, r.reporter, r.reason, r.created_at, r.status, r.resolved_at, r.note,
                                a.taken_down_at, w.suspended_at FROM reports r LEFT JOIN apps a ON a.id = r.app_id LEFT JOIN workspaces w ON w.id = a.workspace_id
                         WHERE (? IS NULL OR r.status = ?) ORDER BY r.created_at DESC LIMIT 200",
                        params![status_param, status_param],
                    )?;
                    return Ok(Some(json!({ "reports": reports })));
                }
                (Some("reports"), Some(id), None, _) if m == Method::POST => {
                    let status = match o.get("status") {
                        None | Some(Value::Null) => "resolved".to_string(),
                        Some(v) => crate::model::js_string(v),
                    };
                    if status != "resolved" && status != "dismissed" {
                        return Err(Problem::new(400, "bad_status", "status is resolved or dismissed."));
                    }
                    let rep = conn.first(
                        "SELECT r.app_id, a.workspace_id FROM reports r LEFT JOIN apps a ON a.id = r.app_id WHERE r.id = ?",
                        [id],
                        |r| Ok((r.get::<_, String>(0)?, r.get::<_, Option<String>>(1)?)),
                    )?;
                    let Some((app_id, ws)) = rep else {
                        return Err(Problem::new(404, "not_found", format!("There is no report {id}.")));
                    };
                    let note = text(&o, "note", 1000);
                    tx(conn, |x| {
                        x.run("UPDATE reports SET status = ?, resolved_at = ?, note = ? WHERE id = ?", params![status, t, note, id])?;
                        if let Some(ws) = &ws {
                            let detail = if note.is_empty() { id.to_string() } else { format!("{id}: {note}") };
                            event(x, ws, OPERATOR, Some(&app_id), &format!("report_{status}"), &detail)?;
                        }
                        Ok(())
                    })?;
                    return Ok(Some(json!({ "report": id, "status": status, "note": note })));
                }
                (Some("apps"), Some(ws), Some(slug), Some(action)) if m == Method::POST => {
                    let app = conn.first(
                        "SELECT a.* FROM apps a JOIN workspaces w ON w.id = a.workspace_id WHERE w.slug = ? AND a.slug = ?",
                        [ws, slug],
                        AppRow::from_row,
                    )?;
                    let Some(app) = app else {
                        return Err(Problem::new(404, "not_found", format!("There is no app {slug} in workspace {ws}.")));
                    };
                    match action {
                        "takedown" => {
                            let reason = text(&o, "reason", 500);
                            if reason.is_empty() {
                                return Err(Problem::new(400, "need_reason", "Give a \"reason\". The owner sees it in get_status and list_apps."));
                            }
                            tx(conn, |x| {
                                x.run("UPDATE apps SET taken_down_at = ?, takedown_reason = ? WHERE id = ?", params![t, reason, app.id])?;
                                x.run(
                                    "UPDATE reports SET status = 'resolved', resolved_at = ?, note = ? WHERE app_id = ? AND status = 'open'",
                                    params![t, format!("taken down: {reason}"), app.id],
                                )?;
                                event(x, &app.workspace_id, OPERATOR, Some(&app.id), "takedown", &reason)
                            })?;
                            return Ok(Some(json!({ "workspace": ws, "app": slug, "taken_down": true, "reason": reason })));
                        }
                        "restore" => {
                            tx(conn, |x| {
                                x.run("UPDATE apps SET taken_down_at = NULL, takedown_reason = '' WHERE id = ?", [&app.id])?;
                                event(x, &app.workspace_id, OPERATOR, Some(&app.id), "restore", &text(&o, "note", 500))
                            })?;
                            return Ok(Some(json!({ "workspace": ws, "app": slug, "taken_down": false })));
                        }
                        "clear" => {
                            let cleared = tx(conn, |x| {
                                let n = x.run(
                                    "UPDATE versions SET scan_cleared_at = ? WHERE app_id = ? AND scan IS NOT NULL AND scan <> '[]' AND scan_cleared_at IS NULL",
                                    params![t, app.id],
                                )?;
                                x.run(
                                    "UPDATE reports SET status = 'resolved', resolved_at = ?, note = 'cleared' WHERE app_id = ? AND kind = 'automatic' AND status = 'open'",
                                    params![t, app.id],
                                )?;
                                event(x, &app.workspace_id, OPERATOR, Some(&app.id), "scan_cleared", &text(&o, "note", 500))?;
                                Ok(n)
                            })?;
                            return Ok(Some(json!({ "workspace": ws, "app": slug, "cleared_versions": cleared })));
                        }
                        _ => {}
                    }
                }
                (Some("workspaces"), Some(ws), Some(action), None) if m == Method::POST => {
                    let id: Option<String> = conn.first("SELECT id FROM workspaces WHERE slug = ?", [ws], |r| r.get(0))?;
                    let Some(id) = id else {
                        return Err(Problem::new(404, "not_found", format!("There is no workspace {ws}.")));
                    };
                    match action {
                        "suspend" => {
                            let reason = text(&o, "reason", 500);
                            if reason.is_empty() {
                                return Err(Problem::new(
                                    400,
                                    "need_reason",
                                    "Give a \"reason\". The workspace sees it in get_status and list_apps.",
                                ));
                            }
                            tx(conn, |x| {
                                x.run("UPDATE workspaces SET suspended_at = ?, suspended_reason = ? WHERE id = ?", params![t, reason, id])?;
                                event(x, &id, OPERATOR, None, "suspend", &reason)
                            })?;
                            return Ok(Some(json!({ "workspace": ws, "suspended": true, "reason": reason })));
                        }
                        "unsuspend" => {
                            tx(conn, |x| {
                                x.run("UPDATE workspaces SET suspended_at = NULL, suspended_reason = '' WHERE id = ?", [&id])?;
                                event(x, &id, OPERATOR, None, "unsuspend", &text(&o, "note", 500))
                            })?;
                            return Ok(Some(json!({ "workspace": ws, "suspended": false })));
                        }
                        "trust" => {
                            tx(conn, |x| {
                                x.run("UPDATE workspaces SET trusted_at = COALESCE(trusted_at, ?) WHERE id = ?", params![t, id])?;
                                event(x, &id, OPERATOR, None, "trust", &text(&o, "note", 500))
                            })?;
                            return Ok(Some(json!({ "workspace": ws, "trusted": true })));
                        }
                        _ => {}
                    }
                }
                _ => {}
            }
            Ok(None)
        })
        .await?;
    match out {
        Some(v) => Ok(crate::http::json(v)),
        None => Err(Problem::new(404, "not_found", format!("No such admin route: {} {path}", req.method))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_addresses_like_the_typescript() {
        let k = |s: &str| ip_key(s.parse().unwrap());
        assert_eq!(k("203.0.113.9"), "203.0.113.9");
        assert_eq!(k("::ffff:203.0.113.9"), "203.0.113.9");
        assert_eq!(k("2001:db8:1:2:3:4:5:6"), "2001:db8:1:2::/64");
        assert_eq!(k("2001:db8::1"), "2001:db8:0:0::/64");
        assert_eq!(k("::1"), "0:0:0:0::/64");
    }
}
