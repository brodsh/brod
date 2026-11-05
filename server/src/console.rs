// SPDX-License-Identifier: AGPL-3.0-only
//! The operator's admin API for running the server (docs/plans/admin-mode.md 1.6): an overview, the instance
//! settings, per-workspace limit overrides, the operator list and the server-wide audit log. Reports, takedowns and
//! suspensions stay in abuse.rs and nodes in nodes.rs; all three accept the same operators (operator.rs).
//!
//! Server-wide changes are written to the one audit log (events) with an empty workspace_id, so they never show up
//! in a workspace's own activity.

use axum::http::Method;
use axum::response::Response;
use serde_json::{Map, Value, json};

use crate::allowances::{self, Override};
use crate::config::Config;
use crate::db::{Connection, Sql, event, params, tx};
use crate::http::{Req, json};
use crate::instance::{self, Settings};
use crate::model::{MB, UNLIMITED};
use crate::operator::Operator;
use crate::problem::{Problem, Result};
use crate::state::State;
use crate::util::now;

/// The workspace_id of server-wide audit events.
pub const SERVER: &str = "";
const PAGE: i64 = 50;

/// Whether `seg` (after /v1) is a route this module serves.
pub fn handles(seg: &[String]) -> bool {
    let s = |i: usize| seg.get(i).map(String::as_str).filter(|x| !x.is_empty());
    match s(1) {
        Some("overview" | "settings" | "operators" | "audit") => true,
        Some("workspaces") => s(2).is_none() || (s(3) == Some("limits") && s(4).is_none()),
        _ => false,
    }
}

pub async fn serve(st: &State, req: &mut Req, seg: &[String]) -> Result<Response> {
    let op = crate::operator::authenticate(st, req).await?;
    let s = |i: usize| seg.get(i).map(String::as_str).filter(|x| !x.is_empty()).map(String::from);
    let m = req.method.clone();
    let body: Map<String, Value> = if m == Method::PATCH || m == Method::POST {
        match serde_json::from_slice(&req.bytes(64 * 1024, "The request body").await?) {
            Ok(Value::Object(o)) => o,
            Ok(_) => return Err(Problem::new(400, "bad_body", "Send a JSON object.")),
            Err(e) => return Err(Problem::new(400, "bad_body", format!("The body is not JSON: {e}."))),
        }
    } else {
        Map::new()
    };
    let (q, cursor) = (req.param("q").unwrap_or_default(), req.param("cursor").unwrap_or_default());
    let cfg = st.cfg.clone();
    let (what, a) = (s(1).unwrap_or_default(), s(2));
    let out = match (what.as_str(), m.clone()) {
        ("overview", Method::GET) => st.db.call(move |c| overview(c, &cfg)).await?,
        ("settings", Method::GET) => json!({ "settings": instance::current(st).await.describe(&st.cfg) }),
        ("settings", Method::PATCH) => {
            let op2 = op.clone();
            st.db.call(move |c| patch_settings(c, &cfg, &op2, &body)).await?;
            let fresh = instance::refresh(st).await?;
            json!({ "settings": fresh.describe(&st.cfg) })
        }
        ("workspaces", Method::GET) if a.is_none() => st.db.call(move |c| list_workspaces(c, &cfg, &q, &cursor)).await?,
        ("workspaces", Method::GET) => st.db.call(move |c| limits_of(c, &cfg, &a.unwrap_or_default())).await?,
        ("workspaces", Method::PATCH) if a.is_some() => {
            let op2 = op.clone();
            st.db.call(move |c| patch_limits(c, &cfg, &op2, &a.unwrap_or_default(), &body)).await?
        }
        ("operators", Method::GET) if a.is_none() => st.db.call(|c| list_operators(c)).await?,
        ("operators", Method::POST) if a.is_none() => {
            let op2 = op.clone();
            st.db.call(move |c| add_operator(c, &op2, &body)).await?
        }
        ("operators", Method::DELETE) if a.is_some() => {
            let op2 = op.clone();
            st.db.call(move |c| remove_operator(c, &cfg, &op2, &a.unwrap_or_default())).await?
        }
        ("audit", Method::GET) => st.db.call(move |c| audit(c, &cursor)).await?,
        _ => return Err(Problem::new(405, "method_not_allowed", "That method is not supported here.")),
    };
    Ok(json(out))
}

fn audit_event(conn: &Connection, op: &Operator, action: &str, detail: &str) -> Result<()> {
    event(conn, SERVER, &op.actor, None, action, detail)
}

/// Counts for the console's first tab.
pub fn overview(conn: &Connection, cfg: &Config) -> Result<Value> {
    let n = |sql: &str| conn.count(sql, ());
    let storage = n("SELECT COALESCE(SUM(size), 0) FROM (SELECT DISTINCT app_id, sha256, size FROM manifest_entries) t")?
        + n(
            "SELECT COALESCE(SUM(v.bytes), 0) FROM versions v WHERE NOT EXISTS (SELECT 1 FROM version_manifests m WHERE m.app_id = v.app_id AND m.version = v.n)",
        )?
        + n("SELECT COALESCE(SUM(file_bytes), 0) FROM apps")?
        + n("SELECT COALESCE(SUM(data_bytes), 0) FROM apps")?;
    Ok(json!({
        "mode": if cfg.mode == crate::config::Mode::Hosted { "hosted" } else { "self-hosted" },
        "version": env!("CARGO_PKG_VERSION"),
        "workspaces": n("SELECT COUNT(*) FROM workspaces")?,
        "suspended_workspaces": n("SELECT COUNT(*) FROM workspaces WHERE suspended_at IS NOT NULL")?,
        "users": n("SELECT COUNT(*) FROM users")?,
        "operators": crate::operator::count(conn)?,
        "apps": {
            "total": n("SELECT COUNT(*) FROM apps")?,
            "live": n("SELECT COUNT(*) FROM apps WHERE status = 'live' AND taken_down_at IS NULL")?,
            "paused": n("SELECT COUNT(*) FROM apps WHERE status = 'paused'")?,
            "taken_down": n("SELECT COUNT(*) FROM apps WHERE taken_down_at IS NOT NULL")?,
        },
        "storage_bytes": storage,
        "open_reports": n("SELECT COUNT(*) FROM reports WHERE status = 'open'")?,
        "warnings": cfg.warnings,
    }))
}

/// `{key: value | null}`: every key is checked before any is written, so a bad body changes nothing.
fn patch_settings(conn: &Connection, cfg: &Config, op: &Operator, body: &Map<String, Value>) -> Result<()> {
    if body.is_empty() {
        return Err(Problem::new(400, "bad_body", "Send the settings to change, such as {\"limits.max_running_apps\": 5}."));
    }
    for (key, v) in body {
        instance::check(cfg, key, (!v.is_null()).then_some(v))?;
    }
    for (key, v) in body {
        let stored = instance::write(conn, cfg, key, (!v.is_null()).then_some(v), &op.actor)?;
        let shown = stored.map_or_else(|| "default".to_string(), |v| v.to_string());
        audit_event(conn, op, "setting_changed", &format!("{key} = {shown}"))?;
    }
    Ok(())
}

fn limit_json(n: i64, scale: i64) -> Value {
    if n == UNLIMITED { Value::Null } else { json!(n / scale) }
}

fn plan_json(p: &crate::model::Plan) -> Value {
    json!({
        "max_running_apps": limit_json(p.apps, 1), "max_members": limit_json(p.members, 1),
        "max_storage_mb": limit_json(p.storage, MB), "analytics_days": p.analytics_days,
    })
}

fn override_json(o: Option<&Override>) -> Value {
    let Some(o) = o else { return Value::Null };
    let f = |v: Option<i64>, scale: i64| match v {
        None => Value::Null,
        Some(n) if n == UNLIMITED => json!("unlimited"),
        Some(n) => json!(n / scale),
    };
    json!({
        "max_running_apps": f(o.max_running_apps, 1), "max_members": f(o.max_members, 1),
        "max_storage_mb": f(o.max_storage, MB), "analytics_days": f(o.analytics_days, 1), "note": o.note,
    })
}

struct Ws {
    id: String,
    slug: String,
    name: String,
    plan: String,
    created_at: i64,
    suspended: bool,
}

fn ws_by_slug(conn: &Connection, slug: &str) -> Result<Ws> {
    conn.first(
        "SELECT id, slug, name, plan, created_at, CASE WHEN suspended_at IS NULL THEN 0 ELSE 1 END FROM workspaces WHERE slug = ?",
        [slug],
        |r| {
            Ok(Ws {
                id: r.get(0)?,
                slug: r.get(1)?,
                name: r.get(2)?,
                plan: r.get(3)?,
                created_at: r.get(4)?,
                suspended: r.get::<_, i64>(5)? == 1,
            })
        },
    )?
    .ok_or_else(|| Problem::new(404, "not_found", format!("There is no workspace {slug:?}.")))
}

/// One workspace with its usage and limits.
fn describe(conn: &Connection, cfg: &Config, settings: &Settings, w: &Ws) -> Result<Value> {
    let o = allowances::override_of(conn, &w.id)?;
    let base = allowances::base(settings, cfg.mode, &w.plan);
    let effective = allowances::apply(base, o.as_ref());
    let count = |sql: &str| conn.count(sql, [&w.id]);
    Ok(json!({
        "slug": w.slug, "name": w.name, "plan": w.plan, "created_at": w.created_at, "suspended": w.suspended,
        "usage": {
            "running_apps": count("SELECT COUNT(*) FROM apps WHERE workspace_id = ? AND status = 'live' AND taken_down_at IS NULL")?,
            "apps": count("SELECT COUNT(*) FROM apps WHERE workspace_id = ?")?,
            "members": count("SELECT COUNT(*) FROM members WHERE workspace_id = ? AND role != 'guest'")?,
            "storage_bytes": crate::usage::workspace_storage(conn, &w.id)?.total(),
        },
        "base": plan_json(&base), "override": override_json(o.as_ref()), "effective": plan_json(&effective),
    }))
}

/// Workspaces, newest first, PAGE at a time. `q` matches slug or name; `cursor` is the offset of the next page.
fn list_workspaces(conn: &Connection, cfg: &Config, q: &str, cursor: &str) -> Result<Value> {
    let offset: i64 = cursor.parse().unwrap_or(0).max(0);
    let like = format!("%{}%", q.trim().to_lowercase().replace('\\', "\\\\").replace('%', "\\%").replace('_', "\\_"));
    let rows = conn.all(
        "SELECT id, slug, name, plan, created_at, CASE WHEN suspended_at IS NULL THEN 0 ELSE 1 END FROM workspaces
         WHERE LOWER(slug) LIKE ? ESCAPE '\\' OR LOWER(name) LIKE ? ESCAPE '\\'
         ORDER BY created_at DESC, id LIMIT ? OFFSET ?",
        params![like, like, PAGE + 1, offset],
        |r| {
            Ok(Ws {
                id: r.get(0)?,
                slug: r.get(1)?,
                name: r.get(2)?,
                plan: r.get(3)?,
                created_at: r.get(4)?,
                suspended: r.get::<_, i64>(5)? == 1,
            })
        },
    )?;
    let settings = Settings::load(conn, cfg)?;
    let more = rows.len() as i64 > PAGE;
    let list = rows.iter().take(PAGE as usize).map(|w| describe(conn, cfg, &settings, w)).collect::<Result<Vec<_>>>()?;
    Ok(json!({ "workspaces": list, "next": more.then(|| (offset + PAGE).to_string()) }))
}

fn limits_of(conn: &Connection, cfg: &Config, slug: &str) -> Result<Value> {
    let w = ws_by_slug(conn, slug)?;
    describe(conn, cfg, &Settings::load(conn, cfg)?, &w)
}

/// A field of the override body: absent keeps it, null inherits, "unlimited" is -1, else a whole number.
fn field(body: &Map<String, Value>, key: &str, max: i64) -> Result<Option<Option<i64>>> {
    let Some(v) = body.get(key) else { return Ok(None) };
    let bad = || Problem::new(400, "bad_limit", format!("{key} must be a whole number from 0 to {max}, \"unlimited\" or null."));
    Ok(Some(match v {
        Value::Null => None,
        Value::String(s) if s == "unlimited" => Some(-1),
        Value::Number(n) => Some(n.as_i64().filter(|n| (0..=max).contains(n)).ok_or_else(bad)?),
        _ => return Err(bad()),
    }))
}

const FIELDS: [(&str, i64); 4] =
    [("max_running_apps", 1_000_000), ("max_members", 1_000_000), ("max_storage_mb", 100_000_000), ("analytics_days", 3650)];

fn patch_limits(conn: &Connection, cfg: &Config, op: &Operator, slug: &str, body: &Map<String, Value>) -> Result<Value> {
    let w = ws_by_slug(conn, slug)?;
    for k in body.keys() {
        if k != "note" && !FIELDS.iter().any(|(f, _)| f == k) {
            return Err(Problem::new(400, "unknown_field", format!("{k:?} is not a limit. Use {}.", FIELDS.map(|f| f.0).join(", "))));
        }
    }
    if body.get("analytics_days").is_some_and(|v| v == "unlimited") {
        return Err(Problem::new(400, "bad_limit", "analytics_days must be a number of days or null."));
    }
    let changes = FIELDS.iter().map(|(k, max)| field(body, k, *max)).collect::<Result<Vec<_>>>()?;
    let note = match body.get("note") {
        None => None,
        Some(Value::Null) => Some(String::new()),
        Some(Value::String(s)) => Some(crate::util::js_slice(s.trim(), 500)),
        Some(_) => return Err(Problem::new(400, "bad_note", "note must be text.")),
    };
    tx(conn, |c| {
        let current: [Option<i64>; 4] = c
            .first(
                "SELECT max_running_apps, max_members, max_storage_mb, analytics_days FROM workspace_limits WHERE workspace_id = ?",
                [&w.id],
                |r| Ok([r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?]),
            )?
            .unwrap_or_default();
        let old_note: String =
            c.first("SELECT note FROM workspace_limits WHERE workspace_id = ?", [&w.id], |r| r.get(0))?.unwrap_or_default();
        let mut next = current;
        for (i, ch) in changes.iter().enumerate() {
            if let Some(v) = ch {
                next[i] = *v;
            }
        }
        let note = note.clone().unwrap_or(old_note);
        c.run("DELETE FROM workspace_limits WHERE workspace_id = ?", [&w.id])?;
        if next.iter().any(Option::is_some) || !note.is_empty() {
            c.run(
                "INSERT INTO workspace_limits (workspace_id, max_running_apps, max_members, max_storage_mb, analytics_days, note, updated_by, updated_at)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                params![w.id, next[0], next[1], next[2], next[3], note, op.actor, now()],
            )?;
        }
        let shown = |v: Option<i64>| v.map_or("inherit".to_string(), |n| if n < 0 { "unlimited".into() } else { n.to_string() });
        let detail = FIELDS.iter().zip(next).map(|((k, _), v)| format!("{k}={}", shown(v))).collect::<Vec<_>>().join(", ");
        event(c, &w.id, &op.actor, None, "limits_changed", &detail)?;
        audit_event(c, op, "limits_changed", &format!("{}: {detail}", w.slug))
    })?;
    limits_of(conn, cfg, slug)
}

fn list_operators(conn: &Connection) -> Result<Value> {
    let rows =
        conn.all("SELECT id, email, name, operator_at FROM users WHERE operator_at IS NOT NULL ORDER BY operator_at, email", (), |r| {
            let (id, email, name, at): (String, String, String, i64) = (r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?);
            Ok(json!({ "id": id, "email": email, "name": name, "since": at }))
        })?;
    Ok(json!({ "operators": rows }))
}

/// Make someone with an account an operator. They must have signed in once, so the email is one they control.
fn add_operator(conn: &Connection, op: &Operator, body: &Map<String, Value>) -> Result<Value> {
    let email = crate::util::norm_email(body.get("email").and_then(Value::as_str).unwrap_or_default());
    if email.is_empty() {
        return Err(Problem::new(400, "need_email", "Send the email of the person to make an operator."));
    }
    tx(conn, |c| {
        let id: Option<String> = c.first("SELECT id FROM users WHERE email = ?", [&email], |r| r.get(0))?;
        let Some(id) = id else {
            return Err(Problem::new(404, "no_account", format!("{email} has no account here yet. Ask them to sign in once first.")));
        };
        if c.run("UPDATE users SET operator_at = ? WHERE id = ? AND operator_at IS NULL", params![now(), id])? > 0 {
            audit_event(c, op, "operator_added", &email)?;
        }
        Ok(())
    })?;
    list_operators(conn)
}

/// Remove an operator. The last one cannot be removed (the admin secret still works, but the console would be
/// orphaned), and the BROD_ADMIN_EMAIL person is made an operator again at the next sign-in, so that is refused too.
fn remove_operator(conn: &Connection, cfg: &Config, op: &Operator, id: &str) -> Result<Value> {
    tx(conn, |c| {
        let email: Option<String> = c.first("SELECT email FROM users WHERE id = ? AND operator_at IS NOT NULL", [id], |r| r.get(0))?;
        let Some(email) = email else {
            return Err(Problem::new(404, "not_found", "That person is not an operator."));
        };
        if cfg.admin_email.as_deref() == Some(email.as_str()) {
            return Err(Problem::new(
                409,
                "admin_email",
                "This is BROD_ADMIN_EMAIL, who is always an operator. Change that environment variable first.",
            ));
        }
        if crate::operator::count(c)? <= 1 {
            return Err(Problem::new(409, "last_operator", "The server needs at least one operator. Add another first."));
        }
        c.run("UPDATE users SET operator_at = NULL WHERE id = ?", [id])?;
        audit_event(c, op, "operator_removed", &email)
    })?;
    list_operators(conn)
}

/// Server-wide audit events, newest first. `cursor` is the id to continue below.
fn audit(conn: &Connection, cursor: &str) -> Result<Value> {
    let before: i64 = cursor.parse().unwrap_or(i64::MAX);
    let rows = conn.all(
        "SELECT id, at, actor, action, detail FROM events WHERE workspace_id = ? AND id < ? ORDER BY id DESC LIMIT ?",
        params![SERVER, before, PAGE + 1],
        |r| {
            let (id, at, actor, action, detail): (i64, i64, String, String, String) =
                (r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?);
            Ok((id, json!({ "id": id, "at": at, "actor": actor, "action": action, "detail": detail })))
        },
    )?;
    let more = rows.len() as i64 > PAGE;
    let page: Vec<_> = rows.into_iter().take(PAGE as usize).collect();
    let next = if more { page.last().map(|(id, _)| id.to_string()) } else { None };
    Ok(json!({ "events": page.into_iter().map(|(_, v)| v).collect::<Vec<_>>(), "next": next }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Mode;

    fn cfg(env: &[(&str, &str)]) -> Config {
        let mut c = Config::for_tests();
        c.mode = Mode::SelfHosted;
        let map: std::collections::HashMap<String, String> = env.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        c.settings_env = instance::from_env(&|k| map.get(k).cloned()).unwrap();
        c
    }

    fn op() -> Operator {
        Operator { actor: "op@x.test".into(), user_id: None }
    }

    fn obj(v: Value) -> Map<String, Value> {
        v.as_object().unwrap().clone()
    }

    #[tokio::test]
    async fn a_bad_settings_patch_changes_nothing() {
        let db = crate::db::test_db();
        db.call(|conn| {
            let c = cfg(&[("BROD_LIMIT_MEMBERS", "3")]);
            let e = patch_settings(conn, &c, &op(), &obj(json!({ "limits.max_running_apps": 4, "nope": 1 }))).unwrap_err();
            assert_eq!(e.status, 404);
            let e = patch_settings(conn, &c, &op(), &obj(json!({ "limits.max_running_apps": 4, "limits.max_members": 9 }))).unwrap_err();
            assert_eq!(e.code, "setting_locked");
            assert_eq!(Settings::load(conn, &c)?.limit("limits.max_running_apps"), None);
            patch_settings(conn, &c, &op(), &obj(json!({ "limits.max_running_apps": 4 })))?;
            assert_eq!(Settings::load(conn, &c)?.limit("limits.max_running_apps"), Some(4));
            patch_settings(conn, &c, &op(), &obj(json!({ "limits.max_running_apps": null })))?;
            assert_eq!(Settings::load(conn, &c)?.limit("limits.max_running_apps"), None);
            let log = audit(conn, "")?;
            assert_eq!(log["events"].as_array().unwrap().len(), 2);
            assert_eq!(log["events"][0]["detail"], "limits.max_running_apps = default");
            Ok(())
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn limit_overrides_set_merge_and_clear() {
        let db = crate::db::test_db();
        db.call(|conn| {
            let c = cfg(&[("BROD_LIMIT_RUNNING_APPS", "2")]);
            conn.run("INSERT INTO workspaces (id, slug, name, plan, created_at) VALUES ('w1', 'acme', 'Acme', 'free', 0)", ())?;
            let v = limits_of(conn, &c, "acme")?;
            assert_eq!((v["effective"]["max_running_apps"].clone(), v["override"].clone()), (json!(2), Value::Null));
            let v = patch_limits(conn, &c, &op(), "acme", &obj(json!({ "max_running_apps": 10, "note": "pilot" })))?;
            assert_eq!(v["effective"]["max_running_apps"], 10);
            let v = patch_limits(conn, &c, &op(), "acme", &obj(json!({ "max_members": "unlimited" })))?;
            assert_eq!((v["override"]["max_running_apps"].clone(), v["override"]["max_members"].clone()), (json!(10), json!("unlimited")));
            assert_eq!(v["effective"]["max_members"], Value::Null);
            assert_eq!(v["override"]["note"], "pilot");
            for bad in [json!({ "max_running_apps": -3 }), json!({ "apps": 1 }), json!({ "analytics_days": "unlimited" })] {
                assert_eq!(patch_limits(conn, &c, &op(), "acme", &obj(bad)).unwrap_err().status, 400);
            }
            let v = patch_limits(conn, &c, &op(), "acme", &obj(json!({ "max_running_apps": null, "max_members": null, "note": null })))?;
            assert_eq!(v["override"], Value::Null);
            assert_eq!(v["effective"]["max_running_apps"], 2);
            assert_eq!(patch_limits(conn, &c, &op(), "nope", &obj(json!({}))).unwrap_err().status, 404);
            let list = list_workspaces(conn, &c, "ACM", "")?;
            assert_eq!(list["workspaces"].as_array().unwrap().len(), 1);
            assert_eq!(list_workspaces(conn, &c, "zzz", "")?["workspaces"].as_array().unwrap().len(), 0);
            Ok(())
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn operators_can_be_added_but_never_all_removed() {
        let db = crate::db::test_db();
        db.call(|conn| {
            let mut c = cfg(&[]);
            let a = crate::people::verified_user(conn, "a@x.test", "")?;
            let b = crate::people::verified_user(conn, "b@x.test", "")?;
            assert_eq!(add_operator(conn, &op(), &obj(json!({ "email": "nobody@x.test" }))).unwrap_err().status, 404);
            add_operator(conn, &op(), &obj(json!({ "email": "A@x.test" })))?;
            assert_eq!(remove_operator(conn, &c, &op(), &a.id).unwrap_err().code, "last_operator");
            let v = add_operator(conn, &op(), &obj(json!({ "email": "b@x.test" })))?;
            assert_eq!(v["operators"].as_array().unwrap().len(), 2);
            c.admin_email = Some("b@x.test".into());
            assert_eq!(remove_operator(conn, &c, &op(), &b.id).unwrap_err().code, "admin_email");
            remove_operator(conn, &c, &op(), &a.id)?;
            assert_eq!(remove_operator(conn, &c, &op(), &a.id).unwrap_err().status, 404);
            assert_eq!(overview(conn, &c)?["operators"], 1);
            Ok(())
        })
        .await
        .unwrap();
    }

    #[test]
    fn routes() {
        let seg = |p: &str| p.split('/').map(String::from).collect::<Vec<_>>();
        assert!(handles(&seg("admin/settings")) && handles(&seg("admin/workspaces")) && handles(&seg("admin/workspaces/acme/limits")));
        assert!(!handles(&seg("admin/workspaces/acme/suspend")) && !handles(&seg("admin/reports")) && !handles(&seg("admin/nodes")));
    }
}
