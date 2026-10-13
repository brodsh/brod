// SPDX-License-Identifier: AGPL-3.0-only
// Shared types and limits.
use crate::db::Row;
use serde::Serialize;
use serde_json::{Map, Value};

pub mod limits {
    pub const INLINE_BYTES: usize = 1024 * 1024;
    pub const DEPLOYS_PER_HOUR: i64 = 30;
    pub const UPLOAD_TTL_MS: i64 = 15 * 60 * 1000;
    pub const DOWNLOAD_TTL_MS: i64 = 15 * 60 * 1000;
    /// How long after someone last worked on an app others are told.
    pub const EDITING_WINDOW_MS: i64 = 2 * 3600 * 1000;
    pub const LOGIN_LINK_TTL_MS: i64 = 15 * 60 * 1000;
    pub const LOGIN_LINKS_PER_HOUR: i64 = 5;
    pub const INVITE_TTL_MS: i64 = 7 * 24 * 3600 * 1000;
    pub const SESSION_TTL_MS: i64 = 30 * 24 * 3600 * 1000;
    pub const APP_CODE_TTL_MS: i64 = 60 * 1000;
    pub const CONFIRM_TTL_MS: i64 = 24 * 3600 * 1000;
    pub const OAUTH_CODE_TTL_MS: i64 = 10 * 60 * 1000;
    /// An OAuth access token lives an hour; the client renews it with its refresh token, which lapses after 30 days unused.
    pub const OAUTH_ACCESS_TTL_MS: i64 = 3600 * 1000;
    pub const OAUTH_REFRESH_TTL_MS: i64 = 30 * 24 * 3600 * 1000;
    /// The longest life a token made on the connections page or with POST /v1/tokens can be given.
    pub const TOKEN_MAX_DAYS: i64 = 365;
    /// MCP clients registering themselves, across the server.
    pub const OAUTH_CLIENTS_PER_HOUR: i64 = 100;
    pub const IDENTITY_TTL_SEC: i64 = 300;
    pub const SERVER_CPU_MS: i64 = 50;
    pub const SERVER_SUBREQUESTS: i64 = 50;
    pub const LOG_BYTES: usize = 8 * 1024;
    pub const LOG_RETENTION_MS: i64 = 7 * 24 * 3600 * 1000;
    /// Wrong passwords for one password-protected app, from anyone.
    pub const PASSWORD_TRIES_PER_15_MIN: i64 = 30;
}

/// Access modes, least open first. Moving right is widening, which an agent needs a person to confirm.
pub const ACCESS: [&str; 6] = ["private", "people", "workspace", "password", "signed_in", "public"];

#[derive(Clone, Debug, Serialize)]
pub struct User {
    pub id: String,
    pub email: String,
    pub name: String,
    pub email_verified_at: Option<i64>,
}

#[derive(Clone, Debug, Serialize)]
pub struct Workspace {
    pub id: String,
    pub slug: String,
    pub name: String,
    pub plan: String,
    pub color: String,
    pub icon: String,
    pub created_at: i64,
}

impl Workspace {
    /// From a row that selected w.* (id, slug, name, plan, color, icon, created_at).
    pub fn from_row(r: &Row) -> crate::problem::Result<Workspace> {
        Ok(Workspace {
            id: r.get("id")?,
            slug: r.get("slug")?,
            name: r.get("name")?,
            plan: r.get("plan")?,
            color: r.get("color")?,
            icon: r.get("icon")?,
            created_at: r.get("created_at")?,
        })
    }
}

#[derive(Clone, Debug)]
pub struct AppRow {
    pub id: String,
    pub workspace_id: String,
    pub owner_id: String,
    pub slug: String,
    pub name: String,
    pub title: String,
    pub welcome: String,
    pub status: String,
    pub access: String,
    /// The app's roles as a JSON list, most powerful first.
    pub roles: String,
    pub live_version: Option<i64>,
    pub created_at: i64,
    pub secrets_rev: i64,
    /// The space the app belongs to, if any.
    pub space_id: Option<String>,
    /// Bytes the app keeps in env.FILES.
    pub file_bytes: i64,
    /// Bytes in the app's database and key-value store, as the runtime last reported.
    pub data_bytes: i64,
    /// The hashed password of a password-protected app (access "password"); None in every other mode.
    pub password_hash: Option<String>,
    /// Set when the platform operator took the app down (abuse.rs), with the reason the owner sees.
    pub taken_down_at: Option<i64>,
    pub takedown_reason: String,
    /// The version waiting on staging (<slug>--staging.<workspace>), if any. It goes live with publish_staging.
    pub staging_version: Option<i64>,
}

impl AppRow {
    pub fn from_row(r: &Row) -> crate::problem::Result<AppRow> {
        Ok(AppRow {
            id: r.get("id")?,
            workspace_id: r.get("workspace_id")?,
            owner_id: r.get("owner_id")?,
            slug: r.get("slug")?,
            name: r.get("name")?,
            title: r.get("title")?,
            welcome: r.get("welcome")?,
            status: r.get("status")?,
            access: r.get("access")?,
            roles: r.get("roles")?,
            live_version: r.get("live_version")?,
            created_at: r.get("created_at")?,
            secrets_rev: r.get("secrets_rev")?,
            space_id: r.get("space_id")?,
            file_bytes: r.get("file_bytes")?,
            data_bytes: r.get("data_bytes")?,
            password_hash: r.get("password_hash")?,
            taken_down_at: r.get("taken_down_at")?,
            takedown_reason: r.get("takedown_reason")?,
            staging_version: r.get("staging_version")?,
        })
    }
    pub fn role_list(&self) -> Vec<String> {
        serde_json::from_str(&self.roles).unwrap_or_else(|_| vec!["owner".into(), "editor".into(), "viewer".into()])
    }
    pub fn display_name(&self) -> &str {
        if self.title.is_empty() { &self.name } else { &self.title }
    }
}

/// Who is acting: a person signed in to the dashboard, or an agent connection acting for the person who made it.
#[derive(Clone, Debug)]
pub struct Caller {
    pub workspace: Workspace,
    pub user: User,
    pub role: String,
    pub actor: String,
    pub agent: bool,
    /// An agent connection with the "read" scope: it may look (status, logs, settings) but not change anything.
    pub read_only: bool,
}

/// Plan allowances. Only running apps count; guests do not count as members. Storage counts every kept version's
/// bundle and every file a server app keeps in env.FILES.
pub struct Plan {
    pub apps: i64,
    pub members: i64,
    pub storage: i64,
    /// Days of analytics (page views, browser events, request stats) the workspace keeps.
    pub analytics_days: i64,
}
pub const MB: i64 = 1024 * 1024;
pub const PLANS: [&str; 3] = ["free", "solo", "team"];
/// A limit that is never reached: what a self-hosted server allows. JSON shows it as null (`limit_json`).
pub const UNLIMITED: i64 = i64::MAX;
/// How long a self-hosted server keeps analytics.
pub const SELF_HOSTED_ANALYTICS_DAYS: i64 = 365;

/// Self-hosted servers have no plans: every workspace may run as many apps, with as many people and as much storage,
/// as the machine holds. Set once at start (state.rs) from BROD_MODE.
static SELF_HOSTED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
pub fn set_self_hosted(on: bool) {
    let _ = SELF_HOSTED.set(on);
}
pub fn self_hosted() -> bool {
    SELF_HOSTED.get().copied().unwrap_or(false)
}

/// The plan name to show for a workspace: its stored plan when hosted, "self-hosted" otherwise.
pub fn plan_label(w: &Workspace) -> &str {
    if self_hosted() { "self-hosted" } else { &w.plan }
}

/// A limit as JSON: a number, or null when there is none.
pub fn limit_json(n: i64) -> serde_json::Value {
    if n == UNLIMITED { serde_json::Value::Null } else { n.into() }
}

pub fn plan_named(name: &str) -> Plan {
    if self_hosted() {
        return Plan { apps: UNLIMITED, members: UNLIMITED, storage: UNLIMITED, analytics_days: SELF_HOSTED_ANALYTICS_DAYS };
    }
    match name {
        "solo" => Plan { apps: 15, members: 1, storage: 5 * 1024 * MB, analytics_days: 365 },
        "team" => Plan { apps: 50, members: 25, storage: 25 * 1024 * MB, analytics_days: 730 },
        _ => Plan { apps: 10, members: 10, storage: FREE_STORAGE.get().copied().unwrap_or(250 * MB), analytics_days: 30 },
    }
}

/// The free plan's storage, smaller only in DEV_MODE (DEV_FREE_STORAGE_MB) so tests can fill it.
static FREE_STORAGE: std::sync::OnceLock<i64> = std::sync::OnceLock::new();
pub fn set_free_storage(bytes: i64) {
    let _ = FREE_STORAGE.set(bytes);
}
pub fn plan(w: &Workspace) -> Plan {
    plan_named(&w.plan)
}

pub fn rank(role: &str) -> i32 {
    match role {
        "admin" => 3,
        "builder" => 2,
        "member" => 1,
        _ => 0,
    }
}

// ---------- reading JSON bodies the way JavaScript does ----------

/// String(v) for a JSON value.
pub fn js_string(v: &Value) -> String {
    match v {
        Value::Null => "null".into(),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => js_number(n),
        Value::String(s) => s.clone(),
        Value::Array(a) => a.iter().map(|x| if x.is_null() { String::new() } else { js_string(x) }).collect::<Vec<_>>().join(","),
        Value::Object(_) => "[object Object]".into(),
    }
}

fn js_number(n: &serde_json::Number) -> String {
    if let Some(i) = n.as_i64() {
        return i.to_string();
    }
    if let Some(u) = n.as_u64() {
        return u.to_string();
    }
    let f = n.as_f64().unwrap_or(f64::NAN);
    if f.fract() == 0.0 && f.abs() < 1e21 { format!("{f:.0}") } else { f.to_string() }
}

/// `String(o[key] ?? '')`
pub fn field(o: &Map<String, Value>, key: &str) -> String {
    match o.get(key) {
        None | Some(Value::Null) => String::new(),
        Some(v) => js_string(v),
    }
}

/// `o[key]` when present and not null.
pub fn present<'a>(o: &'a Map<String, Value>, key: &str) -> Option<&'a Value> {
    o.get(key).filter(|v| !v.is_null())
}

/// Number(v): None for NaN.
pub fn js_to_number(v: Option<&Value>) -> Option<f64> {
    match v {
        None => None,
        Some(Value::Null) => Some(0.0),
        Some(Value::Bool(b)) => Some(if *b { 1.0 } else { 0.0 }),
        Some(Value::Number(n)) => n.as_f64(),
        Some(Value::String(s)) => {
            let t = crate::util::js_trim(s);
            if t.is_empty() { Some(0.0) } else { t.parse::<f64>().ok().filter(|f| f.is_finite()) }
        }
        Some(_) => None,
    }
}

/// Truthiness of a JSON value.
pub fn truthy(v: Option<&Value>) -> bool {
    match v {
        None | Some(Value::Null) => false,
        Some(Value::Bool(b)) => *b,
        Some(Value::Number(n)) => n.as_f64().is_some_and(|f| f != 0.0 && !f.is_nan()),
        Some(Value::String(s)) => !s.is_empty(),
        Some(_) => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn reads_values_like_javascript() {
        assert_eq!(js_string(&json!(5)), "5");
        assert_eq!(js_string(&json!(1.5)), "1.5");
        assert_eq!(js_string(&json!(null)), "null");
        assert_eq!(js_string(&json!(["a", 1])), "a,1");
        let o = json!({ "a": null, "b": "x" });
        assert_eq!(field(o.as_object().unwrap(), "a"), "");
        assert_eq!(field(o.as_object().unwrap(), "b"), "x");
        assert_eq!(js_to_number(Some(&json!("2"))), Some(2.0));
        assert_eq!(js_to_number(Some(&json!("x"))), None);
        assert!(truthy(Some(&json!("a"))) && !truthy(Some(&json!(""))));
    }
}
