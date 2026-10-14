// SPDX-License-Identifier: AGPL-3.0-only
// The control plane. The REST API, the MCP endpoint and the confirmation pages call only these functions.
use crate::db::{Connection, params};
use bytes::Bytes;
use serde_json::{Map, Value, json};

use crate::abuse;
use crate::config::Config;
use crate::db::{Sql, event, tx};
use crate::market::read_tree;
use crate::model::{ACCESS, AppRow, Caller, User, Workspace, field, js_string, limits, plan, present, truthy};
use crate::people::{self, require_role};
use crate::problem::{Problem, Result};
use crate::runtime::{self, ServerInfo};
use crate::secrets;
use crate::state::State;
use crate::tar::{BundleFile, FILE_BYTES, MAX_FILES, UNPACKED_BYTES};
use crate::util::{
    app_url, capitalise, content_type, hash_password, iso, js_slice, js_trim, now, random_id, sha256_hex, slugify, staging_url,
};
use base64::Engine;

// ---------- who is calling ----------

pub const PLATFORM_COOKIE: &str = "brod_platform";

/// The signed-in person behind a dashboard request, from the platform session cookie.
pub fn person(conn: &Connection, cfg: &Config, cookie_header: Option<&str>) -> Result<Option<(User, String)>> {
    let token = crate::util::cookie(cookie_header, &cfg.api_origin, PLATFORM_COOKIE);
    Ok(people::session_user(conn, &token, None)?.map(|s| (s.user, s.hash)))
}

/// A cookie-signed-in browser may only change things from the platform's own pages.
pub fn check_origin(cfg: &Config, method: &str, origin: Option<&str>) -> Result<()> {
    if method == "GET" || method == "HEAD" {
        return Ok(());
    }
    if origin != Some(cfg.api_origin.as_str()) {
        return Err(Problem::new(403, "bad_origin", "Changes made with a sign-in cookie must come from the Brod dashboard."));
    }
    Ok(())
}

/// What authenticate() reads from a request.
#[derive(Clone)]
pub struct Credentials {
    pub method: String,
    pub authorization: Option<String>,
    pub cookie: Option<String>,
    pub origin: Option<String>,
    /// X-Brod-Workspace, or else ?workspace=.
    pub workspace: Option<String>,
}

impl Credentials {
    pub fn of(req: &crate::http::Req) -> Credentials {
        Credentials {
            method: req.method.as_str().to_string(),
            authorization: req.header("authorization").map(String::from),
            cookie: req.header("cookie").map(String::from),
            origin: req.header("origin").map(String::from),
            workspace: req.header("x-brod-workspace").map(String::from).or_else(|| req.param("workspace")),
        }
    }
    /// The token in "Authorization: Bearer <token>".
    pub fn bearer(&self) -> Option<String> {
        let a = self.authorization.as_deref()?;
        let (scheme, rest) = a.split_once(|c: char| c.is_whitespace())?;
        let token = rest.trim_start();
        (scheme.eq_ignore_ascii_case("bearer") && !token.is_empty() && !token.chars().any(char::is_whitespace)).then(|| token.to_string())
    }
}

/// Authenticate an API or MCP request. An agent sends its connection token; a person's browser sends the
/// platform session cookie and names the workspace with the X-Brod-Workspace header or ?workspace=.
pub fn authenticate(conn: &Connection, cfg: &Config, cr: &Credentials) -> Result<Caller> {
    if let Some(token) = cr.bearer() {
        let row = conn.first(
            "SELECT t.id AS tid, t.name AS tname, t.scope, t.expires_at, t.client_id, u.id AS uid, u.email, u.name AS uname, u.email_verified_at, mb.role, w.*
             FROM tokens t JOIN workspaces w ON w.id = t.workspace_id JOIN users u ON u.id = t.user_id
             LEFT JOIN members mb ON mb.workspace_id = t.workspace_id AND mb.user_id = t.user_id
             WHERE t.hash = ? AND t.revoked_at IS NULL",
            [sha256_hex(&token)],
            |r| {
                Ok((
                    (r.get::<_, String>("tid")?, r.get::<_, String>("tname")?, r.get::<_, String>("scope")?),
                    (r.get::<_, Option<i64>>("expires_at")?, r.get::<_, Option<String>>("client_id")?),
                    User {
                        id: r.get("uid")?,
                        email: r.get("email")?,
                        name: r.get("uname")?,
                        email_verified_at: r.get("email_verified_at")?,
                    },
                    r.get::<_, Option<String>>("role")?,
                    Workspace::from_row(r)?,
                ))
            },
        )?;
        let Some(((tid, tname, scope), (expires_at, client_id), user, role, workspace)) = row else {
            return Err(Problem::new(401, "unauthorized", "That token is not valid or has been revoked."));
        };
        if let Some(at) = expires_at.filter(|at| *at <= now()) {
            return Err(Problem::new(
                401,
                "token_expired",
                if client_id.is_some() {
                    "This access token has expired. Get a new one from the token endpoint with the refresh token.".to_string()
                } else {
                    format!("This token expired on {}. Make a new one on the workspace's connections page.", &iso(at)[..10])
                },
            ));
        }
        let role = match role {
            Some(r) if r != "guest" => r,
            _ => {
                return Err(Problem::new(
                    401,
                    "unauthorized",
                    "The person who made this connection is no longer a builder in the workspace.",
                ));
            }
        };
        conn.run("UPDATE tokens SET last_used_at = ? WHERE id = ?", params![now(), tid])?;
        return Ok(Caller { workspace, user, role, actor: tname, agent: true, read_only: scope == "read" });
    }
    let Some((user, _)) = person(conn, cfg, cr.cookie.as_deref())? else {
        return Err(Problem::new(401, "unauthorized", "Sign in, or send an agent token as \"Authorization: Bearer <token>\"."));
    };
    check_origin(cfg, &cr.method, cr.origin.as_deref())?;
    let ws = cr.workspace.as_deref();
    let Some((workspace, role)) = people::membership(conn, &user, ws)? else {
        return Err(match ws {
            Some(w) => Problem::new(404, "no_workspace", format!("You are not in a workspace called \"{w}\".")),
            None => Problem::new(409, "no_workspace", "You are not in any workspace yet. Create one with POST /v1/workspaces."),
        });
    };
    let actor = user.email.clone();
    Ok(Caller { workspace, user, role, actor, agent: false, read_only: false })
}

/// A read-only connection may look but not change anything.
pub fn require_write(c: &Caller, action: &str) -> Result<()> {
    if c.read_only {
        return Err(Problem::new(
            403,
            "read_only",
            format!(
                "This connection is read-only, so it cannot {action}. Ask the person to connect the agent with deploy and manage rights."
            ),
        ));
    }
    Ok(())
}

pub async fn authenticate_async(st: &State, cr: Credentials) -> Result<Caller> {
    let cfg = st.cfg.clone();
    st.db.call(move |c| authenticate(c, &cfg, &cr)).await
}

// ---------- agent connections ----------

/// What a connection may do: "manage" (deploy and change things) or "read" (status, logs and settings only).
pub fn token_scope(v: Option<&Value>) -> Result<String> {
    match v.map(js_string).as_deref().map(str::trim) {
        None | Some("") | Some("manage") => Ok("manage".into()),
        Some("read") => Ok("read".into()),
        Some(_) => Err(Problem::new(400, "bad_scope", "scope is \"manage\" (deploy and change apps) or \"read\" (status and logs only).")),
    }
}

/// When a token made by a person stops working: never (missing, null, 0 or "never"), or in 1 to 365 days.
pub fn token_expiry(v: Option<&Value>) -> Result<Option<i64>> {
    let bad = || {
        Problem::new(
            400,
            "bad_expiry",
            format!("expires_in_days is a whole number of days from 1 to {}, or null for never.", limits::TOKEN_MAX_DAYS),
        )
    };
    let days = match v {
        None | Some(Value::Null) => return Ok(None),
        Some(Value::String(s)) if s.trim().is_empty() || s.trim() == "never" => return Ok(None),
        Some(v) => crate::model::js_to_number(Some(v)).ok_or_else(bad)?,
    };
    if days == 0.0 {
        return Ok(None);
    }
    if days.fract() != 0.0 || !(1.0..=limits::TOKEN_MAX_DAYS as f64).contains(&days) {
        return Err(bad());
    }
    Ok(Some(now() + days as i64 * 24 * 3600 * 1000))
}

/// A token is one named, revocable connection, for example one agent. It is shown once and stored only as a hash.
pub fn create_token(conn: &Connection, c: &Caller, name: &str, scope: &str, expires_at: Option<i64>) -> Result<Value> {
    if c.agent {
        return Err(Problem::new(403, "forbidden", "An agent cannot create connections. Ask the person to do it from the dashboard."));
    }
    require_role(c, "builder", "connect an agent")?;
    let mut clean = js_slice(js_trim(name), 40);
    if clean.is_empty() {
        clean = "agent".into();
    }
    let token = random_id("brod_", 24);
    let id = random_id("tok_", 8);
    tx(conn, |x| {
        x.run(
            "INSERT INTO tokens (id, workspace_id, user_id, name, hash, created_at, scope, expires_at) VALUES (?,?,?,?,?,?,?,?)",
            params![id, c.workspace.id, c.user.id, clean, sha256_hex(&token), now(), scope, expires_at],
        )?;
        event(x, &c.workspace.id, &c.actor, None, "token_created", &format!("connection \"{clean}\" ({scope})"))
    })?;
    Ok(json!({ "id": id, "name": clean, "token": token, "scope": scope, "expires_at": expires_at }))
}

/// A connection made by OAuth sign-in: an access token that lives an hour and a refresh token to renew it.
pub fn create_oauth_token(conn: &Connection, c: &Caller, client_id: &str, name: &str, scope: &str) -> Result<Value> {
    require_role(c, "builder", "connect an agent")?;
    let (access, refresh, id, at) = (random_id("brod_", 24), random_id("brodr_", 24), random_id("tok_", 8), now());
    let clean = js_slice(js_trim(name), 40);
    tx(conn, |x| {
        x.run(
            "INSERT INTO tokens (id, workspace_id, user_id, name, hash, created_at, scope, expires_at, client_id, refresh_hash, refresh_expires_at)
             VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            params![
                id,
                c.workspace.id,
                c.user.id,
                clean,
                sha256_hex(&access),
                at,
                scope,
                at + limits::OAUTH_ACCESS_TTL_MS,
                client_id,
                sha256_hex(&refresh),
                at + limits::OAUTH_REFRESH_TTL_MS
            ],
        )?;
        event(x, &c.workspace.id, &c.actor, None, "token_created", &format!("connection \"{clean}\" ({scope}, signed in)"))
    })?;
    Ok(oauth_pair(&access, &refresh, scope))
}

/// What the token endpoint returns.
pub fn oauth_pair(access: &str, refresh: &str, scope: &str) -> Value {
    json!({
        "access_token": access, "token_type": "Bearer", "expires_in": limits::OAUTH_ACCESS_TTL_MS / 1000,
        "refresh_token": refresh, "scope": if scope == "read" { "brod:read" } else { "brod" },
    })
}

/// Swap a refresh token for a new access token and a new refresh token (rotation). The old refresh token stops working;
/// if it is ever sent again someone has a copy, so the whole connection is revoked. A client may narrow "manage" to
/// "read" but never widen. Err is the reason, for an invalid_grant answer.
pub fn refresh_oauth_token(
    conn: &Connection,
    client_id: &str,
    refresh: &str,
    want: Option<&str>,
) -> Result<std::result::Result<Value, String>> {
    let hash = sha256_hex(refresh);
    let at = now();
    tx(conn, |x| {
        let row = x.first(
            "SELECT t.id, t.workspace_id, t.client_id, t.scope, t.refresh_expires_at, t.revoked_at, m.role
             FROM tokens t LEFT JOIN members m ON m.workspace_id = t.workspace_id AND m.user_id = t.user_id WHERE t.refresh_hash = ?",
            [&hash],
            |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, Option<String>>(2)?,
                    r.get::<_, String>(3)?,
                    r.get::<_, Option<i64>>(4)?,
                    r.get::<_, Option<i64>>(5)?,
                    r.get::<_, Option<String>>(6)?,
                ))
            },
        )?;
        let Some((id, _, cid, scope, lapses, revoked, role)) = row else {
            // A refresh token that was already swapped: whoever sends it now holds a copy. Cut the connection off.
            let reused = x.first(
                "UPDATE tokens SET revoked_at = ? WHERE prev_refresh_hash = ? AND revoked_at IS NULL RETURNING id, workspace_id",
                params![at, hash],
                |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)),
            )?;
            if let Some((id, wid)) = reused {
                event(x, &wid, "brod", None, "token_revoked", &format!("{id}: an old refresh token was used again"))?;
                return Ok(Err("This refresh token was already used, so the connection has been disconnected. Sign in again.".into()));
            }
            return Ok(Err("This refresh token is not valid. Sign in again.".into()));
        };
        if revoked.is_some() {
            return Ok(Err("This connection was disconnected. Sign in again.".into()));
        }
        if cid.as_deref() != Some(client_id) {
            return Ok(Err("The refresh token was issued to another client.".into()));
        }
        if lapses.is_none_or(|l| l <= at) {
            return Ok(Err("This refresh token has lapsed. Sign in again.".into()));
        }
        if !matches!(role.as_deref(), Some("admin" | "builder")) {
            return Ok(Err("The person who signed in is no longer a builder in that workspace.".into()));
        }
        let scope = match want.map(str::trim).filter(|w| !w.is_empty()) {
            None => scope,
            Some(w) => match oauth_scope(w) {
                "manage" if scope == "read" => {
                    return Ok(Err("A refreshed token cannot have more rights than the connection was given.".into()));
                }
                s => s.to_string(),
            },
        };
        let (access, next) = (random_id("brod_", 24), random_id("brodr_", 24));
        x.run(
            "UPDATE tokens SET hash = ?, expires_at = ?, scope = ?, prev_refresh_hash = refresh_hash, refresh_hash = ?, refresh_expires_at = ? WHERE id = ?",
            params![
                sha256_hex(&access),
                at + limits::OAUTH_ACCESS_TTL_MS,
                scope,
                sha256_hex(&next),
                at + limits::OAUTH_REFRESH_TTL_MS,
                id
            ],
        )?;
        Ok(Ok(oauth_pair(&access, &next, &scope)))
    })
}

/// The scope an OAuth client asks for, as space-separated words: "brod:read" without "brod" or "brod:manage" means
/// read-only; anything else deploys and manages. Words Brod does not know (offline_access, openid) are ignored.
pub fn oauth_scope(asked: &str) -> &'static str {
    let words: Vec<&str> = asked.split_whitespace().collect();
    let read = words.contains(&"brod:read") && !words.iter().any(|w| matches!(*w, "brod" | "brod:manage"));
    if read { "read" } else { "manage" }
}

pub fn list_tokens(conn: &Connection, c: &Caller) -> Result<Vec<Value>> {
    require_role(c, "builder", "see agent connections")?;
    conn.rows_json(
        "SELECT t.id, t.name, u.email AS made_by, t.scope, CASE WHEN t.client_id IS NULL THEN 'token' ELSE 'oauth' END AS kind,
         t.created_at, t.last_used_at, t.expires_at, t.refresh_expires_at, t.revoked_at
         FROM tokens t JOIN users u ON u.id = t.user_id WHERE t.workspace_id = ? ORDER BY t.created_at",
        [&c.workspace.id],
    )
}

pub fn revoke_token(conn: &Connection, c: &Caller, id: &str) -> Result<()> {
    require_role(c, "builder", "revoke agent connections")?;
    // Builders revoke their own connections; admins revoke any.
    let n = conn.run(
        "UPDATE tokens SET revoked_at = ? WHERE id = ? AND workspace_id = ? AND revoked_at IS NULL AND (? OR user_id = ?)",
        params![now(), id, c.workspace.id, if c.role == "admin" { 1 } else { 0 }, c.user.id],
    )?;
    if n == 0 {
        return Err(Problem::new(404, "not_found", "No active connection of yours with that id."));
    }
    event(conn, &c.workspace.id, &c.actor, None, "token_revoked", id)
}

// ---------- reading ----------

pub fn get_app(conn: &Connection, c: &Caller, slug: &str) -> Result<AppRow> {
    conn.first(
        "SELECT * FROM apps WHERE slug = ? AND workspace_id = ?",
        params![js_trim(slug).to_lowercase(), c.workspace.id],
        AppRow::from_row,
    )?
    .ok_or_else(|| {
        Problem::new(404, "not_found", format!("There is no app called \"{slug}\" in this workspace. Use list_apps to see them."))
    })
}

pub fn describe(cfg: &Config, c: &Caller, app: &AppRow, grants: Vec<Value>) -> Map<String, Value> {
    let mut m = Map::new();
    m.insert("app".into(), json!(app.slug));
    m.insert("name".into(), json!(app.name));
    m.insert("url".into(), json!(app_url(cfg, &c.workspace.slug, &app.slug)));
    m.insert("status".into(), json!(app.status));
    m.insert("access".into(), json!(app.access));
    m.insert("who_can_open".into(), json!(people::who_can_open(app, &grants, &c.workspace.name)));
    m.insert("live_version".into(), json!(app.live_version));
    m.insert("staging".into(), staging_of(cfg, c, app));
    // What the next update builds on: pass it as base_version so a deploy never undoes someone else's.
    m.insert("current_version".into(), json!(current_version(app)));
    m.insert("roles".into(), json!(app.role_list()));
    m.insert("shared_with".into(), Value::Array(grants));
    if !app.title.is_empty() {
        m.insert("title".into(), json!(app.title));
    }
    if !app.welcome.is_empty() {
        m.insert("welcome".into(), json!(app.welcome));
    }
    m
}

/// The version waiting on staging and where to try it, or null when nothing is waiting.
fn staging_of(cfg: &Config, c: &Caller, app: &AppRow) -> Value {
    match app.staging_version {
        Some(n) => json!({ "version": n, "url": staging_url(cfg, &c.workspace.slug, &app.slug) }),
        None => Value::Null,
    }
}

pub fn described(conn: &Connection, cfg: &Config, c: &Caller, app: &AppRow) -> Result<Map<String, Value>> {
    let mut m = describe(cfg, c, app, people::list_grants(conn, app)?);
    if let Some(id) = &app.space_id {
        let name: Option<String> = conn.first("SELECT name FROM spaces WHERE id = ?", [id], |r| r.get(0))?;
        if let Some(name) = name {
            if app.access == "people" || app.access == "workspace" {
                let who = m["who_can_open"].as_str().unwrap_or("").to_string();
                let who = if who.starts_with("Nobody but you") {
                    format!("Everyone in the {name} space can open it, after signing in.")
                } else {
                    format!("{who} Everyone in the {name} space can too.")
                };
                m.insert("who_can_open".into(), json!(who));
            }
            m.insert("space".into(), json!(name));
        }
    }
    if let Some(link) = crate::market::link(conn, &app.id)? {
        m.insert("marketplace".into(), link);
    }
    // Whether the Brod team took it down, or the phishing check flagged its live version.
    abuse::add_state(conn, app, &mut m)?;
    Ok(m)
}

pub fn list_apps(conn: &Connection, cfg: &Config, c: &Caller) -> Result<Value> {
    let apps = conn.all("SELECT * FROM apps WHERE workspace_id = ? ORDER BY created_at DESC", [&c.workspace.id], AppRow::from_row)?;
    let running = apps.iter().filter(|a| a.status == "live").count();
    let described: Vec<Value> = apps.iter().map(|a| described(conn, cfg, c, a).map(Value::Object)).collect::<Result<_>>()?;
    Ok(
        json!({ "workspace": c.workspace.slug, "plan": c.workspace.plan, "running_apps": running, "app_limit": plan(&c.workspace).apps, "apps": described }),
    )
}

pub fn get_status(conn: &Connection, cfg: &Config, c: &Caller, slug: &str) -> Result<Map<String, Value>> {
    require_role(c, "builder", "see app versions")?;
    let app = get_app(conn, c, slug)?;
    let versions = conn.all(
        "SELECT n, note, actor, file_count, bytes, created_at, server, based_on FROM versions WHERE app_id = ? ORDER BY n DESC LIMIT 50",
        [&app.id],
        |r| {
            let n: i64 = r.get(0)?;
            let server: Option<String> = r.get(6)?;
            Ok(json!({
                "version": n, "live": Some(n) == app.live_version, "staging": Some(n) == app.staging_version, "kind": if server.is_some() { "server" } else { "static" },
                "based_on": r.get::<_, Option<i64>>(7)?, "note": r.get::<_, String>(1)?, "by": r.get::<_, String>(2)?, "files": r.get::<_, i64>(3)?, "bytes": r.get::<_, i64>(4)?, "at": iso(r.get(5)?),
            }))
        },
    )?;
    let mut m = described(conn, cfg, c, &app)?;
    m.insert("versions".into(), Value::Array(versions));
    // Names only: secret values are never returned.
    m.insert("secrets".into(), secrets::list(conn, &app.id)?);
    // What the app lets this workspace customise (its brod.json), and the values set on it.
    m.insert("settings".into(), crate::settings::for_app(conn, &app)?);
    // Where the app may send data (its brod.json), and what it reached without declaring.
    m.insert("network".into(), crate::network::for_app(conn, cfg, &app)?);
    m.insert("domains".into(), crate::domains::app_domains(conn, cfg, &app)?);
    // Who else got its files or deployed it lately: a warning to pass on, never a lock.
    m.extend(editing_notice(conn, c, &app)?);
    Ok(m)
}

fn shape_event(at: i64, actor: String, action: String, detail: String, slug: Option<String>) -> Value {
    let mut m = Map::new();
    m.insert("at".into(), json!(iso(at)));
    m.insert("by".into(), json!(actor));
    m.insert("action".into(), json!(action));
    if let Some(s) = slug.filter(|s| !s.is_empty()) {
        m.insert("app".into(), json!(s));
    }
    m.insert("detail".into(), json!(detail));
    Value::Object(m)
}

pub fn get_logs(conn: &Connection, c: &Caller, slug: &str, search: Option<&str>) -> Result<Value> {
    require_role(c, "builder", "read app activity")?;
    let app = get_app(conn, c, slug)?;
    let events = conn.all("SELECT at, actor, action, detail FROM events WHERE app_id = ? ORDER BY id DESC LIMIT 50", [&app.id], |r| {
        Ok(shape_event(r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, None))
    })?;
    Ok(json!({ "app": app.slug, "events": events, "requests": request_logs(conn, &app, search)? }))
}

/// What a server app's code did per request: console output and exceptions, newest first, kept 7 days.
fn request_logs(conn: &Connection, app: &AppRow, search: Option<&str>) -> Result<Vec<Value>> {
    let q = search.filter(|s| !s.is_empty()).map(|s| {
        let mut e = String::from("%");
        for ch in s.chars() {
            if matches!(ch, '%' | '_' | '\\') {
                e.push('\\');
            }
            e.push(ch);
        }
        e.push('%');
        e
    });
    conn.all(
        "SELECT at, version, method, path, status, outcome, logs, exceptions FROM app_logs WHERE app_id = ? AND at > ?
         AND (? IS NULL OR logs LIKE ? ESCAPE '\\' OR exceptions LIKE ? ESCAPE '\\' OR path LIKE ? ESCAPE '\\') ORDER BY id DESC LIMIT 50",
        params![app.id, now() - limits::LOG_RETENTION_MS, q, q, q, q],
        |r| {
            let logs: Vec<Value> = serde_json::from_str(&r.get::<_, String>(6)?).unwrap_or_default();
            let logs: Vec<String> = logs
                .iter()
                .map(|l| format!("{}: {}", l.get("level").map(js_string).unwrap_or_default(), l.get("message").map(js_string).unwrap_or_default()))
                .collect();
            let exceptions: Value = serde_json::from_str(&r.get::<_, String>(7)?).unwrap_or(Value::Array(vec![]));
            Ok(json!({
                "at": iso(r.get(0)?), "version": r.get::<_, Option<i64>>(1)?, "request": format!("{} {}", r.get::<_, String>(2)?, r.get::<_, String>(3)?),
                "status": r.get::<_, Option<i64>>(4)?, "outcome": r.get::<_, String>(5)?, "logs": logs, "exceptions": exceptions,
            }))
        },
    )
}

/// Set (or with value None, remove) one secret. Agents may set secrets but, like everyone, never read them back.
pub fn set_secret(conn: &Connection, cfg: &Config, c: &Caller, slug: &str, name: &str, value: Option<&str>) -> Result<Value> {
    require_role(c, "builder", "set app secrets")?;
    let app = get_app(conn, c, slug)?;
    let clean = js_trim(name).to_string();
    secrets::check_name(&clean)?;
    tx(conn, |x| {
        match value {
            None => secrets::delete(x, &app.id, &clean)?,
            Some(v) => secrets::put(x, &cfg.secrets_key, &app.id, &clean, v, &c.actor)?,
        }
        event(x, &c.workspace.id, &c.actor, Some(&app.id), if value.is_none() { "secret_removed" } else { "secret_set" }, &clean)
    })?;
    let mut m = Map::new();
    m.insert("app".into(), json!(app.slug));
    m.insert("secret".into(), json!(clean));
    m.insert(if value.is_none() { "removed" } else { "set" }.into(), json!(true));
    m.insert("secrets".into(), secrets::list(conn, &app.id)?);
    m.insert(
        "note".into(),
        json!(format!("The value is stored encrypted and is never shown again. The app sees it as env.{clean} from its next request.")),
    );
    Ok(Value::Object(m))
}

/// One audit log across every app in the workspace, filterable by app and action.
pub fn list_events(conn: &Connection, c: &Caller, app: Option<&str>, action: Option<&str>, limit: Option<f64>) -> Result<Value> {
    require_role(c, "builder", "read the audit log")?;
    let app_id = match app.filter(|a| !a.is_empty()) {
        Some(a) => Some(get_app(conn, c, a)?.id),
        None => None,
    };
    let limit = match limit {
        Some(l) if l != 0.0 && !l.is_nan() => l,
        _ => 100.0,
    }
    .clamp(1.0, 500.0) as i64;
    let events = conn.all(
        "SELECT e.at, e.actor, e.action, e.detail, a.slug FROM events e LEFT JOIN apps a ON a.id = e.app_id
         WHERE e.workspace_id = ? AND (? IS NULL OR e.app_id = ?) AND (? IS NULL OR e.action = ?) ORDER BY e.id DESC LIMIT ?",
        params![c.workspace.id, app_id, app_id, action, action, limit],
        |r| Ok(shape_event(r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
    )?;
    Ok(json!({ "workspace": c.workspace.slug, "events": events }))
}

// ---------- deploying ----------

fn is_junk(path: &str) -> bool {
    let last = path.rsplit('/').next().unwrap_or("");
    let junk_name = last.starts_with("._") || last == ".DS_Store" || last == "Thumbs.db";
    let segments: Vec<&str> = path.split('/').collect();
    let folders = &segments[..segments.len().saturating_sub(1)];
    // .git, and the resource-fork folder macOS adds to every zip it makes.
    junk_name || folders.contains(&".git") || folders.contains(&"__MACOSX")
}

/// Clean bundle paths, drop junk files, and strip a single wrapping folder such as dist/.
pub fn normalise(files: Vec<BundleFile>) -> Result<Vec<BundleFile>> {
    let mut out: Vec<BundleFile> = files
        .into_iter()
        .map(|f| {
            let mut p = f.path.replace('\\', "/");
            while let Some(rest) = p.strip_prefix("./") {
                p = rest.to_string();
            }
            BundleFile { path: p.trim_start_matches('/').to_string(), bytes: f.bytes }
        })
        .filter(|f| !f.path.is_empty() && !is_junk(&f.path))
        .collect();
    for f in &out {
        if f.path.split('/').any(|p| p == ".." || p == ".") {
            return Err(Problem::new(400, "bad_path", format!("File path \"{}\" is not allowed.", f.path)));
        }
        if f.path.encode_utf16().count() > 400 {
            return Err(Problem::new(400, "bad_path", "A file path is longer than 400 characters."));
        }
        if f.path.starts_with("_brod/") {
            return Err(Problem::new(400, "bad_path", "Paths under _brod/ are reserved for the platform."));
        }
        if f.bytes.len() > FILE_BYTES {
            return Err(Problem::new(413, "too_large", format!("{} is larger than {} MB.", f.path, FILE_BYTES / 1_048_576)));
        }
    }
    let marks = |out: &[BundleFile], prefix: &str| {
        out.iter().any(|f| {
            f.path == format!("{prefix}index.html")
                || f.path == format!("{prefix}_worker.js")
                || f.path.starts_with(&format!("{prefix}_worker/"))
        })
    };
    if !marks(&out, "") {
        let mut tops: Vec<&str> = out.iter().map(|f| f.path.split('/').next().unwrap_or("")).collect();
        tops.dedup();
        let mut unique = tops.clone();
        unique.sort();
        unique.dedup();
        if unique.len() == 1 {
            let top = tops[0].to_string();
            if marks(&out, &format!("{top}/")) {
                out = out
                    .into_iter()
                    .map(|f| BundleFile { path: f.path.get(top.len() + 1..).unwrap_or("").to_string(), bytes: f.bytes })
                    .collect();
            }
        }
    }
    if out.is_empty() {
        return Err(Problem::new(400, "empty_bundle", "The bundle has no files."));
    }
    if out.len() > MAX_FILES {
        return Err(Problem::new(413, "too_many_files", format!("A bundle can hold at most {MAX_FILES} files.")));
    }
    let paths: Vec<&str> = out.iter().map(|f| f.path.as_str()).collect();
    if !paths.contains(&"index.html") && runtime::find_server(&paths)?.is_none() {
        return Err(Problem::new(
            400,
            "no_index",
            "There is no index.html or _worker.js at the top of the bundle. Upload the built output folder (for example dist/ or build/), not the source folder. \
             For server code, add a _worker.js module (or a _worker/ folder with index.js) that exports default { fetch(request, env) }.",
        ));
    }
    if out.iter().map(|f| f.bytes.len()).sum::<usize>() > UNPACKED_BYTES {
        return Err(Problem::new(413, "too_large", "The bundle is larger than 60 MB unpacked."));
    }
    Ok(out)
}

fn new_slug(conn: &Connection, c: &Caller, name: &str) -> Result<String> {
    let base = slugify(name);
    for i in 0..6 {
        let s = if i == 0 { base.clone() } else { format!("{base}-{}", random_id("", 2)) };
        if !conn.exists("SELECT 1 FROM apps WHERE workspace_id = ? AND slug = ?", params![c.workspace.id, s])? {
            return Ok(s);
        }
    }
    Ok(format!("{base}-{}", random_id("", 4)))
}

fn check_rate(conn: &Connection, c: &Caller) -> Result<()> {
    let n = conn.count(
        "SELECT COUNT(*) AS n FROM events WHERE workspace_id = ? AND action = 'deploy' AND at > ?",
        params![c.workspace.id, now() - 3_600_000],
    )?;
    if n >= limits::DEPLOYS_PER_HOUR {
        return Err(Problem::new(
            429,
            "rate_limited",
            format!("This workspace has deployed {} times in the last hour. Wait a little and try again.", limits::DEPLOYS_PER_HOUR),
        ));
    }
    Ok(())
}

fn plan_full(conn: &Connection, cfg: &Config, c: &Caller, verb: &str) -> Result<()> {
    let running =
        conn.all("SELECT slug FROM apps WHERE workspace_id = ? AND status = 'live'", [&c.workspace.id], |r| r.get::<_, String>(0))?;
    let limit = plan(&c.workspace).apps;
    if running.len() as i64 >= limit {
        return Err(Problem::new(
            402,
            "plan_limit",
            format!(
                "Your {} plan runs {limit} apps and all {limit} are in use. Pause one with set_paused, or upgrade the plan, to {verb}. Existing apps keep running.",
                c.workspace.plan
            ),
        )
        .with("running_apps", json!(running.len()))
        .with("app_limit", json!(limit))
        .with("running", json!(running))
        .with("upgrade_url", json!(format!("{}/w/{}/admin#billing", cfg.api_origin, c.workspace.slug))));
    }
    Ok(())
}

/// What a deploy targets, as given: "app" for a new version, or "name" for a new app.
#[derive(Clone, Default, Debug)]
pub struct DeployTarget {
    pub app: Option<String>,
    pub name: Option<String>,
    pub note: Option<String>,
    /// "staging" or "production" (also "live"); None for the default, see `deploy_to_staging`.
    pub environment: Option<String>,
    /// The version the deploy's files started from, as given; see `base`.
    pub base_version: Option<Value>,
}

impl DeployTarget {
    pub fn from_json(o: &Map<String, Value>) -> DeployTarget {
        let s = |k: &str| present(o, k).map(js_string);
        DeployTarget {
            app: s("app"),
            name: s("name"),
            note: s("note"),
            environment: s("environment"),
            base_version: present(o, "base_version").cloned(),
        }
    }
    /// "base_version": the version a deploy's files started from. Only for an existing app.
    fn base(&self) -> Result<Option<i64>> {
        let n = match &self.base_version {
            None | Some(Value::Null) => return Ok(None),
            Some(Value::String(v)) if v.is_empty() => return Ok(None),
            Some(Value::Number(v)) => v.as_f64(),
            Some(Value::String(v)) => js_trim(v).parse::<f64>().ok(),
            Some(_) => None,
        };
        let Some(n) = n.filter(|n| n.fract() == 0.0 && *n >= 1.0 && *n < 9e15) else {
            return Err(Problem::new(
                400,
                "bad_base_version",
                "\"base_version\" is the version number your files started from, such as 3.",
            ));
        };
        if self.app_slug().is_none() {
            return Err(Problem::new(400, "bad_base_version", "\"base_version\" goes with \"app\", for a new version of an existing app."));
        }
        Ok(Some(n as i64))
    }
    /// Refuse an environment Brod does not know, before anything is uploaded.
    fn check_environment(&self) -> Result<()> {
        match self.environment.as_deref().map(|e| js_trim(e).to_lowercase()) {
            None => Ok(()),
            Some(e) if matches!(e.as_str(), "" | "staging" | "production" | "live") => Ok(()),
            Some(_) => Err(Problem::new(400, "bad_environment", "\"environment\" is \"staging\" or \"production\".")),
        }
    }
    fn app_slug(&self) -> Option<&str> {
        self.app.as_deref().filter(|a| !a.is_empty())
    }
}

/// Whether a deploy goes to staging instead of live. An agent updating an app that already has a live version deploys
/// to staging unless it asks for production, so the person can try the change before visitors see it. A person, and
/// any first version, goes live unless staging is asked for.
fn deploy_to_staging(c: &Caller, app: &AppRow, created: bool, o: &DeployTarget) -> bool {
    match o.environment.as_deref().map(|e| js_trim(e).to_lowercase()).as_deref() {
        Some("staging") => true,
        Some("production") | Some("live") => false,
        _ => c.agent && !created && app.live_version.is_some(),
    }
}

/// The version an update builds on: what is waiting on staging, or else what is live.
pub fn current_version(app: &AppRow) -> Option<i64> {
    app.staging_version.or(app.live_version)
}

/**
 * The refusal for a deploy whose files started from an older version than the app's current one: deploying them would
 * silently undo what someone else deployed since. It names who changed what, so the agent can tell the person.
 */
fn stale_base(conn: &Connection, app_id: &str, base: i64) -> Result<Problem> {
    let Some(app) = conn.first("SELECT * FROM apps WHERE id = ?", [app_id], AppRow::from_row)? else {
        return Ok(Problem::new(404, "not_found", "The app was deleted during the deploy."));
    };
    let current = current_version(&app);
    let since = conn.all(
        "SELECT n, note, actor, created_at FROM versions WHERE app_id = ? AND n > ? AND n <= ? ORDER BY n DESC LIMIT 10",
        params![app.id, base, current.unwrap_or(0)],
        |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?, r.get::<_, i64>(3)?)),
    )?;
    let environment = current.map(|v| if Some(v) == app.staging_version { "staging" } else { "live" });
    let what = if since.is_empty() {
        format!("The app's current version is {}, not v{base}.", current.map(|v| format!("v{v}")).unwrap_or_else(|| "none".into()))
    } else {
        let list: Vec<String> = since.iter().map(|(n, note, by, _)| format!("v{n} by {by} (\"{note}\")")).collect();
        format!("Since v{base}, {} {} deployed.", list.join(", "), if since.len() == 1 { "was" } else { "were" })
    };
    let again = match current {
        Some(v) => format!("with \"base_version\": {v}"),
        None => "without \"base_version\"".into(),
    };
    let since: Vec<Value> =
        since.into_iter().map(|(n, note, by, at)| json!({ "version": n, "by": by, "note": note, "at": iso(at) })).collect();
    Ok(Problem::new(
        409,
        "stale_base",
        format!(
            "Nothing was deployed: your files start from v{base}, but {} has changed. {what} Deploying your files would undo those changes. \
             Tell the person who changed what. Then get the current files with get_files, add your changes to them, and deploy again {again}, \
             or, only if the person says to replace that work, deploy your files as they are {again}.",
            app.slug
        ),
    )
    .with("your_base", json!(base))
    .with("current_version", json!(current))
    .with("current_environment", json!(environment))
    .with("since", Value::Array(since)))
}

/// Resolve which app a deploy targets, creating it (inside the plan allowance) when it is new.
fn target_app(conn: &Connection, cfg: &Config, c: &Caller, o: &DeployTarget) -> Result<(AppRow, bool)> {
    if let Some(slug) = o.app_slug() {
        return Ok((get_app(conn, c, slug)?, false));
    }
    let name = js_slice(js_trim(o.name.as_deref().unwrap_or("")), 60);
    if name.is_empty() {
        return Err(Problem::new(400, "need_name", "Give \"name\" for a new app, or \"app\" to deploy a new version of an existing one."));
    }
    plan_full(conn, cfg, c, "add another")?;
    let app = AppRow {
        id: random_id("app_", 12),
        workspace_id: c.workspace.id.clone(),
        owner_id: c.user.id.clone(),
        slug: new_slug(conn, c, &name)?,
        name,
        title: String::new(),
        welcome: String::new(),
        status: "live".into(),
        access: "private".into(),
        roles: "[\"owner\",\"editor\",\"viewer\"]".into(),
        live_version: None,
        created_at: now(),
        secrets_rev: 0,
        space_id: None,
        file_bytes: 0,
        data_bytes: 0,
        password_hash: None,
        staging_version: None,
        taken_down_at: None,
        takedown_reason: String::new(),
    };
    conn.run(
        "INSERT INTO apps (id, workspace_id, owner_id, slug, name, status, access, roles, live_version, created_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
        params![app.id, app.workspace_id, app.owner_id, app.slug, app.name, app.status, app.access, app.roles, Option::<i64>::None, app.created_at],
    )?;
    Ok((app, true))
}

pub async fn deploy(st: &State, c: &Caller, o: DeployTarget, files: Vec<BundleFile>) -> Result<Value> {
    {
        let (c, o) = (c.clone(), o.clone());
        st.db
            .call(move |conn| {
                require_role(&c, "builder", "deploy apps")?;
                check_rate(conn, &c)?;
                abuse::check_workspace_up(conn, &c)?;
                match o.app_slug() {
                    Some(slug) => abuse::check_up(conn, &get_app(conn, &c, slug)?),
                    None => Ok(()),
                }
            })
            .await?;
    }
    o.check_environment()?;
    let base = o.base()?;
    let files = normalise(files)?;
    let paths: Vec<&str> = files.iter().map(|f| f.path.as_str()).collect();
    let server = runtime::find_server(&paths)?;
    let settings = crate::settings::from_bundle(&files)?;
    let network = crate::network::from_bundle(&files)?;
    if let Some(s) = &server {
        runtime::check_server(st, s, &files).await?;
    }
    let bytes: usize = files.iter().map(|f| f.bytes.len()).sum();
    // The phishing check: a flagged version still deploys, but its app stays private or people-only and the Brod team gets a report.
    let (files, scan) = tokio::task::spawn_blocking(move || {
        let scan = crate::scan::scan_bundle(&files);
        (files, scan)
    })
    .await
    .map_err(Problem::internal)?;
    let (app, created, n) = {
        let (c, o, cfg) = (c.clone(), o.clone(), st.cfg.clone());
        st.db
            .call(move |conn| {
                crate::usage::check_storage(conn, &cfg, &c.workspace, bytes as i64)?;
                let (app, created) = target_app(conn, &cfg, &c, &o)?;
                // Refuse before uploading when someone else already deployed past the base; checked again when the pointer moves.
                if let Some(b) = base
                    && current_version(&app) != Some(b)
                {
                    return Err(stale_base(conn, &app.id, b)?);
                }
                // Take the next number in one statement, so two deploys at once never get the same one.
                let n: i64 = conn
                    .first(
                        "UPDATE apps SET last_version = COALESCE(last_version, 0) + 1 WHERE id = ? RETURNING last_version",
                        [&app.id],
                        |r| r.get(0),
                    )?
                    .ok_or_else(|| Problem::new(404, "not_found", "The app was deleted during the deploy."))?;
                Ok((app, created, n))
            })
            .await?
    };
    let staging = deploy_to_staging(c, &app, created, &o);
    let note = js_slice(js_trim(o.note.as_deref().unwrap_or("")), 200);
    let note = if note.is_empty() { if created { "First version".to_string() } else { "Update".to_string() } } else { note };
    // Files are written under a new version prefix first; visitors only see them once the pointer moves.
    let count = files.len();
    let mut pending = files.into_iter();
    loop {
        let chunk: Vec<BundleFile> = pending.by_ref().take(20).collect();
        if chunk.is_empty() {
            break;
        }
        futures_util::future::try_join_all(chunk.into_iter().map(|f| {
            let key = format!("{}/{n}/{}", app.id, f.path);
            let ct = content_type(&f.path);
            let store = st.store.clone();
            async move { store.put(&key, Bytes::from(f.bytes), Some(ct)).await }
        }))
        .await?;
    }
    let (c2, cfg) = (c.clone(), st.cfg.clone());
    let server_json = server.as_ref().map(|s| s.to_json());
    let kind = if server.is_some() { "server" } else { "static" };
    let prefix = format!("{}/{n}/", app.id);
    let out = st
        .db
        .call(move |conn| {
            let mut app = app;
            tx(conn, |x| {
                // The pointer moves only if the app's current version is still the base, so a deploy that raced past
                // ours is never undone. A based deploy straight to live builds on what was waiting on staging, so it
                // replaces it: publishing that later would undo this one.
                let mut replaced = None;
                if let Some(b) = base {
                    let (live, on_staging): (Option<i64>, Option<i64>) = x
                        .first("SELECT live_version, staging_version FROM apps WHERE id = ?", [&app.id], |r| Ok((r.get(0)?, r.get(1)?)))?
                        .ok_or_else(|| Problem::new(404, "not_found", "The app was deleted during the deploy."))?;
                    if on_staging.or(live) != Some(b) {
                        return Err(stale_base(x, &app.id, b)?);
                    }
                    if !staging {
                        replaced = on_staging;
                    }
                }
                x.run(
                    "INSERT INTO versions (app_id, n, note, actor, file_count, bytes, created_at, server, scan, settings, network, based_on) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                    params![
                        app.id,
                        n,
                        note,
                        c2.actor,
                        count as i64,
                        bytes as i64,
                        now(),
                        server_json,
                        serde_json::to_string(&scan.reasons)?,
                        settings,
                        network,
                        base
                    ],
                )?;
                let from = base.map(|b| format!(" (from v{b})")).unwrap_or_default();
                if staging {
                    x.run("UPDATE apps SET staging_version = ? WHERE id = ?", params![n, app.id])?;
                    // Still a "deploy" event, so staging deploys count toward the hourly limit.
                    event(x, &c2.workspace.id, &c2.actor, Some(&app.id), "deploy", &format!("v{n} to staging{from}: {note} ({count} files)"))?;
                } else if base.is_some() {
                    x.run("UPDATE apps SET live_version = ?, staging_version = NULL WHERE id = ?", params![n, app.id])?;
                    let also = replaced.map(|r| format!(", replacing v{r} on staging")).unwrap_or_default();
                    event(x, &c2.workspace.id, &c2.actor, Some(&app.id), "deploy", &format!("v{n}{from}{also}: {note} ({count} files)"))?;
                } else {
                    x.run("UPDATE apps SET live_version = ? WHERE id = ?", params![n, app.id])?;
                    event(x, &c2.workspace.id, &c2.actor, Some(&app.id), "deploy", &format!("v{n}: {note} ({count} files)"))?;
                }
                if scan.flagged {
                    let why = scan.reasons.join("; ");
                    x.run(
                        "INSERT INTO reports (id, app_id, reporter, reason, created_at, kind) VALUES (?,?,?,?,?,'automatic')",
                        params![random_id("rep_", 8), app.id, abuse::CHECKER, format!("Phishing check on v{n}: {why}"), now()],
                    )?;
                    event(x, &c2.workspace.id, abuse::CHECKER, Some(&app.id), "flagged", &format!("v{n}: {why}"))?;
                    // Staging is never open beyond the app's builders; the check runs again when it is published.
                    if !staging {
                        abuse::narrow_if_flagged(x, &mut app, n, Some(&scan.reasons))?;
                    }
                }
                Ok(())
            })?;
            if staging {
                app.staging_version = Some(n);
            } else {
                app.live_version = Some(n);
                if base.is_some() {
                    app.staging_version = None;
                }
            }
            mark_editing(conn, &c2, &app.id, Some(n))?;
            let mut m = described(conn, &cfg, &c2, &app)?;
            m.insert("version".into(), json!(n));
            m.insert("based_on".into(), json!(base));
            m.extend(editing_notice(conn, &c2, &app)?);
            m.insert("environment".into(), json!(if staging { "staging" } else { "production" }));
            m.insert("files".into(), json!(count));
            m.insert("bytes".into(), json!(bytes));
            m.insert("created".into(), json!(created));
            m.insert("kind".into(), json!(kind));
            if staging {
                let url = staging_url(&cfg, &c2.workspace.slug, &app.slug);
                m.insert("staging_url".into(), json!(url));
                m.insert(
                    "next_step".into(),
                    json!(format!(
                        "v{n} is on staging, not live: visitors still get {}. Give the person the staging address {url} to try it (only the app's builders can open it). \
                         When they say it is ready, call publish_staging to make v{n} live.",
                        app.live_version.map(|v| format!("v{v}")).unwrap_or_else(|| "nothing yet".into())
                    )),
                );
            }
            Ok(Value::Object(m))
        })
        .await;
    // A refused version never went anywhere: its files go too.
    if out.is_err() {
        st.store.delete_prefix(&prefix).await?;
    }
    out
}

// ---------- working together ----------

/// Files returned inline by get_files, at most; larger versions come as a download address instead.
const INLINE_FILES: i64 = 200;

/**
 * One version's files (by default the current one), so an agent can start from what is deployed instead of from its own
 * older copy, then deploy with base_version. Small versions come inline; larger ones as a short-lived tar.gz address.
 * Getting the files counts as working on the app, so others are told (see others_editing).
 */
pub async fn get_files(st: &State, c: &Caller, slug: &str, version: Option<Value>) -> Result<Value> {
    let (c2, slug2) = (c.clone(), slug.to_string());
    let (mut out, app_id, n, inline) = st
        .db
        .call(move |conn| {
            require_role(&c2, "builder", "get app files")?;
            let app = get_app(conn, &c2, &slug2)?;
            let asked = version.filter(|v| !matches!(v, Value::Null) && !matches!(v, Value::String(s) if s.is_empty()));
            let n = match &asked {
                None => {
                    current_version(&app).ok_or_else(|| Problem::new(409, "no_version", format!("{} has no version yet.", app.slug)))?
                }
                Some(v) => match v {
                    Value::Number(x) => x.as_f64(),
                    Value::String(x) => js_trim(x).parse::<f64>().ok(),
                    _ => None,
                }
                .filter(|f| f.fract() == 0.0 && f.abs() < 9e15)
                .map(|f| f as i64)
                .unwrap_or(i64::MIN),
            };
            let shown = asked.as_ref().map(js_string).unwrap_or_else(|| n.to_string());
            let (file_count, bytes): (i64, i64) = conn
                .first("SELECT file_count, bytes FROM versions WHERE app_id = ? AND n = ?", params![app.id, n], |r| {
                    Ok((r.get(0)?, r.get(1)?))
                })?
                .ok_or_else(|| {
                    Problem::new(404, "no_version", format!("{} has no version {shown}. Use get_status to see its versions.", app.slug))
                })?;
            // A read-only connection can look, but cannot deploy what it changes, so it is not working on the app.
            if !c2.read_only {
                mark_editing(conn, &c2, &app.id, Some(n))?;
            }
            let mut m = Map::new();
            m.insert("app".into(), json!(app.slug));
            m.insert("version".into(), json!(n));
            let environment = if Some(n) == app.staging_version {
                json!("staging")
            } else if Some(n) == app.live_version {
                json!("live")
            } else {
                Value::Null
            };
            m.insert("environment".into(), environment);
            m.insert("current_version".into(), json!(current_version(&app)));
            m.insert("file_count".into(), json!(file_count));
            m.insert("bytes".into(), json!(bytes));
            m.extend(editing_notice(conn, &c2, &app)?);
            Ok((m, app.id, n, bytes <= limits::INLINE_BYTES as i64 && file_count <= INLINE_FILES))
        })
        .await?;
    let slug = out["app"].as_str().unwrap_or("").to_string();
    let then = format!(
        "Make your changes there, then call deploy_app with \"app\": \"{slug}\" and \"base_version\": {n}, so a change someone else deploys meanwhile is never undone. \
         These are the files as deployed (the built output): if the app was built from source with a build step, change the source if you have it rather than these."
    );
    if inline {
        let mut files = read_tree(st, &format!("{app_id}/{n}/")).await?;
        files.sort_by(|a, b| a.path.cmp(&b.path));
        let files: Vec<Value> = files
            .into_iter()
            .map(|f| match String::from_utf8(f.bytes) {
                Ok(text) => json!({ "path": f.path, "content": text }),
                Err(e) => json!({ "path": f.path, "content": base64::engine::general_purpose::STANDARD.encode(e.into_bytes()), "encoding": "base64" }),
            })
            .collect();
        out.insert("files".into(), Value::Array(files));
        out.insert(
            "next_step".into(),
            json!(format!("Write these files into an empty folder, keeping their paths (decode \"base64\" ones). {then}")),
        );
        return Ok(Value::Object(out));
    }
    let id = random_id("dl_", 20);
    let (c3, id2, app_id2) = (c.clone(), id.clone(), app_id.clone());
    st.db
        .call(move |conn| {
            conn.run(
                "INSERT INTO downloads (id, workspace_id, app_id, version, user_id, expires_at) VALUES (?,?,?,?,?,?)",
                params![id2, c3.workspace.id, app_id2, n, c3.user.id, now() + limits::DOWNLOAD_TTL_MS],
            )?;
            Ok(())
        })
        .await?;
    let download_url = format!("{}/v1/downloads/{id}", st.cfg.api_origin);
    out.insert("download_url".into(), json!(download_url));
    out.insert("expires_in_seconds".into(), json!(limits::DOWNLOAD_TTL_MS / 1000));
    out.insert(
        "next_step".into(),
        json!(format!(
            "Download the files into an empty folder with one command:\n  mkdir -p <folder> && curl -sS --fail \"{download_url}\" | tar -xzf - -C <folder>\n{then}"
        )),
    );
    Ok(Value::Object(out))
}

/// A download address: the version's files as a tar.gz, and a file name for it. The address is its own credential and
/// works until it expires.
pub async fn download(st: &State, id: &str) -> Result<(String, Vec<u8>)> {
    let id2 = id.to_string();
    let found = st
        .db
        .call(move |conn| {
            conn.first(
                "SELECT d.app_id, d.version, d.expires_at, a.slug, v.created_at FROM downloads d JOIN apps a ON a.id = d.app_id \
                 JOIN versions v ON v.app_id = d.app_id AND v.n = d.version WHERE d.id = ?",
                [&id2],
                |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?, r.get::<_, i64>(2)?, r.get::<_, String>(3)?, r.get::<_, i64>(4)?)),
            )
        })
        .await?;
    let Some((app_id, n, _, slug, created_at)) = found.filter(|d| d.2 >= now()) else {
        return Err(Problem::new(410, "download_gone", "This download address has expired. Call get_files again for a new one."));
    };
    let mut files = read_tree(st, &format!("{app_id}/{n}/")).await?;
    files.sort_by(|a, b| a.path.cmp(&b.path));
    let body = tokio::task::spawn_blocking(move || crate::tar::pack(&files, created_at)).await.map_err(Problem::internal)?;
    Ok((format!("{slug}-v{n}.tar.gz"), body))
}

/// Note that this person is working on the app (getting its files or deploying it). Others are told, never blocked.
fn mark_editing(conn: &Connection, c: &Caller, app_id: &str, base: Option<i64>) -> Result<()> {
    let t = now();
    conn.run(
        "INSERT INTO editing (app_id, user_id, email, actor, base_version, since, last_at) VALUES (?,?,?,?,?,?,?) \
         ON CONFLICT (app_id, user_id) DO UPDATE SET email = excluded.email, actor = excluded.actor, base_version = excluded.base_version, last_at = excluded.last_at, \
         since = CASE WHEN editing.last_at < ? THEN excluded.since ELSE editing.since END",
        params![app_id, c.user.id, c.user.email, c.actor, base, t, t, t - limits::EDITING_WINDOW_MS],
    )?;
    Ok(())
}

/// How long ago, in words.
fn ago(ms: i64) -> String {
    let m = ((now() - ms) as f64 / 60000.0).round() as i64;
    if m < 1 {
        "just now".into()
    } else if m < 60 {
        format!("{m} minute{} ago", if m == 1 { "" } else { "s" })
    } else {
        format!("{} hour{} ago", (m as f64 / 60.0).round() as i64, if m < 90 { "" } else { "s" })
    }
}

/// `others_editing`: everyone else who got the app's files or deployed it lately, newest first, plus a `warning` to pass
/// on when there is anyone. A warning only: nothing is blocked.
pub fn editing_notice(conn: &Connection, c: &Caller, app: &AppRow) -> Result<Map<String, Value>> {
    let others = conn.all(
        "SELECT email, actor, base_version, since, last_at FROM editing WHERE app_id = ? AND user_id != ? AND last_at > ? ORDER BY last_at DESC",
        params![app.id, c.user.id, now() - limits::EDITING_WINDOW_MS],
        |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, Option<i64>>(2)?, r.get::<_, i64>(3)?, r.get::<_, i64>(4)?))
        },
    )?;
    let mut m = Map::new();
    let list: Vec<Value> = others
        .iter()
        .map(|(email, actor, base, since, last)| {
            let mut o = Map::new();
            o.insert("by".into(), json!(email));
            if actor != email {
                o.insert("via".into(), json!(actor));
            }
            o.insert("base_version".into(), json!(base));
            o.insert("since".into(), json!(iso(*since)));
            o.insert("last_active".into(), json!(iso(*last)));
            Value::Object(o)
        })
        .collect();
    m.insert("others_editing".into(), Value::Array(list));
    if !others.is_empty() {
        let who: Vec<String> = others
            .iter()
            .map(|(email, actor, base, _, last)| {
                let via = if actor != email { format!(" (through {actor})") } else { String::new() };
                let from = base.map(|b| format!("working from v{b}, ")).unwrap_or_default();
                format!("{email}{via}, {from}last active {}", ago(*last))
            })
            .collect();
        m.insert(
            "warning".into(),
            json!(format!(
                "Someone else is also working on {}: {}. Tell the person, so they can agree who changes what. \
                 Nothing is blocked, and a deploy that would undo someone else's changes is refused (stale_base).",
                app.slug,
                who.join("; ")
            )),
        );
    }
    Ok(m)
}

/// For bundles too large to pass inline: a one-time address the agent uploads a tar.gz to.
pub fn create_upload(conn: &Connection, cfg: &Config, c: &Caller, o: &DeployTarget) -> Result<Value> {
    require_role(c, "builder", "deploy apps")?;
    o.check_environment()?;
    let base = o.base()?;
    abuse::check_workspace_up(conn, c)?;
    if let Some(slug) = o.app_slug() {
        abuse::check_up(conn, &get_app(conn, c, slug)?)?;
    } else if js_trim(o.name.as_deref().unwrap_or("")).is_empty() {
        return Err(Problem::new(400, "need_name", "Give \"name\" for a new app, or \"app\" to deploy a new version of an existing one."));
    }
    let id = random_id("up_", 20);
    conn.run(
        "INSERT INTO uploads (id, workspace_id, user_id, actor, app_slug, name, note, expires_at, environment, base_version) VALUES (?,?,?,?,?,?,?,?,?,?)",
        params![
            id,
            c.workspace.id,
            c.user.id,
            c.actor,
            o.app,
            o.name,
            o.note.clone().unwrap_or_default(),
            now() + limits::UPLOAD_TTL_MS,
            o.environment,
            base
        ],
    )?;
    let upload_url = format!("{}/v1/uploads/{id}", cfg.api_origin);
    Ok(json!({
        "upload_url": upload_url, "expires_in_seconds": limits::UPLOAD_TTL_MS / 1000,
        "next_step": format!("Upload the built output folder as a tar.gz with one command. The response is the deploy result.\n  tar -czf - -C <build folder> . | curl -sS -X PUT --data-binary @- \"{upload_url}\""),
    }))
}

pub fn claim_upload(conn: &Connection, id: &str) -> Result<(Caller, DeployTarget)> {
    let gone = |m: &str| Problem::new(410, "upload_gone", m);
    struct Up {
        workspace_id: String,
        user_id: String,
        actor: String,
        app_slug: Option<String>,
        name: Option<String>,
        note: String,
        expires_at: i64,
        used_at: Option<i64>,
        environment: Option<String>,
        base_version: Option<i64>,
    }
    let u = conn.first("SELECT * FROM uploads WHERE id = ?", [id], |r| {
        Ok(Up {
            workspace_id: r.get("workspace_id")?,
            user_id: r.get("user_id")?,
            actor: r.get("actor")?,
            app_slug: r.get("app_slug")?,
            name: r.get("name")?,
            note: r.get("note")?,
            expires_at: r.get("expires_at")?,
            used_at: r.get("used_at")?,
            environment: r.get("environment")?,
            base_version: r.get("base_version")?,
        })
    })?;
    let u = match u {
        Some(u) if u.used_at.is_none() && u.expires_at >= now() => u,
        _ => {
            return Err(gone("This upload address has expired or was already used. Call deploy_app again for a new one."));
        }
    };
    let who = conn.first(
        "SELECT w.*, u.email, u.name AS uname, u.email_verified_at, m.role FROM workspaces w JOIN members m ON m.workspace_id = w.id JOIN users u ON u.id = m.user_id WHERE w.id = ? AND u.id = ?",
        params![u.workspace_id, u.user_id],
        |r| {
            Ok((
                Workspace::from_row(r)?,
                User { id: u.user_id.clone(), email: r.get("email")?, name: r.get("uname")?, email_verified_at: r.get("email_verified_at")? },
                r.get::<_, String>("role")?,
            ))
        },
    )?;
    let Some((workspace, user, role)) = who else {
        return Err(gone("The person who asked for this upload address is no longer in the workspace."));
    };
    if conn.run("UPDATE uploads SET used_at = ? WHERE id = ? AND used_at IS NULL", params![now(), id])? == 0 {
        return Err(gone("This upload address was already used."));
    }
    let caller = Caller { workspace, user, role, actor: u.actor, agent: true, read_only: false };
    let base_version = u.base_version.map(|b| json!(b));
    Ok((caller, DeployTarget { app: u.app_slug, name: u.name, note: Some(u.note), environment: u.environment, base_version }))
}

pub fn release_upload(conn: &Connection, id: &str) -> Result<()> {
    conn.run("UPDATE uploads SET used_at = NULL WHERE id = ? AND expires_at > ?", params![id, now()])?;
    Ok(())
}

// ---------- confirmations ----------

/// An agent asked for a change a person must confirm. Nothing changes until they do.
fn needs_confirmation(
    conn: &Connection,
    cfg: &Config,
    c: &Caller,
    app: Option<&AppRow>,
    kind: &str,
    payload: &Value,
    summary: &str,
) -> Result<Value> {
    let id = random_id("cf_", 16);
    let app_id = app.map(|a| a.id.clone());
    tx(conn, |x| {
        x.run(
            "INSERT INTO confirmations (id, workspace_id, app_id, kind, payload, summary, requested_by, created_at, expires_at) VALUES (?,?,?,?,?,?,?,?,?)",
            params![id, c.workspace.id, app_id, kind, payload.to_string(), summary, c.actor, now(), now() + limits::CONFIRM_TTL_MS],
        )?;
        event(x, &c.workspace.id, &c.actor, app_id.as_deref(), "confirmation_requested", summary)
    })?;
    Ok(json!({
        "needs_confirmation": true, "summary": summary, "confirm_url": format!("{}/confirm/{id}", cfg.api_origin),
        "message": format!("Nothing has changed yet. {summary} needs the owner's confirmation: give them this link to open and confirm. It expires in 24 hours."),
    }))
}

#[derive(Clone, Debug)]
pub struct Confirmation {
    pub id: String,
    pub workspace_id: String,
    pub app_id: Option<String>,
    pub kind: String,
    pub payload: String,
    pub summary: String,
    pub requested_by: String,
    pub expires_at: i64,
    pub done_at: Option<i64>,
}

pub fn get_confirmation(conn: &Connection, id: &str) -> Result<Option<Confirmation>> {
    conn.first("SELECT * FROM confirmations WHERE id = ?", [id], |r| {
        Ok(Confirmation {
            id: r.get("id")?,
            workspace_id: r.get("workspace_id")?,
            app_id: r.get("app_id")?,
            kind: r.get("kind")?,
            payload: r.get("payload")?,
            summary: r.get("summary")?,
            requested_by: r.get("requested_by")?,
            expires_at: r.get("expires_at")?,
            done_at: r.get("done_at")?,
        })
    })
}

/// A person confirms an agent's request. They must be signed in to the same workspace with a role that could make the change.
pub async fn confirm(st: &State, user: &User, id: &str) -> Result<Value> {
    let (u, cid) = (user.clone(), id.to_string());
    let (c, cf, app_slug) = st
        .db
        .call(move |conn| {
            let gone = || Problem::new(410, "confirmation_gone", "This request has expired or was already handled.");
            let cf = get_confirmation(conn, &cid)?.ok_or_else(gone)?;
            if cf.done_at.is_some() || cf.expires_at < now() {
                return Err(gone());
            }
            let slug: Option<String> = conn.first("SELECT slug FROM workspaces WHERE id = ?", [&cf.workspace_id], |r| r.get(0))?;
            let mem = match slug {
                Some(s) => people::membership(conn, &u, Some(&s))?,
                None => None,
            };
            let Some((workspace, role)) = mem else {
                return Err(Problem::new(403, "forbidden", "Only someone in this workspace can confirm this."));
            };
            let actor = u.email.clone();
            let c = Caller { workspace, user: u.clone(), role, actor, agent: false, read_only: false };
            if conn
                .run("UPDATE confirmations SET done_at = ?, done_by = ? WHERE id = ? AND done_at IS NULL", params![now(), u.email, cid])?
                == 0
            {
                return Err(Problem::new(410, "confirmation_gone", "This request was already handled."));
            }
            let app_slug: Option<String> = match &cf.app_id {
                Some(a) => conn.first("SELECT slug FROM apps WHERE id = ?", [a], |r| r.get(0))?,
                None => None,
            };
            Ok((c, cf, app_slug))
        })
        .await?;
    let payload: Map<String, Value> = match serde_json::from_str(&cf.payload) {
        Ok(Value::Object(m)) => m,
        _ => Map::new(),
    };
    let slug = app_slug.unwrap_or_default();
    let result = match cf.kind.as_str() {
        "access" => {
            let (c, cfg) = (c.clone(), st.cfg.clone());
            let hash = payload.get("password_hash").and_then(|v| v.as_str()).map(String::from);
            st.db.call(move |conn| set_access(conn, &cfg, &c, &slug, &payload, hash)).await
        }
        "invite" => invite(st, &c, payload).await,
        "delete" => delete_app(st, &c, &slug).await,
        _ => return Err(Problem::new(400, "bad_confirmation", "Unknown request.")),
    };
    if result.is_err() {
        // Give the request back so it can be retried once the problem is fixed.
        let id = id.to_string();
        st.db.call(move |conn| conn.run("UPDATE confirmations SET done_at = NULL, done_by = NULL WHERE id = ?", [id]).map(|_| ())).await?;
    }
    result
}

// ---------- changing an app ----------

/// Delete a version that is not live, to free its storage. Its files go first, then its row.
pub async fn delete_version(st: &State, c: &Caller, slug: &str, n: i64) -> Result<Value> {
    let (c2, slug2) = (c.clone(), slug.to_string());
    let app = st
        .db
        .call(move |conn| {
            require_role(&c2, "builder", "delete versions")?;
            let app = get_app(conn, &c2, &slug2)?;
            abuse::check_up(conn, &app)?;
            if !conn.exists("SELECT 1 FROM versions WHERE app_id = ? AND n = ?", params![app.id, n])? {
                return Err(Problem::new(404, "no_version", format!("{} has no version {n}.", app.slug)));
            }
            if app.live_version == Some(n) {
                return Err(Problem::new(409, "live_version", format!("v{n} is live. Roll back to another version first.")));
            }
            if app.staging_version == Some(n) {
                return Err(Problem::new(409, "staging_version", format!("v{n} is on staging. Publish or discard it first.")));
            }
            Ok(app)
        })
        .await?;
    st.store.delete_prefix(&format!("{}/{n}/", app.id)).await?;
    let (c3, app_id) = (c.clone(), app.id.clone());
    st.db
        .call(move |conn| {
            tx(conn, |x| {
                let bytes = x.count("SELECT bytes FROM versions WHERE app_id = ? AND n = ?", params![app_id, n])?;
                x.run("DELETE FROM versions WHERE app_id = ? AND n = ?", params![app_id, n])?;
                event(x, &c3.workspace.id, &c3.actor, Some(&app_id), "version_deleted", &format!("v{n} ({})", crate::usage::mb(bytes)))?;
                Ok(json!({ "app": app.slug, "deleted": n, "freed_bytes": bytes }))
            })
        })
        .await
}

pub fn rollback(conn: &Connection, cfg: &Config, c: &Caller, slug: &str, version: Option<f64>) -> Result<Value> {
    require_role(c, "builder", "roll back apps")?;
    let app = get_app(conn, c, slug)?;
    let label = match version {
        Some(v) if v.fract() == 0.0 => format!("{v:.0}"),
        Some(v) => v.to_string(),
        None => "NaN".into(),
    };
    let n = version.filter(|v| v.fract() == 0.0).map(|v| v as i64);
    let exists = match n {
        Some(n) => conn.exists("SELECT 1 FROM versions WHERE app_id = ? AND n = ?", params![app.id, n])?,
        None => false,
    };
    let Some(n) = n.filter(|_| exists) else {
        return Err(Problem::new(404, "no_version", format!("{} has no version {label}. Use get_status to see its versions.", app.slug)));
    };
    if app.live_version == Some(n) {
        let mut m = described(conn, cfg, c, &app)?;
        m.insert("changed".into(), json!(false));
        return Ok(Value::Object(m));
    }
    abuse::check_up(conn, &app)?;
    let from = app.live_version.map(|v| v.to_string()).unwrap_or_else(|| "null".into());
    let flag = abuse::flag_of(conn, &app.id, Some(n))?;
    let mut app = app;
    tx(conn, |x| {
        x.run("UPDATE apps SET live_version = ? WHERE id = ?", params![n, app.id])?;
        event(x, &c.workspace.id, &c.actor, Some(&app.id), "rollback", &format!("v{from} to v{n}"))?;
        abuse::narrow_if_flagged(x, &mut app, n, flag.as_deref())
    })?;
    app.live_version = Some(n);
    let mut m = described(conn, cfg, c, &app)?;
    m.insert("changed".into(), json!(true));
    Ok(Value::Object(m))
}

/// Make the version on staging live. Staging is then empty until the next staging deploy.
pub fn publish_staging(conn: &Connection, cfg: &Config, c: &Caller, slug: &str) -> Result<Value> {
    require_role(c, "builder", "publish apps")?;
    let mut app = get_app(conn, c, slug)?;
    let Some(n) = app.staging_version else {
        return Err(Problem::new(
            409,
            "nothing_on_staging",
            format!("{} has nothing on staging. Deploy with \"environment\": \"staging\" first.", app.slug),
        ));
    };
    abuse::check_up(conn, &app)?;
    let from = app.live_version.map(|v| format!("v{v}")).unwrap_or_else(|| "nothing".into());
    // Publishing is a pointer move like a rollback, so a flagged version narrows the app as it goes live.
    let flag = abuse::flag_of(conn, &app.id, Some(n))?;
    tx(conn, |x| {
        // Only if staging still holds this version, so two publishes at once cannot make an older one live.
        if x.run("UPDATE apps SET live_version = ?, staging_version = NULL WHERE id = ? AND staging_version = ?", params![n, app.id, n])?
            == 0
        {
            return Err(Problem::new(409, "nothing_on_staging", "Staging changed while publishing. Look at get_status and try again."));
        }
        event(x, &c.workspace.id, &c.actor, Some(&app.id), "publish", &format!("v{n} from staging (was {from})"))?;
        abuse::narrow_if_flagged(x, &mut app, n, flag.as_deref())
    })?;
    app.live_version = Some(n);
    app.staging_version = None;
    let mut m = described(conn, cfg, c, &app)?;
    m.insert("published".into(), json!(n));
    Ok(Value::Object(m))
}

/// Take the version off staging without making it live. The version itself is kept, for a rollback or a later deploy.
pub fn discard_staging(conn: &Connection, cfg: &Config, c: &Caller, slug: &str) -> Result<Value> {
    require_role(c, "builder", "change staging")?;
    let mut app = get_app(conn, c, slug)?;
    let Some(n) = app.staging_version else {
        let mut m = described(conn, cfg, c, &app)?;
        m.insert("changed".into(), json!(false));
        return Ok(Value::Object(m));
    };
    tx(conn, |x| {
        x.run("UPDATE apps SET staging_version = NULL WHERE id = ?", [&app.id])?;
        event(x, &c.workspace.id, &c.actor, Some(&app.id), "staging_discarded", &format!("v{n}"))
    })?;
    app.staging_version = None;
    let mut m = described(conn, cfg, c, &app)?;
    m.insert("changed".into(), json!(true));
    Ok(Value::Object(m))
}

fn grant_list(v: Option<&Value>, what: &str) -> Result<Vec<Map<String, Value>>> {
    match v {
        None | Some(Value::Null) => Ok(vec![]),
        Some(Value::Array(a)) => Ok(a
            .iter()
            .map(|x| match x {
                Value::String(s) => {
                    let mut m = Map::new();
                    m.insert(if s.contains('@') { "email" } else { "group" }.into(), json!(s));
                    m
                }
                Value::Object(m) => m.clone(),
                _ => Map::new(),
            })
            .collect()),
        Some(_) => Err(Problem::new(
            400,
            "bad_grant",
            format!("\"{what}\" is a list of grants such as {{ \"group\": \"finance\", \"role\": \"editor\" }}."),
        )),
    }
}

/// A password an app is shared with: 6 to 128 characters (as JavaScript counts them), kept exactly as typed.
fn check_password(v: &Value) -> Result<String> {
    match v {
        Value::String(p) if (6..=128).contains(&p.encode_utf16().count()) => Ok(p.clone()),
        _ => Err(Problem::new(
            400,
            "bad_password",
            "\"password\" is 6 to 128 characters. Pick one that is hard to guess: anyone who has it can open the app.",
        )),
    }
}

/// Change an app's access mode and who holds which app role. Widening access (a more open mode, new grants, or a new
/// password) asked for by an agent waits for a person to confirm it. Narrowing takes effect at once. `password_hash` is
/// a password already hashed when the request was made, for a confirmation, which never stores the password itself.
pub fn set_access(
    conn: &Connection,
    cfg: &Config,
    c: &Caller,
    slug: &str,
    o: &Map<String, Value>,
    password_hash: Option<String>,
) -> Result<Value> {
    require_role(c, "builder", "change who can open apps")?;
    let app = get_app(conn, c, slug)?;
    let given = present(o, "access");
    let mut access = given.map(js_string).unwrap_or_else(|| app.access.clone());
    if !ACCESS.contains(&access.as_str()) {
        return Err(Problem::new(400, "bad_access", format!("Access is one of {}.", ACCESS.join(", "))));
    }
    let roles = app.role_list();
    let mut add = Vec::new();
    for g in grant_list(o.get("add"), "add")? {
        let role = present(&g, "role").map(js_string).unwrap_or_else(|| roles.last().cloned().unwrap_or_default());
        if !roles.contains(&role) {
            return Err(Problem::new(400, "bad_role", format!("{} understands the roles {}.", app.slug, roles.join(", "))));
        }
        add.push((people::resolve_subject(conn, c, &g)?, role));
    }
    let remove = grant_list(o.get("remove"), "remove")?.iter().map(|g| people::resolve_subject(conn, c, g)).collect::<Result<Vec<_>>>()?;
    let password = match o.get("password") {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) if s.is_empty() => None,
        Some(v) => Some(check_password(v)?),
    };
    // A password on its own means sharing with it; sharing a private app with someone means opening it to named people.
    if password.is_some() && given.is_none() {
        access = "password".into();
    }
    if access == "private" && !add.is_empty() && given.is_none() {
        access = "people".into();
    }
    if password.is_some() && access != "password" {
        return Err(Problem::new(400, "bad_password", "A password only works with \"access\": \"password\"."));
    }
    if access == "public" && c.user.email_verified_at.is_none() {
        return Err(Problem::new(403, "unverified", "Confirm your email address before making an app public."));
    }
    // Only a password-protected app keeps a password; leaving that mode forgets it.
    let hash = if access != "password" {
        None
    } else {
        password_hash.or_else(|| password.as_deref().map(hash_password)).or_else(|| app.password_hash.clone())
    };
    if access == "password" && hash.is_none() {
        return Err(Problem::new(
            400,
            "password_needed",
            "Give a \"password\" (6 to 128 characters) to share the app with. Anyone with the address and the password can open it, without signing in.",
        ));
    }
    let new_password = access == "password" && hash != app.password_hash;
    let idx = |a: &str| ACCESS.iter().position(|x| *x == a).map(|i| i as i64).unwrap_or(-1);
    let opening = idx(&access) > idx(&app.access);
    let widening = opening || !add.is_empty() || new_password;
    if widening {
        abuse::check_up(conn, &app)?;
    }
    if opening {
        abuse::check_can_open_outside(conn, c, &access)?;
        abuse::check_not_flagged(conn, &app, &access)?;
    }
    if c.agent && widening {
        let mut parts = Vec::new();
        if access != app.access {
            let how = if access == "password" { " (anyone with the address and the password can open it)" } else { "" };
            parts.push(format!("change {} from {} to {access}{how}", app.slug, app.access));
        } else if new_password {
            parts.push(format!("give {} a new password", app.slug));
        }
        if !add.is_empty() {
            let who: Vec<String> = add.iter().map(|(s, r)| format!("{} the {r} role", s.label)).collect();
            parts.push(format!("give {} on {}", who.join(", "), app.slug));
        }
        let summary = capitalise(&parts.join(" and "));
        let mut payload = json!({ "access": access, "add": o.get("add").filter(|v| !v.is_null()).cloned().unwrap_or(json!([])), "remove": o.get("remove").filter(|v| !v.is_null()).cloned().unwrap_or(json!([])) });
        if new_password {
            payload["password_hash"] = json!(hash);
        }
        return needs_confirmation(conn, cfg, c, Some(&app), "access", &payload, &summary);
    }
    let changes = access != app.access || hash != app.password_hash || !remove.is_empty() || !add.is_empty();
    if changes {
        tx(conn, |x| {
            if access != app.access || hash != app.password_hash {
                x.run("UPDATE apps SET access = ?, password_hash = ? WHERE id = ?", params![access, hash, app.id])?;
            }
            if access != app.access {
                event(x, &c.workspace.id, &c.actor, Some(&app.id), "access", &format!("{} to {access}", app.access))?;
            } else if new_password {
                event(x, &c.workspace.id, &c.actor, Some(&app.id), "password", "a new password")?;
            }
            for r in &remove {
                x.run("DELETE FROM grants WHERE app_id = ? AND subject = ?", params![app.id, r.subject])?;
                event(x, &c.workspace.id, &c.actor, Some(&app.id), "ungrant", &r.label)?;
            }
            for (s, role) in &add {
                x.run(
                    "INSERT INTO grants (app_id, subject, role, created_at) VALUES (?,?,?,?) ON CONFLICT(app_id, subject) DO UPDATE SET role = excluded.role",
                    params![app.id, s.subject, role, now()],
                )?;
                event(x, &c.workspace.id, &c.actor, Some(&app.id), "grant", &format!("{} as {role}", s.label))?;
            }
            Ok(())
        })?;
    }
    let mut app = app;
    app.access = access;
    app.password_hash = hash;
    Ok(Value::Object(described(conn, cfg, c, &app)?))
}

fn valid_role_name(r: &str) -> bool {
    let b = r.as_bytes();
    !b.is_empty()
        && b.len() <= 24
        && b[0].is_ascii_lowercase()
        && b.iter().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'_' || *c == b'-')
}

/// Title, welcome line and the app roles the app understands. Changing these needs no redeploy.
pub fn update_app(conn: &Connection, cfg: &Config, c: &Caller, slug: &str, o: &Map<String, Value>) -> Result<Value> {
    require_role(c, "builder", "change app settings")?;
    let app = get_app(conn, c, slug)?;
    let title = match o.get("title") {
        None => app.title.clone(),
        Some(v) => js_slice(js_trim(&js_string(v)), 80),
    };
    let welcome = match o.get("welcome") {
        None => app.welcome.clone(),
        Some(v) => js_slice(js_trim(&js_string(v)), 200),
    };
    let mut roles = app.roles.clone();
    if let Some(v) = o.get("roles") {
        let list: Vec<String> = match v {
            Value::Array(a) => a.iter().map(|r| js_trim(&js_string(r)).to_lowercase()).collect(),
            _ => vec![],
        };
        let mut uniq = list.clone();
        uniq.sort();
        uniq.dedup();
        if list.is_empty() || list.len() > 8 || uniq.len() != list.len() || !list.iter().all(|r| valid_role_name(r)) {
            return Err(Problem::new(
                400,
                "bad_roles",
                "\"roles\" is a list of up to 8 distinct lowercase role names, most powerful first, for example [\"owner\",\"editor\",\"viewer\"].",
            ));
        }
        let used = conn.all("SELECT DISTINCT role FROM grants WHERE app_id = ?", [&app.id], |r| r.get::<_, String>(0))?;
        let orphaned: Vec<String> = used.into_iter().filter(|r| !list.contains(r)).collect();
        if !orphaned.is_empty() {
            return Err(Problem::new(
                409,
                "roles_in_use",
                format!("People hold the role {} on {}. Move them to another role first.", orphaned.join(", "), app.slug),
            ));
        }
        roles = serde_json::to_string(&list)?;
    }
    tx(conn, |x| {
        x.run("UPDATE apps SET title = ?, welcome = ?, roles = ? WHERE id = ?", params![title, welcome, roles, app.id])?;
        event(x, &c.workspace.id, &c.actor, Some(&app.id), "settings", &format!("title \"{title}\", roles {roles}"))
    })?;
    let mut app = app;
    app.title = title;
    app.welcome = welcome;
    app.roles = roles;
    Ok(Value::Object(described(conn, cfg, c, &app)?))
}

pub fn set_paused(conn: &Connection, cfg: &Config, c: &Caller, slug: &str, paused: bool) -> Result<Value> {
    require_role(c, "builder", "pause or resume apps")?;
    let app = get_app(conn, c, slug)?;
    let status = if paused { "paused" } else { "live" };
    if !paused {
        abuse::check_up(conn, &app)?;
    }
    if !paused && app.status == "paused" {
        plan_full(conn, cfg, c, "resume this one")?;
    }
    tx(conn, |x| {
        x.run("UPDATE apps SET status = ? WHERE id = ?", params![status, app.id])?;
        event(x, &c.workspace.id, &c.actor, Some(&app.id), if paused { "pause" } else { "resume" }, "")
    })?;
    let mut app = app;
    app.status = status.into();
    Ok(Value::Object(described(conn, cfg, c, &app)?))
}

pub async fn delete_app(st: &State, c: &Caller, slug: &str) -> Result<Value> {
    let (c2, s, cfg) = (c.clone(), slug.to_string(), st.cfg.clone());
    let (app, pending) = st
        .db
        .call(move |conn| {
            require_role(&c2, "builder", "delete apps")?;
            let app = get_app(conn, &c2, &s)?;
            abuse::check_up(conn, &app)?; // a taken-down app is kept for the Brod team's review
            if c2.agent {
                let summary = format!("Delete {}, all its versions, and its data", app.slug);
                return Ok((app.clone(), Some(needs_confirmation(conn, &cfg, &c2, Some(&app), "delete", &json!({}), &summary)?)));
            }
            Ok((app, None))
        })
        .await?;
    if let Some(p) = pending {
        return Ok(p);
    }
    st.store.delete_prefix(&format!("{}/", app.id)).await?;
    runtime::wipe_app_data(st, &app.id).await?;
    let c2 = c.clone();
    st.db
        .call(move |conn| {
            tx(conn, |x| {
                // Releases already published from the app stay in the marketplace; the listing just has no app behind it.
                for sql in [
                    "UPDATE listings SET app_id = NULL WHERE app_id = ?",
                    "DELETE FROM installs WHERE app_id = ?",
                    "DELETE FROM secrets WHERE app_id = ?",
                    "DELETE FROM app_settings WHERE app_id = ?",
                    "DELETE FROM network_reports WHERE app_id = ?",
                    "DELETE FROM app_logs WHERE app_id = ?",
                    "DELETE FROM versions WHERE app_id = ?",
                    "DELETE FROM downloads WHERE app_id = ?",
                    "DELETE FROM editing WHERE app_id = ?",
                    "DELETE FROM grants WHERE app_id = ?",
                    "DELETE FROM domains WHERE app_id = ?",
                    "DELETE FROM apps WHERE id = ?",
                ] {
                    x.run(sql, [&app.id])?;
                }
                crate::analytics::forget_app(x, &app.id)?;
                event(x, &c2.workspace.id, &c2.actor, None, "delete", &format!("{} deleted", app.slug))
            })?;
            Ok(json!({ "deleted": app.slug }))
        })
        .await
}

/// The database half of an invitation, then its email.
pub async fn invite(st: &State, c: &Caller, o: Map<String, Value>) -> Result<Value> {
    let (c2, cfg) = (c.clone(), st.cfg.clone());
    let (out, mail) = st
        .db
        .call(move |conn| {
            let getter = |s: &str| get_app(conn, &c2, s);
            people::invite(conn, &cfg, &c2, &o, &getter)
        })
        .await?;
    if let Some(m) = mail {
        crate::email::send(st, &m.to, &m.subject, &m.text).await?;
    }
    Ok(out)
}

/// Invite someone. From an agent this waits for a person to confirm, because it widens who can get in.
pub async fn invite_from(st: &State, c: &Caller, o: Map<String, Value>) -> Result<Value> {
    if !c.agent {
        return invite(st, c, o).await;
    }
    let (c2, cfg) = (c.clone(), st.cfg.clone());
    st.db
        .call(move |conn| {
            let getter = |s: &str| get_app(conn, &c2, s);
            let ci = people::check_invite(conn, &c2, &o, &getter)?;
            let summary = match &ci.app {
                Some(a) => format!(
                    "Invite {} to {} as {}{}",
                    ci.email,
                    a.slug,
                    ci.app_role.clone().unwrap_or_default(),
                    if ci.role != "guest" { format!(" (workspace {})", ci.role) } else { String::new() }
                ),
                None => format!("Invite {} to the workspace as {}", ci.email, ci.role),
            };
            let mut payload = Map::new();
            payload.insert("email".into(), json!(ci.email));
            payload.insert("role".into(), json!(ci.role));
            if let Some(a) = &ci.app {
                payload.insert("app".into(), json!(a.slug));
            }
            payload.insert("app_role".into(), json!(ci.app_role));
            needs_confirmation(conn, &cfg, &c2, ci.app.as_ref(), "invite", &Value::Object(payload), &summary)
        })
        .await
}

/// A ServerInfo as stored in versions.server.
impl ServerInfo {
    pub fn to_json(&self) -> String {
        json!({ "main": self.main, "modules": self.modules }).to_string()
    }
}

/// `String(b.field ?? '')` for request bodies.
pub fn body_str(o: &Map<String, Value>, key: &str) -> String {
    field(o, key)
}

/// `b.accept_terms === true`
pub fn is_true(o: &Map<String, Value>, key: &str) -> bool {
    matches!(o.get(key), Some(Value::Bool(true)))
}

pub fn has_value(o: &Map<String, Value>, key: &str) -> bool {
    truthy(o.get(key))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn warns_about_others_working_on_an_app_never_about_yourself() {
        let db = crate::db::test_db();
        let (mine, theirs, later) = db
            .call(|c| {
                c.run("INSERT INTO workspaces (id, slug, name, created_at) VALUES ('ws_e','e','E',1)", ())?;
                c.run("INSERT INTO users (id, email, created_at) VALUES ('usr_a','a@e.test',1), ('usr_b','b@e.test',1)", ())?;
                c.run("INSERT INTO apps (id, workspace_id, owner_id, slug, name, created_at) VALUES ('app_e','ws_e','usr_a','notes','Notes',1)", ())?;
                let app = c.first("SELECT * FROM apps WHERE id = 'app_e'", (), AppRow::from_row)?.unwrap();
                let w = Workspace { id: "ws_e".into(), slug: "e".into(), name: "E".into(), plan: "free".into(), color: String::new(), icon: String::new(), created_at: 1 };
                let who = |id: &str, email: &str, actor: &str| Caller {
                    workspace: w.clone(),
                    user: User { id: id.into(), email: email.into(), name: String::new(), email_verified_at: None },
                    role: "builder".into(),
                    actor: actor.into(),
                    agent: actor != email,
                    read_only: false,
                };
                let (a, b) = (who("usr_a", "a@e.test", "claude-code"), who("usr_b", "b@e.test", "b@e.test"));
                mark_editing(c, &a, "app_e", Some(3))?;
                mark_editing(c, &a, "app_e", Some(4))?;
                let mine = editing_notice(c, &a, &app)?;
                let theirs = editing_notice(c, &b, &app)?;
                c.run("UPDATE editing SET last_at = ?", [now() - limits::EDITING_WINDOW_MS - 1])?;
                Ok((mine, theirs, editing_notice(c, &b, &app)?))
            })
            .await
            .unwrap();
        assert_eq!(mine["others_editing"], json!([]));
        assert!(mine.get("warning").is_none());
        let o = &theirs["others_editing"][0];
        assert_eq!((o["by"].as_str(), o["via"].as_str(), o["base_version"].as_i64()), (Some("a@e.test"), Some("claude-code"), Some(4)));
        let warning = theirs["warning"].as_str().unwrap();
        assert!(warning.contains("a@e.test (through claude-code), working from v4, last active just now"), "{warning}");
        assert_eq!(later["others_editing"], json!([]));
    }

    fn file(path: &str) -> BundleFile {
        BundleFile { path: path.into(), bytes: b"x".to_vec() }
    }
    fn paths(r: Result<Vec<BundleFile>>) -> Vec<String> {
        r.unwrap().into_iter().map(|f| f.path).collect()
    }
    fn code(r: Result<Vec<BundleFile>>) -> String {
        r.err().map(|e| e.code).unwrap_or_default()
    }

    fn agent(token: &str) -> Credentials {
        Credentials { method: "POST".into(), authorization: Some(format!("Bearer {token}")), cookie: None, origin: None, workspace: None }
    }

    /// A workspace with one builder, and that builder as a dashboard caller.
    fn builder(conn: &Connection) -> Caller {
        let t = now();
        conn.run("INSERT INTO workspaces (id, slug, name, created_at) VALUES ('ws_t', 'tok', 'Tok', ?)", [t]).unwrap();
        conn.run("INSERT INTO users (id, email, name, created_at) VALUES ('usr_t', 'b@tok.test', 'B', ?)", [t]).unwrap();
        conn.run("INSERT INTO members (workspace_id, user_id, role, created_at) VALUES ('ws_t', 'usr_t', 'builder', ?)", [t]).unwrap();
        let workspace = conn.first("SELECT * FROM workspaces WHERE id = 'ws_t'", (), Workspace::from_row).unwrap().unwrap();
        let user = User { id: "usr_t".into(), email: "b@tok.test".into(), name: "B".into(), email_verified_at: None };
        Caller { workspace, user, role: "builder".into(), actor: "b@tok.test".into(), agent: false, read_only: false }
    }

    #[test]
    fn reads_token_scopes_and_expiry() {
        assert_eq!(token_scope(None).unwrap(), "manage");
        assert_eq!(token_scope(Some(&json!("read"))).unwrap(), "read");
        assert_eq!(token_scope(Some(&json!("admin"))).unwrap_err().code, "bad_scope");
        assert_eq!(token_expiry(None).unwrap(), None);
        assert_eq!(token_expiry(Some(&json!("never"))).unwrap(), None);
        assert_eq!(token_expiry(Some(&Value::Null)).unwrap(), None);
        let in_a_week = token_expiry(Some(&json!("7"))).unwrap().unwrap() - now();
        assert!((7 * 86_400_000 - 1000..=7 * 86_400_000).contains(&in_a_week));
        for bad in [json!(366), json!(-1), json!(1.5), json!("soon")] {
            assert_eq!(token_expiry(Some(&bad)).unwrap_err().code, "bad_expiry", "{bad}");
        }
        assert_eq!(oauth_scope(""), "manage");
        assert_eq!(oauth_scope("brod"), "manage");
        assert_eq!(oauth_scope("brod:read"), "read");
        assert_eq!(oauth_scope("offline_access brod:read"), "read");
        assert_eq!(oauth_scope("brod brod:read"), "manage");
        assert_eq!(oauth_scope("openid"), "manage");
    }

    #[tokio::test]
    async fn read_only_and_expired_tokens() {
        let db = crate::db::test_db();
        db.call(|conn| {
            let cfg = Config::for_tests();
            let c = builder(conn);
            let read = create_token(conn, &c, "watcher", "read", None)?;
            let caller = authenticate(conn, &cfg, &agent(read["token"].as_str().unwrap()))?;
            assert!(caller.agent && caller.read_only);
            assert_eq!(require_write(&caller, "deploy").unwrap_err().code, "read_only");
            let manage = create_token(conn, &c, "builder", "manage", Some(now() + 60_000))?;
            assert!(!authenticate(conn, &cfg, &agent(manage["token"].as_str().unwrap()))?.read_only);
            conn.run("UPDATE tokens SET expires_at = ? WHERE id = ?", params![now() - 1, manage["id"].as_str().unwrap()])?;
            let e = authenticate(conn, &cfg, &agent(manage["token"].as_str().unwrap())).unwrap_err();
            assert_eq!((e.status, e.code.as_str()), (401, "token_expired"));
            Ok(())
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn refresh_tokens_rotate_and_a_reused_one_disconnects() {
        let db = crate::db::test_db();
        db.call(|conn| {
            let cfg = Config::for_tests();
            let c = builder(conn);
            let first = create_oauth_token(conn, &c, "cli_a", "Agent", "manage")?;
            let (a1, r1) = (first["access_token"].as_str().unwrap(), first["refresh_token"].as_str().unwrap());
            assert_eq!(first["expires_in"], 3600);
            assert!(refresh_oauth_token(conn, "cli_other", r1, None)?.is_err());
            let second = refresh_oauth_token(conn, "cli_a", r1, Some("brod:read"))?.unwrap();
            assert_eq!(second["scope"], "brod:read");
            assert!(authenticate(conn, &cfg, &agent(a1)).is_err());
            let a2 = second["access_token"].as_str().unwrap();
            assert!(authenticate(conn, &cfg, &agent(a2))?.read_only);
            // Narrowed to read, it cannot widen again.
            assert!(refresh_oauth_token(conn, "cli_a", second["refresh_token"].as_str().unwrap(), Some("brod"))?.is_err());
            // The first refresh token again: someone kept a copy, so the connection goes.
            let why = refresh_oauth_token(conn, "cli_a", r1, None)?.unwrap_err();
            assert!(why.contains("disconnected"), "{why}");
            assert!(authenticate(conn, &cfg, &agent(a2)).is_err());
            assert!(refresh_oauth_token(conn, "cli_a", second["refresh_token"].as_str().unwrap(), None)?.is_err());
            // A lapsed refresh token is refused.
            let other = create_oauth_token(conn, &c, "cli_a", "Agent", "manage")?;
            conn.run("UPDATE tokens SET refresh_expires_at = ? WHERE revoked_at IS NULL", [now() - 1])?;
            assert!(refresh_oauth_token(conn, "cli_a", other["refresh_token"].as_str().unwrap(), None)?.unwrap_err().contains("lapsed"));
            Ok(())
        })
        .await
        .unwrap();
    }

    #[test]
    fn normalise_strips_one_wrapping_folder() {
        assert_eq!(paths(normalise(vec![file("dist/index.html"), file("dist/assets/app.js")])), ["index.html", "assets/app.js"]);
        assert_eq!(paths(normalise(vec![file("build/_worker/index.js"), file("build/style.css")])), ["_worker/index.js", "style.css"]);
        // Two top folders: nothing to strip, and no index.html at the top.
        assert_eq!(code(normalise(vec![file("a/index.html"), file("b/x.js")])), "no_index");
    }

    #[test]
    fn normalise_drops_junk_and_cleans_paths() {
        let out = paths(normalise(vec![
            file("./index.html"),
            file("/a.css"),
            file(".DS_Store"),
            file("x/._y"),
            file(".git/config"),
            file("Thumbs.db"),
            file("__MACOSX/._index.html"),
        ]));
        assert_eq!(out, ["index.html", "a.css"]);
    }

    #[test]
    fn normalise_refuses_bad_bundles() {
        assert_eq!(code(normalise(vec![file("index.html"), file("../etc/passwd")])), "bad_path");
        assert_eq!(code(normalise(vec![file("index.html"), file("a/./b")])), "bad_path");
        assert_eq!(code(normalise(vec![file("index.html"), file("_brod/me")])), "bad_path");
        assert_eq!(code(normalise(vec![file("index.html"), file(&"a".repeat(401))])), "bad_path");
        assert_eq!(code(normalise(vec![file("main.py")])), "no_index");
        assert_eq!(code(normalise(vec![])), "empty_bundle");
        let big = BundleFile { path: "big.bin".into(), bytes: vec![0; FILE_BYTES + 1] };
        let err = normalise(vec![file("index.html"), big]).unwrap_err();
        assert_eq!((err.code.as_str(), err.message.as_str()), ("too_large", "big.bin is larger than 10 MB."));
        let many: Vec<BundleFile> = (0..=MAX_FILES).map(|i| file(&format!("f{i}"))).chain([file("index.html")]).collect();
        assert_eq!(code(normalise(many)), "too_many_files");
        assert_eq!(code(normalise(vec![file("_worker/lib.js")])), "bad_server");
    }

    #[test]
    fn reads_bearer_tokens() {
        let cr = |a: &str| Credentials { method: "GET".into(), authorization: Some(a.into()), cookie: None, origin: None, workspace: None };
        assert_eq!(cr("Bearer brod_x").bearer().as_deref(), Some("brod_x"));
        assert_eq!(cr("bearer   brod_x").bearer().as_deref(), Some("brod_x"));
        assert_eq!(cr("Basic abc").bearer(), None);
        assert_eq!(cr("Bearer a b").bearer(), None);
    }
}
