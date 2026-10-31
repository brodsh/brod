// SPDX-License-Identifier: AGPL-3.0-only
// App MCP: an app's own MCP endpoint, signed in to with Brod's OAuth server, so an MCP client needs only the address.
//
// An app with server code declares one path in its brod.json:
//
//   { "mcp": "/api/mcp" }
//
// The path and everything under it is then the app's MCP endpoint, and its address on each host the app is served at
// is an OAuth protected resource (RFC 9728) whose authorization server is Brod (connect.rs). A client that calls it
// without credentials gets 401 with a pointer to /.well-known/oauth-protected-resource<path> on the app's host, signs
// the person in at Brod with resource=<the address> (RFC 8707), and gets an access token bound to that one address.
//
// The gateway (gateway.rs) takes such a token only on that address: not on Brod's own /mcp or API (those read the
// tokens table, these live in app_tokens), not on another app, not on the app's staging address or a custom domain
// (each is its own resource). On every request it checks that the person may still open the app, exactly as for a
// browser, then strips Authorization and hands the app the usual identity (x-brod-identity and x-brod-user-*), so the
// app's handler reads the person with currentUser() from @brod/auth and never sees a Brod token.
//
// Declaring the path needs nobody's approval, unlike open paths (open_paths.rs): it lets in only people who could
// open the app anyway, and only as themselves. The declaration travels with the version, like open paths and settings.
use serde_json::{Value, json};

use crate::config::Config;
use crate::db::{Connection, Sql, event, params, tx};
use crate::model::{AppRow, User, limits};
use crate::people::{self, Decision};
use crate::problem::{Problem, Result};
use crate::tar::BundleFile;
use crate::util::{app_url, host_origin, is_local, js_slice, js_trim, now, random_id, sha256_hex, staging_url};

/// Prefixes of the tokens made here, so a person (or a secret scanner) can tell them from Brod's own.
pub const ACCESS_PREFIX: &str = "brodapp_";
pub const REFRESH_PREFIX: &str = "brodappr_";

fn bad(msg: String) -> Problem {
    Problem::new(400, "bad_mcp", msg)
}

/// Why a declared MCP path is refused, or None when it is fine: the same rules as an open path, without the trailing
/// "/*" (the path's sub-paths are always part of the endpoint).
pub fn path_problem(p: &str) -> Option<&'static str> {
    if p.ends_with("/*") {
        return Some("covers its sub-paths already; leave out the /*");
    }
    crate::open_paths::pattern_problem(p)
}

/// Read and check the "mcp" value: a path, or null for none.
pub fn parse(v: &Value, whence: &str) -> Result<Option<String>> {
    match v {
        Value::Null => Ok(None),
        Value::String(s) if s.is_empty() => Ok(None),
        Value::String(s) => match path_problem(s) {
            Some(why) => Err(bad(format!("{whence}: the MCP path {s:?} {why}."))),
            None => Ok(Some(s.clone())),
        },
        _ => Err(bad(format!("{whence} is one path, like \"/api/mcp\"."))),
    }
}

/// The "mcp" path a bundle's brod.json declares. None: it declares none.
pub fn from_bundle(files: &[BundleFile]) -> Result<Option<String>> {
    let manifest = crate::settings::MANIFEST;
    let Some(f) = files.iter().find(|f| f.path == manifest) else { return Ok(None) };
    let Ok(Value::Object(doc)) = serde_json::from_slice::<Value>(&f.bytes) else { return Ok(None) };
    match doc.get("mcp") {
        None => Ok(None),
        Some(v) => parse(v, &format!("\"mcp\" in {manifest}")),
    }
}

/// Whether a request path is the MCP endpoint or under it. The path is normalised as for open paths; one that could
/// mean something else to the app (an encoded /, a .. segment) is never the endpoint, so it goes through sign-in.
pub fn matches(mcp: &str, raw_path: &str) -> bool {
    match crate::open_paths::normalize(raw_path) {
        Some(p) => p == mcp || p.strip_prefix(mcp).is_some_and(|rest| rest.starts_with('/')),
        None => false,
    }
}

/// The address of the protected-resource metadata for the endpoint at `origin` + `mcp` (RFC 9728 section 3.1).
pub fn metadata_url(origin: &str, mcp: &str) -> String {
    format!("{origin}/.well-known/oauth-protected-resource{mcp}")
}

/// The protected-resource metadata for the endpoint at `origin` + `mcp`.
pub fn metadata(cfg: &Config, origin: &str, mcp: &str) -> Value {
    json!({ "resource": format!("{origin}{mcp}"), "authorization_servers": [cfg.api_origin], "bearer_methods_supported": ["header"] })
}

/// A `resource` that means Brod's own MCP endpoint (or Brod as a whole), as MCP clients send for /mcp.
pub fn is_brod_resource(cfg: &Config, resource: &str) -> bool {
    let r = resource.trim_end_matches('/');
    let o = cfg.api_origin.trim_end_matches('/');
    r == o || r == format!("{o}/mcp")
}

/// A resource address in the one form tokens are bound to: the scheme Brod serves apps with, a lower-case host, a path,
/// and no query, fragment or trailing slash. None for anything else.
pub fn canonical(cfg: &Config, resource: &str) -> Option<(String, String)> {
    let scheme = if is_local(&cfg.apps_domain) { "http://" } else { "https://" };
    let rest = resource.get(..scheme.len()).filter(|s| s.eq_ignore_ascii_case(scheme)).map(|_| &resource[scheme.len()..])?;
    if rest.is_empty() || rest.chars().any(|c| c.is_whitespace() || c.is_control() || matches!(c, '?' | '#' | '@' | '\\')) {
        return None;
    }
    let slash = rest.find('/')?;
    let host = rest[..slash].to_ascii_lowercase();
    let path = rest[slash..].trim_end_matches('/');
    if host.is_empty() || path.is_empty() {
        return None;
    }
    Some((host, path.to_string()))
}

/// An app's MCP endpoint, found from its address.
#[derive(Clone, Debug)]
pub struct Target {
    /// As served at that address: on a staging address, live_version holds the staging version and the access mode is
    /// the one staging uses, as in the gateway.
    pub app: AppRow,
    pub workspace_slug: String,
    pub workspace_name: String,
    pub staging: bool,
    pub path: String,
    /// The address itself, canonical: what a token is bound to.
    pub resource: String,
}

fn valid_label(s: &str) -> bool {
    !s.is_empty() && s.len() <= 63 && s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// The app MCP endpoint at a resource address: an app served at that host whose served version declares exactly that
/// path. None for anything else, a taken-down or suspended app included.
pub fn resolve(conn: &Connection, cfg: &Config, resource: &str) -> Result<Option<Target>> {
    let Some((host, path)) = canonical(cfg, resource) else { return Ok(None) };
    if host == cfg.api_host {
        return Ok(None);
    }
    enum By {
        Slug(String, String, bool),
        Id(String),
    }
    let by = match host.strip_suffix(&format!(".{}", cfg.apps_domain)) {
        Some(rest) => {
            let labels: Vec<&str> = rest.split('.').collect();
            let [app, ws] = labels.as_slice() else { return Ok(None) };
            if !valid_label(app) || !valid_label(ws) {
                return Ok(None);
            }
            match app.strip_suffix(crate::util::STAGING_SUFFIX) {
                Some(base) if !base.is_empty() => By::Slug(ws.to_string(), base.to_string(), true),
                _ => By::Slug(ws.to_string(), app.to_string(), false),
            }
        }
        None => match crate::domains::resolve_host(conn, cfg, &host)? {
            Some(crate::domains::Target::App(id)) => By::Id(id),
            Some(crate::domains::Target::Wildcard { workspace, slug }) => By::Slug(workspace, slug, false),
            _ => return Ok(None),
        },
    };
    let staging = matches!(by, By::Slug(_, _, true));
    let version = if staging { "staging_version" } else { "live_version" };
    let sql = format!(
        "SELECT a.*, w.slug AS wslug, w.name AS wname, v.mcp AS vmcp FROM apps a JOIN workspaces w ON w.id = a.workspace_id
         LEFT JOIN versions v ON v.app_id = a.id AND v.n = a.{version} WHERE "
    );
    let map = |r: &crate::db::Row| {
        Ok((AppRow::from_row(r)?, r.get::<_, String>("wslug")?, r.get::<_, String>("wname")?, r.get::<_, Option<String>>("vmcp")?))
    };
    let row = match &by {
        By::Slug(ws, slug, _) => conn.first(&format!("{sql}w.slug = ? AND a.slug = ?"), [ws, slug], map)?,
        By::Id(id) => conn.first(&format!("{sql}a.id = ?"), [id], map)?,
    };
    let Some((mut app, workspace_slug, workspace_name, Some(mcp))) = row else { return Ok(None) };
    if mcp != path || crate::abuse::hold_of(conn, &app)?.is_some() {
        return Ok(None);
    }
    if staging {
        served_on_staging(&mut app);
    }
    let resource = format!("{}{path}", host_origin(cfg, &host));
    Ok(Some(Target { app, workspace_slug, workspace_name, staging, path, resource }))
}

/// An app as its staging address serves it: the staging version, and never public, by password or to anyone signed in.
pub fn served_on_staging(app: &mut AppRow) {
    app.live_version = app.staging_version;
    if app.access == "public" || app.access == "password" || app.access == "signed_in" {
        app.access = "people".into();
    }
}

/// Whether a person may use the endpoint: the same decision the gateway makes for their browser. A password-protected
/// app lets in only the people it was shared with by name: a token never stands in for the password.
pub fn decide(conn: &Connection, app: &AppRow, staging: bool, user: &User) -> Result<Decision> {
    let mut d = people::decide(conn, app, Some(user))?;
    if staging {
        crate::gateway::admit_staging(app, &mut d, Some(user));
    }
    Ok(d)
}

// ---------- tokens ----------

fn pair(access: &str, refresh: Option<&str>) -> Value {
    let mut t = json!({ "access_token": access, "token_type": "Bearer", "expires_in": limits::OAUTH_ACCESS_TTL_MS / 1000 });
    if let Some(r) = refresh {
        t["refresh_token"] = json!(r);
    }
    t
}

/// A sign-in to an app's MCP endpoint: an access token bound to its address that lives an hour, and a refresh token.
pub fn issue(conn: &Connection, t: &Target, user: &User, client_id: &str, name: &str) -> Result<Value> {
    let (access, refresh, id, at) = (random_id(ACCESS_PREFIX, 24), random_id(REFRESH_PREFIX, 24), random_id("atk_", 8), now());
    let clean = js_slice(js_trim(name), 40);
    tx(conn, |x| {
        x.run(
            "INSERT INTO app_tokens (id, app_id, user_id, resource, name, client_id, hash, created_at, expires_at, refresh_hash, refresh_expires_at)
             VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            params![
                id,
                t.app.id,
                user.id,
                t.resource,
                clean,
                client_id,
                sha256_hex(&access),
                at,
                at + limits::OAUTH_ACCESS_TTL_MS,
                sha256_hex(&refresh),
                at + limits::OAUTH_REFRESH_TTL_MS
            ],
        )?;
        event(
            x,
            &t.app.workspace_id,
            &user.email,
            Some(&t.app.id),
            "app_mcp_connected",
            &format!("\"{clean}\" signed in to {}", t.resource),
        )
    })?;
    Ok(pair(&access, Some(&refresh)))
}

/// Why a token request is refused: the OAuth error code and a sentence.
pub type Refusal = (&'static str, String);

/// Swap an app refresh token for a new pair, as refresh_oauth_token does for Brod's own: it rotates, a reused one
/// disconnects the client, and it is refused once the person may no longer open the app or the app no longer serves
/// the endpoint at that address. `resource`, when the client sends one, must be the address the token is bound to.
pub fn refresh(
    conn: &Connection,
    cfg: &Config,
    client_id: &str,
    refresh: &str,
    resource: Option<&str>,
) -> Result<std::result::Result<Value, Refusal>> {
    tx(conn, |x| refresh_in(x, cfg, client_id, refresh, resource))
}

fn refresh_in(
    conn: &Connection,
    cfg: &Config,
    client_id: &str,
    refresh: &str,
    resource: Option<&str>,
) -> Result<std::result::Result<Value, Refusal>> {
    let hash = sha256_hex(refresh);
    let at = now();
    let grant = |why: &str| Ok(Err(("invalid_grant", why.to_string())));
    let row = conn.first(
        "SELECT t.id, t.app_id, t.resource, t.client_id, t.refresh_expires_at, t.revoked_at, u.id AS uid, u.email, u.name AS uname, u.email_verified_at
         FROM app_tokens t JOIN users u ON u.id = t.user_id WHERE t.refresh_hash = ?",
        [&hash],
        |r| {
            Ok((
                (r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?),
                (r.get::<_, Option<String>>(3)?, r.get::<_, Option<i64>>(4)?, r.get::<_, Option<i64>>(5)?),
                User { id: r.get("uid")?, email: r.get("email")?, name: r.get("uname")?, email_verified_at: r.get("email_verified_at")? },
            ))
        },
    )?;
    let Some(((id, app_id, bound), (cid, lapses, revoked), user)) = row else {
        let reused = conn.first(
            "UPDATE app_tokens SET revoked_at = ? WHERE prev_refresh_hash = ? AND revoked_at IS NULL RETURNING id, app_id",
            params![at, hash],
            |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)),
        )?;
        if let Some((id, app_id)) = reused {
            let ws: Option<String> = conn.first("SELECT workspace_id FROM apps WHERE id = ?", [&app_id], |r| r.get(0))?;
            if let Some(ws) = ws {
                event(conn, &ws, "brod", Some(&app_id), "app_mcp_disconnected", &format!("{id}: an old refresh token was used again"))?;
            }
            return grant("This refresh token was already used, so the connection has been disconnected. Sign in again.");
        }
        return grant("This refresh token is not valid. Sign in again.");
    };
    if revoked.is_some() {
        return grant("This connection was disconnected. Sign in again.");
    }
    if cid.as_deref() != Some(client_id) {
        return grant("The refresh token was issued to another client.");
    }
    if lapses.is_none_or(|l| l <= at) {
        return grant("This refresh token has lapsed. Sign in again.");
    }
    if let Some(r) = resource.filter(|r| !r.is_empty())
        && canonical_string(cfg, r).as_deref() != Some(bound.as_str())
    {
        return Ok(Err(("invalid_target", "The refresh token is for another resource.".into())));
    }
    let Some(t) = resolve(conn, cfg, &bound)?.filter(|t| t.app.id == app_id) else {
        return grant("The app no longer has an MCP endpoint at this address.");
    };
    if !decide(conn, &t.app, t.staging, &user)?.allowed {
        return grant(&format!("You can no longer open {}.", t.app.display_name()));
    }
    let (access, next) = (random_id(ACCESS_PREFIX, 24), random_id(REFRESH_PREFIX, 24));
    conn.run(
        "UPDATE app_tokens SET hash = ?, expires_at = ?, prev_refresh_hash = refresh_hash, refresh_hash = ?, refresh_expires_at = ? WHERE id = ?",
        params![sha256_hex(&access), at + limits::OAUTH_ACCESS_TTL_MS, sha256_hex(&next), at + limits::OAUTH_REFRESH_TTL_MS, id],
    )?;
    Ok(Ok(pair(&access, Some(&next))))
}

/// The canonical form of a resource address as one string, for comparing with a bound one.
pub fn canonical_string(cfg: &Config, resource: &str) -> Option<String> {
    canonical(cfg, resource).map(|(host, path)| format!("{}{path}", host_origin(cfg, &host)))
}

/// What a bearer token on an app's MCP endpoint turned out to be.
pub enum Bearer {
    /// A live token for exactly this address: whose it is. The access check comes next.
    Person(User),
    /// Not a token for this address (unknown, revoked, expired, Brod's own, another app's or another address's).
    Invalid(&'static str),
}

/// Check a bearer token sent to the MCP endpoint at `resource` of the app `app_id`.
pub fn check(conn: &Connection, token: &str, app_id: &str, resource: &str) -> Result<Bearer> {
    if !token.starts_with(ACCESS_PREFIX) {
        return Ok(Bearer::Invalid("This is not an access token for this app. Sign in to it again."));
    }
    let row = conn.first(
        "SELECT t.id, t.app_id, t.resource, t.expires_at, t.last_used_at, u.id AS uid, u.email, u.name AS uname, u.email_verified_at
         FROM app_tokens t JOIN users u ON u.id = t.user_id WHERE t.hash = ? AND t.revoked_at IS NULL",
        [sha256_hex(token)],
        |r| {
            Ok((
                (r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?),
                (r.get::<_, Option<i64>>(3)?, r.get::<_, Option<i64>>(4)?),
                User { id: r.get("uid")?, email: r.get("email")?, name: r.get("uname")?, email_verified_at: r.get("email_verified_at")? },
            ))
        },
    )?;
    let Some(((id, token_app, bound), (expires_at, last_used), user)) = row else {
        return Ok(Bearer::Invalid("The access token is not valid or was disconnected."));
    };
    if token_app != app_id || bound != resource {
        return Ok(Bearer::Invalid("The access token is for another resource."));
    }
    let at = now();
    if expires_at.is_some_and(|e| e <= at) {
        return Ok(Bearer::Invalid("The access token has expired. Renew it with the refresh token."));
    }
    // Recorded at most once a minute, so a busy client does not write on every call.
    if last_used.is_none_or(|l| l < at - 60_000) {
        conn.run("UPDATE app_tokens SET last_used_at = ? WHERE id = ?", params![at, id])?;
    }
    Ok(Bearer::Person(user))
}

// ---------- personal access tokens ----------

/// A token a person makes for automation that calls one app's MCP endpoint: bound to that endpoint's address (live, or
/// staging with `staging`) like a sign-in, with no refresh token, and checked on every request the same way. Made from
/// the dashboard by the person themselves (never by an agent), who must be able to open the app.
pub fn create_pat(
    conn: &Connection,
    cfg: &Config,
    c: &crate::model::Caller,
    slug: &str,
    staging: bool,
    name: &str,
    expires_at: Option<i64>,
) -> Result<Value> {
    if c.agent {
        return Err(Problem::new(403, "forbidden", "An agent cannot create connections. Ask the person to do it from the dashboard."));
    }
    people::require_role(c, "builder", "make a token for an app's MCP endpoint")?;
    let app = crate::control::get_app(conn, c, slug)?;
    let base = if staging { staging_url(cfg, &c.workspace.slug, &app.slug) } else { app_url(cfg, &c.workspace.slug, &app.slug) };
    let declared = |n: Option<i64>| -> Result<Option<String>> {
        Ok(match n {
            None => None,
            Some(n) => conn.first("SELECT mcp FROM versions WHERE app_id = ? AND n = ?", params![app.id, n], |r| r.get(0))?.flatten(),
        })
    };
    let Some(path) = declared(if staging { app.staging_version } else { app.live_version })? else {
        return Err(Problem::new(
            409,
            "no_mcp",
            format!(
                "{}'s {} version declares no MCP endpoint. Add \"mcp\": \"/api/mcp\" to its brod.json and deploy.",
                app.display_name(),
                if staging { "staging" } else { "live" }
            ),
        ));
    };
    let Some(t) = resolve(conn, cfg, &format!("{base}{path}"))? else {
        return Err(Problem::new(409, "no_mcp", "That MCP endpoint is not being served (the app may be taken down)."));
    };
    if !decide(conn, &t.app, t.staging, &c.user)?.allowed {
        return Err(Problem::new(403, "forbidden", format!("You cannot open {}, so you cannot make a token for it.", app.display_name())));
    }
    let mut clean = js_slice(js_trim(name), 40);
    if clean.is_empty() {
        clean = "automation".into();
    }
    let (token, id, at) = (random_id(ACCESS_PREFIX, 24), random_id("atk_", 8), now());
    tx(conn, |x| {
        x.run(
            "INSERT INTO app_tokens (id, app_id, user_id, resource, name, hash, created_at, expires_at) VALUES (?,?,?,?,?,?,?,?)",
            params![id, app.id, c.user.id, t.resource, clean, sha256_hex(&token), at, expires_at],
        )?;
        event(x, &c.workspace.id, &c.actor, Some(&app.id), "app_mcp_token_created", &format!("\"{clean}\" for {}", t.resource))
    })?;
    Ok(json!({ "id": id, "name": clean, "token": token, "app": app.slug, "resource": t.resource, "expires_at": expires_at }))
}

/// The workspace's app MCP connections (sign-ins and tokens), shaped like its own connections (control::list_tokens).
pub fn list(conn: &Connection, workspace_id: &str) -> Result<Vec<Value>> {
    conn.rows_json(
        "SELECT t.id, t.name, u.email AS made_by, 'app' AS kind, a.slug AS app, t.resource, t.created_at, t.last_used_at, t.expires_at,
         t.refresh_expires_at, t.revoked_at
         FROM app_tokens t JOIN users u ON u.id = t.user_id JOIN apps a ON a.id = t.app_id WHERE a.workspace_id = ? ORDER BY t.created_at",
        [workspace_id],
    )
}

/// Disconnect one: builders their own, admins any in the workspace. false: no such live connection of theirs.
pub fn revoke(conn: &Connection, c: &crate::model::Caller, id: &str) -> Result<bool> {
    let n = conn.run(
        "UPDATE app_tokens SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL AND (? OR user_id = ?)
         AND app_id IN (SELECT id FROM apps WHERE workspace_id = ?)",
        params![now(), id, if c.role == "admin" { 1 } else { 0 }, c.user.id, c.workspace.id],
    )?;
    Ok(n > 0)
}

/// What get_status shows about an app's MCP endpoint: its address on the live and staging hosts, when declared.
pub fn view(conn: &Connection, cfg: &Config, app: &AppRow, workspace_slug: &str) -> Result<Option<Value>> {
    let path_of = |n: Option<i64>| -> Result<Option<String>> {
        match n {
            None => Ok(None),
            Some(n) => Ok(conn.first("SELECT mcp FROM versions WHERE app_id = ? AND n = ?", params![app.id, n], |r| r.get(0))?.flatten()),
        }
    };
    let (live, staging) = (path_of(app.live_version)?, path_of(app.staging_version)?);
    if live.is_none() && staging.is_none() {
        return Ok(None);
    }
    let mut v = json!({
        "how": "Add the url to an MCP client as a remote (HTTP) server. The client signs the person in with Brod; the app's handler reads them with currentUser() from @brod/auth.",
    });
    if let Some(p) = live {
        v["path"] = json!(p);
        v["url"] = json!(format!("{}{p}", app_url(cfg, workspace_slug, &app.slug)));
    }
    if let Some(p) = staging {
        v["staging_url"] = json!(format!("{}{p}", staging_url(cfg, workspace_slug, &app.slug)));
    }
    Ok(Some(v))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checks_the_declared_path() {
        let ok = |v: Value| parse(&v, "test").unwrap();
        assert_eq!(ok(json!("/api/mcp")).as_deref(), Some("/api/mcp"));
        assert_eq!(ok(json!(null)), None);
        assert_eq!(ok(json!("")), None);
        for bad in [json!("/api/mcp/*"), json!("/"), json!("api/mcp"), json!("/_brod/mcp"), json!("/a/../b"), json!(["/api/mcp"]), json!(1)]
        {
            assert_eq!(parse(&bad, "test").unwrap_err().code, "bad_mcp", "{bad}");
        }
        let f = |s: &str| vec![BundleFile { path: "brod.json".into(), bytes: s.as_bytes().to_vec() }];
        assert_eq!(from_bundle(&f(r#"{"mcp":"/api/mcp"}"#)).unwrap().as_deref(), Some("/api/mcp"));
        assert_eq!(from_bundle(&f(r#"{"settings":{}}"#)).unwrap(), None);
        assert_eq!(from_bundle(&[]).unwrap(), None);
        assert_eq!(from_bundle(&f(r#"{"mcp":"/*"}"#)).unwrap_err().code, "bad_mcp");
    }

    #[test]
    fn matches_the_path_and_what_is_under_it() {
        assert!(matches("/api/mcp", "/api/mcp"));
        assert!(matches("/api/mcp", "/api/mcp/sse"));
        assert!(matches("/api/mcp", "//api/m%63p"));
        assert!(!matches("/api/mcp", "/api/mcpx"));
        assert!(!matches("/api/mcp", "/api"));
        assert!(!matches("/api/mcp", "/api%2fmcp"));
        assert!(!matches("/api/mcp", "/api/mcp/../admin"));
        assert!(!matches("/api/mcp", "/API/MCP"));
    }

    #[test]
    fn reads_resource_addresses_in_one_form() {
        let mut cfg = Config::for_tests();
        cfg.apps_domain = "apps.test".into();
        assert_eq!(canonical(&cfg, "https://Notes.Acme.apps.test/api/mcp/"), Some(("notes.acme.apps.test".into(), "/api/mcp".into())));
        assert_eq!(canonical_string(&cfg, "HTTPS://notes.acme.apps.test/api/mcp").as_deref(), Some("https://notes.acme.apps.test/api/mcp"));
        for bad in [
            "http://notes.acme.apps.test/api/mcp",
            "https://notes.acme.apps.test",
            "https://notes.acme.apps.test/",
            "https://notes.acme.apps.test/api/mcp?x=1",
            "https://notes.acme.apps.test/api/mcp#x",
            "https://u@notes.acme.apps.test/api/mcp",
            "notes.acme.apps.test/api/mcp",
            "",
        ] {
            assert_eq!(canonical(&cfg, bad), None, "{bad}");
        }
    }

    #[test]
    fn knows_brods_own_resource() {
        let cfg = Config::for_tests();
        assert!(is_brod_resource(&cfg, "http://localhost:8787/mcp"));
        assert!(is_brod_resource(&cfg, "http://localhost:8787/mcp/"));
        assert!(is_brod_resource(&cfg, "http://localhost:8787"));
        assert!(!is_brod_resource(&cfg, "http://notes.acme.localhost:8787/mcp"));
        assert!(!is_brod_resource(&cfg, "http://localhost:8787/v1"));
    }

    #[test]
    fn describes_the_metadata() {
        let cfg = Config::for_tests();
        let m = metadata(&cfg, "http://notes.acme.localhost:8787", "/api/mcp");
        assert_eq!(m["resource"], "http://notes.acme.localhost:8787/api/mcp");
        assert_eq!(m["authorization_servers"], json!(["http://localhost:8787"]));
        assert_eq!(
            metadata_url("http://notes.acme.localhost:8787", "/api/mcp"),
            "http://notes.acme.localhost:8787/.well-known/oauth-protected-resource/api/mcp"
        );
    }
}
