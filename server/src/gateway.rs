// SPDX-License-Identifier: AGPL-3.0-only
// The gateway. Every visitor request to <slug>.<APPS_DOMAIN> passes through here before it reaches an app's files.
// It signs people in (through the API host), decides access, gives the app the identity contract under /_brod/,
// and serves the app: its files from storage, and anything else from its server code when it has some.
use crate::db::params;
use axum::body::Body;
use axum::http::Method;
use axum::response::Response;
use serde_json::{Value, json};

use crate::config::Config;
use crate::db::{Sql, event, tx};
use crate::http::{Req, bytes_body, json_response, not_found, notice, page, read_capped, redirect, response};
use crate::model::{AppRow, User, limits};
use crate::people::{self, Decision, SessionUser};
use crate::problem::Result;
use crate::runtime::{self, ServerInfo};
use crate::state::State;
use crate::storage::Object;
use crate::util::{
    STAGING_SUFFIX, app_url, cookie, decode_uri_component, encode_uri_component, esc, hmac_b64url, host_origin, js_slice, js_trim, now,
    random_id, safe_equal, set_cookie, sha256_hex, sign_token, staging_url, verify_password,
};

pub const APP_COOKIE: &str = "brod_session";
const PASS_COOKIE: &str = "brod_pass";

pub const CLIENT_JS: &str = "// Brod client: who is signed in to this app, and the settings its workspace chose for it.
window.Brod = {
  async me() { const r = await fetch('/_brod/me', { credentials: 'same-origin' }); return r.ok ? r.json() : null; },
  async settings() { const r = await fetch('/_brod/settings', { credentials: 'same-origin' }); return r.ok ? r.json() : {}; },
  signIn(path) { location.href = '/_brod/signin?return=' + encodeURIComponent(path || location.pathname + location.search); },
  signOut() { location.href = '/_brod/signout'; },
};
";

pub const REPORT_LINK: &str = "<a href=\"/_brod/report\" style=\"position:fixed;right:8px;bottom:8px;font:12px system-ui,sans-serif;opacity:.6;color:inherit;background:transparent;z-index:2147483647\">Report</a>";

/// The key an app uses to check identity tokens. Each app has its own, derived from the platform secret.
pub fn app_identity_key(cfg: &Config, app_id: &str) -> String {
    hmac_b64url(&cfg.identity_secret, &format!("identity:{app_id}"))
}

fn sign_in_url(cfg: &Config, app: &AppRow, workspace_slug: &str, domain: Option<&str>, staging: bool, ret: &str) -> String {
    let host = domain.map(|d| format!("&host={}", encode_uri_component(d))).unwrap_or_default();
    let suffix = if staging { STAGING_SUFFIX } else { "" };
    format!("{}/auth/app?app={}{suffix}.{workspace_slug}{host}&return={}", cfg.api_origin, app.slug, encode_uri_component(ret))
}
fn app_return(r: Option<String>) -> String {
    match r {
        Some(r) if r.starts_with('/') && !r.starts_with("//") && !r.starts_with("/\\") => r,
        _ => "/".into(),
    }
}

/// The identity contract: who is signed in, their role in this app, and a token signed with the app's key.
pub fn identity_for(cfg: &Config, app: &AppRow, workspace_slug: &str, user: &User, d: &Decision) -> (Value, String) {
    let t = now() / 1000;
    let identity = json!({
        "user": { "id": user.id, "email": user.email, "name": user.name },
        "role": d.role, "groups": d.groups, "app": app.slug, "workspace": workspace_slug,
    });
    let mut payload = identity.clone();
    payload["iat"] = json!(t);
    payload["exp"] = json!(t + limits::IDENTITY_TTL_SEC);
    let token = sign_token(&app_identity_key(cfg, &app.id), &payload);
    (identity, token)
}

/// Everything the gateway reads from the database for one request, in one trip to the blocking pool.
struct Visit {
    app: AppRow,
    server: Option<String>,
    /// The outside hosts the served version declares (network.rs), for its Content-Security-Policy.
    network: Vec<String>,
    visitor: Option<SessionUser>,
    decision: Decision,
    workspace_slug: String,
    /// The origin the app was opened at (its own address or a custom domain); its session cookie belongs there.
    origin: String,
    /// The custom domain it was opened at, so a sign-in can be handed back there.
    domain: Option<String>,
    /// Opened at the app's staging address: `app.live_version` then holds the staging version.
    staging: bool,
}

/// The cookie a correct password earns: bound to the app and to its current password, so setting a new one ends it.
fn pass_token(cfg: &Config, app: &AppRow) -> String {
    hmac_b64url(&cfg.identity_secret, &format!("password:{}:{}", app.id, app.password_hash.as_deref().unwrap_or_default()))
}

/// On a password-protected app, a visitor nobody granted a role gets in with the password cookie (as the app's lowest
/// role when signed in, and anonymously otherwise). Returns whether the visitor must still give the password.
fn admit(cfg: &Config, req: &Req, v: &mut Visit) -> bool {
    let d = &mut v.decision;
    if d.allowed || v.app.access != "password" || v.app.password_hash.is_none() {
        return false;
    }
    d.sign_in_needed = false;
    if safe_equal(&cookie(req.header("cookie"), &v.origin, PASS_COOKIE), &pass_token(cfg, &v.app)) {
        d.allowed = true;
        d.role = v.visitor.as_ref().map(|_| v.app.role_list().last().cloned().unwrap_or_default());
        return false;
    }
    true
}

/// The page a password-protected app shows until its password is given.
fn password_page(app: &AppRow, ret: &str, error: &str, status: u16) -> Response {
    let name = esc(app.display_name());
    let error = if error.is_empty() { String::new() } else { format!("<p role=\"alert\">{}</p>", esc(error)) };
    page(
        status,
        &format!("{}: password", app.display_name()),
        &format!(
            "<div class=\"icon\" aria-hidden=\"true\">🔒</div><h1>{name} needs a password</h1>
<p>Whoever shared this app with you has the password. Enter it to open the app.</p>{error}
<form method=\"post\" action=\"/_brod/password\"><input type=\"hidden\" name=\"return\" value=\"{}\">
<input name=\"password\" type=\"password\" required autofocus autocomplete=\"current-password\" placeholder=\"Password\" aria-label=\"Password\"><button class=\"block\">Open {name}</button></form>
<p><small>Have a Brod account with access? <a href=\"/_brod/signin?return={}\">Sign in instead</a></small></p>",
            esc(ret),
            encode_uri_component(ret)
        ),
        None,
        &[],
    )
}

/// Which app a request is for: by `<app>`.`<workspace>` (or its staging address, `<app>`--staging.`<workspace>`), or by id for a
/// custom domain.
pub enum Where {
    Slug { workspace: String, slug: String, staging: bool },
    Id(String),
}

/// Who may open an app's staging address: the people who can change the app (its owner, workspace admins and builders)
/// and anyone granted its top role. Nobody gets in anonymously or with the app's password, whatever its access mode.
fn admit_staging(app: &AppRow, d: &mut Decision, visitor: Option<&SessionUser>) {
    let Some(v) = visitor else {
        *d = Decision { allowed: false, sign_in_needed: true, role: None, groups: vec![], member: None };
        return;
    };
    let top = app.role_list().into_iter().next();
    d.sign_in_needed = false;
    if app.owner_id == v.user.id || matches!(d.member.as_deref(), Some("admin" | "builder")) {
        // The people who can change the app try it as its owner would.
        d.allowed = true;
        d.role = top;
    } else {
        d.allowed = d.allowed && d.role.is_some() && d.role == top;
    }
}

/// Serve an app. `domain` is the custom domain (host and port, as the request named it) it was opened at, if any.
/// Every request that reaches an app is counted for its analytics, with its status, size and server time.
pub async fn serve_app(st: &State, req: Req, at: Where, domain: Option<String>) -> Result<Response> {
    let mut hit = crate::analytics::Hit::new(&req);
    let res = serve(st, req, at, domain, &mut hit).await;
    let (status, bytes) = match &res {
        Ok(r) => {
            (r.status().as_u16(), r.headers().get("content-length").and_then(|v| v.to_str().ok()).and_then(|v| v.parse().ok()).unwrap_or(0))
        }
        Err(e) => (e.status, 0),
    };
    st.analytics.finish(hit, status, bytes);
    res
}

async fn serve(st: &State, mut req: Req, at: Where, domain: Option<String>, hit: &mut crate::analytics::Hit) -> Result<Response> {
    let origin = match (&domain, &at) {
        (Some(d), _) => host_origin(&st.cfg, d),
        (None, Where::Slug { workspace, slug, staging: true }) => staging_url(&st.cfg, workspace, slug),
        (None, Where::Slug { workspace, slug, .. }) => app_url(&st.cfg, workspace, slug),
        (None, Where::Id(_)) => return Err(crate::problem::Problem::internal("an app by id needs its domain")),
    };
    let token = cookie(req.header("cookie"), &origin, APP_COOKIE);
    let staging = matches!(at, Where::Slug { staging: true, .. });
    let visit = st
        .db
        .call(move |c| {
            let version = if staging { "staging_version" } else { "live_version" };
            let sql = format!(
                "SELECT a.*, v.server, v.network, w.slug AS wslug FROM apps a JOIN workspaces w ON w.id = a.workspace_id
                 LEFT JOIN versions v ON v.app_id = a.id AND v.n = a.{version} WHERE "
            );
            let map = |r: &crate::db::Row| {
                Ok((
                    AppRow::from_row(r)?,
                    r.get::<_, Option<String>>("server")?,
                    r.get::<_, String>("wslug")?,
                    crate::network::parse(r.get::<_, Option<String>>("network")?),
                ))
            };
            let row = match &at {
                Where::Slug { workspace, slug, .. } => c.first(&format!("{sql}w.slug = ? AND a.slug = ?"), [workspace, slug], map)?,
                Where::Id(id) => c.first(&format!("{sql}a.id = ?"), [id], map)?,
            };
            let Some((mut app, server, workspace_slug, network)) = row else { return Ok(None) };
            // Taken down by the Brod team, or in a suspended workspace: nothing of the app is served, its /_brod/ pages included.
            if crate::abuse::hold_of(c, &app)?.is_some() {
                return Ok(Some(None));
            }
            if staging {
                // From here on the staging version is the one served, and staging is never public or shared by password.
                app.live_version = app.staging_version;
                if app.access == "public" || app.access == "password" || app.access == "signed_in" {
                    app.access = "people".into();
                }
            }
            let visitor = people::session_user(c, &token, Some(&app.id))?;
            let mut decision = people::decide(c, &app, visitor.as_ref().map(|v| &v.user))?;
            if staging {
                admit_staging(&app, &mut decision, visitor.as_ref());
            }
            Ok(Some(Some(Visit { app, server, network, visitor, decision, workspace_slug, origin, domain, staging })))
        })
        .await?;
    let Some(v) = visit else {
        return Ok(not_found(&st.cfg.api_origin));
    };
    let Some(mut v) = v else { return Ok(crate::abuse::taken_down_page()) };
    let password_needed = admit(&st.cfg, &req, &mut v);
    if req.path.starts_with("/_brod/") {
        return special(st, &mut req, v).await;
    }
    let Visit { app, server, network, visitor, decision, workspace_slug, origin, domain, staging } = v;
    // Requests to the staging address stay out of the app's analytics.
    if !staging {
        hit.app = Some((app.workspace_id.clone(), app.id.clone()));
    }
    let server: Option<ServerInfo> = match server {
        Some(s) => Some(serde_json::from_str(&s)?),
        None => None,
    };
    let is_get = req.method == Method::GET || req.method == Method::HEAD;
    if server.is_none() && !is_get {
        return Ok(notice(405, "Not supported", "This app is a static site and only answers page requests.", ""));
    }
    if app.live_version.is_none() && !staging {
        return Ok(not_found(&st.cfg.api_origin));
    }
    if !decision.allowed {
        let ret = if req.query.is_empty() { req.path.clone() } else { format!("{}?{}", req.path, req.query) };
        if password_needed {
            return Ok(password_page(&app, &ret, "", 401));
        }
        if decision.sign_in_needed {
            return Ok(redirect(&sign_in_url(&st.cfg, &app, &workspace_slug, domain.as_deref(), staging, &ret), &[]));
        }
        // Someone signed in whom the app was not shared with sees what an empty address shows, so nothing leaks about it.
        let email = visitor.as_ref().map(|v| v.user.email.clone()).unwrap_or_default();
        let (ws, app_id, detail) = (app.workspace_id.clone(), app.id.clone(), format!("{email} opened {}", req.path));
        st.db.call(move |c| event(c, &ws, &email, Some(&app_id), "refused", &detail)).await?;
        return Ok(not_found(&st.cfg.api_origin));
    }
    if app.status == "paused" {
        return Ok(notice(503, "Paused", "The owner has paused this app.", ""));
    }
    let Some(version) = app.live_version else {
        // Only reached on a staging address, by someone allowed to see it.
        return Ok(notice(
            404,
            "Nothing on staging",
            "Nothing is waiting on staging for this app: it was published or discarded. Deploy a new version to staging to try it here.",
            "",
        ));
    };

    // Trying a version on staging is not a visit.
    if !staging && crate::usage::is_page_view(&req) && !hit.bot {
        let who = crate::usage::visitor_hash(&st.cfg, &req, &app.id, visitor.as_ref().map(|v| v.user.id.as_str()));
        st.visits.record(&app.id, who.clone());
        let path = decode_uri_component(&req.path).unwrap_or_else(|| req.path.clone());
        hit.view = Some(crate::analytics::page_view(&st.cfg, &req, &app.workspace_id, &app.id, who, visitor.is_some(), &path));
    }

    let identity = match &server {
        Some(_) => visitor.as_ref().map(|v| identity_for(&st.cfg, &app, &workspace_slug, &v.user, &decision)),
        None => None,
    };
    let mut res = serve_version(st, req, &app, version, server, &origin, identity).await?;
    // The page may only reach its own address and the hosts its version declares (network.rs).
    crate::network::protect(&st.cfg, &mut res, &network);
    Ok(res)
}

/// Serve one version of an app's files, or hand the request to its server code, once access has been decided.
/// The marketplace's preview sandbox (preview.rs) serves a release through here too.
pub async fn serve_version(
    st: &State,
    req: Req,
    app: &AppRow,
    version: i64,
    server: Option<ServerInfo>,
    origin: &str,
    identity: Option<(Value, String)>,
) -> Result<Response> {
    let is_get = req.method == Method::GET || req.method == Method::HEAD;
    let Some(path) = decode_uri_component(&req.path) else {
        return Ok(notice(400, "Bad address", "That address is not valid.", ""));
    };
    let path = path.trim_start_matches('/').to_string();
    if path.split('/').any(|p| p == "..") {
        return Ok(notice(400, "Bad address", "That address is not valid.", ""));
    }
    let base = format!("{}/{version}/", app.id);

    if let Some(server) = server {
        // A file that exists in the bundle is served as is, a folder by its index.html; every other request goes to the server code.
        let file = if path.is_empty() || path.ends_with('/') { format!("{path}index.html") } else { path.clone() };
        if is_get
            && !runtime::is_server_path(&file)
            && let Some(obj) = st.store.get(&format!("{base}{file}")).await?
        {
            return file_response(st, &req, app, obj, &file).await;
        }
        return runtime::dispatch(st, req, app, origin, version, &server, identity).await;
    }

    let has_ext = path.rsplit_once('.').is_some_and(|(_, ext)| !ext.is_empty() && ext.bytes().all(|b| b.is_ascii_alphanumeric()));
    // Exact file, then folder index, then the single-page-app fallback to the root index.html.
    let candidates: Vec<String> = if path.is_empty() || path.ends_with('/') {
        vec![format!("{path}index.html")]
    } else if has_ext {
        vec![path.clone()]
    } else {
        vec![path.clone(), format!("{path}/index.html"), format!("{path}.html"), "index.html".into()]
    };
    for c in candidates {
        if let Some(obj) = st.store.get(&format!("{base}{c}")).await? {
            return file_response(st, &req, app, obj, &c).await;
        }
    }
    match st.store.get(&format!("{base}404.html")).await? {
        Some(custom) => Ok(response(404, custom.body, &[("content-type", "text/html; charset=utf-8".into())])),
        None => Ok(notice(404, "Not found", "This app has no page at that address.", "")),
    }
}

async fn file_response(st: &State, req: &Req, app: &AppRow, obj: Object, hit: &str) -> Result<Response> {
    let html = hit.ends_with(".html");
    let is_public = app.access == "public";
    let etag = obj.meta.http_etag();
    let mut headers: Vec<(&str, String)> = vec![
        ("content-type", obj.meta.content_type.clone().unwrap_or_else(|| "application/octet-stream".into())),
        ("etag", etag.clone()),
        // Always revalidate, so a rollback, a new version or an access change shows on the next request.
        ("cache-control", if is_public { "public, no-cache" } else { "private, no-cache" }.into()),
        ("x-content-type-options", "nosniff".into()),
        ("x-brod-app", app.slug.clone()),
        ("x-brod-version", app.live_version.map(|v| v.to_string()).unwrap_or_default()),
    ];
    if !is_public {
        headers.push(("vary", "cookie".into()));
    }
    if html && !is_public {
        headers.push(("x-robots-tag", "noindex".into()));
    }
    if req.header("if-none-match") == Some(etag.as_str()) {
        return Ok(response(304, Body::empty(), &headers));
    }
    if req.method == Method::HEAD {
        // A page grows by the insights script (and a public one by its report link), so its stored size is not the
        // length GET sends.
        if !html {
            headers.push(("content-length", obj.meta.size.to_string()));
        }
        return Ok(response(200, Body::empty(), &headers));
    }
    if html {
        let page = read_capped(obj.body, crate::tar::FILE_BYTES + 1024 * 1024, "The page").await?;
        let page = with_insights(page);
        let page = if is_public && st.cfg.abuse_checks { append_to_body(&page, REPORT_LINK) } else { page };
        return Ok(response(200, bytes_body(page), &headers));
    }
    headers.push(("content-length", obj.meta.size.to_string()));
    Ok(response(200, obj.body, &headers))
}

/// Add the insights script to a page, unless the page already loads it or opts out with
/// `<meta name="brod-insights" content="off">`. A page with no `<body>` gets it at the end.
pub fn with_insights(page: Vec<u8>) -> Vec<u8> {
    let has = |needle: &[u8]| page.windows(needle.len()).any(|w| w.eq_ignore_ascii_case(needle));
    if has(b"/_brod/insights.js") || has(b"name=\"brod-insights\" content=\"off\"") {
        return page;
    }
    if last_index_of(&page, b"<body").is_some() {
        return append_to_body(&page, crate::analytics::INSIGHTS_TAG);
    }
    let mut out = page;
    out.extend_from_slice(crate::analytics::INSIGHTS_TAG.as_bytes());
    out
}

/// Put a snippet at the end of `<body>`: before the last `</body`, whatever its case, or at the end of a document
/// whose `<body>` is never closed. A page without a `<body>` tag is left alone, as HTMLRewriter's body selector does.
pub fn append_to_body(page: &[u8], snippet: &str) -> Vec<u8> {
    let at = match last_index_of(page, b"</body") {
        Some(i) => i,
        None if last_index_of(page, b"<body").is_some() => page.len(),
        None => return page.to_vec(),
    };
    let mut out = Vec::with_capacity(page.len() + snippet.len());
    out.extend_from_slice(&page[..at]);
    out.extend_from_slice(snippet.as_bytes());
    out.extend_from_slice(&page[at..]);
    out
}

fn last_index_of(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if hay.len() < needle.len() {
        return None;
    }
    (0..=hay.len() - needle.len()).rev().find(|&i| hay[i..i + needle.len()].iter().zip(needle).all(|(a, b)| a.to_ascii_lowercase() == *b))
}

async fn special(st: &State, req: &mut Req, v: Visit) -> Result<Response> {
    let report_link = if st.cfg.abuse_checks { "<p><small><a href=\"/_brod/report\">Report this app</a></small></p>" } else { "" };
    let Visit { app, visitor, decision, workspace_slug, origin, domain, staging, .. } = v;
    // What the browser stopped, or would have stopped, under the app's Content-Security-Policy (network.rs). Browsers
    // may send these without the visitor's cookies, so they are taken from anyone: they are only ever shown to the app's
    // own builders, and an app keeps a bounded number of hosts on record.
    if req.path == "/_brod/csp" {
        if req.method != Method::POST || st.cfg.network == crate::config::NetworkPolicy::Off {
            return Ok(crate::http::empty(204));
        }
        let Ok(body) = req.bytes(64 * 1024, "The report").await else { return Ok(crate::http::empty(204)) };
        let hosts = crate::network::hosts_from_report(&body);
        if !hosts.is_empty() {
            let (app_id, version) = (app.id.clone(), app.live_version);
            st.db
                .call(move |c| {
                    for (host, blocked) in &hosts {
                        crate::network::record(c, &app_id, version, host, "browser", 1, *blocked)?;
                    }
                    Ok(())
                })
                .await?;
        }
        return Ok(crate::http::empty(204));
    }
    // The app's settings (settings.rs), for whoever may open the app: { key: value }, and uploaded images by key.
    if req.path == "/_brod/settings" || req.path.starts_with("/_brod/settings/") {
        let nothing = || notice(404, "Not found", "There is nothing at this address.", "");
        let (Some(version), true) = (app.live_version, decision.allowed && app.status != "paused") else { return Ok(nothing()) };
        let public = app.access == "public";
        if let Some(key) = req.path.strip_prefix("/_brod/settings/") {
            return Ok(match crate::settings::image(st, &app.id, &decode_uri_component(key).unwrap_or_default()).await? {
                Some((obj, ct)) => crate::settings::image_response(obj, ct, public),
                None => nothing(),
            });
        }
        let app_id = app.id.clone();
        let values = st.db.call(move |c| crate::settings::values(c, &app_id, version)).await?;
        let cc = if public { "public, max-age=60" } else { "private, no-cache" };
        return Ok(json_response(&Value::Object(values), 200, &[("cache-control", cc.into())]));
    }
    match req.path.as_str() {
        "/_brod/client.js" => Ok(response(
            200,
            CLIENT_JS,
            &[("content-type", "text/javascript; charset=utf-8".into()), ("cache-control", "public, max-age=300".into())],
        )),
        "/_brod/insights.js" => Ok(response(
            200,
            crate::analytics::INSIGHTS_JS,
            &[("content-type", "text/javascript; charset=utf-8".into()), ("cache-control", "public, max-age=3600".into())],
        )),
        "/_brod/insights" => {
            // Only from people who may open the app, and never from crawlers; either way the browser hears nothing back.
            if req.method != Method::POST || !decision.allowed || crate::analytics::is_bot(req.header("user-agent").unwrap_or("")) {
                return Ok(crate::http::empty(204));
            }
            let Ok(body) = req.bytes(16 * 1024, "The insights").await else { return Ok(crate::http::empty(204)) };
            let who = crate::usage::visitor_hash(&st.cfg, req, &app.id, visitor.as_ref().map(|v| v.user.id.as_str()));
            let (views, events) = crate::analytics::ingest(&st.cfg, req, &body, &app.workspace_id, &app.id, &who, visitor.is_some());
            for v in views {
                st.visits.record(&app.id, who.clone());
                st.analytics.view(v);
            }
            st.analytics.events(events);
            Ok(crate::http::empty(204))
        }
        "/_brod/signin" => {
            Ok(redirect(&sign_in_url(&st.cfg, &app, &workspace_slug, domain.as_deref(), staging, &app_return(req.param("return"))), &[]))
        }
        "/_brod/callback" => {
            let hash = sha256_hex(&req.param("code").unwrap_or_default());
            let app_id = app.id.clone();
            let token = st
                .db
                .call(move |c| {
                    let code = c.first(
                        "UPDATE app_codes SET used_at = ? WHERE hash = ? AND app_id = ? AND used_at IS NULL AND expires_at > ? RETURNING user_id, parent",
                        params![now(), hash, app_id, now()],
                        |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)),
                    )?;
                    match code {
                        Some((user_id, parent)) => Ok(Some(people::create_session(c, &user_id, Some(&app_id), Some(&parent))?)),
                        None => Ok(None),
                    }
                })
                .await?;
            let Some(token) = token else {
                return Ok(notice(
                    400,
                    "Sign-in expired",
                    "That sign-in link has expired. Try again.",
                    "<p><a class=\"btn\" href=\"/_brod/signin\">Sign in</a></p>",
                ));
            };
            let cookie = set_cookie(&origin, APP_COOKIE, &token, limits::SESSION_TTL_MS / 1000);
            Ok(redirect(&app_return(req.param("return")), &[("set-cookie", cookie)]))
        }
        "/_brod/signout" => {
            // One sign-in, so signing out of one app signs out of all of them.
            if let Some(parent) = visitor.and_then(|v| v.parent) {
                st.db.call(move |c| people::revoke_session(c, &parent)).await?;
            }
            Ok(page(
                200,
                "Signed out",
                "<h1>Signed out</h1><p>You are signed out of every Brod app.</p><p><a class=\"btn\" href=\"/_brod/signin\">Sign in again</a></p>",
                None,
                &[("set-cookie", set_cookie(&origin, APP_COOKIE, "", 0))],
            ))
        }
        "/_brod/password" => {
            let hash = match (app.access.as_str(), &app.password_hash) {
                ("password", Some(h)) => h.clone(),
                _ => return Ok(redirect(&app_return(req.param("return")), &[])),
            };
            if req.method != Method::POST {
                return Ok(password_page(&app, &app_return(req.param("return")), "", 401));
            }
            let form = if req.header("content-type").unwrap_or("").contains("application/x-www-form-urlencoded") {
                req.form().await.unwrap_or_default()
            } else {
                vec![]
            };
            let get = |k: &str| form.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone()).unwrap_or_default();
            let (ret, password) = (app_return(Some(get("return"))), get("password"));
            let app_id = app.id.clone();
            let tries = st
                .db
                .call(move |c| {
                    c.count(
                        "SELECT COUNT(*) AS n FROM events WHERE app_id = ? AND at > ? AND action = 'password_failed'",
                        params![app_id, now() - 15 * 60 * 1000],
                    )
                })
                .await?;
            if tries >= limits::PASSWORD_TRIES_PER_15_MIN {
                return Ok(password_page(&app, &ret, "Too many wrong passwords. Wait a few minutes and try again.", 429));
            }
            // PBKDF2 takes a while on purpose: keep it off the async workers.
            if !tokio::task::spawn_blocking(move || verify_password(&password, &hash)).await.unwrap_or(false) {
                let actor = visitor.map(|v| v.user.email).unwrap_or_else(|| "visitor".into());
                let (ws, app_id) = (app.workspace_id.clone(), app.id.clone());
                st.db.call(move |c| event(c, &ws, &actor, Some(&app_id), "password_failed", "a wrong password")).await?;
                return Ok(password_page(&app, &ret, "That password is not right. Check it and try again.", 401));
            }
            let cookie = set_cookie(&origin, PASS_COOKIE, &pass_token(&st.cfg, &app), limits::SESSION_TTL_MS / 1000);
            Ok(redirect(&ret, &[("set-cookie", cookie)]))
        }
        "/_brod/me" => {
            let Some(user) = visitor.filter(|_| decision.allowed) else {
                return Ok(json_response(
                    &json!({ "error": { "code": "signed_out", "message": "Nobody is signed in to this app.", "sign_in": "/_brod/signin" } }),
                    401,
                    &[("cache-control", "no-store".into())],
                ));
            };
            let (mut identity, token) = identity_for(&st.cfg, &app, &workspace_slug, &user.user, &decision);
            identity["token"] = json!(token);
            Ok(json_response(&identity, 200, &[("cache-control", "private, no-store".into())]))
        }
        "/_brod/report" if st.cfg.abuse_checks => {
            if req.method == Method::POST {
                let form = if req.header("content-type").unwrap_or("").contains("application/x-www-form-urlencoded") {
                    req.form().await.unwrap_or_default()
                } else {
                    vec![]
                };
                let get = |k: &str| form.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone()).unwrap_or_default();
                let reason = js_slice(js_trim(&get("reason")), 1000);
                if reason.is_empty() {
                    return Ok(notice(
                        400,
                        "Tell us what is wrong",
                        "Describe the problem in a sentence or two.",
                        "<p><a href=\"/_brod/report\">Back</a></p>",
                    ));
                }
                let ip = crate::abuse::client_ip(&st.cfg, req);
                let limited = match ip {
                    Some(ip) => {
                        st.db
                            .call(move |c| {
                                crate::abuse::rate_limit(
                                    c,
                                    "report_ip",
                                    &ip,
                                    crate::abuse::REPORTS_PER_IP_HOUR,
                                    crate::abuse::HOUR,
                                    "Too many reports were sent from your network in the last hour.",
                                )
                            })
                            .await
                    }
                    None => Ok(()),
                };
                if let Err(e) = limited {
                    if e.status == 429 {
                        return Ok(notice(429, "Too many reports", &e.message, ""));
                    }
                    return Err(e);
                }
                let reporter = match visitor {
                    Some(v) => v.user.email,
                    None => {
                        let e = js_slice(js_trim(&get("email")), 254);
                        if e.is_empty() { "anonymous".into() } else { e }
                    }
                };
                st.db
                    .call(move |c| {
                        tx(c, |x| {
                            x.run(
                                "INSERT INTO reports (id, app_id, reporter, reason, created_at) VALUES (?,?,?,?,?)",
                                params![random_id("rep_", 8), app.id, reporter, reason, now()],
                            )?;
                            event(x, &app.workspace_id, "visitor", Some(&app.id), "report", &js_slice(&reason, 120))
                        })
                    })
                    .await?;
                return Ok(notice(200, "Thank you", "Your report was sent to the Brod team for review.", ""));
            }
            Ok(page(
                200,
                "Report this app",
                "<h1>Report this app</h1><p>Tell the Brod team if this app is phishing, malware, spam, or otherwise abusive.</p>
<form method=\"post\"><input name=\"email\" type=\"email\" placeholder=\"Your email (optional)\" aria-label=\"Your email\"><input name=\"reason\" required maxlength=\"1000\" placeholder=\"What is wrong?\" aria-label=\"What is wrong\"><button class=\"block\">Send report</button></form>",
                None,
                &[],
            ))
        }
        _ => Ok(notice(404, "Not found", "There is nothing at this address.", report_link)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn add(html: &str) -> String {
        String::from_utf8(append_to_body(html.as_bytes(), "<a>Report</a>")).unwrap()
    }

    #[test]
    fn puts_the_report_link_before_the_last_body_close() {
        assert_eq!(add("<html><body><h1>x</h1></body></html>"), "<html><body><h1>x</h1><a>Report</a></body></html>");
        assert_eq!(add("<BODY>x</BODY >"), "<BODY>x<a>Report</a></BODY >");
        assert_eq!(add("<body><script>\"</body>\"</script>y</body>"), "<body><script>\"</body>\"</script>y<a>Report</a></body>");
        assert_eq!(add("<body>x"), "<body>x<a>Report</a>");
        assert_eq!(add("<h1>v1</h1>"), "<h1>v1</h1>");
        assert_eq!(add("<body>héllo ✓</body>"), "<body>héllo ✓<a>Report</a></body>");
    }

    #[test]
    fn identity_tokens_verify_with_the_per_app_key() {
        let cfg = Config::for_tests();
        let user = User { id: "usr_1".into(), email: "a@b.co".into(), name: "Ana".into(), email_verified_at: Some(1) };
        let app = AppRow {
            id: "app_1".into(),
            workspace_id: "ws".into(),
            owner_id: "usr_1".into(),
            slug: "notes".into(),
            name: "Notes".into(),
            title: String::new(),
            welcome: String::new(),
            status: "live".into(),
            access: "private".into(),
            roles: "[\"owner\"]".into(),
            live_version: Some(1),
            created_at: 0,
            secrets_rev: 0,
            space_id: None,
            file_bytes: 0,
            data_bytes: 0,
            password_hash: None,
            taken_down_at: None,
            takedown_reason: String::new(),
            staging_version: None,
        };
        let d = Decision { allowed: true, sign_in_needed: false, role: Some("owner".into()), groups: vec!["finance".into()], member: None };
        let (identity, token) = identity_for(&cfg, &app, "acme", &user, &d);
        assert_eq!(identity["role"], "owner");
        let (body, sig) = token.split_once('.').unwrap();
        assert_eq!(sig, hmac_b64url(&app_identity_key(&cfg, "app_1"), body));
        use base64::Engine;
        let payload: Value = serde_json::from_slice(&base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(body).unwrap()).unwrap();
        let keys: Vec<&String> = payload.as_object().unwrap().keys().collect();
        assert_eq!(keys, ["user", "role", "groups", "app", "workspace", "iat", "exp"]);
        assert_eq!(payload["exp"].as_i64().unwrap() - payload["iat"].as_i64().unwrap(), 300);
    }
}
