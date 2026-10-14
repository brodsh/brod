// Connecting an agent: the connections page, and sign-in for MCP clients with OAuth instead of a pasted token.
//
// The OAuth side is what MCP clients expect (OAuth 2.1 with PKCE): /mcp answers 401 with a pointer to the resource
// metadata (RFC 9728), which names this server's metadata (RFC 8414); the client registers itself (RFC 7591), sends
// the person to /oauth/authorize, and swaps the code at /oauth/token. The person picks a workspace on the consent page,
// and the access token is an ordinary connection token: it shows on the connections page and is revoked the same way.
// The access token lives an hour; the client renews it with a refresh token, which rotates on every use (OAuth 2.1).
// Scope "brod:read" makes a read-only connection; "brod" (or none) one that can deploy and manage.
use std::collections::HashMap;

use crate::db::{Connection, params};
use axum::http::Method;
use axum::response::Response;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::config::Config;
use crate::control;
use crate::db::Sql;
use crate::http::{Req, empty, header_pairs, json_response, notice, page, redirect};
use crate::model::{Caller, User, Workspace, js_string, limits};
use crate::people;
use crate::problem::{Problem, Result};
use crate::state::State;
use crate::util::{b64url, encode_uri_component, esc, iso, now, random_id, sha256_hex};

fn cors(mut r: Response) -> Response {
    header_pairs(
        &mut r,
        &[
            ("access-control-allow-origin", "*".into()),
            ("access-control-allow-methods", "GET, POST, OPTIONS".into()),
            ("access-control-allow-headers", "authorization, content-type, mcp-protocol-version".into()),
        ],
    );
    r
}
fn oauth_error(error: &str, description: &str, status: u16) -> Response {
    cors(json_response(&json!({ "error": error, "error_description": description }), status, &[]))
}
fn builds(role: &str) -> bool {
    role == "admin" || role == "builder"
}
fn same_origin(cfg: &Config, req: &Req) -> Result<()> {
    if req.header("origin") != Some(cfg.api_origin.as_str()) {
        return Err(Problem::new(403, "bad_origin", "This form must be sent from Brod itself."));
    }
    Ok(())
}

/// Where /mcp's 401 points a client to learn how to sign in.
pub fn resource_metadata_url(cfg: &Config) -> String {
    format!("{}/.well-known/oauth-protected-resource/mcp", cfg.api_origin)
}

// ---------- redirect addresses ----------

const BLOCKED_SCHEMES: [&str; 9] = ["javascript", "data", "file", "vbscript", "blob", "about", "ftp", "ws", "wss"];
const LOOPBACK: [&str; 3] = ["localhost", "127.0.0.1", "[::1]"];

struct Parts<'a> {
    scheme: &'a str,
    authority: Option<&'a str>,
    rest: &'a str,
}

/// Split an absolute URL into scheme, authority (for scheme://) and the rest, without a URL parser, the same way as connect.ts.
fn parts(uri: &str) -> Option<Parts<'_>> {
    let (scheme, after) = uri.split_once(':')?;
    let valid = scheme.bytes().next().is_some_and(|c| c.is_ascii_lowercase())
        && scheme.bytes().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, b'+' | b'.' | b'-'));
    if !valid {
        return None;
    }
    Some(match after.strip_prefix("//") {
        None => Parts { scheme, authority: None, rest: after },
        Some(a) => {
            let end = a.find(['/', '?']).unwrap_or(a.len());
            Parts { scheme, authority: Some(&a[..end]), rest: &a[end..] }
        }
    })
}
fn host_of(authority: &str) -> &str {
    if authority.starts_with('[') {
        authority.find(']').map(|i| &authority[..=i]).unwrap_or("")
    } else {
        authority.split(':').next().unwrap_or("")
    }
}

/// A redirect address a client may register: https, http on this machine only (a desktop client's local listener,
/// RFC 8252), or an app's own scheme. Never one that runs code or reads files.
pub fn redirect_allowed(uri: &str) -> bool {
    if uri.is_empty() || uri.encode_utf16().count() > 500 || uri.chars().any(|c| c.is_whitespace() || c == '#' || c.is_control()) {
        return false;
    }
    let Some(p) = parts(uri) else { return false };
    if p.scheme == "https" || p.scheme == "http" {
        let Some(a) = p.authority.filter(|a| !a.is_empty() && !a.contains('@')) else { return false };
        return p.scheme == "https" || LOOPBACK.contains(&host_of(a));
    }
    !BLOCKED_SCHEMES.contains(&p.scheme)
}

/// The registered address matches exactly, or both are on this machine and differ only by port (RFC 8252 7.3).
fn redirect_matches(registered: &[String], uri: &str) -> bool {
    if registered.iter().any(|r| r == uri) {
        return true;
    }
    let loose = |u: &str| -> Option<String> {
        let p = parts(u)?;
        let a = p.authority?;
        (p.scheme == "http" && LOOPBACK.contains(&host_of(a))).then(|| format!("http://{}{}", host_of(a), p.rest))
    };
    match loose(uri) {
        Some(l) => registered.iter().any(|r| loose(r).as_deref() == Some(l.as_str())),
        None => false,
    }
}

// ---------- clients and codes ----------

struct Client {
    id: String,
    name: String,
    redirect_uris: Vec<String>,
}

fn client(conn: &Connection, id: Option<&str>) -> Result<Option<Client>> {
    let Some(id) =
        id.filter(|i| i.len() == 20 && i.starts_with("cli_") && i[4..].bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)))
    else {
        return Ok(None);
    };
    conn.first("SELECT id, name, redirect_uris FROM oauth_clients WHERE id = ?", [id], |r| {
        let uris: String = r.get(2)?;
        Ok(Client { id: r.get(0)?, name: r.get(1)?, redirect_uris: serde_json::from_str(&uris).unwrap_or_default() })
    })
}

async fn register(st: &State, req: &mut Req) -> Result<Response> {
    let raw = req.bytes(64 * 1024, "The request body").await?;
    let Ok(b) = serde_json::from_slice::<Value>(&raw) else {
        return Ok(oauth_error("invalid_client_metadata", "The request body must be JSON.", 400));
    };
    let uris: Vec<Value> = b["redirect_uris"].as_array().cloned().unwrap_or_default();
    if uris.is_empty() || uris.len() > 10 || !uris.iter().all(|u| u.as_str().is_some_and(redirect_allowed)) {
        return Ok(oauth_error("invalid_redirect_uri", "Give 1 to 10 redirect_uris: https, http on localhost, or an app scheme.", 400));
    }
    let name = match &b["client_name"] {
        Value::Null => String::new(),
        v => crate::util::js_slice(crate::util::js_trim(&js_string(v)), 60),
    };
    let name = if name.is_empty() { "MCP client".to_string() } else { name };
    let (id, at) = (random_id("cli_", 8), now());
    let (id2, name2, list) = (id.clone(), name.clone(), Value::Array(uris.clone()).to_string());
    if let Some(ip) = crate::abuse::client_ip(&st.cfg, req) {
        let limited = st
            .db
            .call(move |c| {
                crate::abuse::rate_limit(
                    c,
                    "oauth_ip",
                    &ip,
                    crate::abuse::OAUTH_CLIENTS_PER_IP_HOUR,
                    crate::abuse::HOUR,
                    "Too many clients registered from this address in the last hour.",
                )
            })
            .await;
        match limited {
            Err(e) if e.status == 429 => return Ok(oauth_error("temporarily_unavailable", &e.message, 429)),
            other => other?,
        }
    }
    let made = st
        .db
        .call(move |c| {
            if c.count("SELECT COUNT(*) AS n FROM oauth_clients WHERE created_at > ?", [at - 3_600_000])? >= limits::OAUTH_CLIENTS_PER_HOUR
            {
                return Ok(false);
            }
            c.run("INSERT INTO oauth_clients (id, name, redirect_uris, created_at) VALUES (?,?,?,?)", params![id2, name2, list, at])?;
            Ok(true)
        })
        .await?;
    if !made {
        return Ok(oauth_error("temporarily_unavailable", "Too many clients registered in the last hour. Try again later.", 429));
    }
    Ok(cors(json_response(
        &json!({
            "client_id": id, "client_id_issued_at": at / 1000, "client_name": name, "redirect_uris": uris,
            "grant_types": ["authorization_code", "refresh_token"], "response_types": ["code"], "token_endpoint_auth_method": "none",
        }),
        201,
        &[],
    )))
}

/// The parameters of an authorization request, checked.
struct Authz {
    client_id: String,
    client_name: String,
    redirect_uri: String,
    state: String,
    challenge: String,
    /// "manage" or "read".
    scope: &'static str,
}

/// A bad client or redirect address gets a page; anything else goes back to the client.
fn authorize_request(conn: &Connection, q: &HashMap<String, String>) -> Result<std::result::Result<Authz, Response>> {
    let get = |k: &str| q.get(k).cloned().unwrap_or_default();
    let Some(c) = client(conn, q.get("client_id").map(String::as_str))? else {
        return Ok(Err(notice(
            400,
            "Unknown app",
            "This sign-in request comes from an app Brod does not know. Start again from your agent.",
            "",
        )));
    };
    let redirect_uri = get("redirect_uri");
    if !redirect_matches(&c.redirect_uris, &redirect_uri) {
        return Ok(Err(notice(
            400,
            "Wrong return address",
            "This sign-in request asks to return somewhere the app did not register. Start again from your agent.",
            "",
        )));
    }
    let state = get("state");
    if get("response_type") != "code" {
        return Ok(Err(back(&redirect_uri, &[("error", "unsupported_response_type"), ("state", &state)])));
    }
    let challenge = get("code_challenge");
    let challenge_ok =
        (43..=128).contains(&challenge.len()) && challenge.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-');
    if !challenge_ok || get("code_challenge_method") != "S256" {
        return Ok(Err(back(
            &redirect_uri,
            &[("error", "invalid_request"), ("error_description", "PKCE with S256 is required."), ("state", &state)],
        )));
    }
    let scope = control::oauth_scope(&get("scope"));
    Ok(Ok(Authz { client_id: c.id, client_name: c.name, redirect_uri, state, challenge, scope }))
}

fn back(redirect_uri: &str, params: &[(&str, &str)]) -> Response {
    let mut q = form_urlencoded::Serializer::new(String::new());
    for (k, v) in params.iter().filter(|(_, v)| !v.is_empty()) {
        q.append_pair(k, v);
    }
    let sep = if redirect_uri.contains('?') { '&' } else { '?' };
    redirect(&format!("{redirect_uri}{sep}{}", q.finish()), &[])
}

fn consent_page(a: &Authz, email: &str, workspaces: &[Value]) -> Response {
    let target = parts(&a.redirect_uri);
    let where_to = match &target {
        Some(Parts { authority: Some(au), .. }) => host_of(au).to_string(),
        Some(p) => format!("{}:", p.scheme),
        None => String::new(),
    };
    let hidden: String = [
        ("client_id", a.client_id.as_str()),
        ("redirect_uri", &a.redirect_uri),
        ("state", &a.state),
        ("code_challenge", &a.challenge),
        ("code_challenge_method", "S256"),
        ("response_type", "code"),
        ("scope", if a.scope == "read" { "brod:read" } else { "brod" }),
    ]
    .iter()
    .map(|(k, v)| format!("<input type=\"hidden\" name=\"{k}\" value=\"{}\">", esc(v)))
    .collect();
    let s = |w: &Value, k: &str| w[k].as_str().unwrap_or("").to_string();
    let pick = if workspaces.len() == 1 {
        format!(
            "<p>Workspace: <b>{}</b></p><input type=\"hidden\" name=\"workspace\" value=\"{}\">",
            esc(&s(&workspaces[0], "name")),
            esc(&s(&workspaces[0], "slug"))
        )
    } else {
        let options: String =
            workspaces.iter().map(|w| format!("<option value=\"{}\">{}</option>", esc(&s(w, "slug")), esc(&s(w, "name")))).collect();
        format!("<p><label>Workspace<br><select name=\"workspace\" aria-label=\"Workspace\">{options}</select></label></p>")
    };
    let name = esc(&a.client_name);
    page(
        200,
        "Connect an agent",
        &format!(
            "<h1>Connect {name}</h1>
<p><b>{name}</b> wants to act as you (<b>{}</b>) in Brod: {}, in the workspace you pick.</p>
<form method=\"post\" action=\"/oauth/authorize\">{hidden}{pick}
<p class=\"muted\">You will be sent back to {}. You can disconnect it any time from the workspace's connections page.</p>
<div class=\"actions\"><button name=\"decision\" value=\"allow\">Allow</button><button name=\"decision\" value=\"deny\" class=\"secondary\">Cancel</button></div></form>",
            esc(email),
            if a.scope == "read" {
                "see your apps, their status and their logs, but change nothing"
            } else {
                "deploy and manage apps, and invite people"
            },
            esc(&where_to)
        ),
        None,
        &[],
    )
}

async fn authorize(st: &State, req: &mut Req) -> Result<Response> {
    let post = req.method == Method::POST;
    let cfg = st.cfg.clone();
    if post {
        same_origin(&cfg, req)?;
    }
    let q: HashMap<String, String> = if post {
        req.form().await?.into_iter().collect()
    } else {
        form_urlencoded::parse(req.query.as_bytes()).map(|(k, v)| (k.into_owned(), v.into_owned())).collect()
    };
    let here = if req.query.is_empty() { req.path.clone() } else { format!("{}?{}", req.path, req.query) };
    let cookie = req.header("cookie").map(String::from);
    enum Out {
        Done(Response),
        SignIn,
        Consent(Authz, String, Vec<Value>),
        Code(Authz, String),
    }
    let out = st
        .db
        .call(move |c| {
            let a = match authorize_request(c, &q)? {
                Ok(a) => a,
                Err(r) => return Ok(Out::Done(r)),
            };
            let Some((user, _)) = control::person(c, &cfg, cookie.as_deref())? else { return Ok(Out::SignIn) };
            let workspaces: Vec<Value> =
                people::my_workspaces(c, &cfg, &user)?.into_iter().filter(|w| builds(w["role"].as_str().unwrap_or(""))).collect();
            if !post {
                if workspaces.is_empty() {
                    return Ok(Out::Done(notice(
                        403,
                        "No workspace to connect",
                        "An agent works in a workspace where you are a builder or admin. Create a workspace, or ask an admin to make you a builder.",
                        "<p><a class=\"btn\" href=\"/new\">Create a workspace</a></p>",
                    )));
                }
                return Ok(Out::Consent(a, user.email, workspaces));
            }
            if q.get("decision").map(String::as_str) != Some("allow") {
                return Ok(Out::Done(back(&a.redirect_uri, &[("error", "access_denied"), ("state", &a.state)])));
            }
            let ws = q.get("workspace").cloned().unwrap_or_default();
            let mem = people::membership(c, &user, Some(&ws))?;
            let Some((w, _)) = mem.filter(|(_, role)| builds(role)) else {
                return Ok(Out::Done(notice(
                    403,
                    "Not allowed",
                    "You can connect an agent only to a workspace where you are a builder or admin.",
                    "",
                )));
            };
            let code = random_id("", 24);
            c.run(
                "INSERT INTO oauth_codes (hash, client_id, user_id, workspace_id, redirect_uri, challenge, expires_at, scope) VALUES (?,?,?,?,?,?,?,?)",
                params![sha256_hex(&code), a.client_id, user.id, w.id, a.redirect_uri, a.challenge, now() + limits::OAUTH_CODE_TTL_MS, a.scope],
            )?;
            Ok(Out::Code(a, code))
        })
        .await?;
    Ok(match out {
        Out::Done(r) => r,
        Out::SignIn => redirect(&format!("/auth/signin?return={}", encode_uri_component(&here)), &[]),
        Out::Consent(a, email, workspaces) => consent_page(&a, &email, &workspaces),
        Out::Code(a, code) => back(&a.redirect_uri, &[("code", &code), ("state", &a.state), ("iss", &st.cfg.api_origin)]),
    })
}

async fn token(st: &State, req: &mut Req) -> Result<Response> {
    let b: HashMap<String, String> = if req.is_json() {
        match serde_json::from_slice::<Value>(&req.bytes(64 * 1024, "The request body").await?) {
            Ok(Value::Object(m)) => m.into_iter().map(|(k, v)| (k, js_string(&v))).collect(),
            _ => return Ok(oauth_error("invalid_request", "Send the parameters as a form.", 400)),
        }
    } else {
        req.form().await?.into_iter().collect()
    };
    let get = |k: &str| b.get(k).cloned().unwrap_or_default();
    let issued = |t: Value| cors(json_response(&t, 200, &[("cache-control", "no-store".into())]));
    if get("grant_type") == "refresh_token" {
        let (client_id, refresh, scope) = (get("client_id"), get("refresh_token"), b.get("scope").cloned());
        let out = st.db.call(move |c| control::refresh_oauth_token(c, &client_id, &refresh, scope.as_deref())).await?;
        return Ok(match out {
            Ok(t) => issued(t),
            Err(why) => oauth_error("invalid_grant", &why, 400),
        });
    }
    if get("grant_type") != "authorization_code" {
        return Ok(oauth_error("unsupported_grant_type", "Use authorization_code, or refresh_token to renew.", 400));
    }
    let (code, client_id, redirect_uri, verifier) = (get("code"), get("client_id"), get("redirect_uri"), get("code_verifier"));
    let out = st
        .db
        .call(move |c| {
            let row = c.first(
                "UPDATE oauth_codes SET used_at = ? WHERE hash = ? AND used_at IS NULL AND expires_at > ? RETURNING client_id, user_id, workspace_id, redirect_uri, challenge, scope",
                params![now(), sha256_hex(&code), now()],
                |r| {
                    Ok((
                        (r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?),
                        (r.get::<_, String>(3)?, r.get::<_, String>(4)?, r.get::<_, String>(5)?),
                    ))
                },
            )?;
            let Some(((cid, uid, wid), (ruri, challenge, scope))) = row else {
                return Ok(Err("This code has expired or was already used. Sign in again."));
            };
            if cid != client_id || ruri != redirect_uri {
                return Ok(Err("The code was issued to another client or redirect address."));
            }
            let verifier_ok = (43..=128).contains(&verifier.len())
                && verifier.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'~' | b'-'));
            if !verifier_ok || b64url(&Sha256::digest(verifier.as_bytes())) != challenge {
                return Ok(Err("The code_verifier does not match."));
            }
            let who = c.first(
                "SELECT u.id AS uid, u.email, u.name AS uname, u.email_verified_at, m.role AS mrole, w.* FROM users u JOIN members m ON m.user_id = u.id
                 JOIN workspaces w ON w.id = m.workspace_id WHERE u.id = ? AND w.id = ?",
                params![uid, wid],
                |r| {
                    Ok((
                        User { id: r.get("uid")?, email: r.get("email")?, name: r.get("uname")?, email_verified_at: r.get("email_verified_at")? },
                        r.get::<_, String>("mrole")?,
                        Workspace::from_row(r)?,
                    ))
                },
            )?;
            let Some((user, role, workspace)) = who.filter(|(_, role, _)| builds(role)) else {
                return Ok(Err("The person who signed in is no longer a builder in that workspace."));
            };
            let caller = Caller { actor: user.email.clone(), workspace, user, role, agent: false, read_only: false };
            let name = client(c, Some(&cid))?.map(|x| x.name).unwrap_or_else(|| "MCP client".into());
            Ok(Ok(control::create_oauth_token(c, &caller, &cid, &name, &scope)?))
        })
        .await?;
    Ok(match out {
        Err(why) => oauth_error("invalid_grant", why, 400),
        Ok(t) => issued(t),
    })
}

// ---------- the connections page ----------

async fn connections_page(st: &State, req: &mut Req, slug: String) -> Result<Response> {
    let cfg = st.cfg.clone();
    let cookie = req.header("cookie").map(String::from);
    let s2 = slug.clone();
    let cfg2 = cfg.clone();
    let found = st
        .db
        .call(move |c| {
            let Some((user, _)) = control::person(c, &cfg2, cookie.as_deref())? else { return Ok(None) };
            let mem = people::membership(c, &user, Some(&s2))?;
            Ok(Some((user, mem)))
        })
        .await?;
    let Some((user, mem)) = found else {
        return Ok(redirect(&format!("/auth/signin?return={}", encode_uri_component(&format!("/w/{slug}/connections"))), &[]));
    };
    let Some((workspace, role)) = mem else {
        return Ok(notice(404, "Not your workspace", "You are not in this workspace. Ask an admin to invite you.", ""));
    };
    if !builds(&role) {
        return Ok(notice(
            403,
            "Builders only",
            "Only a workspace builder or admin can connect agents. Ask an admin to make you a builder.",
            "",
        ));
    }
    let caller = Caller { actor: user.email.clone(), workspace, user, role, agent: false, read_only: false };
    let mut made = String::new();
    if req.method == Method::POST {
        same_origin(&cfg, req)?;
        let f: HashMap<String, String> = req.form().await?.into_iter().collect();
        let c2 = caller.clone();
        let revoke = f.get("revoke").filter(|v| !v.is_empty()).cloned();
        let name = f.get("name").cloned().unwrap_or_default();
        let scope = control::token_scope(f.get("scope").map(|v| Value::String(v.clone())).as_ref())?;
        let expires_at = control::token_expiry(f.get("expires_in_days").map(|v| Value::String(v.clone())).as_ref())?;
        let t = st
            .db
            .call(move |c| match revoke {
                Some(id) => control::revoke_token(c, &c2, &id).map(|_| None),
                None => control::create_token(c, &c2, &name, &scope, expires_at).map(Some),
            })
            .await?;
        if let Some(t) = t {
            let (tname, tok) = (t["name"].as_str().unwrap_or(""), t["token"].as_str().unwrap_or(""));
            let add = format!("claude mcp add --transport http brod {}/mcp --header \"Authorization: Bearer {tok}\"", cfg.api_origin);
            made = format!(
                "<div role=\"status\"><p><b>Connection “{}” made.</b> Copy its token now: it is shown only this once.</p>
<input readonly value=\"{}\" aria-label=\"Token\" onclick=\"this.select()\">
<p class=\"muted\">For Claude Code:</p><input readonly value=\"{}\" aria-label=\"Claude Code command\" onclick=\"this.select()\"></div>",
                esc(tname),
                esc(tok),
                esc(&add)
            );
        }
    }
    let c3 = caller.clone();
    let list = st.db.call(move |c| control::list_tokens(c, &c3)).await?;
    let day = |v: &Value| v.as_i64().map(|ms| iso(ms)[..10].to_string()).unwrap_or_else(|| "never".into());
    let at = now();
    let lapsed = |v: &Value| v.as_i64().is_some_and(|ms| ms <= at);
    let rows: String = list
        .iter()
        .filter(|t| t["revoked_at"].is_null())
        // A page token past its expiry, or a sign-in whose refresh token lapsed, can never work again.
        .filter(|t| !lapsed(if t["kind"] == "oauth" { &t["refresh_expires_at"] } else { &t["expires_at"] }))
        .map(|t| {
            let by = t["made_by"].as_str().unwrap_or("");
            let button = if caller.role == "admin" || by == caller.user.email {
                format!(
                    "<form method=\"post\"><button name=\"revoke\" value=\"{}\" class=\"secondary small\">Disconnect</button></form>",
                    esc(t["id"].as_str().unwrap_or(""))
                )
            } else {
                String::new()
            };
            let rights = if t["scope"] == "read" { "read-only" } else { "deploy and manage" };
            let life = if t["kind"] == "oauth" {
                format!("signed in, renews while in use until {}", day(&t["refresh_expires_at"]))
            } else if t["expires_at"].is_null() {
                "never expires".into()
            } else {
                format!("expires {}", day(&t["expires_at"]))
            };
            format!(
                "<li><span>{}<br><small>{} · {rights} · made {} · last used {} · {life}</small></span>\n{button}</li>",
                esc(t["name"].as_str().unwrap_or("")),
                esc(by),
                day(&t["created_at"]),
                day(&t["last_used_at"])
            )
        })
        .collect();
    let w = &caller.workspace;
    let add = format!("claude mcp add --transport http brod {}/mcp", cfg.api_origin);
    Ok(page(
        200,
        &format!("Connections · {}", w.name),
        &format!(
            "<p class=\"muted\"><a href=\"/w/{}\">{}</a></p><h1>Connect an agent</h1>
<p>Add Brod to your agent as an MCP server. It opens this site so you can sign in and pick this workspace; no token to copy.</p>
<input readonly value=\"{}\" aria-label=\"Claude Code command\" onclick=\"this.select()\">
<p class=\"muted\">Other MCP clients: add the server address {}/mcp.</p>
<h2>Or make a token</h2><p>For an agent that cannot sign in with a browser.</p>{made}
<form method=\"post\"><input name=\"name\" maxlength=\"40\" placeholder=\"Connection name, for example laptop\" aria-label=\"Connection name\">
<p><label>It may<br><select name=\"scope\" aria-label=\"What it may do\"><option value=\"manage\">Deploy and manage apps</option><option value=\"read\">Only read status and logs</option></select></label>
<label>Expires<br><select name=\"expires_in_days\" aria-label=\"Expires\"><option value=\"30\">in 30 days</option><option value=\"7\">in 7 days</option><option value=\"90\">in 90 days</option><option value=\"365\">in a year</option><option value=\"never\">never</option></select></label></p>
<button>Make a token</button></form>
<h2>Connections</h2>{}",
            esc(&w.slug),
            esc(&w.name),
            esc(&add),
            esc(&cfg.api_origin),
            if rows.is_empty() { "<p>None yet.</p>".to_string() } else { format!("<ul>{rows}</ul>") }
        ),
        Some(&w.color),
        &[],
    ))
}

// ---------- routes ----------

/// The connections page and the OAuth endpoints. None: not one of them.
pub async fn serve(st: &State, req: &mut Req) -> Result<Option<Response>> {
    let p = req.path.trim_end_matches('/').to_string();
    let m = req.method.clone();
    let cfg = &st.cfg;
    let open = p.starts_with("/.well-known/oauth-") || p == "/oauth/register" || p == "/oauth/token";
    if open && m == Method::OPTIONS {
        return Ok(Some(cors(empty(204))));
    }
    if (p == "/.well-known/oauth-protected-resource" || p == "/.well-known/oauth-protected-resource/mcp") && m == Method::GET {
        return Ok(Some(cors(json_response(
            &json!({ "resource": format!("{}/mcp", cfg.api_origin), "authorization_servers": [cfg.api_origin], "bearer_methods_supported": ["header"], "resource_name": "Brod" }),
            200,
            &[],
        ))));
    }
    if p == "/.well-known/oauth-authorization-server" && m == Method::GET {
        let o = &cfg.api_origin;
        return Ok(Some(cors(json_response(
            &json!({
                "issuer": o, "authorization_endpoint": format!("{o}/oauth/authorize"), "token_endpoint": format!("{o}/oauth/token"),
                "registration_endpoint": format!("{o}/oauth/register"), "response_types_supported": ["code"], "grant_types_supported": ["authorization_code", "refresh_token"],
                "code_challenge_methods_supported": ["S256"], "token_endpoint_auth_methods_supported": ["none"], "scopes_supported": ["brod", "brod:read"],
            }),
            200,
            &[],
        ))));
    }
    if p == "/oauth/register" && m == Method::POST {
        return register(st, req).await.map(Some);
    }
    if p == "/oauth/authorize" && (m == Method::GET || m == Method::POST) {
        return authorize(st, req).await.map(Some);
    }
    if p == "/oauth/token" && m == Method::POST {
        return token(st, req).await.map(Some);
    }
    if let Some(slug) = p.strip_prefix("/w/").and_then(|s| s.strip_suffix("/connections"))
        && !slug.is_empty()
        && slug.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && (m == Method::GET || m == Method::POST)
    {
        return connections_page(st, req, slug.to_string()).await.map(Some);
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::{redirect_allowed, redirect_matches};

    #[test]
    fn accepts_only_safe_redirect_addresses() {
        for ok in [
            "http://localhost:4567/callback",
            "http://127.0.0.1/cb",
            "http://[::1]:9/cb",
            "https://claude.ai/api/mcp/auth_callback",
            "cursor://anysphere.cursor-retrieval/oauth/callback",
        ] {
            assert!(redirect_allowed(ok), "{ok}");
        }
        for bad in [
            "http://evil.test/cb",
            "javascript:alert(1)",
            "data:text/html,x",
            "https://a.test/cb#x",
            "https://user@a.test/",
            "HTTPS://a.test/",
            "/relative",
            "",
        ] {
            assert!(!redirect_allowed(bad), "{bad}");
        }
    }

    #[test]
    fn loopback_addresses_match_on_any_port() {
        let reg = vec!["http://localhost/callback".to_string(), "https://a.test/cb".to_string()];
        assert!(redirect_matches(&reg, "http://localhost:51234/callback"));
        assert!(redirect_matches(&reg, "https://a.test/cb"));
        assert!(!redirect_matches(&reg, "https://a.test:8443/cb"));
        assert!(!redirect_matches(&reg, "http://localhost:51234/other"));
        assert!(!redirect_matches(&reg, "http://127.0.0.1:51234/callback"));
    }
}
