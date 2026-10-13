// Pages and sign-in on the API host: magic links, Google, the hand-off of a sign-in to an app's own address,
// invitations, confirmations of agent requests, and the workspace home page.
//
// One sign-in, many addresses: the platform session cookie lives only on the API host. When an app needs a person,
// the gateway sends them to /auth/app, which hands the app a one-time code; the app's host swaps it for its own
// session cookie. Apps never see the platform cookie, and signing out ends every app session made from it.
use crate::db::{Connection, params};
use axum::http::Method;
use axum::response::Response;
use base64::Engine;
use serde_json::{Map, Value, json};

use crate::config::Config;
use crate::control::{self, PLATFORM_COOKIE};
use crate::db::Sql;
use crate::http::{Req, json, notice, page, redirect};
use crate::model::{AppRow, User, js_string, limits};
use crate::people;
use crate::problem::{Problem, Result};
use crate::state::State;
use crate::util::{
    STAGING_SUFFIX, app_url, encode_uri_component, esc, is_email, norm_email, now, random_id, set_cookie, sha256_hex, staging_url,
};

fn safe_return(r: Option<&Value>) -> String {
    match r {
        Some(Value::String(s)) if s.starts_with('/') && !s.starts_with("//") && !s.starts_with("/\\") => s.clone(),
        _ => "/".into(),
    }
}
fn safe_return_str(r: Option<String>) -> String {
    safe_return(r.map(Value::String).as_ref())
}

/// The fields of a JSON body or a form post.
async fn input(req: &mut Req) -> Result<Map<String, Value>> {
    if req.is_json() {
        return req.json_object().await;
    }
    let mut m = Map::new();
    for (k, v) in req.form().await? {
        m.insert(k, Value::String(v));
    }
    Ok(m)
}
fn text(m: &Map<String, Value>, k: &str) -> String {
    match m.get(k) {
        None | Some(Value::Null) => String::new(),
        Some(v) => js_string(v),
    }
}

/// Forms on these pages post back to the API host only. A missing or foreign Origin is refused.
fn same_origin(cfg: &Config, req: &Req) -> Result<()> {
    if req.header("origin") != Some(cfg.api_origin.as_str()) {
        return Err(Problem::new(403, "bad_origin", "This form must be sent from Brod itself."));
    }
    Ok(())
}

fn signed_in(cfg: &Config, token: &str) -> String {
    set_cookie(&cfg.api_origin, PLATFORM_COOKIE, token, limits::SESSION_TTL_MS / 1000)
}

struct BrandedApp {
    app: AppRow,
    /// Named by its staging address (<app>--staging.<workspace>), so a sign-in goes back there.
    staging: bool,
    wslug: String,
    wname: String,
    color: String,
    icon: String,
}

impl BrandedApp {
    /// How the "app" parameter names it: <app>.<workspace>, like the first labels of its address.
    fn reference(&self) -> String {
        format!("{}{}.{}", self.app.slug, if self.staging { STAGING_SUFFIX } else { "" }, self.wslug)
    }
    /// The address the sign-in is handed back to.
    fn url(&self, cfg: &Config) -> String {
        if self.staging { staging_url(cfg, &self.wslug, &self.app.slug) } else { app_url(cfg, &self.wslug, &self.app.slug) }
    }
}

/// Find an app from an "app" parameter written <app>.<workspace>.
fn app_by_ref(conn: &Connection, reference: Option<&str>) -> Result<Option<BrandedApp>> {
    let label = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
    let Some((slug, ws)) = reference.and_then(|r| r.split_once('.')).filter(|(a, w)| label(a) && label(w)) else {
        return Ok(None);
    };
    let (slug, staging) = match slug.strip_suffix(STAGING_SUFFIX) {
        Some(base) if !base.is_empty() => (base, true),
        _ => (slug, false),
    };
    conn.first(
        "SELECT a.*, w.slug AS wslug, w.name AS wname, w.color, w.icon FROM apps a JOIN workspaces w ON w.id = a.workspace_id
         WHERE a.slug = ? AND w.slug = ?",
        [slug, ws],
        |r| {
            Ok(BrandedApp {
                app: AppRow::from_row(r)?,
                staging,
                wslug: r.get("wslug")?,
                wname: r.get("wname")?,
                color: r.get("color")?,
                icon: r.get("icon")?,
            })
        },
    )
}

// ---------- pages ----------

async fn sign_in_page(st: &State, ret: Option<String>, app: Option<String>, sent: Option<(String, Option<String>)>) -> Result<Response> {
    let ret = safe_return_str(ret);
    let app = st.db.call(move |c| app_by_ref(c, app.as_deref())).await?;
    let cfg = &st.cfg;
    let brand = match &app {
        Some(a) => format!(
            "{}<p class=\"muted\">{}</p>",
            if a.icon.is_empty() { String::new() } else { format!("<div class=\"icon\">{}</div>", esc(&a.icon)) },
            esc(&a.wname)
        ),
        None => String::new(),
    };
    let heading = match &app {
        Some(a) => format!("Sign in to {}", esc(a.app.display_name())),
        None => "Sign in to Brod".into(),
    };
    let welcome = match &app {
        Some(a) if !a.app.welcome.is_empty() => format!("<p>{}</p>", esc(&a.app.welcome)),
        _ => "<p>We email you a link. No password needed.</p>".into(),
    };
    let report = match &app {
        Some(a) => format!("<p><small><a href=\"{}/_brod/report\">Report this app</a></small></p>", app_url(cfg, &a.wslug, &a.app.slug)),
        None => String::new(),
    };
    let color = app.as_ref().map(|a| a.color.clone());
    if let Some((email, link)) = sent {
        let dev = link.map(|l| format!("<p><small>Dev mode: <a href=\"{}\">open the link</a></small></p>", esc(&l))).unwrap_or_default();
        return Ok(page(
            200,
            "Check your email",
            &format!(
                "{brand}<h1>Check your email</h1><p>We sent a sign-in link to <b>{}</b>. It works once and expires in 15 minutes.</p>{dev}{report}",
                esc(&email)
            ),
            color.as_deref(),
            &[],
        ));
    }
    let google = if cfg.google_client_id.is_some() {
        format!(
            "<p><a class=\"btn secondary block\" href=\"/auth/google?return={}\">Continue with Google</a></p><div class=\"or\">or</div>",
            encode_uri_component(&ret)
        )
    } else {
        String::new()
    };
    let slug = app.as_ref().map(BrandedApp::reference).unwrap_or_default();
    let newcomer = if app.is_some() { "" } else { "<p class=\"muted\">New to Brod? <a href=\"/auth/signup\">Create a workspace</a></p>" };
    Ok(page(
        200,
        "Sign in",
        &format!(
            "{brand}<h1>{heading}</h1>{welcome}{google}
<form method=\"post\" action=\"/auth/start\"><input type=\"hidden\" name=\"return\" value=\"{}\"><input type=\"hidden\" name=\"app\" value=\"{}\">
<input type=\"email\" name=\"email\" required autocomplete=\"email\" placeholder=\"you@example.com\" aria-label=\"Email address\"><button class=\"block\">Email me a link</button></form>{report}{newcomer}",
            esc(&ret),
            esc(&slug)
        ),
        color.as_deref(),
        &[],
    ))
}

/// Where "Start free" on the landing page leads: the same email form, written for someone who has no account yet.
/// After the link, / sends a person with no workspace on to /new.
fn sign_up_page(cfg: &Config) -> Response {
    let google = if cfg.google_client_id.is_some() {
        "<p><a class=\"btn secondary block\" href=\"/auth/google?return=%2F\">Continue with Google</a></p><div class=\"or\">or</div>"
    } else {
        ""
    };
    page(
        200,
        "Create your workspace",
        &format!(
            "<h1>Create your workspace</h1><p>Free to start. No password and no card.</p>
<ol><li>We email you a sign-in link.</li><li>You name your workspace: one sign-in and one home page for your team's apps.</li><li>You connect your agent and ask it to put something online.</li></ol>{google}
<form method=\"post\" action=\"/auth/start\"><input type=\"hidden\" name=\"return\" value=\"/\"><input type=\"hidden\" name=\"app\" value=\"\">
<input type=\"email\" name=\"email\" required autocomplete=\"email\" placeholder=\"you@example.com\" aria-label=\"Email address\"><button class=\"block\">Email me a link</button></form>
<p class=\"muted\">Already use Brod? <a href=\"/auth/signin\">Sign in</a></p>"
        ),
        None,
        &[],
    )
}

async fn home_page(st: &State, req: &Req, slug: String) -> Result<Response> {
    let cfg = st.cfg.clone();
    let cookie = req.header("cookie").map(String::from);
    let s2 = slug.clone();
    let data = st
        .db
        .call(move |c| {
            let Some((user, _)) = control::person(c, &cfg, cookie.as_deref())? else { return Ok(None) };
            let Some((w, role)) = people::membership(c, &user, Some(&s2))? else { return Ok(Some((user, None))) };
            let apps = c.all(
                "SELECT * FROM apps WHERE workspace_id = ? AND status = 'live' AND live_version IS NOT NULL ORDER BY name",
                [&w.id],
                AppRow::from_row,
            )?;
            let mut mine = Vec::new();
            for a in apps {
                if people::decide(c, &a, Some(&user))?.allowed {
                    mine.push(a);
                }
            }
            let others: Vec<Value> = people::my_workspaces(c, &cfg, &user)?.into_iter().filter(|x| x["slug"] != json!(w.slug)).collect();
            Ok(Some((user, Some((w, role, mine, others)))))
        })
        .await?;
    let Some((user, found)) = data else {
        return Ok(redirect(&format!("/auth/signin?return={}", encode_uri_component(&format!("/w/{slug}"))), &[]));
    };
    let Some((w, role, mine, others)) = found else {
        return Ok(notice(404, "Not your workspace", "You are not in this workspace. Ask an admin to invite you.", ""));
    };
    let builds = role == "admin" || role == "builder";
    // Builders and admins land on the admin console; the plain launcher stays one link away at ?view=apps.
    if builds && req.param("view").as_deref() != Some("apps") {
        return Ok(redirect(&format!("/w/{}/admin", w.slug), &[]));
    }
    let list = if mine.is_empty() {
        format!("<p>No apps here yet that you can open.{}</p>", if builds { "" } else { " Builders deploy them with their agent." })
    } else {
        let items: String = mine
            .iter()
            .map(|a| {
                let welcome = if a.welcome.is_empty() { String::new() } else { format!("<br><small>{}</small>", esc(&a.welcome)) };
                format!(
                    "<li data-name=\"{}\"><a href=\"{}/\">{}</a>{welcome}</li>",
                    esc(&a.display_name().to_lowercase()),
                    app_url(&st.cfg, &slug, &a.slug),
                    esc(a.display_name())
                )
            })
            .collect();
        format!(
            "<input type=\"search\" id=\"q\" placeholder=\"Search apps\" aria-label=\"Search apps\"><ul id=\"apps\">{items}</ul>
<script>q.oninput=()=>{{for(const li of apps.children)li.hidden=!li.dataset.name.includes(q.value.toLowerCase())}}</script>"
        )
    };
    let others = if others.is_empty() {
        String::new()
    } else {
        let links: Vec<String> = others
            .iter()
            .map(|o| format!("<a href=\"/w/{}\">{}</a>", esc(o["slug"].as_str().unwrap_or("")), esc(o["name"].as_str().unwrap_or(""))))
            .collect();
        format!("<p class=\"muted\">Other workspaces: {}</p>", links.join(", "))
    };
    let icon = if w.icon.is_empty() { String::new() } else { format!("<div class=\"icon\">{}</div>", esc(&w.icon)) };
    let connect = if builds {
        format!(
            "<div class=\"actions\"><a class=\"btn\" href=\"/w/{0}/admin\">Admin console</a><a class=\"btn secondary\" href=\"/w/{0}/connections\">Connect an agent</a></div>",
            esc(&w.slug)
        )
    } else {
        String::new()
    };
    Ok(page(
        200,
        &w.name,
        &format!(
            "{icon}<h1>{}</h1>
<p class=\"muted\">Signed in as {} · {}</p>{list}
{connect}
{others}
<form method=\"post\" action=\"/auth/signout\"><button class=\"secondary small\">Sign out</button></form>",
            esc(&w.name),
            esc(&user.email),
            esc(&role)
        ),
        Some(&w.color),
        &[],
    ))
}

fn new_workspace_page(error: &str) -> Response {
    let alert = if error.is_empty() { String::new() } else { format!("<p role=\"alert\"><b>{}</b></p>", esc(error)) };
    page(
        if error.is_empty() { 200 } else { 400 },
        "Create a workspace",
        &format!(
            "<h1>Create a workspace</h1><p>One workspace for your team or company: one sign-in, one set of groups, one home page for every app.</p>
{alert}<form method=\"post\" action=\"/new\"><input name=\"name\" required maxlength=\"60\" placeholder=\"Workspace name, for example Acme\" aria-label=\"Workspace name\">
<p><label><input type=\"checkbox\" name=\"accept_terms\" value=\"1\" required> I accept the <a href=\"/terms\">terms of use and acceptable-use policy</a>.</label></p><button class=\"block\">Create workspace</button></form>"
        ),
        None,
        &[],
    )
}

const TERMS: &str = "<h1>Terms of use (draft)</h1><p>This is a working draft for the private beta and will be replaced by reviewed terms before public launch.</p>
<p>You may host apps for yourself, your team and people you invite. You may not host phishing, malware, spam, sign-in pages that imitate another brand,
content that is illegal where you or your visitors are, or anything that attacks other systems. We may take an app down and tell you why; you can appeal.</p>
<p>You own your apps and their data. For people who sign in to your apps, you are the controller and Brod is your processor. You can export or delete
your data at any time.</p>";

async fn person(st: &State, req: &Req) -> Result<Option<(User, String)>> {
    let cookie = req.header("cookie").map(String::from);
    let cfg = st.cfg.clone();
    st.db.call(move |c| control::person(c, &cfg, cookie.as_deref())).await
}

// ---------- routes ----------

/// The pages and forms on the API host. None: no such page.
pub async fn serve(st: &State, req: &mut Req) -> Result<Option<Response>> {
    let trimmed = req.path.trim_end_matches('/');
    let p = if trimmed.is_empty() { "/".to_string() } else { trimmed.to_string() };
    let m = req.method.clone();
    let cfg = st.cfg.clone();

    if p == "/" && m == Method::GET {
        let Some((user, _)) = person(st, req).await? else {
            // Links made as /?return=... or /?app=... still reach the sign-in form; everyone else gets the landing page.
            if req.param("return").is_some() || req.param("app").is_some() {
                return sign_in_page(st, req.param("return"), req.param("app"), None).await.map(Some);
            }
            return Ok(Some(crate::home::page(&st.cfg, req)));
        };
        let ws = st.db.call(move |c| people::my_workspaces(c, &cfg, &user)).await?;
        let to = ws.first().and_then(|w| w["slug"].as_str()).map(|s| format!("/w/{s}")).unwrap_or_else(|| "/new".into());
        return Ok(Some(redirect(&to, &[])));
    }
    if p == "/terms" {
        return Ok(Some(page(200, "Terms of use", TERMS, None, &[])));
    }
    if p == "/signin" && m == Method::GET {
        let q = if req.query.is_empty() { String::new() } else { format!("?{}", req.query) };
        return Ok(Some(redirect(&format!("/auth/signin{q}"), &[])));
    }
    if p == "/auth/signin" && m == Method::GET {
        return sign_in_page(st, req.param("return"), req.param("app"), None).await.map(Some);
    }
    if p == "/auth/signup" && m == Method::GET {
        if person(st, req).await?.is_some() {
            return Ok(Some(redirect("/", &[])));
        }
        return Ok(Some(sign_up_page(&cfg)));
    }
    if m == Method::GET {
        match p.as_str() {
            "/og.png" => return Ok(Some(crate::home::og_image(req))),
            "/robots.txt" => return Ok(Some(crate::home::robots(req))),
            "/sitemap.xml" => return Ok(Some(crate::home::sitemap(req))),
            _ => {}
        }
    }

    if p == "/auth/start" && m == Method::POST {
        let wants_json = req.is_json();
        if !wants_json {
            same_origin(&cfg, req)?;
        }
        let b = input(req).await?;
        let email = norm_email(&text(&b, "email"));
        if !is_email(&email) {
            return Err(Problem::new(400, "bad_email", "That does not look like an email address."));
        }
        let token = random_id("", 24);
        let ret = safe_return(b.get("return"));
        let (e2, hash) = (email.clone(), sha256_hex(&token));
        let ip = crate::abuse::client_ip(&cfg, req);
        st.db
            .call(move |c| {
                if let Some(ip) = &ip {
                    crate::abuse::rate_limit(
                        c,
                        "signin_ip",
                        ip,
                        crate::abuse::SIGN_IN_LINKS_PER_IP_HOUR,
                        crate::abuse::HOUR,
                        "Too many sign-in links were asked for from your network in the last hour.",
                    )?;
                }
                let recent =
                    c.count("SELECT COUNT(*) AS n FROM login_links WHERE email = ? AND created_at > ?", params![e2, now() - 3_600_000])?;
                if recent >= limits::LOGIN_LINKS_PER_HOUR {
                    return Err(Problem::new(429, "rate_limited", "Too many sign-in links for this address. Wait a little and try again."));
                }
                c.run(
                    "INSERT INTO login_links (hash, email, return_to, created_at, expires_at) VALUES (?,?,?,?,?)",
                    params![hash, e2, ret, now(), now() + limits::LOGIN_LINK_TTL_MS],
                )?;
                Ok(())
            })
            .await?;
        let link = format!("{}/auth/verify?token={token}", cfg.api_origin);
        crate::email::send(
            st,
            &email,
            "Your Brod sign-in link",
            &format!("Open this link to sign in. It works once and expires in 15 minutes:\n{link}\n\nIf you did not ask for it, ignore this email."),
        )
        .await?;
        let dev = cfg.dev_mode.then(|| link.clone());
        if wants_json {
            let mut out = json!({ "sent": true, "email": email });
            if let Some(d) = dev {
                out["dev_link"] = json!(d);
            }
            return Ok(Some(json(out)));
        }
        let app = if crate::model::truthy(b.get("app")) { Some(text(&b, "app")) } else { None };
        return sign_in_page(st, None, app, Some((email, dev))).await.map(Some);
    }

    // GET only shows a button, so a mail scanner that opens the link does not use it up.
    if p == "/auth/verify" && m == Method::GET {
        let token = req.param("token").unwrap_or_default();
        return Ok(Some(page(
            200,
            "Sign in",
            &format!(
                "<h1>Sign in</h1><p>Continue to finish signing in.</p><form method=\"post\" action=\"/auth/verify\"><input type=\"hidden\" name=\"token\" value=\"{}\"><button>Continue</button></form>",
                esc(&token)
            ),
            None,
            &[],
        )));
    }
    if p == "/auth/verify" && m == Method::POST {
        same_origin(&cfg, req)?;
        let b = input(req).await?;
        let hash = sha256_hex(&text(&b, "token"));
        enum Outcome {
            Expired,
            Used,
            Signed(String, String),
        }
        let out = st
            .db
            .call(move |c| {
                let link = c.first("SELECT email, return_to, expires_at, used_at FROM login_links WHERE hash = ?", [&hash], |r| {
                    Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, i64>(2)?, r.get::<_, Option<i64>>(3)?))
                })?;
                let Some((email, return_to, expires_at, used_at)) = link else {
                    return Ok(Outcome::Expired);
                };
                if used_at.is_some() || expires_at < now() || email.is_empty() {
                    return Ok(Outcome::Expired);
                }
                if c.run("UPDATE login_links SET used_at = ? WHERE hash = ? AND used_at IS NULL", params![now(), hash])? == 0 {
                    return Ok(Outcome::Used);
                }
                let user = people::verified_user(c, &email, "")?;
                Ok(Outcome::Signed(return_to, people::create_session(c, &user.id, None, None)?))
            })
            .await?;
        return Ok(Some(match out {
            Outcome::Expired => notice(
                410,
                "Link expired",
                "This sign-in link has expired or was already used. Ask for a new one.",
                "<p><a class=\"btn\" href=\"/auth/signin\">Sign in</a></p>",
            ),
            Outcome::Used => notice(410, "Link expired", "This sign-in link was already used.", ""),
            Outcome::Signed(to, token) => redirect(&to, &[("set-cookie", signed_in(&cfg, &token))]),
        }));
    }

    if p == "/auth/google" && m == Method::GET {
        let Some(client_id) = cfg.google_client_id.clone() else {
            return Ok(Some(notice(404, "Not available", "Google sign-in is not set up on this server.", "")));
        };
        let state = random_id("", 16);
        let (hash, ret) = (sha256_hex(&format!("g:{state}")), safe_return_str(req.param("return")));
        st.db
            .call(move |c| {
                c.run(
                    "INSERT INTO login_links (hash, email, return_to, created_at, expires_at) VALUES (?, '', ?, ?, ?)",
                    params![hash, ret, now(), now() + limits::LOGIN_LINK_TTL_MS],
                )
                .map(|_| ())
            })
            .await?;
        let q = form_urlencoded::Serializer::new(String::new())
            .append_pair("client_id", &client_id)
            .append_pair("redirect_uri", &format!("{}/auth/google/callback", cfg.api_origin))
            .append_pair("response_type", "code")
            .append_pair("scope", "openid email profile")
            .append_pair("state", &state)
            .append_pair("prompt", "select_account")
            .finish();
        return Ok(Some(redirect(&format!("https://accounts.google.com/o/oauth2/v2/auth?{q}"), &[])));
    }
    if p == "/auth/google/callback" && m == Method::GET {
        let (Some(client_id), Some(client_secret)) = (cfg.google_client_id.clone(), cfg.google_client_secret.clone()) else {
            return Ok(Some(notice(404, "Not available", "Google sign-in is not set up on this server.", "")));
        };
        let hash = sha256_hex(&format!("g:{}", req.param("state").unwrap_or_default()));
        let st_row = st
            .db
            .call(move |c| {
                c.first(
                    "UPDATE login_links SET used_at = ? WHERE hash = ? AND email = '' AND used_at IS NULL AND expires_at > ? RETURNING return_to",
                    params![now(), hash, now()],
                    |r| r.get::<_, String>(0),
                )
            })
            .await?;
        let Some(return_to) = st_row else {
            return Ok(Some(notice(
                400,
                "Sign-in expired",
                "That Google sign-in took too long or was already used. Try again.",
                "<p><a class=\"btn\" href=\"/auth/signin\">Sign in</a></p>",
            )));
        };
        let form = form_urlencoded::Serializer::new(String::new())
            .append_pair("code", &req.param("code").unwrap_or_default())
            .append_pair("client_id", &client_id)
            .append_pair("client_secret", &client_secret)
            .append_pair("redirect_uri", &format!("{}/auth/google/callback", cfg.api_origin))
            .append_pair("grant_type", "authorization_code")
            .finish();
        let res = st
            .http
            .post("https://oauth2.googleapis.com/token")
            .header("content-type", "application/x-www-form-urlencoded")
            .body(form)
            .send()
            .await;
        let (ok, body) = match res {
            Ok(r) => (r.status().is_success(), r.json::<Value>().await.unwrap_or(json!({}))),
            Err(e) => {
                eprintln!("google token request failed: {e}");
                (false, json!({}))
            }
        };
        // The ID token came straight from Google's token endpoint over TLS, so its claims are checked but its signature need not be.
        let claims: Value = body["id_token"]
            .as_str()
            .and_then(|t| t.split('.').nth(1))
            .and_then(|p| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(p.trim_end_matches('=')).ok())
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or(json!({}));
        let email = claims["email"].as_str().unwrap_or("").to_string();
        let iss_ok = matches!(claims["iss"].as_str(), Some("accounts.google.com") | Some("https://accounts.google.com"));
        if !ok
            || claims["aud"].as_str() != Some(client_id.as_str())
            || !iss_ok
            || email.is_empty()
            || claims["email_verified"] != json!(true)
        {
            return Ok(Some(notice(
                401,
                "Sign-in failed",
                "Google did not confirm a verified email address. Try again, or use an emailed link.",
                "",
            )));
        }
        let name = claims["name"].as_str().unwrap_or("").to_string();
        let token = st
            .db
            .call(move |c| {
                let user = people::verified_user(c, &email, &name)?;
                people::create_session(c, &user.id, None, None)
            })
            .await?;
        return Ok(Some(redirect(&return_to, &[("set-cookie", signed_in(&cfg, &token))])));
    }

    // Hand a sign-in to an app's own host with a one-time code.
    if p == "/auth/app" && m == Method::GET {
        let ret = safe_return_str(req.param("return"));
        let (slug, cookie, cfg2) = (req.param("app"), req.header("cookie").map(String::from), cfg.clone());
        let host = req.param("host").map(|h| h.to_lowercase());
        let host_param = req.param("host").map(|h| format!("&host={}", encode_uri_component(&h))).unwrap_or_default();
        enum Hand {
            NoApp,
            BadHost,
            SignIn(String),
            Code(String, String),
        }
        let out = st
            .db
            .call(move |c| {
                let Some(app) = app_by_ref(c, slug.as_deref())? else { return Ok(Hand::NoApp) };
                // A custom domain gets the code only when it is a proven address of this very app; anything else would leak it.
                if let Some(h) = &host
                    && !crate::domains::allowed_host(c, &cfg2, &app.app, h)?
                {
                    return Ok(Hand::BadHost);
                }
                let Some((user, hash)) = control::person(c, &cfg2, cookie.as_deref())? else { return Ok(Hand::SignIn(app.reference())) };
                let code = random_id("", 24);
                c.run(
                    "INSERT INTO app_codes (hash, app_id, user_id, parent, expires_at) VALUES (?,?,?,?,?)",
                    params![sha256_hex(&code), app.app.id, user.id, hash, now() + limits::APP_CODE_TTL_MS],
                )?;
                let target = match &host {
                    Some(h) => crate::util::host_origin(&cfg2, h),
                    None => app.url(&cfg2),
                };
                Ok(Hand::Code(target, code))
            })
            .await?;
        return Ok(Some(match out {
            Hand::NoApp => crate::http::not_found(&cfg.api_origin),
            Hand::BadHost => notice(400, "Unknown address", "That address is not a domain of this app.", ""),
            Hand::SignIn(reference) => {
                let inner = format!("/auth/app?app={reference}{host_param}&return={}", encode_uri_component(&ret));
                redirect(&format!("/auth/signin?app={reference}&return={}", encode_uri_component(&inner)), &[])
            }
            Hand::Code(url, code) => redirect(&format!("{url}/_brod/callback?code={code}&return={}", encode_uri_component(&ret)), &[]),
        }));
    }

    if p == "/auth/signout" && m == Method::POST {
        same_origin(&cfg, req)?;
        if let Some((_, hash)) = person(st, req).await? {
            st.db.call(move |c| people::revoke_session(c, &hash)).await?;
        }
        return Ok(Some(redirect("/auth/signin", &[("set-cookie", set_cookie(&cfg.api_origin, PLATFORM_COOKIE, "", 0))])));
    }

    if p == "/auth/invite" && m == Method::GET {
        let hash = sha256_hex(&req.param("token").unwrap_or_default());
        let token = req.param("token").unwrap_or_default();
        let inv = st
            .db
            .call(move |c| {
                c.first(
                    "SELECT i.email, i.role, w.name, a.name AS aname FROM invites i JOIN workspaces w ON w.id = i.workspace_id LEFT JOIN apps a ON a.id = i.app_id WHERE i.hash = ? AND i.used_at IS NULL AND i.revoked_at IS NULL AND i.expires_at > ?",
                    params![hash, now()],
                    |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?, r.get::<_, Option<String>>(3)?)),
                )
            })
            .await?;
        let Some((email, role, wname, aname)) = inv else {
            return Ok(Some(notice(
                410,
                "Invitation expired",
                "This invitation has expired, was already used, or was withdrawn. Ask for a new one.",
                "",
            )));
        };
        let what = match &aname {
            Some(a) => format!(" to the app {} in {}", esc(a), esc(&wname)),
            None => format!(" as a {}", esc(&role)),
        };
        return Ok(Some(page(
            200,
            "Accept invitation",
            &format!(
                "<h1>Join {}</h1><p>You were invited as <b>{}</b>{what}.</p>
<form method=\"post\" action=\"/auth/invite\"><input type=\"hidden\" name=\"token\" value=\"{}\"><button class=\"block\">Accept and sign in</button></form>",
                esc(aname.as_deref().unwrap_or(&wname)),
                esc(&email),
                esc(&token)
            ),
            None,
            &[],
        )));
    }
    if p == "/auth/invite" && m == Method::POST {
        same_origin(&cfg, req)?;
        let token = text(&input(req).await?, "token");
        let (to, session) = st
            .db
            .call(move |c| {
                let a = people::accept_invite(c, &token)?;
                let to = match a.app_ref {
                    Some(s) => format!("/auth/app?app={s}&return=%2F"),
                    None => format!("/w/{}", a.workspace_slug),
                };
                Ok((to, people::create_session(c, &a.user.id, None, None)?))
            })
            .await?;
        return Ok(Some(redirect(&to, &[("set-cookie", signed_in(&cfg, &session))])));
    }

    if p == "/new" && m == Method::GET {
        return Ok(Some(if person(st, req).await?.is_some() {
            new_workspace_page("")
        } else {
            redirect("/auth/signin?return=%2Fnew", &[])
        }));
    }
    if p == "/new" && m == Method::POST {
        same_origin(&cfg, req)?;
        let Some((user, _)) = person(st, req).await? else {
            return Ok(Some(redirect("/auth/signin?return=%2Fnew", &[])));
        };
        let b = input(req).await?;
        let (name, accept) = (text(&b, "name"), b.get("accept_terms") == Some(&json!("1")));
        let made = st.db.call(move |c| people::create_workspace(c, &cfg, &user, &name, accept)).await;
        return Ok(Some(match made {
            Ok(w) => redirect(&format!("/w/{}", w["workspace"].as_str().unwrap_or("")), &[]),
            Err(e) if !e.is_internal() => new_workspace_page(&e.message),
            Err(e) => return Err(e),
        }));
    }

    if let Some(slug) = p.strip_prefix("/w/").and_then(|x| x.strip_suffix("/admin"))
        && !slug.is_empty()
        && slug.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && m == Method::GET
    {
        return crate::admin::page(st, req, slug.to_string()).await.map(Some);
    }

    if let Some(slug) = p.strip_prefix("/w/")
        && !slug.is_empty()
        && slug.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && m == Method::GET
    {
        return home_page(st, req, slug.to_string()).await.map(Some);
    }

    if let Some(id) = p.strip_prefix("/confirm/")
        && id.len() > 3
        && id.starts_with("cf_")
        && id[3..].bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        let Some((user, _)) = person(st, req).await? else {
            return Ok(Some(redirect(&format!("/auth/signin?return={}", encode_uri_component(&p)), &[])));
        };
        let cid = id.to_string();
        let row = st.db.call(move |c| control::get_confirmation(c, &cid)).await?;
        let row = match row {
            Some(r) if r.done_at.is_none() && r.expires_at >= now() => r,
            _ => {
                return Ok(Some(notice(410, "Already handled", "This request has expired or was already confirmed or declined.", "")));
            }
        };
        if m == Method::GET {
            return Ok(Some(page(
                200,
                "Confirm a change",
                &format!(
                    "<h1>Confirm a change</h1><p>Your agent connection <b>{}</b> asked to:</p><p><b>{}</b></p>
<form method=\"post\"><button name=\"decision\" value=\"confirm\">Confirm</button> <button name=\"decision\" value=\"decline\" class=\"secondary\">Decline</button></form>",
                    esc(&row.requested_by),
                    esc(&row.summary)
                ),
                None,
                &[],
            )));
        }
        if m == Method::POST {
            same_origin(&cfg, req)?;
            if input(req).await?.get("decision") != Some(&json!("confirm")) {
                let (by, rid) = (format!("declined by {}", user.email), row.id.clone());
                st.db
                    .call(move |c| {
                        c.run("UPDATE confirmations SET done_at = ?, done_by = ? WHERE id = ? AND done_at IS NULL", params![now(), by, rid])
                            .map(|_| ())
                    })
                    .await?;
                return Ok(Some(notice(200, "Declined", "Nothing was changed.", "")));
            }
            return Ok(Some(match control::confirm(st, &user, &row.id).await {
                Ok(_) => notice(200, "Done", &format!("{}: done.", row.summary), ""),
                Err(e) if !e.is_internal() => notice(e.status, "Could not do that", &e.message, ""),
                Err(e) => return Err(e),
            }));
        }
    }
    Ok(None)
}
