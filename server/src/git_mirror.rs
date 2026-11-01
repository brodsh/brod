// SPDX-License-Identifier: AGPL-3.0-only
// Git mirror and two-way sync: Brod keeps a remote git repository (GitHub, GitLab, Gitea, ...) in step with an app.
//
// Outbound (push): after every deploy, rollback, publish or staging change, a background worker pushes the app's git
// history (git_export.rs) to the remote over smart HTTP (git-receive-pack, written from the protocol documentation, no
// git binary). The live version becomes the remote branch mapped to "main", the staging version the one mapped to
// "staging", and every version a tag vN. Only fast-forwards are ever sent: when the remote branch holds a commit Brod does
// not know, the branch is skipped and marked "diverged"; an existing tag with another commit is left alone. Brod never
// force-pushes and never deletes a ref.
//
// A remote tip that Brod does know but that is not an ancestor of the new commit (it is a commit imported from the
// remote, or one Brod pushed earlier before a rollback) is continued with an ordinary commit on top of it carrying the new
// version's files, so the remote history only ever grows.
//
// Inbound (sync): with sync_inbound on, a push to the configured remote branch (a signed webhook, or polling when no
// webhook arrives) is fetched through the import path (git_import.rs) and lands on STAGING as a new version, merged with
// what is there by the same three-way merge as a patch deploy. A conflict creates no version: it is recorded with the
// conflicting paths and the app's owner is told. Commits Brod pushed itself are recognised by id and never re-imported.
//
// The push credential is sealed like an app secret but kept apart from them (an app's code reads its secrets), is never
// returned by any call and never exported. Every request goes through outbound.rs.
use std::collections::{HashMap, HashSet};
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};

use axum::response::Response;
use hmac::{Hmac, Mac};
use serde_json::{Map, Value, json};
use sha2::Sha256;
use tokio::sync::Notify;

use crate::config::Config;
use crate::control;
use crate::db::{Connection, Row, Sql, params, tx};
use crate::git::{self, Ident, Kind, Oid};
use crate::git_export;
use crate::git_import::{self, Landing};
use crate::http::{Req, json_response};
use crate::model::{AppRow, Caller, User, Workspace};
use crate::outbound::{self, Policy};
use crate::people::require_role;
use crate::problem::{Problem, Result};
use crate::secrets;
use crate::state::State;
use crate::util::{iso, now, random_id, safe_equal};

/// How long a burst of deploys is gathered into one push.
const DEBOUNCE: Duration = Duration::from_millis(1500);
/// Pushes tried before the mirror shows "error" (the first and four retries).
pub const MAX_TRIES: u32 = 5;
const MAX_PACK: usize = 200 * 1024 * 1024;
const WEBHOOK_BODY: usize = 5 * 1024 * 1024;
const WEBHOOKS_PER_IP_MINUTE: i64 = 120;
const WEBHOOKS_PER_APP_MINUTE: i64 = 60;
/// Inbound events and sent commits kept per app.
const KEEP_EVENTS: i64 = 200;

type Object = (Oid, Kind, Vec<u8>);

// ---------- the pure parts ----------

/// One ref the remote should move: from `old` (None: create it) to `new`.
#[derive(Clone, Debug, PartialEq)]
pub struct Update {
    pub name: String,
    pub old: Option<Oid>,
    pub new: Oid,
}

/// The git-receive-pack request: one command per update (the capabilities ride on the first), a flush, then the pack.
pub fn receive_request(updates: &[Update], pack: &[u8]) -> Vec<u8> {
    let zero = "0".repeat(40);
    let mut out = Vec::new();
    for (i, u) in updates.iter().enumerate() {
        let old = u.old.map(|o| git::hex(&o)).unwrap_or_else(|| zero.clone());
        let mut line = format!("{old} {} {}", git::hex(&u.new), u.name);
        if i == 0 {
            line.push_str("\0report-status agent=brod");
        }
        out.extend_from_slice(&git::pkt(line.as_bytes()));
    }
    out.extend_from_slice(git::FLUSH);
    out.extend_from_slice(pack);
    out
}

/// What the remote said about a push.
#[derive(Debug, PartialEq)]
pub struct Report {
    pub unpack: std::result::Result<(), String>,
    pub refs: Vec<(String, std::result::Result<(), String>)>,
}

/// Read the report-status of a receive-pack answer: "unpack ok", then `"ok <ref>"` or `"ng <ref> <reason>"` per command.
pub fn parse_report(body: &[u8]) -> std::result::Result<Report, String> {
    let mut pos = 0;
    let mut pkts: Vec<Vec<u8>> = Vec::new();
    while let Some(p) = git::read_pkt(body, &mut pos)? {
        if let git::Pkt::Data(d) = p {
            pkts.push(d.to_vec());
        }
    }
    // With side-band the report is wrapped in band 1 (and progress on band 2, errors on band 3).
    if pkts.first().is_some_and(|d| matches!(d.first(), Some(1..=3))) {
        let mut inner = Vec::new();
        for d in &pkts {
            match d.first() {
                Some(1) => inner.extend_from_slice(&d[1..]),
                Some(3) => return Err(String::from_utf8_lossy(&d[1..]).trim().to_string()),
                _ => {}
            }
        }
        let (mut p, mut again) = (0, Vec::new());
        while let Some(x) = git::read_pkt(&inner, &mut p)? {
            if let git::Pkt::Data(d) = x {
                again.push(d.to_vec());
            }
        }
        pkts = again;
    }
    let mut report = Report { unpack: Err("the remote did not report on the objects".into()), refs: Vec::new() };
    for d in pkts {
        let line = String::from_utf8_lossy(&d).trim_end().to_string();
        if let Some(rest) = line.strip_prefix("unpack ") {
            report.unpack = if rest == "ok" { Ok(()) } else { Err(rest.to_string()) };
        } else if let Some(name) = line.strip_prefix("ok ") {
            report.refs.push((name.to_string(), Ok(())));
        } else if let Some(rest) = line.strip_prefix("ng ") {
            let (name, why) = rest.split_once(' ').unwrap_or((rest, "rejected"));
            report.refs.push((name.to_string(), Err(why.to_string())));
        } else if let Some(e) = line.strip_prefix("ERR ") {
            return Err(e.to_string());
        }
    }
    if report.unpack.is_err() && report.refs.is_empty() && !body.windows(6).any(|w| w == b"unpack") {
        return Err("the answer is not a push report".into());
    }
    Ok(report)
}

/// What to do with one branch of the remote.
#[derive(Debug, PartialEq)]
pub enum Decision {
    /// The remote already has these files at its tip.
    UpToDate,
    /// The branch does not exist on the remote.
    Create,
    /// The remote tip is an ancestor of the new commit.
    FastForward,
    /// The remote tip is a commit Brod knows but not an ancestor (imported from the remote, or pushed before a
    /// rollback): add a commit on top of it.
    Continue,
    Diverged,
}

/// `known` maps every commit id Brod recognises (its own, imported ones, ones it continued with) to the tree it holds.
pub fn decide_branch(remote: Option<Oid>, commit: Oid, tree: Oid, ancestors: &HashSet<Oid>, known: &HashMap<Oid, Oid>) -> Decision {
    match remote {
        None => Decision::Create,
        Some(t) if t == commit => Decision::UpToDate,
        Some(t) if ancestors.contains(&t) => Decision::FastForward,
        Some(t) => match known.get(&t) {
            Some(held) if *held == tree => Decision::UpToDate,
            Some(_) => Decision::Continue,
            None => Decision::Diverged,
        },
    }
}

/// Tags are only created: an existing tag at another commit stays where it is.
pub fn decide_tag(remote: Option<Oid>, commit: Oid) -> Decision {
    match remote {
        None => Decision::Create,
        Some(t) if t == commit => Decision::UpToDate,
        Some(_) => Decision::Diverged,
    }
}

/// A commit that carries `tree` on top of the remote's `parent`.
pub fn continuation(parent: Oid, tree: Oid, message: &str, domain: &str, at_secs: i64) -> (Oid, Vec<u8>) {
    let who = Ident { name: "Brod".into(), email: git_export::noreply_email("brod", domain), time: at_secs };
    let data = git::encode_commit(&tree, &[parent], &who, &who, message);
    (git::object_oid(Kind::Commit, &data), data)
}

/// Seconds to wait before retry number `attempt` (1 is the first retry): 10 s, 40 s, 160 s, then 10 minutes at most.
pub fn backoff(attempt: u32) -> Duration {
    Duration::from_secs((10u64 << (2 * attempt.saturating_sub(1).min(8))).min(600))
}

fn hmac_sha256(secret: &str) -> Hmac<Sha256> {
    Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("HMAC takes a key of any length")
}

/// GitHub's X-Hub-Signature-256: "sha256=" and the hex HMAC-SHA256 of the body under the webhook secret, compared in
/// constant time.
pub fn verify_github(secret: &str, body: &[u8], header: &str) -> bool {
    let Some(hex_sig) = header.trim().strip_prefix("sha256=") else { return false };
    let Ok(sig) = hex::decode(hex_sig) else { return false };
    let mut mac = hmac_sha256(secret);
    mac.update(body);
    mac.verify_slice(&sig).is_ok()
}

/// GitLab's X-Gitlab-Token is the secret itself.
pub fn verify_gitlab(secret: &str, header: &str) -> bool {
    safe_equal(secret, header.trim())
}

/// Whether the request is signed with this secret, by either service's scheme.
pub fn verify_webhook(secret: &str, body: &[u8], github_signature: Option<&str>, gitlab_token: Option<&str>) -> bool {
    if secret.is_empty() {
        return false;
    }
    let github = github_signature.is_some_and(|h| verify_github(secret, body, h));
    let gitlab = gitlab_token.is_some_and(|h| verify_gitlab(secret, h));
    github || gitlab
}

/// A push to a branch, from a webhook body.
#[derive(Debug, PartialEq)]
pub struct PushEvent {
    pub branch: String,
    pub after: Option<Oid>,
}

/// None for anything that is not a push to a branch (a ping, an issue, a tag push, a branch deletion).
pub fn parse_push(github_event: Option<&str>, gitlab_event: Option<&str>, body: &[u8]) -> Option<PushEvent> {
    if github_event.is_some_and(|e| e != "push") || gitlab_event.is_some_and(|e| e != "Push Hook") {
        return None;
    }
    let v: Value = serde_json::from_slice(body).ok()?;
    let branch = v.get("ref")?.as_str()?.strip_prefix("refs/heads/")?.to_string();
    let after = v.get("after").or_else(|| v.get("checkout_sha")).and_then(Value::as_str).and_then(git::parse_oid);
    if after.is_some_and(|o| o == [0u8; 20]) {
        return None;
    }
    Some(PushEvent { branch, after })
}

/// A remote branch name Brod may map to: letters, digits and . _ / - only, no ".." or leading/trailing slash.
fn check_branch(name: &str) -> Result<()> {
    let ok = !name.is_empty()
        && name.len() <= 100
        && name.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '/' | '-'))
        && !name.contains("..")
        && !name.contains("//")
        && !name.starts_with(['/', '-', '.'])
        && !name.ends_with(['/', '.'])
        && !name.ends_with(".lock");
    if !ok {
        return Err(Problem::new(
            400,
            "bad_branch",
            format!("\"{name}\" is not a branch name Brod will push to: use letters, digits and . _ / - only."),
        ));
    }
    Ok(())
}

/// The remote's address as Brod stores it: https only (http only in DEV_MODE with DEV_ALLOW_LOOPBACK_GIT), no login in the
/// address, no query, no non-public IP literal.
pub fn check_url(cfg: &Config, url: &str) -> Result<String> {
    let bad = |m: &str| Problem::new(400, "bad_url", m.to_string());
    let u = reqwest::Url::parse(url.trim())
        .map_err(|_| bad("That is not a valid repository address. Use https://github.com/owner/repo.git."))?;
    let dev = cfg.dev_allow_loopback_git;
    if u.scheme() != "https" && !(dev && u.scheme() == "http") {
        return Err(bad("The remote must be an https address, such as https://github.com/owner/repo.git."));
    }
    if !u.username().is_empty() || u.password().is_some() {
        return Err(bad("Leave the user name and password out of the address: give the access token separately."));
    }
    if u.query().is_some() || u.fragment().is_some() {
        return Err(bad("Give the repository address without a query or fragment."));
    }
    match u.host() {
        None => return Err(bad("The address has no host.")),
        Some(url::Host::Ipv4(a)) if !outbound::is_public(a.into()) && !(dev && a.is_loopback()) => {
            return Err(bad("That address is not a public one, so Brod will not push to it."));
        }
        Some(url::Host::Ipv6(a)) if !outbound::is_public(a.into()) && !(dev && a.is_loopback()) => {
            return Err(bad("That address is not a public one, so Brod will not push to it."));
        }
        Some(url::Host::Domain(d)) if d.eq_ignore_ascii_case("localhost") && !dev => {
            return Err(bad("That address is not a public one, so Brod will not push to it."));
        }
        _ => {}
    }
    Ok(u.to_string().trim_end_matches('/').to_string())
}

// ---------- the stored configuration ----------

#[derive(Clone, Debug)]
pub struct Mirror {
    pub app_id: String,
    pub url: String,
    pub enabled: bool,
    pub main_branch: String,
    /// The remote branch for staging; None: staging is not pushed.
    pub staging_branch: Option<String>,
    pub push_tags: bool,
    token_sealed: Option<String>,
    pub token_secret: Option<String>,
    pub sync_inbound: bool,
    pub inbound_branch: String,
    webhook_secret: Option<String>,
    pub last_webhook_at: Option<i64>,
    pub last_poll_at: Option<i64>,
    pub last_inbound_oid: Option<String>,
    pub last_push_at: Option<i64>,
    pub last_status: String,
    pub last_error: Option<String>,
    pub inbound_status: Option<String>,
    pub inbound_error: Option<String>,
    pub inbound_conflicts: Vec<String>,
}

impl Mirror {
    fn from_row(r: &Row) -> Result<Mirror> {
        let branches: Value = serde_json::from_str(&r.get::<_, String>("branches")?).unwrap_or(Value::Null);
        let name = |k: &str| branches.get(k).and_then(Value::as_str).filter(|s| !s.is_empty()).map(String::from);
        Ok(Mirror {
            app_id: r.get("app_id")?,
            url: r.get("url")?,
            enabled: r.get::<_, i64>("enabled")? != 0,
            main_branch: name("main").unwrap_or_else(|| "main".into()),
            staging_branch: name("staging"),
            push_tags: r.get::<_, i64>("push_tags")? != 0,
            token_sealed: r.get("token_sealed")?,
            token_secret: r.get("token_secret")?,
            sync_inbound: r.get::<_, i64>("sync_inbound")? != 0,
            inbound_branch: r.get("inbound_branch")?,
            webhook_secret: r.get("webhook_secret")?,
            last_webhook_at: r.get("last_webhook_at")?,
            last_poll_at: r.get("last_poll_at")?,
            last_inbound_oid: r.get("last_inbound_oid")?,
            last_push_at: r.get("last_push_at")?,
            last_status: r.get("last_status")?,
            last_error: r.get("last_error")?,
            inbound_status: r.get("inbound_status")?,
            inbound_error: r.get("inbound_error")?,
            inbound_conflicts: serde_json::from_str(&r.get::<_, Option<String>>("inbound_conflicts")?.unwrap_or_default())
                .unwrap_or_default(),
        })
    }

    /// The access token, from the sealed one or the named app secret.
    fn token(&self, cfg: &Config, conn: &Connection) -> std::result::Result<String, Fail> {
        if let Some(s) = &self.token_sealed {
            return Ok(secrets::open(&cfg.secrets_key, &self.app_id, s)?);
        }
        if let Some(name) = &self.token_secret {
            let sealed: Option<String> =
                conn.first("SELECT value FROM secrets WHERE app_id = ? AND name = ?", params![self.app_id, name], |r| r.get(0))?;
            return match sealed {
                Some(s) => Ok(secrets::open(&cfg.secrets_key, &self.app_id, &s)?),
                None => Err(Fail::permanent(format!("The app has no secret called {name}, which the git mirror uses as its token."))),
            };
        }
        Err(Fail::permanent("The git mirror has no access token: set one with set_git_mirror."))
    }

    fn webhook(&self, cfg: &Config) -> Option<String> {
        self.webhook_secret.as_ref().and_then(|s| secrets::open(&cfg.secrets_key, &self.app_id, s).ok())
    }
}

fn load_mirror(conn: &Connection, app_id: &str) -> Result<Option<Mirror>> {
    conn.first("SELECT * FROM git_mirrors WHERE app_id = ?", [app_id], Mirror::from_row)
}

/// Only the app's owner or a workspace admin may change or read how the app is mirrored.
fn require_owner(c: &Caller, app: &AppRow, what: &str) -> Result<()> {
    require_role(c, "builder", what)?;
    if c.role != "admin" && app.owner_id != c.user.id {
        return Err(Problem::new(403, "forbidden", format!("Only the app's owner or a workspace admin can {what}. You are a {}.", c.role)));
    }
    Ok(())
}

/// One line for get_status and the app description: how the mirror is doing. None when the app has no mirror.
pub fn summary(conn: &Connection, app_id: &str) -> Result<Option<Value>> {
    let Some(m) = load_mirror(conn, app_id)? else { return Ok(None) };
    let status = if m.enabled { m.last_status.clone() } else { "disabled".to_string() };
    let mut v = json!({
        "status": status,
        "last_push_at": m.last_push_at.map(iso),
        "error": m.last_error,
        "url": m.url,
    });
    if m.sync_inbound {
        v["inbound"] = json!({ "status": m.inbound_status.clone().unwrap_or_else(|| "idle".into()), "error": m.inbound_error, "conflicts": m.inbound_conflicts });
    }
    Ok(Some(v))
}

// ---------- configuring ----------

fn webhook_url(cfg: &Config, ws_slug: &str, slug: &str) -> String {
    format!("{}/v1/apps/{slug}/git-webhook?workspace={ws_slug}", cfg.api_origin)
}

fn view(conn: &Connection, cfg: &Config, c: &Caller, app: &AppRow, m: &Mirror) -> Result<Value> {
    let refs = conn.rows_json(
        "SELECT ref_name AS ref, remote_oid, version, status, message, pushed_at FROM git_mirror_refs WHERE app_id = ? ORDER BY ref_name",
        [app.id.as_str()],
    )?;
    let events = conn.rows_json(
        "SELECT at, source, remote_oid AS oid, branch, result, version, detail FROM git_sync_events WHERE app_id = ? AND source != 'push' ORDER BY at DESC LIMIT 10",
        [app.id.as_str()],
    )?;
    let token = if m.token_sealed.is_some() {
        json!("set")
    } else if let Some(n) = &m.token_secret {
        json!(format!("secret:{n}"))
    } else {
        json!("none")
    };
    let mut v = json!({
        "app": app.slug,
        "url": m.url,
        "enabled": m.enabled,
        "branches": { "main": m.main_branch, "staging": m.staging_branch },
        "push_tags": m.push_tags,
        "token": token,
        "status": if m.enabled { m.last_status.clone() } else { "disabled".to_string() },
        "last_push_at": m.last_push_at.map(iso),
        "error": m.last_error,
        "refs": refs,
        "sync_inbound": m.sync_inbound,
    });
    if m.sync_inbound {
        v["inbound_branch"] = json!(m.inbound_branch);
        v["webhook_url"] = json!(webhook_url(cfg, &c.workspace.slug, &app.slug));
        v["inbound"] = json!({
            "status": m.inbound_status.clone().unwrap_or_else(|| "idle".into()),
            "error": m.inbound_error,
            "conflicts": m.inbound_conflicts,
            "last_webhook_at": m.last_webhook_at.map(iso),
            "last_poll_at": m.last_poll_at.map(iso),
        });
        v["recent_sync"] = Value::Array(events);
    }
    Ok(v)
}

/// get_git_mirror / GET: the configuration, never the token or the webhook secret.
pub fn get(conn: &Connection, cfg: &Config, c: &Caller, slug: &str) -> Result<Value> {
    require_role(c, "builder", "see how an app is mirrored")?;
    let app = control::get_app(conn, c, slug)?;
    match load_mirror(conn, &app.id)? {
        Some(m) => view(conn, cfg, c, &app, &m),
        None => Ok(
            json!({ "app": app.slug, "configured": false, "message": "This app is not mirrored to a git remote. Use set_git_mirror to set one up." }),
        ),
    }
}

fn opt_str(b: &Map<String, Value>, k: &str) -> Result<Option<String>> {
    match b.get(k) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => Ok(Some(s.trim().to_string())),
        Some(_) => Err(Problem::new(400, "bad_value", format!("\"{k}\" must be a string."))),
    }
}

fn opt_bool(b: &Map<String, Value>, k: &str) -> Result<Option<bool>> {
    match b.get(k) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Bool(x)) => Ok(Some(*x)),
        Some(_) => Err(Problem::new(400, "bad_value", format!("\"{k}\" must be true or false."))),
    }
}

/// set_git_mirror / PUT: create or change the app's mirror. Fields left out keep their value. The webhook secret is
/// generated when inbound sync is first turned on (or with rotate_webhook_secret) and shown in this answer only.
pub async fn set(st: &State, c: &Caller, slug: &str, b: &Map<String, Value>) -> Result<Value> {
    let (c2, slug2, b2, cfg) = (c.clone(), slug.to_string(), b.clone(), st.cfg.clone());
    let (out, app_id, enabled) = st
        .db
        .call(move |conn| {
            let app = control::get_app(conn, &c2, &slug2)?;
            require_owner(&c2, &app, "set up a git mirror")?;
            let old = load_mirror(conn, &app.id)?;
            let b = &b2;

            let url = match opt_str(b, "url")? {
                Some(u) if !u.is_empty() => check_url(&cfg, &u)?,
                _ => match &old {
                    Some(o) => o.url.clone(),
                    None => return Err(Problem::new(400, "need_url", "Give the remote's \"url\", for example https://github.com/owner/repo.git.")),
                },
            };
            let token = opt_str(b, "token")?.filter(|t| !t.is_empty());
            let token_secret = opt_str(b, "token_secret")?.filter(|t| !t.is_empty());
            if token.is_some() && token_secret.is_some() {
                return Err(Problem::new(400, "bad_token", "Give \"token\" or \"token_secret\", not both."));
            }
            if token.as_deref().is_some_and(|t| t.len() > 2048) {
                return Err(Problem::new(400, "bad_token", "That token is too long."));
            }
            let (mut sealed, mut secret_name) = match &old {
                Some(o) => (o.token_sealed.clone(), o.token_secret.clone()),
                None => (None, None),
            };
            if let Some(t) = &token {
                sealed = Some(secrets::seal(&cfg.secrets_key, &app.id, t)?);
                secret_name = None;
            }
            if let Some(n) = &token_secret {
                secrets::check_name(n)?;
                if !conn.exists("SELECT 1 FROM secrets WHERE app_id = ? AND name = ?", params![app.id, n])? {
                    return Err(Problem::new(400, "no_secret", format!("{slug2} has no secret called {n}. Add it with set_secret first.")));
                }
                secret_name = Some(n.clone());
                sealed = None;
            }
            if sealed.is_none() && secret_name.is_none() {
                return Err(Problem::new(400, "need_token", "Give an access token that can push to the repository: \"token\", or \"token_secret\" naming one of the app's secrets."));
            }

            let enabled = opt_bool(b, "enabled")?.unwrap_or(old.as_ref().is_none_or(|o| o.enabled));
            let push_tags = opt_bool(b, "push_tags")?.unwrap_or(old.as_ref().is_none_or(|o| o.push_tags));
            let mut main_branch = old.as_ref().map(|o| o.main_branch.clone()).unwrap_or_else(|| "main".into());
            let mut staging_branch = match &old {
                Some(o) => o.staging_branch.clone(),
                None => Some("staging".into()),
            };
            if let Some(Value::Object(m)) = b.get("branches") {
                if let Some(v) = m.get("main") {
                    main_branch = v.as_str().unwrap_or_default().trim().to_string();
                    check_branch(&main_branch)?;
                }
                if let Some(v) = m.get("staging") {
                    staging_branch = v.as_str().map(str::trim).filter(|s| !s.is_empty()).map(String::from);
                    if let Some(s) = &staging_branch {
                        check_branch(s)?;
                    }
                }
            } else if b.get("branches").is_some_and(|v| !v.is_null()) {
                return Err(Problem::new(400, "bad_value", "\"branches\" is an object like {\"main\": \"main\", \"staging\": \"staging\"}."));
            }
            if staging_branch.as_deref() == Some(main_branch.as_str()) {
                return Err(Problem::new(400, "bad_branch", "The live and staging versions need different remote branches."));
            }

            let sync_inbound = opt_bool(b, "sync_inbound")?.unwrap_or(old.as_ref().is_some_and(|o| o.sync_inbound));
            let inbound_branch = match opt_str(b, "inbound_branch")? {
                Some(s) if !s.is_empty() => {
                    check_branch(&s)?;
                    s
                }
                _ => match &old {
                    Some(o) if o.inbound_branch != "main" || !b.contains_key("branches") => o.inbound_branch.clone(),
                    _ => main_branch.clone(),
                },
            };
            let inbound_branch = if old.is_none() && opt_str(b, "inbound_branch")?.is_none_or(|s| s.is_empty()) { main_branch.clone() } else { inbound_branch };

            let rotate = opt_bool(b, "rotate_webhook_secret")?.unwrap_or(false);
            let mut shown_secret = None;
            let mut webhook_sealed = old.as_ref().and_then(|o| o.webhook_secret.clone());
            if sync_inbound && (webhook_sealed.is_none() || rotate) {
                let fresh = format!("whsec_{}", crate::util::random_id("", 24));
                webhook_sealed = Some(secrets::seal(&cfg.secrets_key, &app.id, &fresh)?);
                shown_secret = Some(fresh);
            }
            if !sync_inbound {
                webhook_sealed = None;
            }

            let t = now();
            let branches = json!({ "main": main_branch, "staging": staging_branch }).to_string();
            conn.run(
                "INSERT INTO git_mirrors (app_id, url, enabled, branches, push_tags, token_sealed, token_secret, sync_inbound, inbound_branch, webhook_secret, created_at, updated_at, updated_by) \
                 VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?) \
                 ON CONFLICT (app_id) DO UPDATE SET url = excluded.url, enabled = excluded.enabled, branches = excluded.branches, push_tags = excluded.push_tags, \
                 token_sealed = excluded.token_sealed, token_secret = excluded.token_secret, sync_inbound = excluded.sync_inbound, inbound_branch = excluded.inbound_branch, \
                 webhook_secret = excluded.webhook_secret, updated_at = excluded.updated_at, updated_by = excluded.updated_by",
                params![
                    app.id, url, enabled as i64, branches, push_tags as i64, sealed, secret_name, sync_inbound as i64, inbound_branch, webhook_sealed, t, t,
                    c2.actor
                ],
            )?;
            if old.as_ref().is_some_and(|o| o.url != url) {
                // Another remote: what was known about the old one no longer applies.
                conn.run("DELETE FROM git_mirror_refs WHERE app_id = ?", [app.id.as_str()])?;
                conn.run(
                    "UPDATE git_mirrors SET last_status = 'idle', last_error = NULL, last_inbound_oid = NULL, inbound_status = NULL, inbound_error = NULL, inbound_conflicts = NULL WHERE app_id = ?",
                    [app.id.as_str()],
                )?;
            }
            crate::db::event(conn, &c2.workspace.id, &c2.actor, Some(&app.id), "git_mirror", &format!("{} ({})", url, if enabled { "on" } else { "off" }))?;
            let m = load_mirror(conn, &app.id)?.ok_or_else(|| Problem::internal("mirror vanished"))?;
            let mut out = view(conn, &cfg, &c2, &app, &m)?;
            if let Some(s) = shown_secret {
                out["webhook_secret"] = json!(s);
                out["webhook_secret_note"] = json!(
                    "Shown once. Put it in the webhook's Secret field on GitHub (content type application/json, event: push), or in GitLab's Secret token field."
                );
            }
            Ok((out, app.id, enabled))
        })
        .await?;
    if enabled {
        poke(&app_id);
    }
    Ok(out)
}

/// DELETE: stop mirroring. The remote repository is not touched.
pub fn remove(conn: &Connection, c: &Caller, slug: &str) -> Result<Value> {
    let app = control::get_app(conn, c, slug)?;
    require_owner(c, &app, "remove a git mirror")?;
    let n = conn.run("DELETE FROM git_mirrors WHERE app_id = ?", [app.id.as_str()])?;
    conn.run("DELETE FROM git_mirror_refs WHERE app_id = ?", [app.id.as_str()])?;
    conn.run("DELETE FROM git_sync_events WHERE app_id = ?", [app.id.as_str()])?;
    if n > 0 {
        crate::db::event(conn, &c.workspace.id, &c.actor, Some(&app.id), "git_mirror", "removed")?;
    }
    Ok(json!({ "app": app.slug, "removed": n > 0 }))
}

// ---------- pushing ----------

#[derive(Debug)]
struct Fail {
    message: String,
    transient: bool,
}

impl Fail {
    fn permanent(m: impl Into<String>) -> Fail {
        Fail { message: m.into(), transient: false }
    }
    fn transient(m: impl Into<String>) -> Fail {
        Fail { message: m.into(), transient: true }
    }
}

impl From<Problem> for Fail {
    fn from(p: Problem) -> Fail {
        Fail { transient: p.is_internal() || matches!(p.code.as_str(), "fetch_failed" | "fetch_timeout"), message: p.message }
    }
}

#[derive(Default)]
struct Job {
    due: Option<Instant>,
    attempts: u32,
    running: bool,
    dirty: bool,
}

static JOBS: LazyLock<Mutex<HashMap<String, Job>>> = LazyLock::new(Default::default);
static WAKE: Notify = Notify::const_new();

fn jobs() -> std::sync::MutexGuard<'static, HashMap<String, Job>> {
    JOBS.lock().unwrap_or_else(|p| p.into_inner())
}

/// Something changed in the app (deploy, rollback, publish, staging change): push it soon. Cheap, never blocks, and calls
/// close together are one push. Safe to call for an app with no mirror.
pub fn poke(app_id: &str) {
    {
        let mut j = jobs();
        let job = j.entry(app_id.to_string()).or_default();
        if job.running {
            job.dirty = true;
        } else if job.due.is_none() {
            job.due = Some(Instant::now() + DEBOUNCE);
            job.attempts = 0;
        }
    }
    WAKE.notify_one();
}

/// The background task that pushes: started once from main.rs.
pub async fn worker(st: State) {
    loop {
        tokio::select! {
            _ = WAKE.notified() => {}
            _ = tokio::time::sleep(Duration::from_millis(500)) => {}
        }
        let due: Vec<String> = {
            let mut j = jobs();
            let t = Instant::now();
            let mut out = Vec::new();
            for (id, job) in j.iter_mut() {
                if !job.running && job.due.is_some_and(|d| d <= t) {
                    job.running = true;
                    job.due = None;
                    out.push(id.clone());
                }
            }
            out
        };
        for id in due {
            let st = st.clone();
            tokio::spawn(async move { run_job(st, id).await });
        }
    }
}

enum Next {
    Done,
    Again(Duration),
    GiveUp,
}

async fn run_job(st: State, id: String) {
    let result = push_app(&st, &id).await;
    let (next, error) = {
        let mut j = jobs();
        let Some(job) = j.get_mut(&id) else { return };
        job.running = false;
        let mut error = None;
        let next = match &result {
            _ if job.dirty => {
                job.dirty = false;
                job.attempts = 0;
                Next::Again(DEBOUNCE)
            }
            Err(f) if f.transient => {
                job.attempts += 1;
                error = Some(f.message.clone());
                if job.attempts >= MAX_TRIES { Next::GiveUp } else { Next::Again(backoff(job.attempts)) }
            }
            _ => Next::Done,
        };
        match &next {
            Next::Again(d) => job.due = Some(Instant::now() + *d),
            Next::Done | Next::GiveUp => {
                j.remove(&id);
            }
        }
        (next, error)
    };
    if let Some(message) = error {
        let (status, message) = match next {
            Next::GiveUp => ("error", format!("Gave up after {MAX_TRIES} tries: {message}")),
            _ => ("retrying", message),
        };
        if let Err(e) = write_status(&st, &id, status, Some(&message), false).await {
            tracing::warn!("git mirror status not saved: {}", e.message);
        }
    }
}

async fn write_status(st: &State, app_id: &str, status: &str, error: Option<&str>, pushed: bool) -> Result<()> {
    let (id, status, error) = (app_id.to_string(), status.to_string(), error.map(String::from));
    st.db
        .call(move |conn| {
            let t = now();
            conn.run("UPDATE git_mirrors SET last_status = ?, last_error = ? WHERE app_id = ?", params![status, error, id])?;
            if pushed {
                conn.run("UPDATE git_mirrors SET last_push_at = ? WHERE app_id = ?", params![t, id])?;
            }
            Ok(())
        })
        .await
}

struct Target {
    remote_ref: String,
    commit: Oid,
    tree: Oid,
    version: i64,
    tag: bool,
}

struct RefResult {
    name: String,
    /// What the remote holds at the ref once this push is done, as far as Brod knows.
    remote: Option<Oid>,
    tree: Option<Oid>,
    version: i64,
    status: &'static str,
    message: Option<String>,
    pushed: bool,
    tag: bool,
}

fn short(o: &Oid) -> String {
    git::hex(o)[..8].to_string()
}

/// Push the app's current state to its mirror. A failure that may pass is returned as transient (the worker retries); one
/// that will not is recorded as the mirror's status here.
async fn push_app(st: &State, app_id: &str) -> std::result::Result<(), Fail> {
    let r = push_inner(st, app_id).await;
    if let Err(f) = &r
        && !f.transient
        && let Err(e) = write_status(st, app_id, "error", Some(&f.message), false).await
    {
        tracing::warn!("git mirror status not saved: {}", e.message);
    }
    r
}

async fn push_inner(st: &State, app_id: &str) -> std::result::Result<(), Fail> {
    let (id, cfg) = (app_id.to_string(), st.cfg.clone());
    let loaded = st
        .db
        .call(move |conn| {
            let Some(m) = load_mirror(conn, &id)? else { return Ok(None) };
            if !m.enabled {
                return Ok(None);
            }
            let Some(app) = conn.first("SELECT * FROM apps WHERE id = ?", [id.as_str()], AppRow::from_row)? else { return Ok(None) };
            let token = m.token(&cfg, conn);
            Ok(Some((m, app, token)))
        })
        .await?;
    let Some((m, app, token)) = loaded else { return Ok(()) };
    let token = token?;
    if app.live_version.is_none() && app.staging_version.is_none() {
        return Ok(());
    }

    let plan = git_export::plan_app(st, app.clone()).await?;
    let id = app.id.clone();
    let known: HashMap<Oid, Oid> = st
        .db
        .call(move |conn| {
            let mut known = HashMap::new();
            let mut add = |oid: Option<String>, tree: Option<String>| {
                if let (Some(o), Some(t)) = (oid.as_deref().and_then(git::parse_oid), tree.as_deref().and_then(git::parse_oid)) {
                    known.insert(o, t);
                }
            };
            for (c, s, t) in
                conn.all("SELECT commit_oid, source_commit_oid, tree_oid FROM version_git_commits WHERE app_id = ?", [id.as_str()], |r| {
                    Ok((
                        r.get::<_, String>("commit_oid")?,
                        r.get::<_, Option<String>>("source_commit_oid")?,
                        r.get::<_, String>("tree_oid")?,
                    ))
                })?
            {
                add(Some(c), Some(t.clone()));
                add(s, Some(t));
            }
            for (o, t) in conn.all(
                "SELECT remote_oid, tree_oid FROM git_mirror_refs WHERE app_id = ? AND remote_oid IS NOT NULL AND tree_oid IS NOT NULL",
                [id.as_str()],
                |r| Ok((r.get::<_, String>("remote_oid")?, r.get::<_, String>("tree_oid")?)),
            )? {
                add(Some(o), Some(t));
            }
            Ok(known)
        })
        .await?;

    let policy = Policy::from_config(&st.cfg);
    let auth = git_import::basic_auth(&token);
    let advert = git_import::advertise(policy, &m.url, "git-receive-pack", Some(&auth)).await?;
    if !advert.caps.iter().any(|c| c == "report-status") {
        return Err(Fail::permanent(
            "The remote does not support git-receive-pack with report-status, so Brod cannot tell whether a push worked.",
        ));
    }
    let remote: HashMap<&str, Oid> = advert.refs.iter().map(|(n, o)| (n.as_str(), *o)).collect();

    // What each ref should be.
    let mut targets: Vec<Target> = Vec::new();
    let mut add = |ref_name: String, n: i64, tag: bool| {
        if let Some(c) = plan.history.commits.get(&n) {
            targets.push(Target { remote_ref: ref_name, commit: c.commit, tree: c.tree, version: n, tag });
        }
    };
    if let Some(n) = app.live_version {
        add(format!("refs/heads/{}", m.main_branch), n, false);
    }
    if let (Some(b), Some(n)) = (&m.staging_branch, app.staging_version) {
        add(format!("refs/heads/{b}"), n, false);
    }
    if m.push_tags {
        let versions: Vec<i64> = plan.history.commits.keys().copied().collect();
        for n in versions {
            add(format!("refs/tags/v{n}"), n, true);
        }
    }

    let mut updates: Vec<Update> = Vec::new();
    let mut extra: Vec<Object> = Vec::new();
    let mut sent: Vec<(Oid, i64)> = Vec::new();
    let mut results: Vec<RefResult> = Vec::new();
    let mut pending: Vec<(usize, String)> = Vec::new();
    for t in &targets {
        let cur = remote.get(t.remote_ref.as_str()).copied();
        let decision =
            if t.tag { decide_tag(cur, t.commit) } else { decide_branch(cur, t.commit, t.tree, &plan.ancestors_of(t.commit), &known) };
        let mut r = RefResult {
            name: t.remote_ref.clone(),
            remote: cur,
            tree: Some(t.tree),
            version: t.version,
            status: "ok",
            message: None,
            pushed: false,
            tag: t.tag,
        };
        let mut new = None;
        match decision {
            Decision::UpToDate => {
                r.remote = cur;
            }
            Decision::Create | Decision::FastForward => new = Some(t.commit),
            Decision::Continue => {
                let parent = cur.unwrap_or_default();
                let msg = git_export::message(t.version, "");
                let (oid, data) = continuation(parent, t.tree, &msg, &st.cfg.apps_domain, now() / 1000);
                extra.push((oid, Kind::Commit, data));
                sent.push((oid, t.version));
                new = Some(oid);
            }
            Decision::Diverged if t.tag => {
                r.status = "skipped";
                r.tree = None;
                r.message = Some(format!(
                    "The tag {} already points at another commit on the remote. Brod never moves a tag.",
                    t.remote_ref.trim_start_matches("refs/tags/")
                ));
            }
            Decision::Diverged => {
                r.status = "diverged";
                r.tree = None;
                r.message = Some(format!(
                    "The remote branch {} is at {}, which is not part of this app's history, so Brod left it alone (it never force-pushes). Merge or reset it on the remote, or let Brod import it with sync_inbound.",
                    t.remote_ref.trim_start_matches("refs/heads/"),
                    cur.map(|o| short(&o)).unwrap_or_default()
                ));
            }
        }
        if let Some(new) = new {
            updates.push(Update { name: t.remote_ref.clone(), old: cur, new });
            pending.push((results.len(), t.remote_ref.clone()));
            r.remote = Some(new);
            r.pushed = true;
        }
        results.push(r);
    }

    if !updates.is_empty() {
        // Brod's own continuation commits are recorded before they are sent, so that the webhook they cause is ignored.
        if !sent.is_empty() {
            let (id, rows) = (app.id.clone(), sent.clone());
            st.db
                .call(move |conn| {
                    for (oid, n) in rows {
                        conn.run(
                            "INSERT INTO git_sync_events (id, app_id, at, source, remote_oid, branch, result, version, detail) VALUES (?,?,?,?,?,?,?,?,?)",
                            params![random_id("gse_", 8), id, now(), "push", git::hex(&oid), "", "pushed", n, "a commit Brod added on top of the remote branch"],
                        )?;
                    }
                    Ok(())
                })
                .await?;
        }
        let wants: Vec<Oid> = updates.iter().map(|u| u.new).collect();
        let haves: Vec<Oid> = advert.refs.iter().map(|(_, o)| *o).collect();
        let pack = plan.pack_for(st, &wants, &haves, &extra).await?;
        if pack.len() > MAX_PACK {
            return Err(Fail::permanent(format!(
                "The objects to push are {} MB, over the {} MB Brod sends in one push.",
                pack.len() >> 20,
                MAX_PACK >> 20
            )));
        }
        let reply = outbound::send(
            policy,
            &outbound::Request {
                post: true,
                url: git_import::git_url(&m.url, "/git-receive-pack")?,
                headers: vec![
                    ("authorization", auth.clone()),
                    ("content-type", "application/x-git-receive-pack-request".into()),
                    ("accept", "application/x-git-receive-pack-result".into()),
                ],
                body: receive_request(&updates, &pack),
            },
            2 * 1024 * 1024,
        )
        .await?;
        match reply.status {
            200 => {}
            401 | 403 => {
                return Err(Fail::permanent("The remote refused the access token: it needs permission to push to the repository."));
            }
            s if s >= 500 || s == 429 => return Err(Fail::transient(format!("The remote answered {s} to the push."))),
            s => return Err(Fail::permanent(format!("The remote answered {s} to the push."))),
        }
        let report =
            parse_report(&reply.body).map_err(|e| Fail::permanent(format!("The remote's answer to the push could not be read: {e}")))?;
        if let Err(why) = &report.unpack {
            return Err(Fail::permanent(format!("The remote could not unpack the objects: {why}")));
        }
        for (i, name) in pending {
            let r = &mut results[i];
            match report.refs.iter().find(|(n, _)| *n == name) {
                Some((_, Ok(()))) => {}
                other => {
                    let why = match other {
                        Some((_, Err(w))) => w.clone(),
                        _ => "the remote did not report on it".to_string(),
                    };
                    r.status = "rejected";
                    r.pushed = false;
                    r.remote = remote.get(name.as_str()).copied();
                    r.tree = None;
                    r.message = Some(format!("The remote rejected {}: {why}.", name.rsplit('/').next().unwrap_or(&name)));
                }
            }
        }
    }

    // Record the outcome.
    let diverged: Vec<&RefResult> = results.iter().filter(|r| r.status == "diverged").collect();
    let rejected: Vec<&RefResult> = results.iter().filter(|r| r.status == "rejected").collect();
    let (status, error) = if let Some(r) = diverged.first() {
        ("diverged", r.message.clone())
    } else if let Some(r) = rejected.first() {
        ("error", r.message.clone())
    } else {
        ("ok", None)
    };
    let any_pushed = results.iter().any(|r| r.pushed);
    let (id, status, error) = (app.id.clone(), status.to_string(), error);
    st.db
        .call(move |conn| {
            tx(conn, |x| {
                let t = now();
                for r in &results {
                    x.run(
                        "INSERT INTO git_mirror_refs (app_id, ref_name, remote_oid, tree_oid, version, status, message, pushed_at) VALUES (?,?,?,?,?,?,?,?) \
                         ON CONFLICT (app_id, ref_name) DO UPDATE SET remote_oid = excluded.remote_oid, tree_oid = excluded.tree_oid, version = excluded.version, \
                         status = excluded.status, message = excluded.message, pushed_at = COALESCE(excluded.pushed_at, git_mirror_refs.pushed_at)",
                        params![
                            id,
                            r.name,
                            r.remote.map(|o| git::hex(&o)),
                            r.tree.map(|o| git::hex(&o)),
                            r.version,
                            r.status,
                            r.message,
                            if r.pushed { Some(t) } else { None }
                        ],
                    )?;
                    let _ = r.tag;
                }
                x.run("UPDATE git_mirrors SET last_status = ?, last_error = ? WHERE app_id = ?", params![status, error, id])?;
                if any_pushed {
                    x.run("UPDATE git_mirrors SET last_push_at = ? WHERE app_id = ?", params![t, id])?;
                }
                Ok(())
            })
        })
        .await?;
    Ok(())
}

// ---------- inbound ----------

/// The paths a merge conflict names.
pub fn conflict_paths(p: &Problem) -> Vec<String> {
    p.extra
        .get("conflicts")
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(|c| c.get("path").and_then(Value::as_str).map(String::from)).collect())
        .unwrap_or_default()
}

/// Whether a remote commit is one Brod made or already handled: it is a version's commit (exported or imported), the tip
/// of a ref Brod pushed, or a commit Brod pushed or imported earlier. Such a commit is never imported again.
pub fn already_handled(conn: &Connection, app_id: &str, oid: &Oid) -> Result<Option<&'static str>> {
    let hex = git::hex(oid);
    if conn.exists(
        "SELECT 1 FROM version_git_commits WHERE app_id = ? AND (commit_oid = ? OR source_commit_oid = ?)",
        params![app_id, hex, hex],
    )? {
        return Ok(Some("a commit that is already a version of the app"));
    }
    if conn.exists("SELECT 1 FROM git_mirror_refs WHERE app_id = ? AND remote_oid = ?", params![app_id, hex])? {
        return Ok(Some("a commit Brod pushed"));
    }
    if conn.exists(
        "SELECT 1 FROM git_sync_events WHERE app_id = ? AND remote_oid = ? AND result IN ('pushed', 'imported', 'ignored', 'unchanged')",
        params![app_id, hex],
    )? {
        return Ok(Some("a commit Brod pushed or already handled"));
    }
    Ok(None)
}

static INBOUND: LazyLock<Mutex<HashMap<String, bool>>> = LazyLock::new(Default::default);

/// Look at the remote branch now (in the background). Calls for an app already being looked at are folded into one more
/// look after it.
pub fn spawn_inbound(st: State, app_id: String, source: &'static str) {
    tokio::spawn(async move {
        {
            let mut j = INBOUND.lock().unwrap_or_else(|p| p.into_inner());
            if let Some(dirty) = j.get_mut(&app_id) {
                *dirty = true;
                return;
            }
            j.insert(app_id.clone(), false);
        }
        loop {
            inbound_once(&st, &app_id, source).await;
            let mut j = INBOUND.lock().unwrap_or_else(|p| p.into_inner());
            if j.get(&app_id).copied().unwrap_or(false) {
                j.insert(app_id.clone(), false);
            } else {
                j.remove(&app_id);
                break;
            }
        }
    });
}

async fn inbound_once(st: &State, app_id: &str, source: &'static str) {
    if let Err(e) = inbound_inner(st, app_id, source).await {
        tracing::warn!("git sync of app {app_id} failed: {}", e.message);
        let (id, msg) = (app_id.to_string(), e.message.clone());
        let _ = st
            .db
            .call(move |conn| {
                conn.run("UPDATE git_mirrors SET inbound_status = 'error', inbound_error = ? WHERE app_id = ?", params![msg, id])?;
                Ok(())
            })
            .await;
    }
}

struct SyncEvent<'a> {
    source: &'a str,
    oid: &'a str,
    branch: &'a str,
    result: &'a str,
    version: Option<i64>,
    detail: &'a str,
}

fn record_event(conn: &Connection, app_id: &str, e: &SyncEvent) -> Result<()> {
    conn.run(
        "INSERT INTO git_sync_events (id, app_id, at, source, remote_oid, branch, result, version, detail) VALUES (?,?,?,?,?,?,?,?,?)",
        params![random_id("gse_", 8), app_id, now(), e.source, e.oid, e.branch, e.result, e.version, e.detail],
    )?;
    conn.run(
        "DELETE FROM git_sync_events WHERE app_id = ? AND source != 'push' AND id NOT IN \
         (SELECT id FROM git_sync_events WHERE app_id = ? AND source != 'push' ORDER BY at DESC LIMIT ?)",
        params![app_id, app_id, KEEP_EVENTS],
    )?;
    Ok(())
}

async fn inbound_inner(st: &State, app_id: &str, source: &'static str) -> Result<()> {
    let (id, cfg) = (app_id.to_string(), st.cfg.clone());
    let loaded = st
        .db
        .call(move |conn| {
            let Some(m) = load_mirror(conn, &id)? else { return Ok(None) };
            if !m.enabled || !m.sync_inbound {
                return Ok(None);
            }
            let Some(app) = conn.first("SELECT * FROM apps WHERE id = ?", [id.as_str()], AppRow::from_row)? else { return Ok(None) };
            conn.run("UPDATE git_mirrors SET last_poll_at = ? WHERE app_id = ?", params![now(), id])?;
            let token = m.token(&cfg, conn).map_err(|f| Problem::new(409, "no_token", f.message));
            let who = conn.first(
                "SELECT w.*, u.email, u.name AS uname, u.email_verified_at, m.role FROM workspaces w JOIN members m ON m.workspace_id = w.id JOIN users u ON u.id = m.user_id WHERE w.id = ? AND u.id = ?",
                params![app.workspace_id, app.owner_id],
                |r| {
                    Ok((
                        Workspace::from_row(r)?,
                        User { id: r.get("id")?, email: r.get("email")?, name: r.get("uname")?, email_verified_at: r.get("email_verified_at")? },
                        r.get::<_, String>("role")?,
                    ))
                },
            )?;
            Ok(Some((m, app, token, who)))
        })
        .await?;
    let Some((m, app, token, who)) = loaded else { return Ok(()) };
    let token = token?;
    let Some((workspace, mut user, role)) = who else {
        return Err(Problem::new(409, "no_owner", "The app's owner is no longer in the workspace, so Brod cannot apply a sync as them."));
    };
    user.id = app.owner_id.clone();
    let caller = Caller { workspace, user: user.clone(), role, actor: "git sync".into(), agent: true, read_only: false };

    // The ids Brod gives its own versions must be known before the remote's tip is compared with them.
    let _ = git_export::plan_app(st, app.clone()).await;

    let policy = Policy::from_config(&st.cfg);
    let auth = git_import::basic_auth(&token);
    let advert = git_import::advertise(policy, &m.url, "git-upload-pack", Some(&auth)).await?;
    let ref_name = format!("refs/heads/{}", m.inbound_branch);
    let Some((_, tip)) = advert.refs.iter().find(|(n, _)| *n == ref_name) else {
        return Err(Problem::new(409, "no_branch", format!("The remote has no branch {}.", m.inbound_branch)));
    };
    let tip = *tip;
    let hex = git::hex(&tip);
    if m.last_inbound_oid.as_deref() == Some(hex.as_str()) && m.inbound_status.as_deref() != Some("error") {
        return Ok(());
    }

    // Brod's own commits, and ones already handled, are not imported again.
    let (id, h2) = (app.id.clone(), tip);
    let handled = st.db.call(move |conn| already_handled(conn, &id, &h2)).await?;
    if let Some(why) = handled {
        let (id, branch, hex2, why2) = (app.id.clone(), m.inbound_branch.clone(), hex.clone(), why.to_string());
        st.db
            .call(move |conn| {
                record_event(conn, &id, &SyncEvent { source, oid: &hex2, branch: &branch, result: "ignored", version: None, detail: &why2 })?;
                conn.run(
                    "UPDATE git_mirrors SET last_inbound_oid = ?, inbound_status = 'idle', inbound_error = NULL, inbound_conflicts = NULL WHERE app_id = ?",
                    params![hex2, id],
                )?;
                Ok(())
            })
            .await?;
        return Ok(());
    }

    let pack = git_import::fetch_commit(policy, &m.url, &tip, MAX_PACK, Some(&auth)).await?;
    let objs = git_import::parse_pack(&pack)?;
    let commit = git_import::peel(&objs, tip)?;
    let landing = Landing {
        base_version: None,
        history_all: false,
        environment: Some("staging".into()),
        note: Some(format!("Synced from {} ({})", m.inbound_branch, short(&tip))),
    };
    let outcome = git_import::apply(st, &caller, &app, &objs, commit, &ref_name, landing).await;
    let (id, branch, hex2) = (app.id.clone(), m.inbound_branch.clone(), hex.clone());
    match outcome {
        Ok(v) => {
            let unchanged = v.get("unchanged").and_then(Value::as_bool).unwrap_or(false);
            let version = v
                .get("version")
                .and_then(Value::as_i64)
                .or_else(|| v.get("versions_created").and_then(Value::as_array).and_then(|a| a.last()).and_then(Value::as_i64));
            let result = if unchanged { "unchanged" } else { "imported" };
            let detail = if unchanged { "the commit is already a version of the app".to_string() } else { "landed on staging".to_string() };
            st.db
                .call(move |conn| {
                    record_event(conn, &id, &SyncEvent { source, oid: &hex2, branch: &branch, result, version, detail: &detail })?;
                    conn.run(
                        "UPDATE git_mirrors SET last_inbound_oid = ?, inbound_status = 'ok', inbound_error = NULL, inbound_conflicts = NULL WHERE app_id = ?",
                        params![hex2, id],
                    )?;
                    Ok(())
                })
                .await?;
            Ok(())
        }
        Err(p) if p.code == "merge_conflict" => {
            let paths = conflict_paths(&p);
            let (message, list) = (p.message.clone(), serde_json::to_string(&paths).unwrap_or_default());
            let detail = format!("conflict in {}", paths.join(", "));
            let (id2, hex3) = (id.clone(), hex2.clone());
            st.db
                .call(move |conn| {
                    record_event(conn, &id2, &SyncEvent { source, oid: &hex3, branch: &branch, result: "conflict", version: None, detail: &detail })?;
                    conn.run(
                        "UPDATE git_mirrors SET last_inbound_oid = ?, inbound_status = 'conflict', inbound_error = ?, inbound_conflicts = ? WHERE app_id = ?",
                        params![hex3, message, list, id2],
                    )?;
                    Ok(())
                })
                .await?;
            if user.email.contains('@') {
                let text = format!(
                    "The remote branch {} of {} moved to {}, and its changes could not be merged with what is on staging, so nothing was imported.\n\nConflicting files:\n{}\n\nResolve it by changing those files on the remote or on staging (deploy_app to staging), and the next push to the branch syncs again.",
                    m.inbound_branch,
                    app.slug,
                    short(&tip),
                    paths.iter().map(|p| format!("  {p}")).collect::<Vec<_>>().join("\n")
                );
                if let Err(e) = crate::email::send(st, &user.email, &format!("Brod: git sync conflict in {}", app.slug), &text).await {
                    tracing::warn!("could not tell the owner of a sync conflict: {}", e.message);
                }
            }
            Ok(())
        }
        Err(p) => {
            let (msg, detail) = (p.message.clone(), p.message.clone());
            st.db
                .call(move |conn| {
                    record_event(
                        conn,
                        &id,
                        &SyncEvent { source, oid: &hex2, branch: &branch, result: "error", version: None, detail: &detail },
                    )?;
                    conn.run("UPDATE git_mirrors SET inbound_status = 'error', inbound_error = ? WHERE app_id = ?", params![msg, id])?;
                    Ok(())
                })
                .await?;
            Ok(())
        }
    }
}

/// POST /v1/apps/:slug/git-webhook: a push on the remote. Authenticated by the signature alone.
pub async fn webhook(st: &State, req: &mut Req, slug: &str) -> Result<Response> {
    let ip = crate::abuse::client_ip(&st.cfg, req).unwrap_or_default();
    st.db
        .call(move |conn| {
            crate::abuse::rate_limit(
                conn,
                "git-webhook",
                &ip,
                WEBHOOKS_PER_IP_MINUTE,
                60_000,
                "Too many webhook calls from this address. Wait a minute.",
            )
        })
        .await?;
    let body = req.bytes(WEBHOOK_BODY, "The webhook body").await?;
    let h = |n: &str| req.header(n).map(String::from);
    let (github_sig, gitlab_token, github_event, gitlab_event) =
        (h("x-hub-signature-256"), h("x-gitlab-token"), h("x-github-event"), h("x-gitlab-event"));
    let hint = req.param("workspace");
    let (slug2, cfg) = (slug.to_string(), st.cfg.clone());
    let body2 = body.clone();
    let found = st
        .db
        .call(move |conn| {
            let ids: Vec<String> = match &hint {
                Some(w) => conn.all(
                    "SELECT m.app_id FROM git_mirrors m JOIN apps a ON a.id = m.app_id JOIN workspaces w ON w.id = a.workspace_id WHERE a.slug = ? AND w.slug = ? AND m.sync_inbound = 1",
                    params![slug2, w],
                    |r| r.get::<_, String>(0),
                )?,
                None => conn.all(
                    "SELECT m.app_id FROM git_mirrors m JOIN apps a ON a.id = m.app_id WHERE a.slug = ? AND m.sync_inbound = 1",
                    params![slug2],
                    |r| r.get::<_, String>(0),
                )?,
            };
            for id in ids {
                let Some(m) = load_mirror(conn, &id)? else { continue };
                let Some(secret) = m.webhook(&cfg) else { continue };
                if verify_webhook(&secret, &body2, github_sig.as_deref(), gitlab_token.as_deref()) {
                    crate::abuse::rate_limit(conn, "git-webhook-app", &id, WEBHOOKS_PER_APP_MINUTE, 60_000, "Too many webhook calls for this app. Wait a minute.")?;
                    return Ok(Some(m));
                }
            }
            Ok(None)
        })
        .await?;
    let Some(m) = found else {
        return Err(Problem::new(401, "bad_signature", "The webhook signature is missing or wrong."));
    };
    let Some(push) = parse_push(github_event.as_deref(), gitlab_event.as_deref(), &body) else {
        return Ok(json_response(&json!({ "accepted": true, "ignored": "not a push to a branch" }), 202, &[]));
    };
    if push.branch != m.inbound_branch {
        return Ok(json_response(&json!({ "accepted": true, "ignored": format!("{} is not the synced branch", push.branch) }), 202, &[]));
    }
    let id = m.app_id.clone();
    st.db
        .call({
            let id = id.clone();
            move |conn| {
                conn.run("UPDATE git_mirrors SET last_webhook_at = ? WHERE app_id = ?", params![now(), id])?;
                Ok(())
            }
        })
        .await?;
    spawn_inbound(st.clone(), id, "webhook");
    Ok(json_response(&json!({ "accepted": true }), 202, &[]))
}

/// The background task that looks at remotes whose webhook is quiet: started once from main.rs.
pub async fn poller(st: State) {
    let mut tick = tokio::time::interval(Duration::from_secs(60));
    loop {
        tick.tick().await;
        let minutes = crate::instance::current(&st).await.int("git.sync_poll_minutes");
        if minutes <= 0 {
            continue;
        }
        let every = minutes * 60_000;
        let due = st
            .db
            .call(move |conn| {
                let t = now();
                let rows = conn.all(
                    "SELECT app_id, last_webhook_at, last_poll_at, inbound_status FROM git_mirrors WHERE enabled = 1 AND sync_inbound = 1",
                    (),
                    |r| {
                        Ok((
                            r.get::<_, String>("app_id")?,
                            r.get::<_, Option<i64>>("last_webhook_at")?,
                            r.get::<_, Option<i64>>("last_poll_at")?,
                            r.get::<_, Option<String>>("inbound_status")?,
                        ))
                    },
                )?;
                Ok(rows
                    .into_iter()
                    .filter(|(_, hook, poll, status)| poll_due(t, every, *hook, *poll, status.as_deref()))
                    .map(|(id, ..)| id)
                    .collect::<Vec<_>>())
            })
            .await;
        match due {
            Ok(ids) => {
                for id in ids {
                    spawn_inbound(st.clone(), id, "poll");
                }
            }
            Err(e) => tracing::warn!("git sync poll: {}", e.message),
        }
    }
}

/// Poll when the last poll is older than the interval and no webhook came lately (or the last look failed).
pub fn poll_due(now_ms: i64, every_ms: i64, last_webhook: Option<i64>, last_poll: Option<i64>, status: Option<&str>) -> bool {
    let poll_old = last_poll.is_none_or(|p| now_ms - p >= every_ms);
    let hook_recent = last_webhook.is_some_and(|w| now_ms - w < 2 * every_ms);
    poll_old && (!hook_recent || status == Some("error"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn oid(n: u8) -> Oid {
        [n; 20]
    }

    #[test]
    fn a_receive_request_has_one_command_per_ref_the_capabilities_on_the_first_then_the_pack() {
        let updates = vec![
            Update { name: "refs/heads/main".into(), old: None, new: oid(1) },
            Update { name: "refs/tags/v1".into(), old: Some(oid(2)), new: oid(3) },
        ];
        let body = receive_request(&updates, b"PACKDATA");
        let mut pos = 0;
        let mut lines = Vec::new();
        while let Some(git::Pkt::Data(d)) = git::read_pkt(&body, &mut pos).unwrap() {
            lines.push(String::from_utf8_lossy(d).into_owned());
        }
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0], format!("{} {} refs/heads/main\0report-status agent=brod", "0".repeat(40), "01".repeat(20)));
        assert_eq!(lines[1], format!("{} {} refs/tags/v1", "02".repeat(20), "03".repeat(20)));
        assert_eq!(&body[pos..], b"PACKDATA", "a flush, then the pack");
    }

    fn report(lines: &[&str]) -> Vec<u8> {
        let mut out = Vec::new();
        for l in lines {
            out.extend_from_slice(&git::pkt(format!("{l}\n").as_bytes()));
        }
        out.extend_from_slice(git::FLUSH);
        out
    }

    #[test]
    fn the_report_names_each_ref_ok_or_rejected() {
        let r =
            parse_report(&report(&["unpack ok", "ok refs/heads/main", "ng refs/heads/staging protected branch hook declined"])).unwrap();
        assert_eq!(r.unpack, Ok(()));
        assert_eq!(r.refs[0], ("refs/heads/main".to_string(), Ok(())));
        assert_eq!(r.refs[1], ("refs/heads/staging".to_string(), Err("protected branch hook declined".to_string())));
        let bad = parse_report(&report(&["unpack index-pack abnormal exit", "ng refs/heads/main unpacker error"])).unwrap();
        assert_eq!(bad.unpack, Err("index-pack abnormal exit".to_string()));
    }

    #[test]
    fn a_report_inside_side_band_is_read_and_an_error_band_fails() {
        let inner = report(&["unpack ok", "ok refs/heads/main"]);
        let mut banded = git::pkt(&[&[1u8][..], &inner[..]].concat());
        banded.extend_from_slice(git::FLUSH);
        let r = parse_report(&banded).unwrap();
        assert_eq!(r.refs, vec![("refs/heads/main".to_string(), Ok(()))]);
        let mut err = git::pkt(&[&[3u8][..], b"denied"].concat());
        err.extend_from_slice(git::FLUSH);
        assert_eq!(parse_report(&err).unwrap_err(), "denied");
        assert!(parse_report(b"<html>nope</html>").is_err());
    }

    fn ancestors(list: &[Oid]) -> HashSet<Oid> {
        list.iter().copied().collect()
    }

    #[test]
    fn branches_only_ever_fast_forward() {
        let (old, new) = (oid(1), oid(2));
        let anc = ancestors(&[old, new]);
        let none = HashMap::new();
        assert_eq!(decide_branch(None, new, oid(9), &anc, &none), Decision::Create);
        assert_eq!(decide_branch(Some(new), new, oid(9), &anc, &none), Decision::UpToDate);
        assert_eq!(decide_branch(Some(old), new, oid(9), &anc, &none), Decision::FastForward);
        // A commit the history does not hold, and Brod has never seen: diverged, never forced.
        assert_eq!(decide_branch(Some(oid(7)), new, oid(9), &anc, &none), Decision::Diverged);
    }

    #[test]
    fn a_remote_tip_brod_knows_is_continued_not_forced() {
        let anc = ancestors(&[oid(2)]);
        let mut known = HashMap::new();
        known.insert(oid(7), oid(8));
        // The remote tip is an imported commit with other files: add a commit on top.
        assert_eq!(decide_branch(Some(oid(7)), oid(2), oid(9), &anc, &known), Decision::Continue);
        // With the same files there is nothing to push.
        assert_eq!(decide_branch(Some(oid(7)), oid(2), oid(8), &anc, &known), Decision::UpToDate);
        let (c, data) = continuation(oid(7), oid(9), "Version 3\n\nBrod-Version: 3\n", "apps.test", 1_700_000_000);
        let parsed = git::parse_commit(&data).unwrap();
        assert_eq!((parsed.parents, parsed.tree), (vec![oid(7)], oid(9)));
        assert_eq!(c, git::object_oid(Kind::Commit, &data));
    }

    #[test]
    fn a_tag_is_created_and_never_moved() {
        assert_eq!(decide_tag(None, oid(1)), Decision::Create);
        assert_eq!(decide_tag(Some(oid(1)), oid(1)), Decision::UpToDate);
        assert_eq!(decide_tag(Some(oid(2)), oid(1)), Decision::Diverged);
    }

    #[test]
    fn retries_back_off_and_cap() {
        let secs: Vec<u64> = (1..=6).map(|n| backoff(n).as_secs()).collect();
        assert_eq!(secs, [10, 40, 160, 600, 600, 600]);
        assert_eq!(MAX_TRIES, 5);
    }

    fn sign(secret: &str, body: &[u8]) -> String {
        let mut mac = hmac_sha256(secret);
        mac.update(body);
        format!("sha256={}", hex::encode(mac.finalize().into_bytes()))
    }

    #[test]
    fn webhook_signatures_are_checked_for_github_and_gitlab() {
        let body = br#"{"ref":"refs/heads/main"}"#;
        let good = sign("whsec_x", body);
        assert!(verify_webhook("whsec_x", body, Some(&good), None));
        assert!(!verify_webhook("whsec_x", body, Some(&sign("other", body)), None), "wrong secret");
        assert!(!verify_webhook("whsec_x", b"{}", Some(&good), None), "body changed");
        assert!(!verify_webhook("whsec_x", body, Some("sha256=zz"), None), "not hex");
        assert!(!verify_webhook("whsec_x", body, Some(good.trim_start_matches("sha256=")), None), "no prefix");
        assert!(!verify_webhook("whsec_x", body, None, None), "unsigned");
        assert!(verify_webhook("whsec_x", body, None, Some("whsec_x")));
        assert!(!verify_webhook("whsec_x", body, None, Some("whsec_y")));
        assert!(!verify_webhook("", body, Some(&sign("", body)), Some("")), "an empty secret never verifies");
    }

    #[test]
    fn only_pushes_to_a_branch_are_events() {
        let hex = "ab".repeat(20);
        let body = format!(r#"{{"ref":"refs/heads/main","after":"{hex}"}}"#);
        let e = parse_push(Some("push"), None, body.as_bytes()).unwrap();
        assert_eq!((e.branch.as_str(), e.after), ("main", git::parse_oid(&hex)));
        assert!(parse_push(Some("ping"), None, body.as_bytes()).is_none());
        assert!(parse_push(None, Some("Issue Hook"), body.as_bytes()).is_none());
        assert!(parse_push(None, Some("Push Hook"), body.as_bytes()).is_some());
        assert!(parse_push(Some("push"), None, br#"{"ref":"refs/tags/v1"}"#).is_none(), "a tag");
        let gone = format!(r#"{{"ref":"refs/heads/main","after":"{}"}}"#, "0".repeat(40));
        assert!(parse_push(Some("push"), None, gone.as_bytes()).is_none(), "a deleted branch");
        assert!(parse_push(Some("push"), None, b"not json").is_none());
    }

    #[test]
    fn polling_waits_for_the_interval_and_for_a_quiet_webhook() {
        let every = 600_000;
        assert!(poll_due(10_000_000, every, None, None, None));
        assert!(!poll_due(10_000_000, every, None, Some(9_700_000), None), "polled lately");
        assert!(!poll_due(10_000_000, every, Some(9_900_000), Some(8_000_000), None), "the webhook is working");
        assert!(poll_due(10_000_000, every, Some(1_000_000), Some(8_000_000), None), "the webhook went quiet");
        assert!(poll_due(10_000_000, every, Some(9_900_000), Some(8_000_000), Some("error")), "retry after a failure");
    }

    #[test]
    fn urls_must_be_https_and_public() {
        let cfg = Config::for_tests();
        for ok in ["https://github.com/o/r.git", "https://gitlab.example.com/g/p"] {
            assert!(check_url(&cfg, ok).is_ok(), "{ok}");
        }
        for bad in [
            "http://github.com/o/r.git",
            "https://user:pw@github.com/o/r.git",
            "https://github.com/o/r.git?x=1",
            "https://127.0.0.1/r.git",
            "https://10.0.0.5/r.git",
            "https://localhost/r.git",
            "ssh://git@github.com/o/r.git",
            "not a url",
        ] {
            assert_eq!(check_url(&cfg, bad).unwrap_err().status, 400, "{bad}");
        }
    }

    #[test]
    fn branch_names_are_checked() {
        for ok in ["main", "release/1.0", "brod-staging"] {
            assert!(check_branch(ok).is_ok(), "{ok}");
        }
        for bad in ["", "a..b", "-x", "a b", "/x", "x/", "x.lock", "a//b"] {
            assert!(check_branch(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn conflicts_name_their_paths() {
        let p = Problem::new(409, "merge_conflict", "x").with("conflicts", json!([{ "path": "a.txt" }, { "path": "b/c.js" }]));
        assert_eq!(conflict_paths(&p), ["a.txt", "b/c.js"]);
        assert!(conflict_paths(&Problem::new(400, "x", "y")).is_empty());
    }

    #[tokio::test]
    async fn commits_brod_pushed_or_imported_are_not_imported_again() {
        let db = crate::db::test_db();
        db.call(|conn| {
            let t = now();
            conn.run("INSERT INTO workspaces (id, slug, name, created_at) VALUES ('ws_g', 'g', 'G', ?)", [t])?;
            conn.run("INSERT INTO users (id, email, name, created_at) VALUES ('usr_g', 'g@g.test', 'G', ?)", [t])?;
            conn.run("INSERT INTO apps (id, workspace_id, owner_id, slug, name, created_at) VALUES ('app_g','ws_g','usr_g','g','G',1)", ())?;
            let (a, b, c, d) = (git::hex(&oid(1)), git::hex(&oid(2)), git::hex(&oid(3)), git::hex(&oid(4)));
            conn.run("INSERT INTO version_git_commits (app_id, version, commit_oid, tree_oid) VALUES ('app_g', 1, ?, ?)", params![a, d])?;
            conn.run(
                "INSERT INTO git_mirror_refs (app_id, ref_name, remote_oid, tree_oid, version) VALUES ('app_g', 'refs/heads/main', ?, ?, 1)",
                params![b, d],
            )?;
            record_event(conn, "app_g", &SyncEvent { source: "push", oid: &c, branch: "", result: "pushed", version: Some(1), detail: "" })?;
            assert!(already_handled(conn, "app_g", &oid(1))?.is_some(), "a version's commit");
            assert!(already_handled(conn, "app_g", &oid(2))?.is_some(), "the tip Brod pushed");
            assert!(already_handled(conn, "app_g", &oid(3))?.is_some(), "a continuation Brod pushed");
            assert!(already_handled(conn, "app_g", &oid(9))?.is_none(), "someone else's commit");
            Ok(())
        })
        .await
        .unwrap();
    }
}
