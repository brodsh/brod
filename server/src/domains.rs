// Custom domains. Mirrors src/domains.ts: the same checks in the same order, the same errors, the same JSON.
//
// A workspace can serve one app at a domain it owns (shop.example.com), or point a whole domain at the workspace
// (*.apps.example.com: <app>.apps.example.com opens that app, apps.example.com the home page). A domain is claimed,
// then proven with a TXT record at _brod.<domain> holding brod-verify=<token>. Only proven domains are served (and
// get certificates, see tls.rs and /_caddy/ask), and only one workspace can prove a name. Signing in still happens on
// the API host: /auth/app hands the one-time code only to a proven domain of that same app (allowed_host).
use crate::db::{Connection, Row, params};
use serde_json::{Map, Value, json};

use crate::config::Config;
use crate::db::{Sql, event, tx};
use crate::model::{AppRow, Caller, js_string};
use crate::people::require_role;
use crate::problem::{Problem, Result};
use crate::state::State;
use crate::util::{host_origin, is_local, iso, now, random_id};

pub const DOMAINS_PER_WORKSPACE: i64 = 50;

#[derive(Clone, Debug)]
pub struct DomainRow {
    pub id: String,
    pub hostname: String,
    pub workspace_id: String,
    pub app_id: Option<String>,
    pub token: String,
    pub verified_at: Option<i64>,
    /// The app's slug, for an app domain.
    pub slug: Option<String>,
}

impl DomainRow {
    fn from_row(r: &Row) -> Result<DomainRow> {
        Ok(DomainRow {
            id: r.get("id")?,
            hostname: r.get("hostname")?,
            workspace_id: r.get("workspace_id")?,
            app_id: r.get("app_id")?,
            token: r.get("token")?,
            verified_at: r.get("verified_at")?,
            slug: r.get("slug")?,
        })
    }
    fn name(&self) -> String {
        if self.app_id.is_none() { format!("*.{}", self.hostname) } else { self.hostname.clone() }
    }
}

fn valid_label(l: &str) -> bool {
    let b = l.as_bytes();
    !b.is_empty()
        && b.len() <= 63
        && b.iter().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
        && b[0] != b'-'
        && b[b.len() - 1] != b'-'
}
fn hostname_of(host_and_port: &str) -> String {
    host_and_port.split(':').next().unwrap_or("").to_lowercase()
}

/// "Shop.Example.com." -> shop.example.com; "*.apps.example.com" -> apps.example.com as a wildcard.
pub fn norm_domain(cfg: &Config, raw: &str) -> Result<(String, bool)> {
    let mut h = raw.trim().to_lowercase();
    for scheme in ["http://", "https://"] {
        if let Some(rest) = h.strip_prefix(scheme) {
            h = rest.to_string();
        }
    }
    if let Some(i) = h.find(['/', '?', '#']) {
        h.truncate(i);
    }
    if h.ends_with('.') {
        h.pop();
    }
    let wildcard = h.starts_with("*.");
    if wildcard {
        h = h[2..].to_string();
    }
    let labels: Vec<&str> = h.split('.').collect();
    let numeric_tld = labels.last().is_some_and(|l| l.bytes().all(|b| b.is_ascii_digit()));
    if h.len() > 253 || labels.len() < 2 || !labels.iter().all(|l| valid_label(l)) || numeric_tld {
        return Err(Problem::new(
            400,
            "bad_domain",
            format!(
                "\"{raw}\" is not a domain name. Give one like shop.example.com, or *.apps.example.com to serve every app in the workspace."
            ),
        ));
    }
    for own in [hostname_of(&cfg.api_host), hostname_of(&cfg.apps_domain)] {
        if h == own || h.ends_with(&format!(".{own}")) {
            return Err(Problem::new(400, "bad_domain", format!("{h} is one of Brod's own addresses. Use a domain you own.")));
        }
    }
    Ok((h, wildcard))
}

/// A TXT record as resolvers print it: one or more quoted strings ("a" "b"), joined.
pub fn parse_txt(data: &str) -> String {
    let (mut parts, mut cur, mut inside, mut escaped, mut any) = (String::new(), String::new(), false, false, false);
    for ch in data.chars() {
        if !inside {
            if ch == '"' {
                inside = true;
                any = true;
            }
            continue;
        }
        if escaped {
            cur.push(ch);
            escaped = false;
        } else if ch == '\\' {
            escaped = true;
        } else if ch == '"' {
            parts.push_str(&cur);
            cur.clear();
            inside = false;
        } else {
            cur.push(ch);
        }
    }
    if any && !inside { parts } else { data.to_string() }
}

/// The TXT strings at a name, from a DNS-over-HTTPS resolver. None when the resolver could not be reached.
pub async fn txt_records(st: &State, name: &str) -> Option<Vec<String>> {
    let r = st
        .http
        .get(&st.cfg.dns_resolver_url)
        .query(&[("name", name), ("type", "TXT")])
        .header("accept", "application/dns-json")
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .await
        .ok()?;
    if !r.status().is_success() {
        return None;
    }
    let j: Value = r.json().await.ok()?;
    Some(
        j.get("Answer")
            .and_then(|a| a.as_array())
            .map(|a| {
                a.iter()
                    .filter(|x| x.get("type").and_then(|t| t.as_i64()) == Some(16))
                    .filter_map(|x| x.get("data").and_then(|d| d.as_str()).map(parse_txt))
                    .collect()
            })
            .unwrap_or_default(),
    )
}

fn describe(cfg: &Config, d: &DomainRow) -> Map<String, Value> {
    let wildcard = d.app_id.is_none();
    let target = cfg.custom_domain_target.clone().unwrap_or_else(|| hostname_of(&cfg.api_host));
    let verified = d.verified_at.is_some();
    let mut m = Map::new();
    m.insert("domain".into(), json!(d.name()));
    m.insert("kind".into(), json!(if wildcard { "workspace" } else { "app" }));
    if !wildcard {
        m.insert("app".into(), json!(d.slug));
    }
    m.insert("status".into(), json!(if verified { "verified" } else { "pending" }));
    let at = if wildcard { format!("<app>.{}", d.hostname) } else { d.hostname.clone() };
    m.insert("url".into(), json!(host_origin(cfg, &at)));
    if let Some(v) = d.verified_at {
        m.insert("verified_at".into(), json!(iso(v)));
    }
    m.insert(
        "dns".into(),
        json!([
            { "type": "TXT", "name": format!("_brod.{}", d.hostname), "value": format!("brod-verify={}", d.token), "purpose": "Proves the workspace owns the domain. Keep it." },
            { "type": "CNAME", "name": if wildcard { format!("*.{}", d.hostname) } else { d.hostname.clone() }, "value": target, "purpose": "Sends visitors to Brod." },
        ]),
    );
    let next = if verified {
        if wildcard {
            format!("Every app in the workspace opens at <app>.{}.", d.hostname)
        } else {
            format!("The app opens at {}.", host_origin(cfg, &d.hostname))
        }
    } else {
        format!(
            "Add both DNS records at your DNS provider, then verify (POST /v1/domains/<domain>/verify, or set_domain again). DNS changes can take a few minutes to show. \
             A bare domain such as example.com cannot have a CNAME: use your provider's ALIAS, ANAME or CNAME flattening to {target} instead."
        )
    };
    m.insert("next_step".into(), json!(next));
    m
}

fn find(conn: &Connection, workspace_id: &str, hostname: &str) -> Result<Option<DomainRow>> {
    conn.first(
        "SELECT d.*, a.slug FROM domains d LEFT JOIN apps a ON a.id = d.app_id WHERE d.hostname = ? AND d.workspace_id = ?",
        [hostname, workspace_id],
        DomainRow::from_row,
    )
}
fn role_for(c: &Caller, wildcard: bool, verb: &str) -> Result<()> {
    if wildcard {
        require_role(c, "admin", &format!("{verb} a domain for the whole workspace"))
    } else {
        require_role(c, "builder", &format!("{verb} custom domains"))
    }
}
fn taken(hostname: &str) -> Problem {
    Problem::new(409, "domain_taken", format!("Another workspace has already proven it owns {hostname}."))
}

/// Look for the TXT record and mark the domain proven when it is there. Returns the row as it now stands, and the
/// TXT values found when they did not match.
async fn check(st: &State, c: &Caller, d: DomainRow, quiet: bool) -> Result<(DomainRow, Option<Vec<String>>)> {
    if d.verified_at.is_some() {
        return Ok((d, None));
    }
    let Some(found) = txt_records(st, &format!("_brod.{}", d.hostname)).await else {
        if quiet {
            return Ok((d, None));
        }
        return Err(Problem::new(502, "dns_unavailable", "The DNS lookup failed. Try verifying again in a minute."));
    };
    let want = format!("brod-verify={}", d.token);
    if !found.iter().any(|v| v.trim() == want) {
        return Ok((d, Some(found)));
    }
    let (c2, d2) = (c.clone(), d.clone());
    let at = st
        .db
        .call(move |conn| {
            if conn.exists("SELECT 1 FROM domains WHERE hostname = ? AND verified_at IS NOT NULL", [&d2.hostname])? {
                return Err(taken(&d2.hostname));
            }
            let at = now();
            tx(conn, |x| {
                x.run("UPDATE domains SET verified_at = ? WHERE id = ? AND verified_at IS NULL", params![at, d2.id])?;
                event(x, &c2.workspace.id, &c2.actor, d2.app_id.as_deref(), "domain_verified", &d2.name())
            })
            // Lost a race on the domains_verified index.
            .map_err(|e| if e.is_internal() { taken(&d2.hostname) } else { e })?;
            Ok(at)
        })
        .await?;
    Ok((DomainRow { verified_at: Some(at), ..d }, None))
}
fn result(cfg: &Config, (d, found): (DomainRow, Option<Vec<String>>)) -> Value {
    let mut m = describe(cfg, &d);
    if let Some(f) = found {
        m.insert("txt_found".into(), json!(f));
    }
    Value::Object(m)
}

pub fn list_domains(conn: &Connection, cfg: &Config, c: &Caller) -> Result<Value> {
    require_role(c, "builder", "see custom domains")?;
    let rows = conn.all(
        "SELECT d.*, a.slug FROM domains d LEFT JOIN apps a ON a.id = d.app_id WHERE d.workspace_id = ? ORDER BY d.hostname",
        [&c.workspace.id],
        DomainRow::from_row,
    )?;
    Ok(json!({ "workspace": c.workspace.slug, "domains": rows.iter().map(|d| Value::Object(describe(cfg, d))).collect::<Vec<_>>() }))
}

/// Claim a domain for an app (give app) or, as an admin, for the whole workspace (give *.domain).
pub async fn add_domain(st: &State, c: &Caller, domain: &str, app: Option<String>) -> Result<Value> {
    let (hostname, wildcard) = norm_domain(&st.cfg, domain)?;
    let app_ref = app.filter(|a| !a.trim().is_empty());
    if wildcard && app_ref.is_some() {
        return Err(Problem::new(
            400,
            "bad_domain",
            format!(
                "*.{hostname} serves every app in the workspace, so leave out \"app\". To give one app a domain, name it without \"*.\"."
            ),
        ));
    }
    if !wildcard && app_ref.is_none() {
        return Err(Problem::new(
            400,
            "need_app",
            format!("Give \"app\" to serve one app at {hostname}, or ask for *.{hostname} to serve every app in the workspace under it."),
        ));
    }
    role_for(c, wildcard, "add")?;
    let (c2, actor) = (c.clone(), c.actor.clone());
    let row = st
        .db
        .call(move |conn| {
            let app = match &app_ref {
                Some(a) => Some(crate::control::get_app(conn, &c2, a)?),
                None => None,
            };
            if let Some(had) = find(conn, &c2.workspace.id, &hostname)? {
                if had.app_id != app.as_ref().map(|a| a.id.clone()) {
                    let what = match &had.slug {
                        Some(s) => format!("for {s}"),
                        None => "for every app".into(),
                    };
                    return Err(Problem::new(
                        409,
                        "domain_in_use",
                        format!("{hostname} is already set up in this workspace {what}. Remove it first."),
                    ));
                }
                return Ok(had);
            }
            if conn.exists("SELECT 1 FROM domains WHERE hostname = ? AND verified_at IS NOT NULL", [&hostname])? {
                return Err(taken(&hostname));
            }
            if conn.count("SELECT COUNT(*) AS n FROM domains WHERE workspace_id = ?", [&c2.workspace.id])? >= DOMAINS_PER_WORKSPACE {
                return Err(Problem::new(
                    429,
                    "too_many_domains",
                    format!("A workspace can have {DOMAINS_PER_WORKSPACE} custom domains. Remove one first."),
                ));
            }
            let d = DomainRow {
                id: random_id("dom_", 8),
                hostname,
                workspace_id: c2.workspace.id.clone(),
                app_id: app.as_ref().map(|a| a.id.clone()),
                token: random_id("", 16),
                verified_at: None,
                slug: app.map(|a| a.slug),
            };
            tx(conn, |x| {
                x.run(
                    "INSERT INTO domains (id, hostname, workspace_id, app_id, token, verified_at, created_by, created_at) VALUES (?,?,?,?,?,?,?,?)",
                    params![d.id, d.hostname, d.workspace_id, d.app_id, d.token, None::<i64>, actor, now()],
                )?;
                event(x, &c2.workspace.id, &c2.actor, d.app_id.as_deref(), "domain_added", &d.name())
            })?;
            Ok(d)
        })
        .await?;
    // The records may already be there, for example when a domain moves between apps.
    Ok(result(&st.cfg, check(st, c, row, true).await?))
}

async fn mine(st: &State, c: &Caller, domain: &str, verb: &'static str) -> Result<DomainRow> {
    let (hostname, _) = norm_domain(&st.cfg, domain)?;
    let ws = c.workspace.id.clone();
    let h = hostname.clone();
    let d = st.db.call(move |conn| find(conn, &ws, &h)).await?;
    let Some(d) = d else {
        return Err(Problem::new(404, "not_found", format!("{hostname} is not set up in this workspace. Add it first.")));
    };
    role_for(c, d.app_id.is_none(), verb)?;
    Ok(d)
}

pub async fn verify_domain(st: &State, c: &Caller, domain: &str) -> Result<Value> {
    let d = mine(st, c, domain, "verify").await?;
    Ok(result(&st.cfg, check(st, c, d, false).await?))
}

pub async fn remove_domain(st: &State, c: &Caller, domain: &str) -> Result<Value> {
    let d = mine(st, c, domain, "remove").await?;
    let c2 = c.clone();
    let name = d.name();
    let n = name.clone();
    st.db
        .call(move |conn| {
            tx(conn, |x| {
                x.run("DELETE FROM domains WHERE id = ?", [&d.id])?;
                event(x, &c2.workspace.id, &c2.actor, d.app_id.as_deref(), "domain_removed", &n)
            })
        })
        .await?;
    Ok(json!({ "removed": name }))
}

/// For set_domain: add a domain, check a pending one again, or remove one.
pub async fn set_domain(st: &State, c: &Caller, a: &Map<String, Value>) -> Result<Value> {
    let domain = match a.get("domain") {
        None | Some(Value::Null) => String::new(),
        Some(v) => js_string(v),
    };
    if matches!(a.get("remove"), Some(Value::Bool(true))) {
        return remove_domain(st, c, &domain).await;
    }
    let app = match a.get("app") {
        Some(Value::String(s)) => Some(s.clone()),
        _ => None,
    };
    let (hostname, _) = norm_domain(&st.cfg, &domain)?;
    let ws = c.workspace.id.clone();
    let had = st.db.call(move |conn| find(conn, &ws, &hostname)).await?;
    if let Some(had) = had {
        let same = match &app {
            None => true,
            Some(a) => a.trim().is_empty() || Some(a.trim().to_lowercase()) == had.slug,
        };
        if same {
            return verify_domain(st, c, &domain).await;
        }
    }
    add_domain(st, c, &domain, app).await
}

/// An app's own domains and the addresses it gets from the workspace's wildcard domains, for get_status.
pub fn app_domains(conn: &Connection, cfg: &Config, app: &AppRow) -> Result<Value> {
    let rows = conn.all(
        "SELECT * FROM domains WHERE (app_id = ? OR (app_id IS NULL AND workspace_id = ?)) ORDER BY hostname",
        [&app.id, &app.workspace_id],
        |r| Ok((r.get::<_, String>("hostname")?, r.get::<_, Option<String>>("app_id")?, r.get::<_, Option<i64>>("verified_at")?)),
    )?;
    Ok(Value::Array(
        rows.into_iter()
            .map(|(h, app_id, verified_at)| {
                let at = if app_id.is_some() { h } else { format!("{}.{h}", app.slug) };
                json!({ "domain": at, "status": if verified_at.is_some() { "verified" } else { "pending" }, "url": host_origin(cfg, &at) })
            })
            .collect(),
    ))
}

// ---------- serving ----------

/// The hostname of a request's host, or None when it carries a port outside local development.
fn served_name(cfg: &Config, host: &str) -> Option<String> {
    let host = host.to_lowercase();
    match host.split_once(':') {
        Some(_) if !is_local(&cfg.apps_domain) => None,
        Some((name, _)) => Some(name.to_string()),
        None => Some(host),
    }
}

/// What a custom domain serves.
#[derive(Debug, PartialEq)]
pub enum Target {
    /// One app, by id.
    App(String),
    /// <app>.<wildcard domain>: the app with this slug in the workspace with this slug.
    Wildcard { workspace: String, slug: String },
    /// The wildcard domain itself: the workspace home page.
    Home(String),
}

pub fn resolve_host(conn: &Connection, cfg: &Config, host: &str) -> Result<Option<Target>> {
    let Some(name) = served_name(cfg, host) else { return Ok(None) };
    let (first, parent) = name.split_once('.').unwrap_or((name.as_str(), ""));
    let d = conn.first(
        "SELECT d.hostname, d.app_id, w.slug AS wslug FROM domains d JOIN workspaces w ON w.id = d.workspace_id
         WHERE d.verified_at IS NOT NULL AND (d.hostname = ? OR (d.hostname = ? AND d.app_id IS NULL)) ORDER BY length(d.hostname) DESC LIMIT 1",
        [name.as_str(), parent],
        |r| Ok((r.get::<_, String>(0)?, r.get::<_, Option<String>>(1)?, r.get::<_, String>(2)?)),
    )?;
    Ok(match d {
        None => None,
        Some((h, Some(app_id), _)) if h == name => Some(Target::App(app_id)),
        Some((h, None, wslug)) if h == name => Some(Target::Home(wslug)),
        Some((_, _, wslug)) if valid_label(first) => Some(Target::Wildcard { workspace: wslug, slug: first.to_string() }),
        Some(_) => None,
    })
}

/// Whether `host` is a proven address of this app, so a sign-in for it may be handed there.
pub fn allowed_host(conn: &Connection, cfg: &Config, app: &AppRow, host: &str) -> Result<bool> {
    let Some(name) = served_name(cfg, host) else { return Ok(false) };
    let (first, parent) = name.split_once('.').unwrap_or((name.as_str(), ""));
    conn.exists(
        "SELECT 1 FROM domains WHERE verified_at IS NOT NULL AND ((hostname = ? AND app_id = ?) OR (hostname = ? AND app_id IS NULL AND workspace_id = ? AND ? = ?))",
        params![name, app.id, parent, app.workspace_id, first, app.slug],
    )
}

/// Whether a certificate may be issued for `host`: a proven app domain, a proven wildcard domain itself, or an
/// existing app under a proven wildcard domain. For on-demand TLS (tls.rs) and /_caddy/ask.
pub fn may_serve(conn: &Connection, cfg: &Config, host: &str) -> Result<bool> {
    Ok(match resolve_host(conn, cfg, host)? {
        None => false,
        Some(Target::App(_)) | Some(Target::Home(_)) => true,
        Some(Target::Wildcard { workspace, slug }) => conn
            .exists("SELECT 1 FROM apps a JOIN workspaces w ON w.id = a.workspace_id WHERE w.slug = ? AND a.slug = ?", [workspace, slug])?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalises_and_refuses_domains() {
        let cfg = Config::for_tests();
        assert_eq!(norm_domain(&cfg, " Shop.Example.COM. ").unwrap(), ("shop.example.com".into(), false));
        assert_eq!(norm_domain(&cfg, "https://shop.example.com/x").unwrap(), ("shop.example.com".into(), false));
        assert_eq!(norm_domain(&cfg, "*.apps.example.com").unwrap(), ("apps.example.com".into(), true));
        for bad in ["", "localhost", "x.localhost", "not a domain", "1.2.3.4", "-a.example.com", "a..b"] {
            assert_eq!(norm_domain(&cfg, bad).unwrap_err().code, "bad_domain", "{bad}");
        }
    }

    #[test]
    fn reads_txt_records_as_resolvers_print_them() {
        assert_eq!(parse_txt("\"brod-verify=abc\""), "brod-verify=abc");
        assert_eq!(parse_txt("\"brod-verify=\" \"abc\""), "brod-verify=abc");
        assert_eq!(parse_txt("\"a \\\"quoted\\\" b\""), "a \"quoted\" b");
        assert_eq!(parse_txt("bare"), "bare");
    }
}
