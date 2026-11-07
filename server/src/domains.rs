// SPDX-License-Identifier: AGPL-3.0-only
// Custom domains.
//
// A workspace can serve one app at a domain it owns (shop.example.com), or point a whole domain at the workspace
// (*.apps.example.com: <app>.apps.example.com opens that app, apps.example.com the home page). A domain is claimed,
// then proven with a TXT record at _brod.<domain> holding brod-verify=<token>. Only proven domains are served (and
// get certificates, see tls.rs and /_caddy/ask), and only one workspace can prove a name. Signing in still happens on
// the API host: /auth/app hands the one-time code only to a proven domain of that same app (allowed_host).
//
// A domain whose DNS is on Cloudflare (found from its public NS records, no account or token needed) also gets a link
// to the zone's DNS records, a zone file to import, and a warning when its record looks proxied, which Brod cannot
// serve through. A failed lookup only means those extras are left out. A server that has set up Domain Connect
// (domain_connect.rs) also offers a link that adds the records there once the person confirms.
use crate::db::{Connection, Row, params};
use serde_json::{Map, Value, json};
use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard, OnceLock, PoisonError};
use std::time::{Duration, Instant};

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

/// One query to the DNS-over-HTTPS resolver, as its JSON answer. None when the resolver could not be reached.
async fn doh(st: &State, name: &str, rtype: &str, timeout: Duration) -> Option<Value> {
    let r = st
        .http
        .get(&st.cfg.dns_resolver_url)
        .query(&[("name", name), ("type", rtype)])
        .header("accept", "application/dns-json")
        .timeout(timeout)
        .send()
        .await
        .ok()?;
    if !r.status().is_success() {
        return None;
    }
    r.json().await.ok()
}

/// The TXT strings at a name. None when the resolver could not be reached.
pub async fn txt_records(st: &State, name: &str) -> Option<Vec<String>> {
    let j = doh(st, name, "TXT", Duration::from_secs(10)).await?;
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

// ---------- Cloudflare ----------

/// The DNS records page of a zone. Cloudflare's dashboard asks which account and zone when there is more than one.
const CLOUDFLARE_RECORDS_URL: &str = "https://dash.cloudflare.com/?to=/:account/:zone/dns/records";
/// A page of the domains list should not wait long on DNS. Whatever is not answered by then is left out.
const CLOUDFLARE_LOOKUP: Duration = Duration::from_secs(3);
const CLOUDFLARE_SEEN_FOR: Duration = Duration::from_secs(120);
/// Domain Connect has this long, so that when it is slow the rest of the lookup still arrives in CLOUDFLARE_LOOKUP.
const DOMAIN_CONNECT_LOOKUP: Duration = Duration::from_millis(2500);

fn dns_name(name: &str) -> String {
    name.trim_end_matches('.').to_lowercase()
}
fn answers<'a>(j: &'a Value, section: &str, rtype: i64) -> impl Iterator<Item = (String, &'a str)> {
    j.get(section)
        .and_then(|a| a.as_array())
        .into_iter()
        .flatten()
        .filter(move |x| x.get("type").and_then(|t| t.as_i64()) == Some(rtype))
        .filter_map(|x| Some((dns_name(x.get("name")?.as_str()?), x.get("data")?.as_str()?)))
}
fn is_cloudflare_ns(host: &str) -> bool {
    dns_name(host).ends_with(".ns.cloudflare.com")
}

/// What an NS answer for `q` says about the zone holding `q`: its name and whether Cloudflare runs it, or None when it
/// says nothing and the parent has to be asked. Records for other names do not count: a name that is a CNAME is
/// answered with the nameservers of its target, and that may well be someone else's Cloudflare zone.
fn read_zone(q: &str, j: &Value) -> Option<(String, bool)> {
    if answers(j, "Answer", 5).any(|(name, _)| name == q) {
        return None;
    }
    let ns: Vec<&str> = answers(j, "Answer", 2).filter(|(name, _)| name == q).map(|(_, host)| host).collect();
    if !ns.is_empty() {
        return Some((q.to_string(), ns.iter().all(|host| is_cloudflare_ns(host))));
    }
    answers(j, "Answer", 6).chain(answers(j, "Authority", 6)).find_map(|(name, soa)| {
        let holds_q = q == name || q.ends_with(&format!(".{name}"));
        holds_q.then(|| (name, soa.split_whitespace().next().is_some_and(is_cloudflare_ns)))
    })
}

/// The Cloudflare zone holding a hostname, if it is on Cloudflare.
async fn cloudflare_zone(st: &State, hostname: &str) -> Option<String> {
    let labels: Vec<&str> = hostname.split('.').collect();
    for i in 0..labels.len().saturating_sub(1).min(6) {
        let q = labels[i..].join(".");
        let j = doh(st, &q, "NS", CLOUDFLARE_LOOKUP).await?;
        if let Some((zone, cloudflare)) = read_zone(&q, &j) {
            return cloudflare.then_some(zone);
        }
    }
    None
}

/// Whether public A answers show a name going somewhere other than the target. A proxied record never shows its CNAME
/// and answers with Cloudflare's addresses. A flattened one, as at a zone's root, has no CNAME either but answers with
/// the target's addresses, so that is what they are compared with.
fn differs_from_target(at: &Value, target: &Value) -> bool {
    if answers(at, "Answer", 5).next().is_some() {
        return false;
    }
    let want: Vec<&str> = answers(target, "Answer", 1).map(|(_, ip)| ip).collect();
    let got: Vec<&str> = answers(at, "Answer", 1).map(|(_, ip)| ip).collect();
    !want.is_empty() && !got.is_empty() && !got.iter().any(|ip| want.contains(ip))
}

async fn looks_proxied(st: &State, d: &DomainRow, target: &str) -> bool {
    // Any name under a wildcard record answers for it.
    let name = if d.app_id.is_none() { format!("brod-check.{}", d.hostname) } else { d.hostname.clone() };
    let (at, target) = tokio::join!(doh(st, &name, "A", CLOUDFLARE_LOOKUP), doh(st, target, "A", CLOUDFLARE_LOOKUP));
    matches!((at, target), (Some(at), Some(target)) if differs_from_target(&at, &target))
}

#[derive(Clone)]
struct OnCloudflare {
    zone: String,
    proxied: bool,
    /// Where the provider applies this server's Domain Connect template. The link itself is made per request: the
    /// domain's token differs between the workspaces that claim it, and this is kept by name.
    sync_ux: Option<String>,
}

/// The `host` of a Domain Connect link for this domain, when it can have one: a pending subdomain of the zone for one
/// app. The template's CNAME sits at @, which the spec allows only with hostRequired, so the root of a zone cannot use
/// it, and it cannot make the *.domain record a wildcard domain needs. Those keep the ordinary steps.
fn apply_host<'a>(d: &'a DomainRow, zone: &str) -> Option<&'a str> {
    if d.verified_at.is_some() || d.app_id.is_none() {
        return None;
    }
    d.hostname.strip_suffix(zone)?.strip_suffix('.').filter(|host| !host.is_empty())
}

async fn on_cloudflare(st: &State, d: &DomainRow) -> Option<OnCloudflare> {
    let started = tokio::time::Instant::now();
    let lookup = async {
        let zone = cloudflare_zone(st, &d.hostname).await?;
        let sync_ux = async {
            let dc = st.cfg.domain_connect.as_ref().filter(|_| apply_host(d, &zone).is_some())?;
            tokio::time::timeout_at(started + DOMAIN_CONNECT_LOOKUP, dc.sync_ux(st, &zone)).await.ok().flatten()
        };
        let target = target_of(&st.cfg);
        let (proxied, sync_ux) = tokio::join!(looks_proxied(st, d, &target), sync_ux);
        Some(OnCloudflare { zone, proxied, sync_ux })
    };
    tokio::time::timeout(CLOUDFLARE_LOOKUP, lookup).await.ok().flatten()
}

type CloudflareSeen = HashMap<String, (Instant, Option<OnCloudflare>)>;

/// What the domains list last found, by domain: every redraw of the page reads the list, and a workspace can have 50
/// domains. Adding or verifying a domain always looks again, for someone who has just changed the records.
fn cloudflare_seen() -> MutexGuard<'static, CloudflareSeen> {
    static SEEN: OnceLock<Mutex<CloudflareSeen>> = OnceLock::new();
    SEEN.get_or_init(Default::default).lock().unwrap_or_else(PoisonError::into_inner)
}

async fn on_cloudflare_for_list(st: &State, d: &DomainRow) -> Option<OnCloudflare> {
    if let Some((at, found)) = cloudflare_seen().get(&d.name())
        && at.elapsed() < CLOUDFLARE_SEEN_FOR
    {
        return found.clone();
    }
    let found = on_cloudflare(st, d).await;
    let mut seen = cloudflare_seen();
    seen.retain(|_, (at, _)| at.elapsed() < CLOUDFLARE_SEEN_FOR);
    seen.insert(d.name(), (Instant::now(), found.clone()));
    found
}

async fn on_cloudflare_now(st: &State, d: &DomainRow) -> Option<OnCloudflare> {
    cloudflare_seen().remove(&d.name());
    on_cloudflare(st, d).await
}

/// The domain's two records as a BIND zone file for Cloudflare's Import and Export. The tag makes the CNAME DNS only
/// whatever the import form's "Proxy imported DNS records" box says.
fn cloudflare_zone_file(d: &DomainRow, target: &str) -> String {
    let (h, token, target) = (&d.hostname, &d.token, target.trim_end_matches('.'));
    let cname = if d.app_id.is_none() { format!("*.{h}") } else { h.clone() };
    format!("_brod.{h}. 300 IN TXT \"brod-verify={token}\"\n{cname}. 300 IN CNAME {target}. ; cf_tags=cf-proxied:false\n")
}

fn add_cloudflare(cfg: &Config, d: &DomainRow, m: &mut Map<String, Value>, on: OnCloudflare) {
    let target = target_of(cfg);
    let cname = if d.app_id.is_none() { format!("*.{}", d.hostname) } else { d.hostname.clone() };
    let mut info = json!({
        "zone": on.zone,
        "records_url": CLOUDFLARE_RECORDS_URL,
        "cname_proxy_status": "DNS only",
        "zone_file": cloudflare_zone_file(d, &target),
        "zone_file_name": format!("{}-brod-dns.txt", d.hostname),
    });
    if on.proxied {
        let warning = format!(
            "{cname} does not point straight at {target}. In Cloudflare, set the record to DNS only (grey cloud) and remove any older A or AAAA record there: Brod cannot serve this domain through Cloudflare's proxy."
        );
        info["warning"] = json!(warning);
    }
    let apply_url = on
        .sync_ux
        .as_deref()
        .and_then(|sync_ux| cfg.domain_connect.as_ref()?.apply_url(sync_ux, &on.zone, apply_host(d, &on.zone)?, &d.token));
    if let Some(url) = &apply_url {
        info["apply_url"] = json!(url);
        m.insert(
            "next_step".into(),
            json!(format!(
                "This domain's DNS is on Cloudflare, in the zone {}. Give the person this link to open: {url}. Cloudflare asks them to sign in and confirm, then adds both DNS records. Then verify (POST /v1/domains/<domain>/verify, or set_domain again). \
                 If the link does not work, they can add the records at {CLOUDFLARE_RECORDS_URL}, with the CNAME's proxy status set to DNS only (grey cloud), not Proxied.",
                on.zone
            )),
        );
    } else if d.verified_at.is_none() {
        m.insert(
            "next_step".into(),
            json!(format!(
                "This domain's DNS is on Cloudflare, in the zone {}. Give the person this link to open: {CLOUDFLARE_RECORDS_URL}. There they add both DNS records (choosing the zone if asked), with the CNAME's proxy status set to DNS only (grey cloud), not Proxied. \
                 Or import cloudflare.zone_file there with Import and Export, which sets it for you. Then verify (POST /v1/domains/<domain>/verify, or set_domain again). \
                 Cloudflare flattens a CNAME at the root of a zone, so a bare domain works too.",
                on.zone
            )),
        );
    } else if let Some(w) = info.get("warning").and_then(|w| w.as_str()) {
        m.insert("next_step".into(), json!(w));
    }
    m.insert("cloudflare".into(), info);
}

fn target_of(cfg: &Config) -> String {
    cfg.custom_domain_target.clone().unwrap_or_else(|| hostname_of(&cfg.api_host))
}

fn describe(cfg: &Config, d: &DomainRow) -> Map<String, Value> {
    let wildcard = d.app_id.is_none();
    let target = target_of(cfg);
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
fn result(cfg: &Config, (d, found): (DomainRow, Option<Vec<String>>), cloudflare: Option<OnCloudflare>) -> Value {
    let mut m = describe(cfg, &d);
    if let Some(f) = found {
        m.insert("txt_found".into(), json!(f));
    }
    if let Some(on) = cloudflare {
        add_cloudflare(cfg, &d, &mut m, on);
    }
    Value::Object(m)
}

pub async fn list_domains(st: &State, c: &Caller) -> Result<Value> {
    require_role(c, "builder", "see custom domains")?;
    let ws = c.workspace.id.clone();
    let rows = st
        .db
        .call(move |conn| {
            conn.all(
                "SELECT d.*, a.slug FROM domains d LEFT JOIN apps a ON a.id = d.app_id WHERE d.workspace_id = ? ORDER BY d.hostname",
                [&ws],
                DomainRow::from_row,
            )
        })
        .await?;
    let domains = futures_util::future::join_all(rows.into_iter().map(|d| async move {
        let cloudflare = on_cloudflare_for_list(st, &d).await;
        result(&st.cfg, (d, None), cloudflare)
    }))
    .await;
    Ok(json!({ "workspace": c.workspace.slug, "domains": domains }))
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
    let (checked, cloudflare) = tokio::join!(check(st, c, row.clone(), true), on_cloudflare_now(st, &row));
    Ok(result(&st.cfg, checked?, cloudflare))
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
    let (checked, cloudflare) = tokio::join!(check(st, c, d.clone(), false), on_cloudflare_now(st, &d));
    Ok(result(&st.cfg, checked?, cloudflare))
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
    /// `<app>`.`<wildcard domain>`: the app with this slug in the workspace with this slug.
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

    const CF_SOA: &str = "addyson.ns.cloudflare.com. dns.cloudflare.com. 2418963829 10000 2400 604800 1800";

    #[test]
    fn finds_the_cloudflare_zone_from_ns_answers() {
        // These are the shapes cloudflare-dns.com returned for real names.
        let apex = json!({ "Answer": [
            { "name": "brod.sh", "type": 2, "data": "lou.ns.cloudflare.com." },
            { "name": "brod.sh", "type": 2, "data": "addyson.ns.cloudflare.com." } ] });
        assert_eq!(read_zone("brod.sh", &apex), Some(("brod.sh".into(), true)));

        let below = json!({ "Status": 0, "Authority": [{ "name": "brod.sh", "type": 6, "data": CF_SOA }] });
        assert_eq!(read_zone("www.brod.sh", &below), Some(("brod.sh".into(), true)));

        let elsewhere = json!({ "Answer": [
            { "name": "github.com", "type": 2, "data": "dns1.p08.nsone.net." } ] });
        assert_eq!(read_zone("github.com", &elsewhere), Some(("github.com".into(), false)));
        let elsewhere_soa =
            json!({ "Authority": [{ "name": "example.org", "type": 6, "data": "ns1.example.net. h.example.net. 1 2 3 4 5" }] });
        assert_eq!(read_zone("shop.example.org", &elsewhere_soa), Some(("example.org".into(), false)));

        assert_eq!(read_zone("shop.example.org", &json!({ "Status": 0 })), None);
    }

    #[test]
    fn a_cname_answer_does_not_make_someone_elses_zone_ours() {
        // A customer's name already pointed at brod.sh is answered with brod.sh's own nameservers.
        let chain = json!({ "Answer": [
            { "name": "shop.example.org", "type": 5, "data": "brod.sh." },
            { "name": "brod.sh", "type": 2, "data": "lou.ns.cloudflare.com." } ] });
        assert_eq!(read_zone("shop.example.org", &chain), None);
        // An authority record for a zone that does not hold the name says nothing either.
        let other = json!({ "Authority": [{ "name": "brod.sh", "type": 6, "data": CF_SOA }] });
        assert_eq!(read_zone("shop.example.org", &other), None);
        // Nor does a parent ending in the same letters.
        assert_eq!(read_zone("shop.notbrod.sh", &other), None);
    }

    #[test]
    fn tells_a_proxied_name_from_a_dns_only_one() {
        let target = json!({ "Answer": [{ "name": "brod.sh", "type": 1, "data": "89.58.60.193" }] });
        let proxied = json!({ "Answer": [{ "name": "shop.example.org", "type": 1, "data": "104.21.1.1" }] });
        assert!(differs_from_target(&proxied, &target));
        let dns_only = json!({ "Answer": [
            { "name": "shop.example.org", "type": 5, "data": "brod.sh." },
            { "name": "brod.sh", "type": 1, "data": "89.58.60.193" } ] });
        assert!(!differs_from_target(&dns_only, &target));
        let flattened = json!({ "Answer": [{ "name": "example.org", "type": 1, "data": "89.58.60.193" }] });
        assert!(!differs_from_target(&flattened, &target), "a CNAME at the root of a zone");
        assert!(!differs_from_target(&json!({ "Status": 3 }), &target), "no record yet");
        assert!(!differs_from_target(&proxied, &json!({ "Status": 3 })), "nothing to compare with");
    }

    fn row(app: Option<&str>) -> DomainRow {
        DomainRow {
            id: "dom_1".into(),
            hostname: "shop.example.org".into(),
            workspace_id: "w".into(),
            app_id: app.map(String::from),
            token: "abc".into(),
            verified_at: None,
            slug: None,
        }
    }

    #[test]
    fn only_a_pending_subdomain_for_one_app_can_have_an_apply_link() {
        assert_eq!(apply_host(&row(Some("a")), "example.org"), Some("shop"));
        assert_eq!(apply_host(&DomainRow { hostname: "a.b.example.org".into(), ..row(Some("a")) }, "example.org"), Some("a.b"));
        assert_eq!(apply_host(&row(Some("a")), "shop.example.org"), None, "the root of a zone");
        assert_eq!(apply_host(&row(None), "example.org"), None, "a wildcard domain");
        assert_eq!(apply_host(&DomainRow { verified_at: Some(1), ..row(Some("a")) }, "example.org"), None, "already verified");
        assert_eq!(apply_host(&row(Some("a")), "ple.org"), None, "a zone that only ends in the same letters");
    }

    #[test]
    fn with_no_provider_support_the_cloudflare_steps_are_the_ordinary_ones() {
        let cfg = Config::for_tests();
        let mut m = Map::new();
        add_cloudflare(&cfg, &row(Some("a")), &mut m, OnCloudflare { zone: "example.org".into(), proxied: false, sync_ux: None });
        assert!(m["cloudflare"].get("apply_url").is_none());
        assert_eq!(m["cloudflare"]["records_url"], CLOUDFLARE_RECORDS_URL);
        assert!(m["next_step"].as_str().unwrap().contains(CLOUDFLARE_RECORDS_URL));
        // A provider answer kept from earlier means nothing to a server with no key.
        let mut m = Map::new();
        add_cloudflare(
            &cfg,
            &row(Some("a")),
            &mut m,
            OnCloudflare { zone: "example.org".into(), proxied: false, sync_ux: Some("https://dash.cloudflare.com/domainconnect".into()) },
        );
        assert!(m["cloudflare"].get("apply_url").is_none());
    }

    #[test]
    fn the_zone_file_keeps_the_cname_out_of_the_proxy() {
        assert_eq!(
            cloudflare_zone_file(&row(Some("a")), "brod.sh"),
            "_brod.shop.example.org. 300 IN TXT \"brod-verify=abc\"\nshop.example.org. 300 IN CNAME brod.sh. ; cf_tags=cf-proxied:false\n"
        );
        assert!(cloudflare_zone_file(&row(None), "brod.sh.").contains("\n*.shop.example.org. 300 IN CNAME brod.sh. ;"));
    }
}
