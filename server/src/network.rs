// Outside addresses: an app may only send data to the hosts it declares. A scan cannot prove code is harmless, so Brod
// does not try to; it makes leaving undeclared impossible instead, in both places an app's code runs:
//
//   - server code: every outgoing fetch passes the runtime's outbound gate (AppOutbound in deploy/runtime/host.js),
//     which checks the host against the app's declaration;
//   - the browser: every response from the app carries a Content-Security-Policy built from the declaration, so the
//     page cannot fetch, post, load or connect anywhere else; the browser reports what it stopped to /_brod/csp.
//
// An app declares its hosts in the "network" list of its brod.json, next to its settings:
//
//   { "network": ["api.stripe.com", "*.googleapis.com"] }
//
// No list means the app talks to its own address only. The declaration is kept with the version and travels with
// marketplace releases, so an installer sees and approves it, and approves again when an update adds a host.
//
// BROD_NETWORK sets what happens to an undeclared request: "log" (the default) lets it through and records it, so
// makers can complete their declarations first; "enforce" refuses it and records it; "off" does neither.
use crate::db::{Connection, params};
use axum::http::{HeaderName, HeaderValue};
use axum::response::Response;
use serde_json::{Value, json};

use crate::config::{Config, NetworkPolicy};
use crate::db::Sql;
use crate::model::AppRow;
use crate::problem::{Problem, Result};
use crate::tar::BundleFile;
use crate::util::{iso, now};

pub const MAX_HOSTS: usize = 30;
/// An app keeps at most this many distinct undeclared hosts on record, so reports cannot fill the database.
const MAX_REPORTED_HOSTS: i64 = 200;

fn bad(msg: String) -> Problem {
    Problem::new(400, "bad_network", msg)
}

/// "api.stripe.com" or "*.googleapis.com": a host name with at least two labels, an optional "*." in front, no scheme,
/// port or path.
pub fn valid_host(h: &str) -> bool {
    let name = h.strip_prefix("*.").unwrap_or(h);
    let labels: Vec<&str> = name.split('.').collect();
    name.len() <= 253
        && labels.len() >= 2
        && labels.iter().all(|l| {
            let b = l.as_bytes();
            !b.is_empty()
                && b.len() <= 63
                && b.iter().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
                && b[0] != b'-'
                && b[b.len() - 1] != b'-'
        })
}

/// Whether a host is covered by a declaration. "*.example.com" covers its subdomains, not example.com itself, as in CSP.
pub fn allowed(declared: &[String], host: &str) -> bool {
    let host = host.to_ascii_lowercase();
    declared.iter().any(|d| match d.strip_prefix("*.") {
        Some(base) => host.len() > base.len() + 1 && host.ends_with(base) && host.as_bytes()[host.len() - base.len() - 1] == b'.',
        None => *d == host,
    })
}

/// Read the "network" list from a bundle's brod.json, as the JSON kept with the version. None: it declares no hosts.
/// A list Brod cannot use refuses the deploy, so the maker sees the mistake.
pub fn from_bundle(files: &[BundleFile]) -> Result<Option<String>> {
    let manifest = crate::settings::MANIFEST;
    let Some(f) = files.iter().find(|f| f.path == manifest) else { return Ok(None) };
    // settings::from_bundle has already refused a brod.json that is not a JSON object.
    let Ok(Value::Object(doc)) = serde_json::from_slice::<Value>(&f.bytes) else { return Ok(None) };
    let Some(list) = doc.get("network") else { return Ok(None) };
    let Some(list) = list.as_array() else {
        return Err(bad(format!("\"network\" in {manifest} is a list of host names, like [\"api.stripe.com\"].")));
    };
    if list.len() > MAX_HOSTS {
        return Err(bad(format!("An app can declare at most {MAX_HOSTS} outside hosts; {manifest} has {}.", list.len())));
    }
    let mut out: Vec<String> = Vec::new();
    for h in list {
        let raw = h.as_str().unwrap_or("").trim().to_ascii_lowercase();
        if !valid_host(&raw) {
            return Err(bad(format!(
                "{manifest}: {h} is not a host name. Write hosts without https:// or a path, like \"api.stripe.com\" or \"*.googleapis.com\"."
            )));
        }
        if !out.contains(&raw) {
            out.push(raw);
        }
    }
    if out.is_empty() { Ok(None) } else { Ok(Some(json!(out).to_string())) }
}

pub fn parse(json: Option<String>) -> Vec<String> {
    json.and_then(|j| serde_json::from_str::<Vec<String>>(&j).ok()).unwrap_or_default()
}

/// The hosts a version of an app declares. A marketplace preview sandbox runs a release by its listing's id.
pub fn declared(conn: &Connection, app_id: &str, version: i64) -> Result<Vec<String>> {
    let sql = if app_id.starts_with("lst_") {
        "SELECT network FROM releases WHERE listing_id = ? AND n = ?"
    } else {
        "SELECT network FROM versions WHERE app_id = ? AND n = ?"
    };
    Ok(parse(conn.first(sql, params![app_id, version], |r| r.get::<_, Option<String>>(0))?.flatten()))
}

/// The Content-Security-Policy for an app's responses: its own address, plus https and wss to the hosts it declares.
/// Inline scripts and styles stay allowed: this policy is about where data can go, not about what the page runs.
pub fn csp(hosts: &[String]) -> String {
    let ext = hosts.iter().flat_map(|h| [format!("https://{h}"), format!("wss://{h}")]).collect::<Vec<_>>().join(" ");
    let with = |base: &str| if ext.is_empty() { base.to_string() } else { format!("{base} {ext}") };
    [
        format!("default-src {}", with("'self'")),
        format!("script-src {}", with("'self' 'unsafe-inline' 'unsafe-eval' blob:")),
        format!("style-src {}", with("'self' 'unsafe-inline'")),
        format!("img-src {}", with("'self' data: blob:")),
        format!("font-src {}", with("'self' data:")),
        format!("media-src {}", with("'self' data: blob:")),
        format!("connect-src {}", with("'self'")),
        format!("frame-src {}", with("'self'")),
        format!("form-action {}", with("'self'")),
        "worker-src 'self' blob:".into(),
        "object-src 'none'".into(),
        "base-uri 'self'".into(),
        "report-uri /_brod/csp".into(),
    ]
    .join("; ")
}

/// Put the policy on a response from the app: enforced, or report-only while BROD_NETWORK is "log".
pub fn protect(cfg: &Config, res: &mut Response, hosts: &[String]) {
    let name = match cfg.network {
        NetworkPolicy::Off => return,
        NetworkPolicy::Log => "content-security-policy-report-only",
        NetworkPolicy::Enforce => "content-security-policy",
    };
    if let Ok(v) = HeaderValue::try_from(csp(hosts)) {
        res.headers_mut().append(HeaderName::from_static(name), v);
    }
}

/// The hosts a browser's CSP report names, with whether it blocked them. Both the report-uri format
/// ({"csp-report": {...}}) and the Reporting API's (a list of {"type": "csp-violation", "body": {...}}) are read.
pub fn hosts_from_report(body: &[u8]) -> Vec<(String, bool)> {
    let Ok(v) = serde_json::from_slice::<Value>(body) else { return Vec::new() };
    let reports: Vec<&Value> = match &v {
        Value::Array(list) => list.iter().filter(|r| r["type"] == "csp-violation").map(|r| &r["body"]).collect(),
        Value::Object(_) => vec![&v["csp-report"]],
        _ => Vec::new(),
    };
    let mut out: Vec<(String, bool)> = Vec::new();
    for r in reports.into_iter().take(20) {
        let uri = r["blocked-uri"].as_str().or(r["blockedURL"].as_str()).unwrap_or("");
        let enforced = r["disposition"].as_str().unwrap_or("enforce") == "enforce";
        let Some(rest) = uri.split_once("://").map(|(_, r)| r) else { continue };
        let host = rest.split(['/', '?', '#']).next().unwrap_or("").rsplit('@').next().unwrap_or("");
        let host = host.split(':').next().unwrap_or("").to_ascii_lowercase();
        if valid_host(&host) && !out.iter().any(|(h, _)| *h == host) {
            out.push((host, enforced));
        }
    }
    out
}

/// Count an undeclared request. Never for a preview sandbox, which has no app row (the preview guard covers it).
pub fn record(conn: &Connection, app_id: &str, version: Option<i64>, host: &str, source: &str, count: i64, blocked: bool) -> Result<()> {
    if app_id.starts_with("lst_") || !valid_host(host) || !conn.exists("SELECT 1 FROM apps WHERE id = ?", [app_id])? {
        return Ok(());
    }
    let known = conn.exists("SELECT 1 FROM network_reports WHERE app_id = ? AND host = ? AND source = ?", params![app_id, host, source])?;
    if !known && conn.count("SELECT COUNT(*) FROM network_reports WHERE app_id = ?", [app_id])? >= MAX_REPORTED_HOSTS {
        return Ok(());
    }
    let t = now();
    conn.run(
        "INSERT INTO network_reports (app_id, host, source, version, count, blocked, first_at, last_at) VALUES (?,?,?,?,?,?,?,?)
         ON CONFLICT(app_id, host, source) DO UPDATE SET count = network_reports.count + excluded.count, version = excluded.version,
           blocked = excluded.blocked, last_at = excluded.last_at",
        params![app_id, host, source, version, count.clamp(1, 1_000_000), blocked as i64, t, t],
    )?;
    Ok(())
}

/// Where an app may send data, and what it reached without declaring: for the people who run the app.
pub fn for_app(conn: &Connection, cfg: &Config, app: &AppRow) -> Result<Value> {
    let declared_hosts = match app.live_version.or(app.staging_version) {
        Some(n) => declared(conn, &app.id, n)?,
        None => Vec::new(),
    };
    let undeclared = conn.all(
        "SELECT host, source, version, count, blocked, first_at, last_at FROM network_reports WHERE app_id = ? ORDER BY last_at DESC LIMIT 50",
        [&app.id],
        |r| {
            Ok(json!({
                "host": r.get::<_, String>(0)?, "source": r.get::<_, String>(1)?, "version": r.get::<_, Option<i64>>(2)?,
                "count": r.get::<_, i64>(3)?, "blocked": r.get::<_, i64>(4)? == 1, "first": iso(r.get(5)?), "last": iso(r.get(6)?),
            }))
        },
    )?;
    Ok(json!({ "policy": cfg.network.name(), "declared": declared_hosts, "undeclared": undeclared }))
}

/// The hosts in `new` that `old` does not declare.
pub fn added(old: &[String], new: &[String]) -> Vec<String> {
    new.iter().filter(|h| !old.contains(h)).cloned().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bundle(manifest: &str) -> Vec<BundleFile> {
        vec![BundleFile { path: "brod.json".into(), bytes: manifest.as_bytes().to_vec() }]
    }

    #[test]
    fn reads_the_declared_hosts() {
        let got = from_bundle(&bundle(r#"{ "network": ["API.Stripe.com", "*.googleapis.com", "api.stripe.com"] }"#)).unwrap();
        assert_eq!(parse(got), vec!["api.stripe.com", "*.googleapis.com"]);
        assert_eq!(from_bundle(&bundle(r#"{ "network": [] }"#)).unwrap(), None);
        assert_eq!(from_bundle(&bundle("{}")).unwrap(), None);
        for bad in [
            r#"{ "network": "api.stripe.com" }"#,
            r#"{ "network": ["https://api.stripe.com"] }"#,
            r#"{ "network": ["api.stripe.com/v1"] }"#,
            r#"{ "network": ["localhost"] }"#,
            r#"{ "network": ["*"] }"#,
            r#"{ "network": ["a.*.com"] }"#,
            r#"{ "network": ["host.test:8080"] }"#,
        ] {
            assert_eq!(from_bundle(&bundle(bad)).unwrap_err().code, "bad_network", "{bad}");
        }
    }

    #[test]
    fn matches_hosts_like_csp() {
        let d = vec!["api.stripe.com".to_string(), "*.googleapis.com".to_string()];
        assert!(allowed(&d, "api.stripe.com"));
        assert!(allowed(&d, "API.STRIPE.COM"));
        assert!(allowed(&d, "fonts.googleapis.com"));
        assert!(allowed(&d, "a.b.googleapis.com"));
        assert!(!allowed(&d, "googleapis.com"));
        assert!(!allowed(&d, "evilgoogleapis.com"));
        assert!(!allowed(&d, "stripe.com"));
        assert!(!allowed(&d, "api.stripe.com.evil.test"));
        assert!(!allowed(&[], "anything.test"));
    }

    #[test]
    fn builds_a_policy_from_the_declaration() {
        let none = csp(&[]);
        assert!(none.contains("connect-src 'self';"));
        assert!(none.contains("form-action 'self';"));
        assert!(none.contains("report-uri /_brod/csp"));
        let some = csp(&["api.stripe.com".into()]);
        assert!(some.contains("connect-src 'self' https://api.stripe.com wss://api.stripe.com;"));
    }

    #[test]
    fn reads_browser_reports_in_both_formats() {
        let old = br#"{"csp-report":{"blocked-uri":"https://evil.test:8443/steal?d=1","disposition":"report"}}"#;
        assert_eq!(hosts_from_report(old), vec![("evil.test".to_string(), false)]);
        let new = br#"[{"type":"csp-violation","body":{"blockedURL":"wss://user@x.evil.test/s","disposition":"enforce"}},{"type":"deprecation","body":{}}]"#;
        assert_eq!(hosts_from_report(new), vec![("x.evil.test".to_string(), true)]);
        // Inline code, eval and data URLs are not hosts.
        assert!(hosts_from_report(br#"{"csp-report":{"blocked-uri":"inline"}}"#).is_empty());
        assert!(hosts_from_report(b"not json").is_empty());
    }
}
