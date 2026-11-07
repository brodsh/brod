// SPDX-License-Identifier: AGPL-3.0-only
// Open paths: addresses of a private app that anyone may reach without signing in, such as a webhook receiver or an
// MCP endpoint that does its own authentication. An app declares them in the "open_paths" list of its brod.json:
//
//   { "open_paths": ["/api/webhooks/*", { "path": "/api/mcp", "methods": ["POST"] }] }
//
// A deploy can never widen exposure on its own. The declaration travels with the version (versions.open_paths); what a
// person approved lives on the app (apps.open_paths). A path is open only while the served version declares it AND an
// approved entry covers it, so a version that stops declaring a path closes it at once, and a new path stays closed
// until a person approves it (an agent's deploy gets a confirm_url; a person's deploy approves it directly).
//
// A request on an open path skips sign-in and the access check (takedowns, suspensions and pauses still apply). It
// reaches the app anonymously: no identity, no x-brod-* headers from the visitor, no session cookie.
use percent_encoding::{AsciiSet, CONTROLS, percent_decode_str, utf8_percent_encode};
use serde_json::{Value, json};

use crate::problem::{Problem, Result};
use crate::tar::BundleFile;

pub const MAX_ENTRIES: usize = 10;
pub const MAX_LEN: usize = 200;
pub const METHODS: [&str; 7] = ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"];

/// One entry: an exact path ("/api/mcp") or a prefix ("/api/webhooks/*"), for every method or only the listed ones.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpenPath {
    pub path: String,
    /// Upper case, sorted, without repeats. None: every method.
    pub methods: Option<Vec<String>>,
    /// The app's own login page: signed-out visitors are sent here, and its sign-in routes answer (app_signin.rs).
    pub sign_in_page: bool,
}

impl OpenPath {
    /// "/api/webhooks/*" -> Some("/api/webhooks").
    fn prefix(&self) -> Option<&str> {
        self.path.strip_suffix("/*")
    }

    /// Whether a normalised request path and method fall under this entry. A prefix covers its base path too.
    pub fn matches(&self, path: &str, method: &str) -> bool {
        let path_ok = match self.prefix() {
            Some(base) => path == base || path.strip_prefix(base).is_some_and(|rest| rest.starts_with('/')),
            None => path == self.path,
        };
        let method_ok = match &self.methods {
            None => true,
            Some(m) => m.iter().any(|x| x == method) || (method == "HEAD" && m.iter().any(|x| x == "GET")),
        };
        path_ok && method_ok
    }

    /// Whether this entry opens at least everything `other` would: the same or a wider path, and the same or more methods.
    pub fn covers(&self, other: &OpenPath) -> bool {
        let path_ok = match (self.prefix(), other.prefix()) {
            (Some(a), Some(b)) => b == a || b.strip_prefix(a).is_some_and(|r| r.starts_with('/')),
            (Some(a), None) => other.path == a || other.path.strip_prefix(a).is_some_and(|r| r.starts_with('/')),
            (None, Some(_)) => false,
            (None, None) => self.path == other.path,
        };
        let methods_ok = match (&self.methods, &other.methods) {
            (None, _) => true,
            (Some(_), None) => false,
            (Some(a), Some(b)) => b.iter().all(|m| a.contains(m)),
        };
        path_ok && methods_ok
    }

    pub fn to_json(&self) -> Value {
        match (&self.methods, self.sign_in_page) {
            (None, false) => json!(self.path),
            (Some(m), false) => json!({ "path": self.path, "methods": m }),
            (None, true) => json!({ "path": self.path, "sign_in_page": true }),
            (Some(m), true) => json!({ "path": self.path, "methods": m, "sign_in_page": true }),
        }
    }

    /// "/api/mcp (POST)" for summaries.
    pub fn label(&self) -> String {
        let page = if self.sign_in_page { ", the app's sign-in page" } else { "" };
        match &self.methods {
            None => format!("{}{page}", self.path),
            Some(m) => format!("{} ({}){page}", self.path, m.join(", ")),
        }
    }
}

fn bad(msg: String) -> Problem {
    Problem::new(400, "bad_open_paths", msg)
}

/// Why a pattern is refused, or None when it is fine.
pub fn pattern_problem(p: &str) -> Option<&'static str> {
    if p.len() > MAX_LEN {
        return Some("is longer than 200 characters");
    }
    if !p.starts_with('/') {
        return Some("must start with /");
    }
    if p == "/" || p == "/*" {
        return Some("would open the whole app; set_access with \"access\": \"public\" does that");
    }
    let base = p.strip_suffix("/*").unwrap_or(p);
    if base.contains('*') {
        return Some("may only use * as a whole last segment, as in \"/api/webhooks/*\"");
    }
    if base.contains("//") || base.ends_with('/') && base.len() > 1 {
        return Some("has an empty segment (\"//\" or a trailing /)");
    }
    if base.split('/').any(|s| s == "." || s == "..") {
        return Some("has a . or .. segment");
    }
    if base.contains('%') {
        return Some("has a % escape; write the path as it reads, without encoding");
    }
    if !base.bytes().all(|b| b.is_ascii_alphanumeric() || b"/-._~!$&'()+,;=:@".contains(&b)) {
        return Some("has a character paths cannot hold here (spaces, quotes, ?, #, \\ and the like)");
    }
    if base == "/_brod" || base.starts_with("/_brod/") {
        return Some("is under /_brod/, which Brod itself answers");
    }
    None
}

/// Read and check a list of open paths: strings, or { path, methods }.
pub fn parse_list(v: &Value, whence: &str) -> Result<Vec<OpenPath>> {
    let Some(list) = v.as_array() else {
        return Err(bad(format!(
            "{whence} is a list of paths, like [\"/api/webhooks/*\", {{ \"path\": \"/api/mcp\", \"methods\": [\"POST\"] }}]."
        )));
    };
    if list.len() > MAX_ENTRIES {
        return Err(bad(format!("An app can have at most {MAX_ENTRIES} open paths; {whence} has {}.", list.len())));
    }
    let mut out: Vec<OpenPath> = Vec::new();
    for item in list {
        let sign_in_page = item.get("sign_in_page").and_then(Value::as_bool).unwrap_or(false);
        let (path, methods) = match item {
            Value::String(s) => (s.clone(), None),
            Value::Object(o) => (
                o.get("path").and_then(|p| p.as_str()).unwrap_or("").to_string(),
                match o.get("methods") {
                    None | Some(Value::Null) => None,
                    Some(Value::Array(m)) if !m.is_empty() => {
                        let mut ms = Vec::new();
                        for x in m {
                            let name = x.as_str().unwrap_or("").to_ascii_uppercase();
                            if !METHODS.contains(&name.as_str()) {
                                return Err(bad(format!("{whence}: {x} is not a method. Use {}.", METHODS.join(", "))));
                            }
                            if !ms.contains(&name) {
                                ms.push(name);
                            }
                        }
                        ms.sort();
                        Some(ms)
                    }
                    Some(_) => return Err(bad(format!("{whence}: \"methods\" is a non-empty list, like [\"POST\"]."))),
                },
            ),
            _ => return Err(bad(format!("{whence}: each open path is a string or {{ \"path\", \"methods\" }}, not {item}."))),
        };
        if let Some(why) = pattern_problem(&path) {
            return Err(bad(format!("{whence}: the open path {path:?} {why}.")));
        }
        if sign_in_page {
            if path.ends_with("/*") {
                return Err(bad(format!("{whence}: the sign-in page {path:?} must be one exact path, not a prefix.")));
            }
            if methods.as_ref().is_some_and(|m| !m.iter().any(|x| x == "GET")) {
                return Err(bad(format!("{whence}: the sign-in page {path:?} must answer GET.")));
            }
            if out.iter().any(|e| e.sign_in_page && e.path != path) {
                return Err(bad(format!("{whence}: an app has one sign-in page.")));
            }
        }
        let entry = OpenPath { path, methods, sign_in_page };
        if !out.contains(&entry) {
            out.push(entry);
        }
    }
    Ok(out)
}

/// The list as JSON for the database.
pub fn to_json(list: &[OpenPath]) -> String {
    Value::Array(list.iter().map(OpenPath::to_json).collect()).to_string()
}

/// A list as stored, read leniently (it was checked when it was written).
pub fn parse(stored: Option<&str>) -> Vec<OpenPath> {
    stored.and_then(|s| serde_json::from_str::<Value>(s).ok()).and_then(|v| parse_list(&v, "stored").ok()).unwrap_or_default()
}

/// The app's own login page, if the served version names one that a person approved. `open` is `effective`'s result.
pub fn sign_in_page(open: &[OpenPath]) -> Option<&str> {
    open.iter().find(|e| e.sign_in_page).map(|e| e.path.as_str())
}

/// Read the "open_paths" list from a bundle's brod.json, as the JSON kept with the version. None: it declares none.
pub fn from_bundle(files: &[BundleFile]) -> Result<Option<String>> {
    let manifest = crate::settings::MANIFEST;
    let Some(f) = files.iter().find(|f| f.path == manifest) else { return Ok(None) };
    let Ok(Value::Object(doc)) = serde_json::from_slice::<Value>(&f.bytes) else { return Ok(None) };
    let Some(list) = doc.get("open_paths") else { return Ok(None) };
    let list = parse_list(list, &format!("\"open_paths\" in {manifest}"))?;
    Ok(if list.is_empty() { None } else { Some(to_json(&list)) })
}

/// The declared entries an approved one covers: what is actually open.
pub fn effective(approved: &[OpenPath], declared: &[OpenPath]) -> Vec<OpenPath> {
    declared.iter().filter(|d| approved.iter().any(|a| a.covers(d))).cloned().collect()
}

/// The entries of `wanted` no entry of `have` covers: what approving them would newly open.
pub fn uncovered(have: &[OpenPath], wanted: &[OpenPath]) -> Vec<OpenPath> {
    wanted.iter().filter(|w| !have.iter().any(|h| h.covers(w))).cloned().collect()
}

/// `have` plus the entries of `add` it does not hold yet, refused past MAX_ENTRIES.
pub fn union(have: &[OpenPath], add: &[OpenPath]) -> Result<Vec<OpenPath>> {
    let mut out = have.to_vec();
    for a in add {
        if !out.contains(a) {
            out.push(a.clone());
        }
    }
    if out.len() > MAX_ENTRIES {
        return Err(bad(format!(
            "An app can have at most {MAX_ENTRIES} approved open paths; this would make {}. Remove some with set_open_paths first.",
            out.len()
        )));
    }
    Ok(out)
}

/// The characters a path segment cannot hold as they are: the request path is re-encoded with this after matching.
const PATH: &AsciiSet = &CONTROLS.add(b' ').add(b'"').add(b'#').add(b'%').add(b'<').add(b'>').add(b'?').add(b'`').add(b'{').add(b'}');

/// The path an open-path match is decided on: percent-decoded once, with runs of / collapsed. None when the path could
/// mean something else to the app than to the gateway (an encoded / or \, a . or .. segment, bytes that are not UTF-8),
/// so it never matches an open path and goes through sign-in like any other.
pub fn normalize(raw: &str) -> Option<String> {
    let lower = raw.to_ascii_lowercase();
    if lower.contains("%2f") || lower.contains("%5c") || raw.contains('\\') {
        return None;
    }
    let decoded = percent_decode_str(raw).decode_utf8().ok()?;
    if !decoded.starts_with('/') || decoded.chars().any(|c| c.is_control() || c == '\\') {
        return None;
    }
    let mut out = String::with_capacity(decoded.len());
    for c in decoded.chars() {
        if c == '/' && out.ends_with('/') {
            continue;
        }
        out.push(c);
    }
    if out.split('/').any(|s| s == "." || s == "..") {
        return None;
    }
    Some(out)
}

/// The open entry a request falls under, if any, with the path to forward: the normalised one, re-encoded, so the
/// app gets exactly the path that was matched.
pub fn match_request(open: &[OpenPath], raw_path: &str, method: &str) -> Option<String> {
    if open.is_empty() {
        return None;
    }
    let path = normalize(raw_path)?;
    open.iter().any(|e| e.matches(&path, method)).then(|| utf8_percent_encode(&path, PATH).to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn list(v: Value) -> Vec<OpenPath> {
        parse_list(&v, "test").unwrap()
    }

    #[test]
    fn a_sign_in_page_is_one_exact_path_that_answers_get() {
        let parsed = parse_list(&json!([{ "path": "/login", "sign_in_page": true }, "/assets/*"]), "t").unwrap();
        assert_eq!(sign_in_page(&parsed), Some("/login"));
        assert_eq!(parse(Some(&to_json(&parsed))), parsed);
        assert!(parse_list(&json!([{ "path": "/login/*", "sign_in_page": true }]), "t").is_err());
        assert!(parse_list(&json!([{ "path": "/login", "methods": ["POST"], "sign_in_page": true }]), "t").is_err());
        assert!(parse_list(&json!([{ "path": "/a", "sign_in_page": true }, { "path": "/b", "sign_in_page": true }]), "t").is_err());
    }

    #[test]
    fn a_sign_in_page_counts_only_once_a_person_approved_its_path() {
        let declared = parse_list(&json!([{ "path": "/login", "sign_in_page": true }]), "t").unwrap();
        assert_eq!(sign_in_page(&effective(&[], &declared)), None);
        let approved = parse_list(&json!(["/login"]), "t").unwrap();
        assert_eq!(sign_in_page(&effective(&approved, &declared)), Some("/login"));
        assert_eq!(sign_in_page(&effective(&declared, &parse_list(&json!(["/login"]), "t").unwrap())), None);
    }

    #[test]
    fn checks_patterns() {
        for ok in ["/api/mcp", "/api/webhooks/*", "/hooks/stripe.json", "/a/b-c_d~e/@x:y"] {
            assert_eq!(pattern_problem(ok), None, "{ok}");
        }
        let long = format!("/{}", "a".repeat(200));
        for bad in [
            "",
            "api",
            "/",
            "/*",
            "*",
            "/api/*/x",
            "/api*",
            "/api/x*",
            "/*/x",
            "/api//mcp",
            "/api/",
            "/api/../admin",
            "/api/./x",
            "/api%2fmcp",
            "/api/m%63p",
            "/api?x",
            "/api#x",
            "/a b",
            "/_brod/me",
            "/_brod",
            "/api\\x",
            long.as_str(),
        ] {
            assert!(pattern_problem(bad).is_some(), "{bad}");
        }
        assert_eq!(pattern_problem(&format!("/{}", "a".repeat(199))), None);
    }

    #[test]
    fn parses_lists_with_methods() {
        let l = list(json!(["/api/webhooks/*", { "path": "/api/mcp", "methods": ["post", "GET", "POST"] }, "/api/webhooks/*"]));
        assert_eq!(l.len(), 2);
        assert_eq!(l[1].methods.as_deref(), Some(&["GET".to_string(), "POST".to_string()][..]));
        assert_eq!(to_json(&l), r#"["/api/webhooks/*",{"path":"/api/mcp","methods":["GET","POST"]}]"#);
        assert_eq!(parse(Some(&to_json(&l))), l);
        let err = |v: Value| parse_list(&v, "test").unwrap_err().code;
        assert_eq!(err(json!("/api")), "bad_open_paths");
        assert_eq!(err(json!([{ "path": "/x", "methods": ["TRACE"] }])), "bad_open_paths");
        assert_eq!(err(json!([{ "path": "/x", "methods": [] }])), "bad_open_paths");
        assert_eq!(err(json!([1])), "bad_open_paths");
        assert_eq!(err(json!(["/"])), "bad_open_paths");
        let eleven: Vec<String> = (0..11).map(|i| format!("/p{i}")).collect();
        assert_eq!(err(json!(eleven)), "bad_open_paths");
        assert!(parse(Some("not json")).is_empty() && parse(None).is_empty());
    }

    #[test]
    fn reads_the_declaration_from_brod_json() {
        let f = |s: &str| vec![BundleFile { path: "brod.json".into(), bytes: s.as_bytes().to_vec() }];
        assert_eq!(from_bundle(&f(r#"{"open_paths":["/hook"]}"#)).unwrap().as_deref(), Some(r#"["/hook"]"#));
        assert_eq!(from_bundle(&f(r#"{"open_paths":[]}"#)).unwrap(), None);
        assert_eq!(from_bundle(&f(r#"{"settings":{}}"#)).unwrap(), None);
        assert_eq!(from_bundle(&[]).unwrap(), None);
        assert_eq!(from_bundle(&f(r#"{"open_paths":["/*"]}"#)).unwrap_err().code, "bad_open_paths");
    }

    #[test]
    fn normalises_request_paths_and_refuses_ambiguous_ones() {
        assert_eq!(normalize("/api/mcp").as_deref(), Some("/api/mcp"));
        assert_eq!(normalize("//api//mcp").as_deref(), Some("/api/mcp"));
        assert_eq!(normalize("/api/m%63p").as_deref(), Some("/api/mcp"));
        assert_eq!(normalize("/a%20b").as_deref(), Some("/a b"));
        for refused in [
            "/api%2fmcp",
            "/api%2Fmcp",
            "/api%5cmcp",
            "/api\\mcp",
            "/api/mcp/../admin",
            "/api/%2e%2e/admin",
            "/./x",
            "/x/%2E",
            "/%ff",
            "/a%00b",
            "api",
        ] {
            assert_eq!(normalize(refused), None, "{refused}");
        }
        // Decoded once only: %252f stays a literal "%2f" and is re-encoded as such.
        assert_eq!(normalize("/api%252fmcp").as_deref(), Some("/api%2fmcp"));
    }

    #[test]
    fn matches_exact_paths_and_prefixes_without_bypasses() {
        let open = list(json!([{ "path": "/api/mcp", "methods": ["POST"] }, "/api/webhooks/*"]));
        let m = |p: &str, method: &str| match_request(&open, p, method);
        assert_eq!(m("/api/mcp", "POST").as_deref(), Some("/api/mcp"));
        assert_eq!(m("/api/mcp", "GET"), None, "the method is part of the entry");
        assert_eq!(m("/api/mcpx", "POST"), None);
        assert_eq!(m("/api/mcp/", "POST"), None);
        assert_eq!(m("/api/mcp/x", "POST"), None);
        assert_eq!(m("/api/mcp/../admin", "POST"), None);
        assert_eq!(m("/api%2fmcp", "POST"), None);
        assert_eq!(m("/api/m%63p", "POST").as_deref(), Some("/api/mcp"), "forwarded as matched");
        assert_eq!(m("//api/mcp", "POST").as_deref(), Some("/api/mcp"), "collapsed, and forwarded collapsed");
        assert_eq!(m("/api/webhooks/stripe", "POST").as_deref(), Some("/api/webhooks/stripe"));
        assert_eq!(m("/api/webhooks/a/b", "PUT").as_deref(), Some("/api/webhooks/a/b"));
        assert_eq!(m("/api/webhooks", "GET").as_deref(), Some("/api/webhooks"));
        assert_eq!(m("/api/webhooksx", "POST"), None);
        assert_eq!(m("/api/webhooksx/y", "POST"), None);
        assert_eq!(m("/api/webhooks/../../admin", "POST"), None);
        assert_eq!(m("/api/webhooks/a%20b", "POST").as_deref(), Some("/api/webhooks/a%20b"));
        assert_eq!(m("/API/MCP", "POST"), None, "paths are case-sensitive");
        assert_eq!(match_request(&list(json!([{ "path": "/r", "methods": ["GET"] }])), "/r", "HEAD").as_deref(), Some("/r"));
        assert_eq!(match_request(&[], "/api/mcp", "POST"), None);
    }

    #[test]
    fn an_entry_is_open_only_when_declared_and_covered_by_an_approval() {
        let approved = list(json!(["/api/webhooks/*", { "path": "/api/mcp", "methods": ["POST"] }]));
        let declared = list(json!([
            "/api/webhooks/stripe/*",
            "/api/webhooks/github",
            { "path": "/api/mcp", "methods": ["POST"] },
            "/api/mcp",
            "/admin"
        ]));
        let open = effective(&approved, &declared);
        assert_eq!(
            open.iter().map(OpenPath::label).collect::<Vec<_>>(),
            ["/api/webhooks/stripe/*", "/api/webhooks/github", "/api/mcp (POST)"]
        );
        let pending = uncovered(&approved, &declared);
        assert_eq!(pending.iter().map(OpenPath::label).collect::<Vec<_>>(), ["/api/mcp", "/admin"]);
        assert!(!list(json!(["/api/webhooks/x"]))[0].covers(&list(json!(["/api/webhooks/*"]))[0]));
        assert!(!list(json!(["/api/web/*"]))[0].covers(&list(json!(["/api/webhooks/*"]))[0]));
        assert_eq!(union(&approved, &pending).unwrap().len(), 4);
        let ten: Vec<String> = (0..10).map(|i| format!("/p{i}")).collect();
        assert_eq!(union(&list(json!(ten)), &list(json!(["/x"]))).unwrap_err().code, "bad_open_paths");
    }
}
