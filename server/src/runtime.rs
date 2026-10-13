// Server apps: bundles with a _worker.js (or a _worker/ folder), in the Cloudflare Pages layout.
//
// The Rust server does not run JavaScript itself. With BROD_RUNTIME_URL and BROD_RUNTIME_SECRET set, it hands
// server code to a workerd sidecar (deploy/runtime/host.js), the open-source Workers runtime, which loads each app
// into its own isolate with the Worker Loader and gives it its own SQLite database (a Durable Object on disk).
// The gateway decides access here and forwards the request with the identity headers; the sidecar fetches the code
// and the decrypted secrets from the internal /_runtime/ endpoints below, and posts logs and file operations back.
//
// Without a runtime, deploys with server code are refused with `server_apps_unavailable`, exactly as the Vercel host does.
use crate::db::params;
use axum::body::Body;
use axum::http::{HeaderMap, HeaderName, HeaderValue, Method};
use axum::response::Response;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use bytes::Bytes;
use futures_util::{StreamExt, TryStreamExt};
use serde_json::{Map, Value, json};

use crate::db::{Sql, tx};
use crate::gateway::APP_COOKIE;
use crate::http::{Req, bytes_body, empty, json, notice, read_capped, response};
use crate::model::{AppRow, limits};
use crate::problem::{Problem, Result};
use crate::state::State;
use crate::tar::BundleFile;
use crate::util::{encode_uri_component, now, safe_equal};

#[derive(Clone, Debug, PartialEq, serde::Deserialize)]
pub struct ServerInfo {
    pub main: String,
    pub modules: Vec<String>,
}

/// Server code in a bundle: _worker.js at the top, or a _worker/ folder with index.js (the Cloudflare Pages layout).
pub fn find_server(paths: &[&str]) -> Result<Option<ServerInfo>> {
    if paths.contains(&"_worker.js") {
        return Ok(Some(ServerInfo { main: "_worker.js".into(), modules: vec!["_worker.js".into()] }));
    }
    let folder: Vec<String> = paths.iter().filter(|p| p.starts_with("_worker/")).map(|p| p.to_string()).collect();
    if folder.is_empty() {
        return Ok(None);
    }
    let main = ["_worker/index.js", "_worker/index.mjs"].into_iter().find(|m| folder.iter().any(|f| f == m));
    match main {
        Some(m) => Ok(Some(ServerInfo { main: m.into(), modules: folder })),
        None => Err(Problem::new(400, "bad_server", "A _worker/ folder needs an index.js that exports a fetch handler.")),
    }
}

pub fn is_server_path(p: &str) -> bool {
    p == "_worker.js" || p.starts_with("_worker/")
}

fn unavailable() -> Problem {
    Problem::new(503, "runtime_unavailable", "The server-app runtime is not reachable. Try again in a minute.")
}

/// Refuse server code that cannot start, so a broken deploy never replaces the live version. The sidecar imports the
/// app's main module (running its top-level code) and checks it exports a fetch handler, without calling it.
pub async fn check_server(st: &State, server: &ServerInfo, files: &[BundleFile]) -> Result<()> {
    let Some(rt) = &st.cfg.runtime else {
        return Err(Problem::new(
            400,
            "server_apps_unavailable",
            format!(
                "This Brod host serves static apps only: server code ({}) needs the Cloudflare deployment. Remove _worker.js or _worker/ and deploy the static files, or deploy on Cloudflare.",
                server.main
            ),
        ));
    };
    let mut modules = Map::new();
    for f in files.iter().filter(|f| server.modules.contains(&f.path)) {
        if f.path.to_lowercase().ends_with(".json") && serde_json::from_slice::<Value>(&f.bytes).is_err() {
            return Err(Problem::new(400, "bad_server", format!("{} is not valid JSON.", f.path)));
        }
        modules.insert(f.path.clone(), json!(STANDARD.encode(&f.bytes)));
    }
    // Top-level code that never finishes stalls the runtime like a request would; the watchdog sees it here.
    let ticket = crate::watchdog::start(st, "", None, "POST", "/_runtime/check");
    let res = match st
        .http
        .post(format!("{}/_runtime/check", rt.url))
        .header("x-brod-runtime-secret", &rt.secret)
        .json(&json!({ "main": server.main, "modules": modules }))
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            if let Some(reason) = ticket.stopped() {
                return Err(stopped_at_start(server, reason));
            }
            eprintln!("runtime check failed: {e}");
            return Err(unavailable());
        }
    };
    drop(ticket);
    if !res.status().is_success() {
        eprintln!("runtime check answered {}", res.status());
        return Err(unavailable());
    }
    let v: Value = res.json().await.map_err(Problem::internal)?;
    if let Some(e) = v.get("error").and_then(|e| e.as_str()) {
        return Err(Problem::new(
            400,
            "server_failed",
            format!("The server code did not start: {e}. Nothing was deployed; the live version is unchanged."),
        ));
    }
    if v.get("verdict").and_then(|x| x.as_str()) != Some("ok") {
        return Err(Problem::new(
            400,
            "server_failed",
            format!("{} must export default an object with a fetch(request, env, ctx) method. Nothing was deployed.", server.main),
        ));
    }
    Ok(())
}

fn stopped_at_start(server: &ServerInfo, reason: crate::watchdog::Reason) -> Problem {
    let why = match reason {
        crate::watchdog::Reason::Cpu => "its top-level code ran for seconds without finishing (a loop that does not end?)",
        _ => "it used too much memory while it started",
    };
    Problem::new(
        400,
        "server_failed",
        format!(
            "The server code did not start: Brod stopped {} because {why}. Nothing was deployed; the live version is unchanged.",
            server.main
        ),
    )
}

const HOP_BY_HOP: [&str; 8] = ["connection", "keep-alive", "transfer-encoding", "te", "trailer", "upgrade", "proxy-connection", "host"];

/// Hand a request to the app's server code. The app gets the request as the visitor sent it, minus the platform's
/// session cookie and any X-Brod-* headers the visitor tried to set, plus the signed-in person as X-Brod-* headers.
pub async fn dispatch(
    st: &State,
    mut req: Req,
    app: &AppRow,
    origin: &str,
    version: i64,
    _server: &ServerInfo,
    identity: Option<(Value, String)>,
) -> Result<Response> {
    let failed = || {
        notice(502, "This app failed", "The app's server code failed on this request. Its owner can see the error in the app's logs.", "")
    };
    let Some(rt) = &st.cfg.runtime else {
        eprintln!("server app {} has no runtime on this host", app.slug);
        return Ok(failed());
    };
    if let Some(p) = st.watchdog.paused(&app.id) {
        return Ok(paused(p.left.as_secs()));
    }
    let mut headers = HeaderMap::new();
    for (k, v) in req.headers.iter() {
        let name = k.as_str();
        if name.starts_with("x-brod-") || name == "cookie" || name == "content-length" || HOP_BY_HOP.contains(&name) {
            continue;
        }
        headers.append(k.clone(), v.clone());
    }
    let cookies: Vec<&str> = req
        .header("cookie")
        .unwrap_or("")
        .split(';')
        .map(str::trim)
        .filter(|c| !c.is_empty() && !c.starts_with(&format!("{APP_COOKIE}=")) && !c.starts_with(&format!("__Host-{APP_COOKIE}=")))
        .collect();
    let set = |h: &mut HeaderMap, k: &str, v: &str| {
        if let (Ok(n), Ok(v)) = (HeaderName::try_from(k), HeaderValue::try_from(v)) {
            h.insert(n, v);
        }
    };
    if !cookies.is_empty() {
        set(&mut headers, "cookie", &cookies.join("; "));
    }
    if let Some((identity, token)) = identity {
        let s = |k: &str| identity["user"][k].as_str().unwrap_or("").to_string();
        set(&mut headers, "x-brod-user-id", &s("id"));
        set(&mut headers, "x-brod-user-email", &s("email"));
        set(&mut headers, "x-brod-user-name", &encode_uri_component(&s("name")));
        set(&mut headers, "x-brod-role", identity["role"].as_str().unwrap_or(""));
        let groups: Vec<&str> = identity["groups"].as_array().map(|g| g.iter().filter_map(|x| x.as_str()).collect()).unwrap_or_default();
        set(&mut headers, "x-brod-groups", &groups.join(","));
        set(&mut headers, "x-brod-identity", &token);
    }
    let url = format!("{}{}{}", origin, req.path, if req.query.is_empty() { String::new() } else { format!("?{}", req.query) });
    set(&mut headers, "x-brod-runtime-secret", &rt.secret);
    set(&mut headers, "x-brod-runtime-app", &app.id);
    set(&mut headers, "x-brod-runtime-version", &version.to_string());
    set(&mut headers, "x-brod-runtime-rev", &app.secrets_rev.to_string());
    set(&mut headers, "x-brod-runtime-url", &url);

    let method = reqwest::Method::from_bytes(req.method.as_str().as_bytes()).map_err(Problem::internal)?;
    let mut out = st.http.request(method, format!("{}{}", rt.url, req.path)).headers(headers);
    if req.method != Method::GET && req.method != Method::HEAD {
        let stream = req.take_body().into_data_stream().map_err(std::io::Error::other);
        out = out.body(reqwest::Body::wrap_stream(stream));
    }
    let ticket = crate::watchdog::start(st, &app.id, Some(version), req.method.as_str(), &req.path);
    // While the supervisor restarts workerd (a second or two), a request without a body waits for it to come back
    // when it was not sent, or when it only queued behind an app that stalled the runtime (watchdog.rs): it never ran.
    let wait_until = std::time::Instant::now() + std::time::Duration::from_secs(10);
    let sent = loop {
        let Some(again) = out.try_clone() else { break out.send().await };
        match out.send().await {
            Err(e) if (e.is_connect() || ticket.take_queued()) && std::time::Instant::now() < wait_until => {
                tokio::time::sleep(std::time::Duration::from_millis(250)).await;
                out = again;
            }
            r => break r,
        }
    };
    let res = match sent {
        Ok(r) => r,
        Err(e) => {
            if let Some(reason) = ticket.stopped() {
                eprintln!("server app {} was stopped: {reason:?}", app.slug);
                return Ok(stopped(reason));
            }
            eprintln!("server app {} failed: runtime unreachable: {e}", app.slug);
            ticket.dropped();
            return Ok(failed());
        }
    };
    if res.headers().contains_key("x-brod-runtime-error") {
        eprintln!("server app {} failed: {}", app.slug, res.text().await.unwrap_or_default());
        return Ok(failed());
    }
    let status = res.status().as_u16();
    let mut h: Vec<(String, String)> = Vec::new();
    for (k, v) in res.headers() {
        if HOP_BY_HOP.contains(&k.as_str()) || k.as_str() == "content-length" {
            continue;
        }
        if let Ok(v) = v.to_str() {
            h.push((k.as_str().to_string(), v.to_string()));
        }
    }
    let header = |h: &[(String, String)], k: &str| h.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone());
    h.retain(|(k, _)| k != "x-brod-app" && k != "x-brod-version");
    h.push(("x-brod-app".into(), app.slug.clone()));
    h.push(("x-brod-version".into(), version.to_string()));
    let is_public = app.access == "public";
    if !is_public {
        // A private app's answers are for one person: never let a shared cache keep them.
        let cc = header(&h, "cache-control").unwrap_or_default();
        let has_private = cc.split(|c: char| !c.is_ascii_alphanumeric() && c != '-').any(|w| w == "private" || w == "no-store");
        if !has_private {
            h.retain(|(k, _)| k != "cache-control");
            h.push(("cache-control".into(), "private, no-cache".into()));
        }
        h.push(("vary".into(), "cookie".into()));
    }
    let html = header(&h, "content-type").is_some_and(|c| c.starts_with("text/html"));
    let pairs: Vec<(&str, String)> = h.iter().map(|(k, v)| (k.as_str(), v.clone())).collect();
    if req.method == Method::HEAD {
        return Ok(response(status, Body::empty(), &pairs));
    }
    if is_public && html {
        let page = read_capped(Body::from_stream(res.bytes_stream()), crate::tar::FILE_BYTES * 2, "The page").await?;
        return Ok(response(status, bytes_body(crate::gateway::append_to_body(&page, crate::gateway::REPORT_LINK)), &pairs));
    }
    // The request stays in flight until its body has been passed on: an app can stall the runtime mid-stream too.
    let body = res.bytes_stream().inspect(move |_| {
        let _ = &ticket;
    });
    Ok(response(status, Body::from_stream(body), &pairs))
}

/// The page for a request the watchdog stopped (the runtime was restarted under it).
fn stopped(reason: crate::watchdog::Reason) -> Response {
    let why = match reason {
        crate::watchdog::Reason::Cpu => "Its server code ran too long without pausing, which holds up other apps, so Brod stopped it.",
        _ => "Its server code used too much memory, so Brod stopped it.",
    };
    notice(503, "This app was stopped", &format!("{why} Its owner can see the details in the app's logs."), "")
}

/// The page while an app is stopped for having stalled the runtime.
fn paused(secs: u64) -> Response {
    let mins = secs.div_ceil(60).max(1);
    let mut res = notice(
        503,
        "This app is paused",
        &format!(
            "Its server code recently held up the server it runs on, so Brod paused it for a while. Try again in {mins} min. Its owner can see why in the app's logs."
        ),
        "",
    );
    if let Ok(v) = HeaderValue::try_from(secs.max(1).to_string()) {
        res.headers_mut().insert("retry-after", v);
    }
    res.headers_mut().insert("x-brod-paused", HeaderValue::from_static("1"));
    res
}

/// Empty an app's database and key-value store when the app is deleted. Its files go with its storage prefix.
pub async fn wipe_app_data(st: &State, app_id: &str) -> Result<()> {
    let Some(rt) = &st.cfg.runtime else {
        return Ok(());
    };
    let res = st
        .http
        .post(format!("{}/_runtime/wipe", rt.url))
        .header("x-brod-runtime-secret", &rt.secret)
        .json(&json!({ "app": app_id }))
        .send()
        .await;
    match res {
        Ok(r) if r.status().is_success() => Ok(()),
        Ok(r) => Err(Problem::internal(format!("runtime wipe answered {}", r.status()))),
        Err(e) => Err(Problem::internal(format!("runtime wipe failed: {e}"))),
    }
}

// ---------- the internal endpoints the sidecar calls ----------

/// /_runtime/*: code and secrets for an app version, its files, and its request logs. Only on the internal address,
/// only with the shared secret, and only when a runtime is configured.
pub async fn internal(st: &State, mut req: Req) -> Result<Response> {
    let Some(rt) = &st.cfg.runtime else {
        return Ok(empty(404));
    };
    if !safe_equal(req.header("x-brod-runtime-secret").unwrap_or(""), &rt.secret) {
        return Ok(empty(403));
    }
    let path = req.path.clone();
    if path == "/_runtime/code" && req.method == Method::GET {
        let app_id = req.param("app").unwrap_or_default();
        let version: i64 = req.param("version").and_then(|v| v.parse().ok()).unwrap_or(0);
        let key = st.cfg.secrets_key.clone();
        let a2 = app_id.clone();
        let policy = st.cfg.network.name();
        let (server, secrets, settings, network) = st
            .db
            .call(move |c| {
                // The app's settings as env.SETTINGS; changing one bumps the revision the code is cached under.
                let settings = crate::settings::values(c, &a2, version)?;
                // The outside hosts its outbound gate lets through (network.rs).
                let network = crate::network::declared(c, &a2, version)?;
                // A marketplace preview sandbox runs a listing's release by the listing's id, with no secrets (preview.rs).
                if a2.starts_with("lst_") {
                    let server: Option<String> = c
                        .first("SELECT server FROM releases WHERE listing_id = ? AND n = ?", params![a2, version], |r| r.get(0))?
                        .flatten();
                    return Ok((server, Vec::new(), settings, network));
                }
                let server: Option<String> =
                    c.first("SELECT server FROM versions WHERE app_id = ? AND n = ?", params![a2, version], |r| r.get(0))?.flatten();
                let secrets = crate::secrets::read_all(c, &key, &a2)?;
                Ok((server, secrets, settings, network))
            })
            .await?;
        let Some(server) = server else {
            return Err(Problem::new(404, "not_found", "No server code for that version."));
        };
        let server: ServerInfo = serde_json::from_str(&server)?;
        let mut modules = Map::new();
        for p in &server.modules {
            let bytes = st
                .store
                .read(&format!("{app_id}/{version}/{p}"), crate::tar::FILE_BYTES)
                .await?
                .ok_or_else(|| Problem::new(500, "missing_module", format!("The server module {p} is missing.")))?;
            modules.insert(p.clone(), json!(STANDARD.encode(bytes)));
        }
        let secrets: Map<String, Value> = secrets.into_iter().map(|(k, v)| (k, json!(v))).collect();
        return Ok(json(json!({ "main": server.main, "modules": modules, "secrets": secrets, "settings": settings,
            "network": { "policy": policy, "allow": network } })));
    }
    if path == "/_runtime/network" && req.method == Method::POST {
        // Server code reached (or was refused) a host it does not declare: counted for the app's Network page.
        let r: Value = serde_json::from_slice(&req.bytes(16 * 1024, "The report").await?)?;
        let s = |k: &str| r.get(k).and_then(|v| v.as_str()).unwrap_or("").to_string();
        let (app_id, host) = (s("app"), s("host").to_ascii_lowercase());
        let version = r.get("version").and_then(Value::as_i64);
        let count = r.get("count").and_then(Value::as_i64).unwrap_or(1);
        let blocked = r.get("blocked").and_then(Value::as_bool).unwrap_or(false);
        st.db.call(move |c| crate::network::record(c, &app_id, version, &host, "server", count, blocked)).await?;
        return Ok(empty(204));
    }
    if path == "/_runtime/logs" && req.method == Method::POST {
        let rows: Vec<Value> = serde_json::from_slice(&req.bytes(4 * 1024 * 1024, "The logs").await?)?;
        st.db
            .call(move |c| {
                tx(c, |x| {
                    for r in &rows {
                        let s = |k: &str| r.get(k).and_then(|v| v.as_str()).unwrap_or("").to_string();
                        x.run(
                            "INSERT INTO app_logs (app_id, at, version, method, path, status, outcome, logs, exceptions) VALUES (?,?,?,?,?,?,?,?,?)",
                            params![s("app_id"), r["at"].as_i64().unwrap_or_else(now), r["version"].as_i64(), s("method"), s("path"), r["status"].as_i64(), s("outcome"), s("logs"), s("exceptions")],
                        )?;
                    }
                    // Keep 7 days. Pruning now and then on write keeps this free of a scheduled job.
                    if crate::util::random_bytes(1)[0] < 13 {
                        x.run("DELETE FROM app_logs WHERE at < ?", [now() - limits::LOG_RETENTION_MS])?;
                    }
                    Ok(())
                })
            })
            .await?;
        return Ok(json(json!({ "ok": true })));
    }
    if path == "/_runtime/stopped" && req.method == Method::POST {
        // The supervisor is restarting workerd (deploy/runtime/supervisor/): stop the app that made it.
        let body: Value = serde_json::from_slice(&req.bytes(16 * 1024, "The report").await?)?;
        return Ok(json(crate::watchdog::stopped(st, &body).await?));
    }
    if path == "/_runtime/usage" && req.method == Method::POST {
        let b = req.json_object().await?;
        let app = b.get("app").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let bytes = b.get("data_bytes").and_then(|v| v.as_i64()).unwrap_or(0);
        return Ok(json(st.db.call(move |c| crate::usage::report_data_bytes(c, &app, bytes)).await?));
    }
    if let Some(rest) = path.strip_prefix("/_runtime/files/") {
        let (app_id, key) = match rest.split_once('/') {
            Some((a, k)) => (a.to_string(), crate::util::decode_uri_component(k).unwrap_or_default()),
            None => (rest.to_string(), String::new()),
        };
        // An app's own files, or a preview sandbox's (lst_, removed again after the capture).
        if app_id.is_empty() || !(app_id.starts_with("app_") || app_id.starts_with("lst_")) || app_id.contains("..") || app_id.contains('/')
        {
            return Ok(empty(400));
        }
        let base = format!("{app_id}/files/");
        if key.is_empty() && req.method == Method::GET {
            let prefix = format!("{base}{}", req.param("prefix").unwrap_or_default());
            let (objects, _) = st.store.list(&prefix, None, 1000).await?;
            let list: Vec<Value> =
                objects.iter().map(|o| json!({ "key": o.key[base.len()..], "size": o.size, "uploaded": o.uploaded })).collect();
            return Ok(json(Value::Array(list)));
        }
        if key.is_empty() || key.split('/').any(|p| p == ".." || p == "." || p.is_empty()) {
            return Ok(empty(400));
        }
        let full = format!("{base}{key}");
        return match req.method {
            Method::PUT => {
                let ct = req.header("content-type").unwrap_or("application/octet-stream").to_string();
                let bytes = req.bytes(crate::tar::BUNDLE_BYTES, "The file").await?;
                // Files count toward the workspace's storage: refuse a write that would go over, then keep the total.
                let old = st.store.head(&full).await?.map(|m| m.size as i64).unwrap_or(0);
                let delta = bytes.len() as i64 - old;
                let a2 = app_id.clone();
                st.db.call(move |c| crate::usage::check_app_storage(c, &a2, delta)).await?;
                let meta = st.store.put(&full, Bytes::from(bytes), Some(&ct)).await?;
                st.db.call(move |c| crate::usage::add_file_bytes(c, &app_id, delta)).await?;
                Ok(json(json!({ "key": key, "size": meta.size })))
            }
            Method::GET => match st.store.get(&full).await? {
                Some(o) => Ok(response(
                    200,
                    o.body,
                    &[
                        ("content-type", o.meta.content_type.clone().unwrap_or_else(|| "application/octet-stream".into())),
                        ("etag", o.meta.http_etag()),
                    ],
                )),
                None => Ok(empty(404)),
            },
            Method::DELETE => {
                let old = st.store.head(&full).await?.map(|m| m.size as i64).unwrap_or(0);
                st.store.delete(&full).await?;
                if old > 0 {
                    st.db.call(move |c| crate::usage::add_file_bytes(c, &app_id, -old)).await?;
                }
                Ok(json(json!({ "deleted": key })))
            }
            _ => Ok(empty(405)),
        };
    }
    Ok(empty(404))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_server_code_in_the_pages_layout() {
        assert_eq!(find_server(&["index.html"]).unwrap(), None);
        assert_eq!(find_server(&["_worker.js", "x"]).unwrap().unwrap().main, "_worker.js");
        let s = find_server(&["_worker/db.js", "_worker/index.js", "style.css"]).unwrap().unwrap();
        assert_eq!((s.main.as_str(), s.modules.len()), ("_worker/index.js", 2));
        assert_eq!(find_server(&["_worker/lib.js"]).unwrap_err().code, "bad_server");
        assert!(is_server_path("_worker/x.js") && !is_server_path("worker.js"));
    }
}
