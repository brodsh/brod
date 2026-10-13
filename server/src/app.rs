// One server, four jobs, split by hostname and path (the fetch handler in src/index.ts):
//   <slug>.<workspace>.<APPS_DOMAIN>  -> gateway (signs people in, decides access, serves an app)
//   <workspace>.<APPS_DOMAIN>         -> redirect to the workspace home page
//   a proven custom domain            -> the same gateway (domains.rs)
//   anything else, /mcp   -> MCP endpoint for agents
//   anything else, /v1/*  -> REST control-plane API (agents with a token, the dashboard with a session)
//   anything else         -> sign-in, invitations, confirmations and workspace home pages,
//                            the connections page and OAuth sign-in for agents (connect.rs)
// Plus /_caddy/ask, which Caddy calls before it gets a certificate for a host.
use axum::body::Body;
use axum::http::Method;
use axum::http::header::CONTENT_LENGTH;
use axum::response::Response;
use serde_json::json;

use crate::db::Sql;
use crate::http::{Req, empty, json, json_response, notice};
use crate::problem::{Problem, Result};
use crate::state::State;

fn valid_slug(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// The labels in front of APPS_DOMAIN ("todo.acme.<APPS_DOMAIN>" -> ["todo", "acme"]), empty for a malformed
/// one, None for any other host (the API host included).
pub fn app_labels(st: &State, host: &str) -> Option<Vec<String>> {
    if host == st.cfg.api_host {
        return None;
    }
    let rest = host.strip_suffix(&format!(".{}", st.cfg.apps_domain))?;
    let labels: Vec<String> = rest.split('.').map(String::from).collect();
    Some(if labels.iter().all(|l| valid_slug(l) && l.len() <= 63) { labels } else { Vec::new() })
}

pub async fn handle(st: State, mut req: Req) -> Response {
    // A marketplace preview sandbox, for the capturing browser only: never on the public HTTPS listener.
    if req.via == crate::http::Via::Internal
        && let Some(token) = crate::preview::token_of(&req.host).map(String::from)
    {
        return crate::preview::serve(&st, req, &token).await.unwrap_or_else(|e| e.response());
    }
    if let Some(labels) = app_labels(&st, &req.host) {
        // App hosts answer HEAD themselves (gateway.rs), and a server app sees the method it was sent.
        return match labels.as_slice() {
            [app, workspace] => {
                // <app>--staging.<workspace> is the app's staging address.
                let (slug, staging) = match app.strip_suffix(crate::util::STAGING_SUFFIX) {
                    Some(base) if !base.is_empty() => (base.to_string(), true),
                    _ => (app.clone(), false),
                };
                let at = crate::gateway::Where::Slug { workspace: workspace.clone(), slug, staging };
                crate::gateway::serve_app(&st, req, at, None).await.unwrap_or_else(|e| e.response())
            }
            [w] if w == "www" => crate::http::redirect(&st.cfg.api_origin, &[]),
            [workspace] => crate::http::redirect(&format!("{}/w/{workspace}", st.cfg.api_origin), &[]),
            _ => crate::http::not_found(&st.cfg.api_origin),
        };
    }
    if req.host != st.cfg.api_host {
        // A custom domain a workspace has proven it owns.
        let (cfg, host) = (st.cfg.clone(), req.host.clone());
        match st.db.call(move |c| crate::domains::resolve_host(c, &cfg, &host)).await {
            Err(e) => return e.response(),
            Ok(None) => {}
            Ok(Some(crate::domains::Target::Home(w))) => return crate::http::redirect(&format!("{}/w/{w}", st.cfg.api_origin), &[]),
            Ok(Some(t)) => {
                let at = match t {
                    crate::domains::Target::App(id) => crate::gateway::Where::Id(id),
                    crate::domains::Target::Wildcard { workspace, slug } => crate::gateway::Where::Slug { workspace, slug, staging: false },
                    crate::domains::Target::Home(_) => unreachable!(),
                };
                let domain = Some(req.host.clone());
                return crate::gateway::serve_app(&st, req, at, domain).await.unwrap_or_else(|e| e.response());
            }
        }
    }
    // HEAD on the API host is GET without the body (uptime monitors and link previews use it): the same status,
    // redirects, cookies and headers, and the length of the body that was left out. /mcp is POST only and keeps its answer.
    if req.method == Method::HEAD && req.path != "/mcp" {
        req.method = Method::GET;
        return without_body(api_host(st, req).await);
    }
    api_host(st, req).await
}

/// A response for HEAD: the headers of the GET response, with content-length when the body's size is known.
fn without_body(res: Response) -> Response {
    let (mut parts, body) = res.into_parts();
    if let Some(n) = axum::body::HttpBody::size_hint(&body).exact()
        && !parts.headers.contains_key(CONTENT_LENGTH)
    {
        parts.headers.insert(CONTENT_LENGTH, n.into());
    }
    Response::from_parts(parts, Body::empty())
}

async fn api_host(st: State, mut req: Req) -> Response {
    let r = match req.path.as_str() {
        "/_caddy/ask" if is_internal(&st, &req) => caddy_ask(&st, &req).await,
        p if p.starts_with("/_runtime/") && is_internal(&st, &req) => crate::runtime::internal(&st, req).await,
        "/mcp" => crate::mcp::serve(&st, req).await,
        "/stripe/webhook" if req.method == Method::POST => {
            let body = req.bytes(1024 * 1024, "The webhook").await;
            match body {
                Ok(body) => crate::billing::webhook(&st, req.header("stripe-signature"), &body).await.map(json),
                Err(e) => Err(e),
            }
        }
        p if p.starts_with("/v1/") => crate::api::serve(&st, req).await,
        "/healthz" => Ok(json(
            json!({ "service": "brod", "ok": true, "mcp": format!("{}/mcp", req.origin()), "api": format!("{}/v1", req.origin()) }),
        )),
        _ => {
            let wants_json = req.is_json();
            let r = match crate::connect::serve(&st, &mut req).await {
                Ok(None) => crate::auth::serve(&st, &mut req).await,
                other => other,
            };
            match r {
                Ok(Some(r)) => Ok(r),
                Ok(None) => Ok(json_response(&json!({ "error": { "code": "not_found", "message": "Nothing here." } }), 404, &[])),
                // People filling in a form get a page, not JSON.
                Err(e) if !e.is_internal() && !wants_json => {
                    Ok(notice(e.status, "Something needs attention", &e.message, "<p><a href=\"/\">Back</a></p>"))
                }
                Err(e) => Err(e),
            }
        }
    };
    r.unwrap_or_else(|e| e.response())
}

/// /_caddy/ask answers only on an address that is neither the API host nor an app host: Caddy calls it as
/// http://brod:8080 inside the Docker network, and every public request Caddy forwards carries one of the public hosts.
/// Never on Brod's own public HTTPS listener (tls.rs), whatever the host.
fn is_internal(st: &State, req: &Req) -> bool {
    req.via == crate::http::Via::Internal && req.host != st.cfg.api_host && !req.host.ends_with(&format!(".{}", st.cfg.apps_domain))
}

/// Caddy's on-demand TLS asks here before it requests a certificate.
async fn caddy_ask(st: &State, req: &Req) -> Result<Response> {
    let domain = req.param("domain").unwrap_or_default().trim_end_matches('.').to_lowercase();
    Ok(empty(if may_have_certificate(st, &domain).await? { 200 } else { 404 }))
}

/// Whether a certificate may be issued for `domain`: the API host, www, an existing <workspace>.<APPS_DOMAIN>, an
/// existing <slug>.<workspace>.<APPS_DOMAIN>, or a proven custom domain, so certificates are issued only for real
/// addresses. For /_caddy/ask and Brod's own on-demand TLS (tls.rs).
pub async fn may_have_certificate(st: &State, domain: &str) -> Result<bool> {
    let domain = domain.trim_end_matches('.').to_lowercase();
    let strip_port = |h: &str| h.split(':').next().unwrap_or("").to_string();
    if domain.is_empty() || domain.contains(':') {
        return Ok(false);
    }
    if domain == strip_port(&st.cfg.api_host) {
        return Ok(true);
    }
    let apps = strip_port(&st.cfg.apps_domain);
    let Some(rest) = domain.strip_suffix(&format!(".{apps}")) else {
        let cfg = st.cfg.clone();
        return st.db.call(move |c| crate::domains::may_serve(c, &cfg, &domain)).await;
    };
    let labels: Vec<String> = rest.split('.').map(String::from).collect();
    if !labels.iter().all(|l| valid_slug(l)) {
        return Ok(false);
    }
    let exists = match labels.as_slice() {
        [w] if w == "www" => true,
        [w] => {
            let w = w.clone();
            st.db.call(move |c| c.exists("SELECT 1 FROM workspaces WHERE slug = ?", [w])).await?
        }
        [a, w] => {
            let (a, w) = (a.clone(), w.clone());
            st.db
                .call(move |c| {
                    c.exists("SELECT 1 FROM apps a JOIN workspaces w ON w.id = a.workspace_id WHERE w.slug = ? AND a.slug = ?", [w, a])
                })
                .await?
        }
        _ => false,
    };
    Ok(exists)
}

/// Make a Req from what hyper hands us.
pub fn request(st: &State, parts: axum::http::request::Parts, body: axum::body::Body) -> std::result::Result<Req, Problem> {
    let host = parts
        .headers
        .get("host")
        .and_then(|v| v.to_str().ok())
        .map(String::from)
        .or_else(|| parts.uri.authority().map(|a| a.to_string()))
        .unwrap_or_else(|| "localhost".into())
        .to_lowercase();
    let forwarded = st
        .cfg
        .trust_proxy
        .then(|| {
            parts
                .headers
                .get("x-forwarded-proto")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.split(',').next())
                .map(|v| v.trim().to_lowercase())
        })
        .flatten()
        .filter(|p| p == "https" || p == "http");
    let via = parts.extensions.get::<crate::http::Via>().copied().unwrap_or(crate::http::Via::Internal);
    // An http URL keeps its port in URL.host unless it is the default one.
    let scheme = if via == crate::http::Via::Https { "https".into() } else { forwarded.unwrap_or_else(|| "http".into()) };
    let host = match (scheme.as_str(), host.strip_suffix(":80"), host.strip_suffix(":443")) {
        ("http", Some(h), _) => h.to_string(),
        ("https", _, Some(h)) => h.to_string(),
        _ => host,
    };
    Ok(Req {
        method: parts.method,
        scheme,
        host,
        path: crate::http::normalize_path(parts.uri.path()),
        query: parts.uri.query().unwrap_or("").to_string(),
        peer: parts.extensions.get::<crate::http::Peer>().map(|p| p.0),
        via,
        headers: parts.headers,
        body: std::sync::Mutex::new(body),
    })
}

/// Serve one connection (plain TCP from main.rs, or TLS from tls.rs) with HTTP/1.1 or HTTP/2.
pub async fn serve_connection<I>(st: State, io: I, peer: std::net::IpAddr, via: crate::http::Via)
where
    I: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let service = hyper::service::service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
        let st = st.clone();
        async move {
            let (mut parts, body) = req.into_parts();
            parts.extensions.insert(crate::http::Peer(peer));
            parts.extensions.insert(via);
            let res = match request(&st, parts, axum::body::Body::new(body)) {
                Ok(r) => handle(st, r).await,
                Err(e) => e.response(),
            };
            Ok::<_, std::convert::Infallible>(res)
        }
    });
    let mut builder = hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new());
    builder.http1().timer(hyper_util::rt::TokioTimer::new()).header_read_timeout(std::time::Duration::from_secs(30)).keep_alive(true);
    let _ = builder.serve_connection_with_upgrades(hyper_util::rt::TokioIo::new(io), service).await;
}
