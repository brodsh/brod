// SPDX-License-Identifier: AGPL-3.0-only
//! What the node answers over its connection to Brod, once the roles have reversed: Brod is the HTTP/2 client and the
//! node the server, so only Brod can send these requests.
//! ```text
//!   GET  /v1/ping   "pong"
//!   GET  /v1/info   the node's id, name, version, capabilities and usage (as in a heartbeat)
//!   POST /v1/echo   the request body streamed straight back, to check the tunnel end to end
//!   /v1/builds, /v1/images, /v1/containers, /v1/proxy   workloads (work.rs)
//!   /v1/db/accept, /v1/db/conns/<id>                    the database proxy (db.rs)
//! ```
use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;

use http_body_util::BodyExt;
use hyper::body::Incoming;
use hyper::{Method, Request, Response};

use crate::Node;
use crate::work::{Body, BoxError, full};

async fn handle(node: Arc<Node>, req: Request<Incoming>) -> Result<Response<Body>, Infallible> {
    if crate::db::handles(req.uri().path()) {
        return Ok(crate::db::handle(node, req).await);
    }
    if crate::work::handles(req.uri().path()) {
        return Ok(crate::work::handle(node, req).await);
    }
    Ok(match (req.method(), req.uri().path()) {
        (&Method::GET, "/v1/ping") => full(200, "text/plain", "pong"),
        (&Method::GET, "/v1/info") => {
            let mut v = crate::report(&node);
            v["id"] = node.me.id.clone().into();
            v["name"] = node.name.clone().into();
            full(200, "application/json", v.to_string())
        }
        (&Method::POST, "/v1/echo") => {
            let mut res = Response::new(req.into_body().map_err(|e| -> BoxError { Box::new(e) }).boxed());
            if let Ok(v) = "application/octet-stream".parse() {
                res.headers_mut().insert("content-type", v);
            }
            res
        }
        _ => full(404, "application/json", r#"{"error":{"code":"not_found","message":"Nothing here."}}"#),
    })
}

/// Serve HTTP/2 to Brod over the upgraded connection until it closes.
pub async fn serve(node: Arc<Node>, io: hyper::upgrade::Upgraded) -> Result<(), String> {
    let svc = hyper::service::service_fn(move |req| handle(node.clone(), req));
    hyper::server::conn::http2::Builder::new(hyper_util::rt::TokioExecutor::new())
        .timer(hyper_util::rt::TokioTimer::new())
        // Notice a Brod that went away without closing (a lost network) within 30 s.
        .keep_alive_interval(Duration::from_secs(15))
        .keep_alive_timeout(Duration::from_secs(15))
        .serve_connection(io, svc)
        .await
        .map_err(|e| format!("the connection to Brod failed: {e}"))
}
