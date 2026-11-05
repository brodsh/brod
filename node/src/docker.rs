// SPDX-License-Identifier: AGPL-3.0-only
//! The Docker Engine API over its unix socket (BROD_NODE_DOCKER_SOCKET, default /var/run/docker.sock): one HTTP/1.1
//! connection per call. Builds use the docker CLI's buildx instead (work.rs), since BuildKit's API is gRPC.
use std::path::PathBuf;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::Request;
use hyper::body::Incoming;
use hyper_util::rt::TokioIo;
use serde_json::Value;

use crate::work::{Body, BoxError};

/// How long an API call without a streamed body may take.
const CALL_TIMEOUT: Duration = Duration::from_secs(120);

pub struct Docker {
    socket: PathBuf,
}

/// Percent-encode a query value.
pub fn q(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => (b as char).to_string(),
            _ => format!("%{b:02X}"),
        })
        .collect()
}

pub fn empty() -> Body {
    Full::new(Bytes::new()).map_err(|never| match never {}).boxed()
}

impl Docker {
    pub fn from_env() -> Docker {
        Docker { socket: crate::sys::docker_socket().into() }
    }

    /// Send a request and get the response with its body still streaming.
    pub async fn send(
        &self,
        method: &str,
        path: &str,
        content_type: Option<&str>,
        body: Body,
    ) -> Result<hyper::Response<Incoming>, String> {
        let stream = tokio::net::UnixStream::connect(&self.socket)
            .await
            .map_err(|e| format!("Docker is not reachable at {}: {e}", self.socket.display()))?;
        let (mut send, conn) =
            hyper::client::conn::http1::handshake(TokioIo::new(stream)).await.map_err(|e| format!("Docker did not answer: {e}"))?;
        tokio::spawn(conn);
        let mut req = Request::builder().method(method).uri(path).header("host", "docker");
        if let Some(ct) = content_type {
            req = req.header("content-type", ct);
        }
        let req = req.body(body).map_err(|e| e.to_string())?;
        send.send_request(req).await.map_err(|e| format!("Docker failed: {e}"))
    }

    /// A call with an optional JSON body; the status and the JSON (or text, as a string) it answers.
    pub async fn call(&self, method: &str, path: &str, body: Option<&Value>) -> Result<(u16, Value), String> {
        let work = async {
            let res = match body {
                Some(b) => {
                    let body = Full::new(Bytes::from(b.to_string())).map_err(|never| -> BoxError { match never {} }).boxed();
                    self.send(method, path, Some("application/json"), body).await?
                }
                None => self.send(method, path, None, empty()).await?,
            };
            let status = res.status().as_u16();
            let bytes = res.into_body().collect().await.map_err(|e| format!("Docker's answer broke off: {e}"))?.to_bytes();
            let v = serde_json::from_slice(&bytes).unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).trim().to_string()));
            Ok((status, v))
        };
        tokio::time::timeout(CALL_TIMEOUT, work).await.map_err(|_| format!("Docker took too long to answer {method} {path}"))?
    }

    /// Like call, but anything other than 2xx is an error carrying Docker's message.
    pub async fn ok(&self, method: &str, path: &str, body: Option<&Value>) -> Result<Value, String> {
        let (status, v) = self.call(method, path, body).await?;
        if (200..300).contains(&status) { Ok(v) } else { Err(message(status, &v)) }
    }
}

/// Docker's error message.
pub fn message(status: u16, v: &Value) -> String {
    let m = v["message"].as_str().or(v.as_str()).unwrap_or("").trim();
    format!("Docker answered {status}: {m}")
}

/// Split Docker's multiplexed log stream (8-byte frame headers: stream, 3 zero bytes, a big-endian length) into
/// (stream, line) pairs. A TTY container's raw output (no headers) is read as plain lines from stdout.
pub fn demux(mut b: &[u8]) -> Vec<(&'static str, String)> {
    let framed = b.len() >= 8 && matches!(b[0], 0..=2) && b[1..4] == [0, 0, 0];
    if !framed {
        return String::from_utf8_lossy(b).lines().map(|l| ("stdout", l.to_string())).collect();
    }
    let mut out = Vec::new();
    while b.len() >= 8 {
        let stream = if b[0] == 2 { "stderr" } else { "stdout" };
        let n = u32::from_be_bytes([b[4], b[5], b[6], b[7]]) as usize;
        let end = (8 + n).min(b.len());
        for l in String::from_utf8_lossy(&b[8..end]).lines() {
            out.push((stream, l.to_string()));
        }
        b = &b[end..];
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_multiplexed_logs() {
        let mut b = vec![1, 0, 0, 0, 0, 0, 0, 6];
        b.extend_from_slice(b"a\nbcd\n");
        b.extend_from_slice(&[2, 0, 0, 0, 0, 0, 0, 3]);
        b.extend_from_slice(b"err");
        assert_eq!(demux(&b), [("stdout", "a".to_string()), ("stdout", "bcd".into()), ("stderr", "err".into())]);
        assert_eq!(demux(b"plain\nlines"), [("stdout", "plain".to_string()), ("stdout", "lines".into())]);
        assert_eq!(q("a b/c"), "a%20b%2Fc");
    }
}
