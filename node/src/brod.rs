// SPDX-License-Identifier: AGPL-3.0-only
//! Talking to Brod: one HTTP/1.1 connection per call, over TLS for an https:// address and plain TCP for http:// (local
//! and development). TLS offers only http/1.1, so the connect Upgrade works through Brod's own TLS listener and Caddy.
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::Request;
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncRead, AsyncWrite};

/// How long a call to Brod may take, connecting included.
const CALL_TIMEOUT: Duration = Duration::from_secs(30);

/// Where Brod is, from its public address.
#[derive(Clone, Debug, PartialEq)]
pub struct Brod {
    pub url: String,
    tls: bool,
    host: String,
    port: u16,
}

impl Brod {
    /// `http(s)://host[:port]`, with any path ignored.
    pub fn parse(url: &str) -> Result<Brod, String> {
        let url = url.trim().trim_end_matches('/');
        let (tls, rest) = if let Some(r) = url.strip_prefix("https://") {
            (true, r)
        } else if let Some(r) = url.strip_prefix("http://") {
            (false, r)
        } else {
            return Err(format!("{url} must start with https:// (or http:// for a local Brod)"));
        };
        let authority = rest.split('/').next().unwrap_or("");
        // An IPv6 address is in brackets: [::1]:8080.
        let split = match authority.rfind(']') {
            Some(end) => authority[end + 1..].strip_prefix(':').map(|p| (&authority[..=end], p)),
            None => authority.rsplit_once(':'),
        };
        let (host, port) = match split {
            Some((h, p)) => (h, p.parse::<u16>().map_err(|_| format!("{url} has a bad port"))?),
            None if authority.contains(']') || !authority.contains(':') => (authority, if tls { 443 } else { 80 }),
            None => return Err(format!("{url} has a bad host")),
        };
        if host.is_empty() {
            return Err(format!("{url} has no host"));
        }
        Ok(Brod { url: format!("{}://{authority}", if tls { "https" } else { "http" }), tls, host: host.to_string(), port })
    }

    /// The Host header: the host, and the port unless it is the scheme's default.
    pub fn authority(&self) -> String {
        if self.port == if self.tls { 443 } else { 80 } { self.host.clone() } else { format!("{}:{}", self.host, self.port) }
    }

    async fn dial(&self) -> Result<Box<dyn Io>, String> {
        let host = self.host.trim_start_matches('[').trim_end_matches(']').to_string();
        let tcp =
            tokio::net::TcpStream::connect((host.as_str(), self.port)).await.map_err(|e| format!("cannot reach {}: {e}", self.url))?;
        let _ = tcp.set_nodelay(true);
        if !self.tls {
            return Ok(Box::new(tcp));
        }
        let name = rustls::pki_types::ServerName::try_from(host.clone()).map_err(|_| format!("{host} is not a valid TLS name"))?;
        let tls =
            tokio_rustls::TlsConnector::from(tls_config()).connect(name, tcp).await.map_err(|e| format!("TLS with {}: {e}", self.url))?;
        Ok(Box::new(tls))
    }

    /// Send one request and read the whole answer: its status and body.
    pub async fn call(&self, req: Request<Full<Bytes>>) -> Result<(u16, Bytes), String> {
        let run = async {
            let mut send = self.handshake().await?;
            let res = send.send_request(req).await.map_err(|e| format!("{}: {e}", self.url))?;
            let status = res.status().as_u16();
            let body = res.into_body().collect().await.map_err(|e| format!("{}: {e}", self.url))?.to_bytes();
            Ok((status, body))
        };
        tokio::time::timeout(CALL_TIMEOUT, run).await.map_err(|_| format!("{} did not answer in time", self.url))?
    }

    /// Send a request that asks to upgrade the connection. The upgraded connection, or the status and body of a refusal.
    pub async fn upgrade(&self, req: Request<Full<Bytes>>) -> Result<Result<hyper::upgrade::Upgraded, (u16, Bytes)>, String> {
        let run = async {
            let mut send = self.handshake().await?;
            let res = send.send_request(req).await.map_err(|e| format!("{}: {e}", self.url))?;
            if res.status() != hyper::StatusCode::SWITCHING_PROTOCOLS {
                let status = res.status().as_u16();
                let body = res.into_body().collect().await.map(|b| b.to_bytes()).unwrap_or_default();
                return Ok(Err((status, body)));
            }
            hyper::upgrade::on(res).await.map(Ok).map_err(|e| format!("the upgrade failed: {e}"))
        };
        tokio::time::timeout(CALL_TIMEOUT, run).await.map_err(|_| format!("{} did not answer in time", self.url))?
    }

    async fn handshake(&self) -> Result<hyper::client::conn::http1::SendRequest<Full<Bytes>>, String> {
        let io = self.dial().await?;
        let (send, conn) = hyper::client::conn::http1::handshake(TokioIo::new(io)).await.map_err(|e| format!("{}: {e}", self.url))?;
        tokio::spawn(async move {
            let _ = conn.with_upgrades().await;
        });
        Ok(send)
    }

    /// A request to `path` on Brod with the Host header set.
    pub fn request(&self, method: &str, path: &str) -> hyper::http::request::Builder {
        Request::builder().method(method).uri(path).header("host", self.authority())
    }
}

/// A connection to Brod, plain or TLS.
trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}

fn tls_config() -> Arc<rustls::ClientConfig> {
    static CONFIG: std::sync::OnceLock<Arc<rustls::ClientConfig>> = std::sync::OnceLock::new();
    CONFIG
        .get_or_init(|| {
            let roots = rustls::RootCertStore { roots: webpki_roots::TLS_SERVER_ROOTS.to_vec() };
            let mut c = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .expect("TLS versions")
                .with_root_certificates(roots)
                .with_no_client_auth();
            // HTTP/1.1 only: an Upgrade does not exist in HTTP/2.
            c.alpn_protocols = vec![b"http/1.1".to_vec()];
            Arc::new(c)
        })
        .clone()
}

/// The `message` of a Problem answer from Brod, or the raw text.
pub fn problem(body: &[u8]) -> String {
    serde_json::from_slice::<serde_json::Value>(body)
        .ok()
        .and_then(|v| v["error"]["message"].as_str().map(String::from))
        .unwrap_or_else(|| String::from_utf8_lossy(body).chars().take(300).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_brod_addresses() {
        let b = Brod::parse("https://brod.example.com/").unwrap();
        assert_eq!(
            (b.url.as_str(), b.tls, b.host.as_str(), b.port, b.authority()),
            ("https://brod.example.com", true, "brod.example.com", 443, "brod.example.com".into())
        );
        let b = Brod::parse("http://brod:8080").unwrap();
        assert_eq!((b.tls, b.host.as_str(), b.port, b.authority()), (false, "brod", 8080, "brod:8080".into()));
        let b = Brod::parse("http://[::1]:9000/x").unwrap();
        assert_eq!((b.host.as_str(), b.port), ("[::1]", 9000));
        assert!(Brod::parse("brod.example.com").is_err());
        assert!(Brod::parse("https://:443").is_err());
        assert!(Brod::parse("http://h:port").is_err());
    }

    #[test]
    fn reads_problem_messages() {
        assert_eq!(problem(br#"{"error":{"code":"x","message":"Nope."}}"#), "Nope.");
        assert_eq!(problem(b"plain"), "plain");
    }
}
