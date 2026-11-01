// SPDX-License-Identifier: AGPL-3.0-only
// The one way Brod makes an HTTP request to an address a user supplied (importing an app from a git url). It exists so
// that request cannot be used to reach the server's own network: loopback, private, link-local (cloud metadata is at
// 169.254.169.254), carrier-grade NAT and every other non-public range are refused, for the address in the url and for
// every address a redirect leads to.
//
// DNS rebinding: the name is resolved here, every address it resolves to must be public, and the connection is then
// made to one of those addresses (reqwest's `resolve`), so a second lookup by the HTTP client cannot return a different
// answer. The url's host name is still used for TLS and the Host header.
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use futures_util::StreamExt;
use reqwest::Url;
use reqwest::header::HeaderMap;

use crate::problem::{Problem, Result};

pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
pub const TOTAL_TIMEOUT: Duration = Duration::from_secs(120);
const MAX_REDIRECTS: usize = 5;

/// What a request may reach. There is no setting for `allow_loopback`: only tests build a policy that has it, to talk to a
/// listener on 127.0.0.1. Every other non-public range stays refused under it.
#[derive(Clone, Copy, Debug)]
pub struct Policy {
    allow_loopback: bool,
}

impl Policy {
    pub const fn strict() -> Policy {
        Policy { allow_loopback: false }
    }
    #[cfg(test)]
    pub const fn permissive_for_tests() -> Policy {
        Policy { allow_loopback: true }
    }
}

pub struct Request {
    pub post: bool,
    pub url: String,
    pub headers: Vec<(&'static str, String)>,
    pub body: Vec<u8>,
}

pub struct Reply {
    pub status: u16,
    pub headers: HeaderMap,
    pub body: Vec<u8>,
}

fn v4_public(a: Ipv4Addr) -> bool {
    let o = a.octets();
    !(a.is_loopback()
        || a.is_private()
        || a.is_link_local()
        || a.is_unspecified()
        || a.is_broadcast()
        || a.is_multicast()
        || o[0] == 0
        || (o[0] == 100 && (64..128).contains(&o[1]))
        || (o[0] == 192 && o[1] == 0 && o[2] == 0)
        || (o[0] == 192 && o[1] == 0 && o[2] == 2)
        || (o[0] == 198 && (o[1] == 18 || o[1] == 19))
        || (o[0] == 198 && o[1] == 51 && o[2] == 100)
        || (o[0] == 203 && o[1] == 0 && o[2] == 113)
        || o[0] >= 240)
}

fn v6_public(a: Ipv6Addr) -> bool {
    let s = a.segments();
    if a.is_loopback() || a.is_unspecified() || a.is_multicast() {
        return false;
    }
    // fc00::/7 unique local, fe80::/10 link-local, fec0::/10 site-local
    if (s[0] & 0xfe00) == 0xfc00 || (s[0] & 0xffc0) == 0xfe80 || (s[0] & 0xffc0) == 0xfec0 {
        return false;
    }
    // 2001:db8::/32 documentation
    if s[0] == 0x2001 && s[1] == 0x0db8 {
        return false;
    }
    let embedded = |hi: u16, lo: u16| Ipv4Addr::new((hi >> 8) as u8, hi as u8, (lo >> 8) as u8, lo as u8);
    // ::ffff:a.b.c.d (mapped) and ::a.b.c.d (deprecated compatible)
    if s[..5] == [0, 0, 0, 0, 0] && (s[5] == 0xffff || s[5] == 0) {
        return v4_public(embedded(s[6], s[7]));
    }
    // 64:ff9b::/96 NAT64 carries an IPv4 address in its last 32 bits
    if s[0] == 0x64 && s[1] == 0xff9b && s[2..6] == [0, 0, 0, 0] {
        return v4_public(embedded(s[6], s[7]));
    }
    // 2002::/16 6to4 carries one in bits 16..48
    if s[0] == 0x2002 {
        return v4_public(embedded(s[1], s[2]));
    }
    true
}

pub fn is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(a) => v4_public(a),
        IpAddr::V6(a) => v6_public(a),
    }
}

fn refused(what: impl Into<String>) -> Problem {
    Problem::new(400, "blocked_url", what.into())
}

/// Check the url and resolve its host to addresses that are all allowed. Returns the host name to pin and the address
/// to connect to (None for an IP literal, which needs no pinning).
async fn vet(policy: Policy, url: &Url) -> Result<Option<(String, SocketAddr)>> {
    if !matches!(url.scheme(), "http" | "https") {
        return Err(refused("Only http and https addresses can be fetched."));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(refused("The address may not contain a user name or password."));
    }
    let port = url.port_or_known_default().unwrap_or(80);
    match url.host() {
        None => Err(refused("The address has no host.")),
        Some(url::Host::Ipv4(a)) => {
            if !(policy.allow_loopback && a.is_loopback()) && !v4_public(a) {
                return Err(refused(format!("{a} is not a public address, so Brod will not fetch from it.")));
            }
            Ok(None)
        }
        Some(url::Host::Ipv6(a)) => {
            if !(policy.allow_loopback && a.is_loopback()) && !v6_public(a) {
                return Err(refused(format!("{a} is not a public address, so Brod will not fetch from it.")));
            }
            Ok(None)
        }
        Some(url::Host::Domain(d)) => {
            let host = d.to_string();
            let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host.as_str(), port))
                .await
                .map_err(|_| Problem::new(502, "fetch_failed", format!("Could not find {host}.")))?
                .collect();
            if addrs.is_empty() {
                return Err(Problem::new(502, "fetch_failed", format!("Could not find {host}.")));
            }
            if let Some(bad) = addrs.iter().find(|a| !is_public(a.ip()) && !(policy.allow_loopback && a.ip().is_loopback())) {
                return Err(refused(format!(
                    "{host} points at {}, which is not a public address, so Brod will not fetch from it.",
                    bad.ip()
                )));
            }
            Ok(Some((host, addrs[0])))
        }
    }
}

/// Make the request, following at most a few redirects, each vetted like the first address. The body is read up to
/// `max_body` bytes; a longer one is an error.
pub async fn send(policy: Policy, req: &Request, max_body: usize) -> Result<Reply> {
    let mut url = Url::parse(&req.url).map_err(|_| refused("That is not a valid address."))?;
    let (mut post, mut body) = (req.post, req.body.clone());
    for _ in 0..=MAX_REDIRECTS {
        let pin = vet(policy, &url).await?;
        let mut b = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(CONNECT_TIMEOUT)
            .timeout(TOTAL_TIMEOUT)
            .user_agent("brod");
        if let Some((host, addr)) = pin {
            b = b.resolve(&host, addr);
        }
        let client = b.build().map_err(Problem::internal)?;
        let mut r = if post { client.post(url.clone()).body(body.clone()) } else { client.get(url.clone()) };
        for (k, v) in &req.headers {
            r = r.header(*k, v);
        }
        let resp = r.send().await.map_err(|e| {
            if e.is_timeout() {
                Problem::new(504, "fetch_timeout", "The repository took too long to answer.")
            } else {
                Problem::new(502, "fetch_failed", "Could not connect to the repository.")
            }
        })?;
        let status = resp.status().as_u16();
        if matches!(status, 301 | 302 | 303 | 307 | 308) {
            let to = resp
                .headers()
                .get("location")
                .and_then(|v| v.to_str().ok())
                .and_then(|l| url.join(l).ok())
                .ok_or_else(|| Problem::new(502, "fetch_failed", "The repository sent a redirect with no usable address."))?;
            if matches!(status, 301..=303) {
                post = false;
                body = Vec::new();
            }
            url = to;
            continue;
        }
        let headers = resp.headers().clone();
        if resp.content_length().is_some_and(|n| n > max_body as u64) {
            return Err(Problem::new(413, "too_large", "The repository is larger than Brod accepts."));
        }
        let mut out = Vec::new();
        let mut stream = resp.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|_| Problem::new(502, "fetch_failed", "The connection to the repository broke."))?;
            if out.len() + chunk.len() > max_body {
                return Err(Problem::new(413, "too_large", "The repository is larger than Brod accepts."));
            }
            out.extend_from_slice(&chunk);
        }
        return Ok(Reply { status, headers, body: out });
    }
    Err(Problem::new(502, "fetch_failed", "The repository redirected too many times."))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn only_public_addresses_pass() {
        for ok in ["8.8.8.8", "1.1.1.1", "93.184.216.34", "2606:4700:4700::1111", "::ffff:8.8.8.8"] {
            assert!(is_public(ip(ok)), "{ok} should be allowed");
        }
        for bad in [
            "127.0.0.1",
            "127.1.2.3",
            "10.0.0.5",
            "172.16.0.1",
            "172.31.255.255",
            "192.168.1.1",
            "169.254.169.254",
            "100.64.0.1",
            "100.127.255.255",
            "0.0.0.0",
            "0.1.2.3",
            "224.0.0.1",
            "240.0.0.1",
            "255.255.255.255",
            "192.0.2.1",
            "198.18.0.1",
            "198.51.100.1",
            "203.0.113.1",
            "::1",
            "::",
            "fe80::1",
            "fc00::1",
            "fd12:3456::1",
            "ff02::1",
            "2001:db8::1",
            "::ffff:127.0.0.1",
            "::ffff:169.254.169.254",
            "::ffff:10.0.0.1",
            "64:ff9b::7f00:1",
            "2002:7f00:1::",
        ] {
            assert!(!is_public(ip(bad)), "{bad} should be refused");
        }
    }

    async fn refused_msg(url: &str) -> String {
        let r = Request { post: false, url: url.into(), headers: vec![], body: vec![] };
        match send(Policy::strict(), &r, 1000).await {
            Err(p) => p.message,
            Ok(_) => panic!("{url} was fetched"),
        }
    }

    #[tokio::test]
    async fn the_guard_refuses_private_targets_and_odd_urls() {
        assert!(refused_msg("http://127.0.0.1:9/x").await.contains("not a public address"));
        assert!(refused_msg("http://[::1]/x").await.contains("not a public address"));
        assert!(refused_msg("http://169.254.169.254/latest/meta-data").await.contains("not a public address"));
        assert!(refused_msg("http://localhost/x").await.contains("not a public address"));
        assert!(refused_msg("ftp://example.com/x").await.contains("Only http"));
        assert!(refused_msg("file:///etc/passwd").await.contains("Only http"));
        assert!(refused_msg("http://user:pw@example.com/").await.contains("user name"));
        assert!(refused_msg("not a url").await.contains("valid address"));
    }

    async fn serve_once(reply: String) -> u16 {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        tokio::spawn(async move {
            if let Ok((mut s, _)) = l.accept().await {
                let mut buf = [0u8; 4096];
                let _ = s.read(&mut buf).await;
                let _ = s.write_all(reply.as_bytes()).await;
            }
        });
        port
    }

    #[tokio::test]
    async fn a_permissive_policy_reaches_a_local_listener_and_caps_the_body() {
        let port = serve_once("HTTP/1.1 200 OK\r\ncontent-length: 5\r\nconnection: close\r\n\r\nhello".into()).await;
        let r = Request { post: false, url: format!("http://127.0.0.1:{port}/"), headers: vec![], body: vec![] };
        let got = send(Policy::permissive_for_tests(), &r, 100).await.unwrap();
        assert_eq!((got.status, got.body.as_slice()), (200, &b"hello"[..]));
        let port = serve_once("HTTP/1.1 200 OK\r\ncontent-length: 5\r\nconnection: close\r\n\r\nhello".into()).await;
        let r = Request { post: false, url: format!("http://127.0.0.1:{port}/"), headers: vec![], body: vec![] };
        assert_eq!(send(Policy::permissive_for_tests(), &r, 3).await.err().map(|p| p.status), Some(413));
    }

    #[tokio::test]
    async fn a_redirect_to_a_private_address_is_refused() {
        let port = serve_once(
            "HTTP/1.1 302 Found\r\nlocation: http://169.254.169.254/latest\r\ncontent-length: 0\r\nconnection: close\r\n\r\n".into(),
        )
        .await;
        let r = Request { post: false, url: format!("http://127.0.0.1:{port}/"), headers: vec![], body: vec![] };
        let e = send(Policy::permissive_for_tests(), &r, 100).await.err().unwrap();
        assert_eq!(e.code, "blocked_url");
        assert!(e.message.contains("169.254.169.254"));
    }
}
