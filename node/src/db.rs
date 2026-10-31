// SPDX-License-Identifier: AGPL-3.0-only
//! The database proxy (plan D5): an app's containers reach its managed Postgres at brod-db.internal:5432, and the node
//! carries each TCP connection to Brod over the tunnel. The database itself is never on the network.
//!
//! One listener per app bridge, bound where only that bridge reaches it:
//!   ip       the bridge's gateway address, port 5432; firewall.rs lets the bridge reach that port and nothing else on
//!            the node, and a connection from outside the bridge's subnet is refused here too
//!   attach   the node's own address on the bridge (the node is a container joined to it)
//!   publish  127.0.0.1 on a port of its own, reached through host-gateway (Docker Desktop: development only, since
//!            every container can reach the host there; Brod's checks still keep each app to its own database)
//! The container gets `brod-db.internal` as an extra host pointing at the listener.
//!
//! The tunnel's roles are reversed (Brod is the HTTP/2 client), so the node cannot open a stream itself. Instead:
//!   GET    /v1/db/accept       a long-lived stream Brod keeps open: one NDJSON line {"conn", "app"} per accepted
//!                              connection, `app` being the app whose listener accepted it
//!   POST   /v1/db/conns/<id>   Brod takes the connection: its request body goes to the socket, the socket's bytes come
//!                              back as the response body (one full-duplex HTTP/2 stream)
//!   DELETE /v1/db/conns/<id>   Brod refuses it; the socket closes
//! A connection Brod does not take within 15 s is closed.
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::BodyExt;
use hyper::body::Incoming;
use hyper::{Method, Request, Response};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;

use crate::Node;
use crate::work::{Body, Reach, channel, fail, reply};

/// The name containers reach their database by, and its port.
pub const HOST: &str = "brod-db.internal";
pub const PORT: u16 = 5432;
/// How long an accepted connection waits for Brod to take it.
const PENDING: Duration = Duration::from_secs(15);
/// Accepted connections waiting for Brod, at most.
const MAX_PENDING: usize = 256;

macro_rules! log {
    ($($t:tt)*) => { eprintln!("brod-node: {}", format!($($t)*)) };
}

struct Listener {
    app: String,
    addr: SocketAddr,
    task: tokio::task::AbortHandle,
}

struct Inner {
    /// By network name.
    listeners: Mutex<HashMap<String, Listener>>,
    /// Accepted connections waiting for Brod, by connection id: the app and the socket.
    pending: Mutex<HashMap<String, (String, TcpStream)>>,
    tx: mpsc::UnboundedSender<(String, String)>,
    rx: tokio::sync::Mutex<mpsc::UnboundedReceiver<(String, String)>>,
}

#[derive(Clone)]
pub struct Proxy(Arc<Inner>);

impl Default for Proxy {
    fn default() -> Proxy {
        let (tx, rx) = mpsc::unbounded_channel();
        Proxy(Arc::new(Inner {
            listeners: Mutex::new(HashMap::new()),
            pending: Mutex::new(HashMap::new()),
            tx,
            rx: tokio::sync::Mutex::new(rx),
        }))
    }
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn conn_id() -> String {
    let mut b = [0u8; 16];
    let _ = ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut b);
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// An IPv4 subnet "a.b.c.d/n" as (network, mask).
pub fn parse_subnet(s: &str) -> Option<(u32, u32)> {
    let (ip, bits) = s.split_once('/')?;
    let ip: Ipv4Addr = ip.parse().ok()?;
    let bits: u32 = bits.parse().ok().filter(|b| *b <= 32)?;
    let mask = if bits == 0 { 0 } else { u32::MAX << (32 - bits) };
    Some((u32::from(ip) & mask, mask))
}

/// Whether `ip` is inside the subnet.
pub fn inside(subnet: (u32, u32), ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => u32::from(v4) & subnet.1 == subnet.0,
        IpAddr::V6(v6) => v6.to_ipv4_mapped().is_some_and(|v4| u32::from(v4) & subnet.1 == subnet.0),
    }
}

/// Where the listener for a bridge goes: the address to bind and who may connect (None: anyone who reaches it).
pub struct Bind {
    pub addr: SocketAddr,
    pub subnet: Option<(u32, u32)>,
    /// What the container's extra host points at: an address, or "host-gateway".
    pub extra_host: String,
}

impl Proxy {
    /// Make sure the bridge `network` has a listener for `app`. The address it listens on.
    pub fn ensure(&self, network: &str, app: &str, bind: Bind) -> Result<SocketAddr, String> {
        let mut l = lock(&self.0.listeners);
        if let Some(x) = l.get(network) {
            if x.app == app && !x.task.is_finished() {
                return Ok(x.addr);
            }
            x.task.abort();
            l.remove(network);
        }
        let std = std::net::TcpListener::bind(bind.addr).map_err(|e| format!("The database listener could not bind {}: {e}", bind.addr))?;
        std.set_nonblocking(true).map_err(|e| e.to_string())?;
        let listener = TcpListener::from_std(std).map_err(|e| e.to_string())?;
        let addr = listener.local_addr().map_err(|e| e.to_string())?;
        let task = tokio::spawn(accept(self.clone(), listener, app.to_string(), bind.subnet)).abort_handle();
        log!("database listener for {app} on {addr} ({network})");
        l.insert(network.to_string(), Listener { app: app.to_string(), addr, task });
        Ok(addr)
    }
}

async fn accept(proxy: Proxy, listener: TcpListener, app: String, subnet: Option<(u32, u32)>) {
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(x) => x,
            Err(e) => {
                log!("database listener for {app}: {e}");
                tokio::time::sleep(Duration::from_millis(200)).await;
                continue;
            }
        };
        if let Some(s) = subnet
            && !inside(s, peer.ip())
        {
            log!("database listener for {app}: refused {peer}, which is not on the app's bridge");
            continue;
        }
        let _ = stream.set_nodelay(true);
        let id = conn_id();
        {
            let mut p = lock(&proxy.0.pending);
            if p.len() >= MAX_PENDING {
                log!("database listener for {app}: too many connections waiting for Brod; refused {peer}");
                continue;
            }
            p.insert(id.clone(), (app.clone(), stream));
        }
        let _ = proxy.0.tx.send((id.clone(), app.clone()));
        let p = proxy.clone();
        tokio::spawn(async move {
            tokio::time::sleep(PENDING).await;
            if lock(&p.0.pending).remove(&id).is_some() {
                log!("database connection {id}: Brod did not take it in time");
            }
        });
    }
}

/// Whether the request is one db.rs answers.
pub fn handles(path: &str) -> bool {
    path == "/v1/db/accept" || path.starts_with("/v1/db/conns/")
}

pub async fn handle(node: Arc<Node>, req: Request<Incoming>) -> Response<Body> {
    let path = req.uri().path().to_string();
    let proxy = node.db.clone();
    match (req.method(), path.strip_prefix("/v1/db/conns/")) {
        (&Method::GET, None) if path == "/v1/db/accept" => accept_stream(proxy),
        (&Method::POST, Some(id)) => pipe(&proxy, id, req),
        (&Method::DELETE, Some(id)) => {
            lock(&proxy.0.pending).remove(id);
            reply(200, json!({ "ok": true }))
        }
        _ => fail(404, "not_found", "Nothing here."),
    }
}

/// GET /v1/db/accept: the accepted connections, one line each, for as long as Brod keeps the stream open. A newer
/// stream (after a reconnect) takes over once the older one is gone.
fn accept_stream(proxy: Proxy) -> Response<Body> {
    let (tx, body) = channel();
    tokio::spawn(async move {
        if tx.send(Bytes::from("{\"ready\":true}\n")).await.is_err() {
            return;
        }
        let mut rx = proxy.0.rx.lock().await;
        loop {
            tokio::select! {
                _ = tx.closed() => break,
                item = rx.recv() => {
                    let Some((id, app)) = item else { break };
                    let line = format!("{}\n", json!({ "conn": id, "app": app }));
                    if tx.send(Bytes::from(line)).await.is_err() {
                        // The stream went away: the next one gets this connection.
                        let _ = proxy.0.tx.send((id, app));
                        break;
                    }
                }
            }
        }
    });
    Response::builder().status(200).header("content-type", "application/x-ndjson").body(body).expect("response")
}

/// POST /v1/db/conns/<id>: Brod's request body to the socket, the socket's bytes back as the response body.
fn pipe(proxy: &Proxy, id: &str, req: Request<Incoming>) -> Response<Body> {
    let Some((_, stream)) = lock(&proxy.0.pending).remove(id) else {
        return fail(404, "not_found", "No such connection: it closed or waited too long.");
    };
    let (mut rd, mut wr) = stream.into_split();
    let (tx, body) = channel();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 32 * 1024];
        loop {
            match rd.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if tx.send(Bytes::copy_from_slice(&buf[..n])).await.is_err() {
                        break;
                    }
                }
            }
        }
    });
    let mut incoming = req.into_body();
    tokio::spawn(async move {
        while let Some(Ok(frame)) = incoming.frame().await {
            if let Ok(data) = frame.into_data()
                && wr.write_all(&data).await.is_err()
            {
                break;
            }
        }
        let _ = wr.shutdown().await;
    });
    Response::builder().status(200).header("content-type", "application/octet-stream").body(body).expect("response")
}

/// Where the listener for an app's bridge goes, given the bridge as Docker describes it (GET /networks/<name>).
pub async fn bind_for(node: &Node, reach: Reach, network: &Value, port_hint: Option<u16>) -> Result<Bind, String> {
    let config =
        network["IPAM"]["Config"].as_array().and_then(|c| c.iter().find(|c| c["Subnet"].as_str().is_some_and(|s| !s.contains(':'))));
    let subnet = config.and_then(|c| c["Subnet"].as_str()).and_then(parse_subnet);
    match reach {
        Reach::Publish => {
            Ok(Bind { addr: SocketAddr::from(([127, 0, 0, 1], port_hint.unwrap_or(0))), subnet: None, extra_host: "host-gateway".into() })
        }
        Reach::Ip => {
            let gw: Ipv4Addr = config
                .and_then(|c| c["Gateway"].as_str())
                .and_then(|g| g.parse().ok())
                .ok_or("The app's bridge has no IPv4 gateway for the database listener.")?;
            Ok(Bind { addr: SocketAddr::from((gw, PORT)), subnet, extra_host: gw.to_string() })
        }
        Reach::Attach => {
            let name = network["Name"].as_str().unwrap_or("");
            let ip = crate::work::own_address(node, name).await?;
            Ok(Bind { addr: SocketAddr::from((ip, PORT)), subnet, extra_host: ip.to_string() })
        }
    }
}

/// DATABASE_URL with the listener's port, where it is not 5432 (publish).
pub fn with_port(url: &str, port: u16) -> String {
    if port == PORT {
        return url.to_string();
    }
    url.replacen(&format!("@{HOST}:{PORT}/"), &format!("@{HOST}:{port}/"), 1)
}

/// After a restart: listeners again for the bridges of the containers that have a database (label brod.db).
pub async fn restore(node: Arc<Node>) {
    let filters = crate::docker::q(r#"{"label":["brod.db"]}"#);
    let list = match node.work.docker().ok("GET", &format!("/containers/json?all=1&filters={filters}"), None).await {
        Ok(v) => v,
        Err(e) => return log!("could not list containers with a database: {e}"),
    };
    let mut done = std::collections::HashSet::new();
    for c in list.as_array().into_iter().flatten() {
        let labels = &c["Labels"];
        let (Some(app), Some(network)) = (labels["brod.db"].as_str(), labels["brod.network"].as_str()) else { continue };
        if !done.insert(network.to_string()) {
            continue;
        }
        let port = labels["brod.db.port"].as_str().and_then(|p| p.parse().ok());
        if let Err(e) = crate::work::database_listener(&node, network, app, port).await {
            log!("could not restore the database listener for {app}: {e}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checks_subnets() {
        let s = parse_subnet("172.30.0.0/16").unwrap();
        assert!(inside(s, "172.30.4.2".parse().unwrap()));
        assert!(!inside(s, "172.31.0.2".parse().unwrap()));
        assert!(!inside(s, "::1".parse().unwrap()));
        assert!(inside(s, "::ffff:172.30.0.9".parse().unwrap()));
        assert!(parse_subnet("nope").is_none() && parse_subnet("10.0.0.0/33").is_none());
        assert!(inside(parse_subnet("0.0.0.0/0").unwrap(), "8.8.8.8".parse().unwrap()));
    }

    #[test]
    fn rewrites_the_port_only_when_it_differs() {
        let u = "postgres://app_1:pw@brod-db.internal:5432/app_1?sslmode=disable";
        assert_eq!(with_port(u, 5432), u);
        assert_eq!(with_port(u, 54011), "postgres://app_1:pw@brod-db.internal:54011/app_1?sslmode=disable");
    }
}
