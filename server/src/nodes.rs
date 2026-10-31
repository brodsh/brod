// SPDX-License-Identifier: AGPL-3.0-only
// Nodes: machines that will run workloads for Brod (brod-node, in node/). A node holds an Ed25519 key, and its id is
// derived from the public key, so a node that changes address stays the same node. Under /_node/:
//   POST /_node/join       a one-time join token binds the node's public key to a node row (status joining)
//   POST /_node/challenge  a single-use challenge for connect
//   GET  /_node/connect    the node signs the challenge, Brod answers 101 and the roles reverse: Brod runs an HTTP/2
//                          client over the upgraded connection and the node an HTTP/2 server, so Brod can send the
//                          node requests (`request`) though the node is behind NAT and has no open port
//   POST /_node/heartbeat  every 10 s, signed with the node's key: version, capabilities, resource usage
// Every endpoint but join checks the node's key. The operator's API is under /v1/admin/nodes (ADMIN_SECRET):
//   POST   /v1/admin/nodes/join-tokens            a join token, good once for 15 minutes
//   GET    /v1/admin/nodes, /v1/admin/nodes/<id>  nodes with their status, connection, capabilities and resources
//   POST   /v1/admin/nodes/<id>/drain|disable|enable
//   DELETE /v1/admin/nodes/<id>                   refused while connected, unless disabled first
//   *      /v1/admin/nodes/<id>/tunnel/<path>     a request sent to the node through its tunnel, streamed both ways
use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use axum::body::Body;
use axum::http::Method;
use axum::response::Response;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::{Map, Value, json};

use crate::db::{Connection, Sql, params, tx};
use crate::http::{Req, json as json_ok, json_response};
use crate::problem::{Problem, Result};
use crate::state::State;
use crate::util::{now, random_bytes, safe_equal, sha256_hex};

/// The Upgrade token and the prefix of every message a node signs.
pub const PROTOCOL: &str = "brod-node/1";
/// How long a join token works.
pub const JOIN_TOKEN_MS: i64 = 15 * 60_000;
/// How long a connect challenge works.
const CHALLENGE_MS: i64 = 60_000;
/// How far a signed request's timestamp may be from Brod's clock.
pub const SKEW_MS: i64 = 60_000;
/// A node with no heartbeat and no connection for this long is offline.
pub const OFFLINE_AFTER_MS: i64 = 30_000;
/// Challenges and seen signatures kept at most, so unauthenticated callers cannot grow them without bound.
const MAX_PENDING: usize = 10_000;

/// Where a node is in its life. Draining and disabled are the operator's; online and offline follow the connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    Joining,
    Online,
    Draining,
    Offline,
    Disabled,
}

impl Status {
    pub fn name(self) -> &'static str {
        match self {
            Status::Joining => "joining",
            Status::Online => "online",
            Status::Draining => "draining",
            Status::Offline => "offline",
            Status::Disabled => "disabled",
        }
    }
    pub fn parse(s: &str) -> Option<Status> {
        Some(match s {
            "joining" => Status::Joining,
            "online" => Status::Online,
            "draining" => Status::Draining,
            "offline" => Status::Offline,
            "disabled" => Status::Disabled,
            _ => return None,
        })
    }
}

/// What happens to a node.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Change {
    /// It connected and proved its key.
    Connect,
    /// No heartbeat and no connection for OFFLINE_AFTER_MS.
    Lose,
    Drain,
    Disable,
    /// `connected`: it has a live connection right now.
    Enable {
        connected: bool,
    },
}

/// The status after `change`. Draining and disabled are kept across connects and losses: they are the operator's
/// choice, and `connected` and `last_seen_at` say whether the node is there.
pub fn next(from: Status, change: Change) -> Result<Status> {
    use Status::*;
    Ok(match (from, change) {
        (Disabled, Change::Connect) => return Err(Problem::new(403, "node_disabled", "This node is disabled. An operator can enable it.")),
        (Draining, Change::Connect) => Draining,
        (_, Change::Connect) => Online,
        (Online, Change::Lose) => Offline,
        (s, Change::Lose) => s,
        (Disabled, Change::Drain) => {
            return Err(Problem::new(409, "node_disabled", "This node is disabled. Enable it before draining it."));
        }
        (_, Change::Drain) => Draining,
        (_, Change::Disable) => Disabled,
        (Disabled | Draining, Change::Enable { connected: true }) => Online,
        (Disabled | Draining, Change::Enable { connected: false }) => Offline,
        (s, Change::Enable { .. }) => s,
    })
}

/// A node's id: "node_" and the first 16 bytes of the SHA-256 of its raw 32-byte public key, in hex.
pub fn node_id(public_key: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    format!("node_{}", hex::encode(&Sha256::digest(public_key)[..16]))
}

/// What a node signs to join with `token`.
pub fn join_message(token: &str) -> String {
    format!("{PROTOCOL} join\n{token}")
}

/// What a node signs to connect with a challenge.
pub fn connect_message(node: &str, challenge: &str) -> String {
    format!("{PROTOCOL} connect\n{node}\n{challenge}")
}

/// What a node signs for a request to Brod: the method, the path, its id, the time (ms) and the body's SHA-256 in hex.
pub fn request_message(method: &str, path: &str, node: &str, timestamp: i64, body: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    format!("{PROTOCOL} {method} {path}\n{node}\n{timestamp}\n{}", hex::encode(Sha256::digest(body)))
}

/// Whether `signature` is `public_key`'s Ed25519 signature of `message`.
pub fn verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, public_key).verify(message, signature).is_ok()
}

fn decode(s: &str) -> Option<Vec<u8>> {
    URL_SAFE_NO_PAD.decode(s.trim()).ok()
}

/// An Ed25519 public key as base64url, 32 bytes.
fn public_key(s: &str) -> Result<Vec<u8>> {
    decode(s)
        .filter(|k| k.len() == 32)
        .ok_or_else(|| Problem::new(400, "bad_key", "public_key must be a 32-byte Ed25519 key in base64url."))
}

fn unauthorized(message: &str) -> Problem {
    Problem::new(401, "unauthorized", message)
}

type Sender = hyper::client::conn::http2::SendRequest<Body>;

struct Tunnel {
    /// Tells a replaced connection from the one that replaced it.
    serial: u64,
    send: Sender,
    task: tokio::task::AbortHandle,
}

/// The live tunnels, by node id, and the short-lived state that keeps node authentication single-use.
#[derive(Default)]
pub struct Nodes {
    tunnels: Mutex<HashMap<String, Tunnel>>,
    /// Connect challenges issued and not yet used, with when they expire.
    challenges: Mutex<HashMap<String, i64>>,
    /// Signatures of signed requests already accepted, with when they stop mattering (their timestamp is then too old).
    seen: Mutex<HashMap<String, i64>>,
    serial: AtomicU64,
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Remember `key` until `until`; false when it is already there. Expired keys are dropped first.
fn remember(map: &Mutex<HashMap<String, i64>>, key: String, until: i64) -> Result<bool> {
    let mut m = lock(map);
    let t = now();
    if m.len() >= MAX_PENDING {
        m.retain(|_, exp| *exp > t);
        if m.len() >= MAX_PENDING {
            return Err(Problem::new(503, "busy", "Too many node requests at once. Try again shortly."));
        }
    }
    if m.get(&key).is_some_and(|exp| *exp > t) {
        return Ok(false);
    }
    m.insert(key, until);
    Ok(true)
}

impl Nodes {
    /// Whether the node has a live tunnel.
    pub fn connected(&self, node: &str) -> bool {
        lock(&self.tunnels).get(node).is_some_and(|t| !t.send.is_closed())
    }

    /// The ids of the nodes with a live tunnel.
    pub fn connected_ids(&self) -> Vec<String> {
        lock(&self.tunnels).iter().filter(|(_, t)| !t.send.is_closed()).map(|(k, _)| k.clone()).collect()
    }

    /// Keep a new tunnel for `node`, closing the one it replaces. Returns its serial for `detach`.
    fn attach(&self, node: &str, send: Sender, task: tokio::task::AbortHandle) -> u64 {
        let serial = self.serial.fetch_add(1, Ordering::Relaxed) + 1;
        if let Some(old) = lock(&self.tunnels).insert(node.to_string(), Tunnel { serial, send, task }) {
            old.task.abort();
        }
        serial
    }

    /// Forget the tunnel `serial` once it has ended, unless another has replaced it.
    fn detach(&self, node: &str, serial: u64) {
        let mut t = lock(&self.tunnels);
        if t.get(node).is_some_and(|x| x.serial == serial) {
            t.remove(node);
        }
    }

    /// Close the node's tunnel, if it has one.
    pub fn close(&self, node: &str) {
        if let Some(t) = lock(&self.tunnels).remove(node) {
            t.task.abort();
        }
    }

    fn sender(&self, node: &str) -> Option<Sender> {
        lock(&self.tunnels).get(node).filter(|t| !t.send.is_closed()).map(|t| t.send.clone())
    }

    /// A fresh challenge, good once for CHALLENGE_MS.
    fn challenge(&self) -> Result<(String, i64)> {
        let c = URL_SAFE_NO_PAD.encode(random_bytes(32));
        let until = now() + CHALLENGE_MS;
        remember(&self.challenges, c.clone(), until)?;
        Ok((c, until))
    }

    /// Use up a challenge; false when it was never issued, is used or has expired.
    fn take_challenge(&self, c: &str) -> bool {
        lock(&self.challenges).remove(c).is_some_and(|exp| exp > now())
    }
}

/// Send a request to a node over its tunnel and get its response, bodies streaming both ways. Only the path and query
/// of the request's URI are used. 503 node_unreachable when the node has no live tunnel.
pub async fn request(st: &State, node: &str, req: axum::http::Request<Body>) -> Result<Response> {
    let Some(mut send) = st.nodes.sender(node) else {
        return Err(Problem::new(503, "node_unreachable", "The node is not connected to Brod."));
    };
    let (mut parts, body) = req.into_parts();
    let pq = parts.uri.path_and_query().map(|p| p.as_str()).unwrap_or("/");
    // HTTP/2 needs a scheme and an authority; the node answers whatever authority it is sent.
    parts.uri =
        format!("http://brod-node{pq}").parse().map_err(|e| Problem::new(400, "bad_path", format!("Not a path for a node: {e}")))?;
    let unreachable = |e: hyper::Error| Problem::new(503, "node_unreachable", format!("The node's connection failed: {e}"));
    send.ready().await.map_err(unreachable)?;
    let res = send.send_request(axum::http::Request::from_parts(parts, body)).await.map_err(unreachable)?;
    Ok(res.map(Body::new))
}

/// Where the request came from: the first X-Forwarded-For address behind a trusted proxy, else the connection's.
fn address(st: &State, req: &Req) -> Option<String> {
    let forwarded =
        st.cfg.trust_proxy.then(|| req.header("x-forwarded-for")).flatten().and_then(|v| v.split(',').next()).map(|v| v.trim().to_string());
    forwarded.filter(|a| a.parse::<std::net::IpAddr>().is_ok()).or_else(|| req.peer.map(|p| p.to_string()))
}

/// The node's public key and status, by id.
fn find(c: &Connection, id: &str) -> Result<Option<(Vec<u8>, Status)>> {
    let row =
        c.first("SELECT public_key, status FROM nodes WHERE id = ?", [id], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?;
    Ok(row.and_then(|(k, s)| Some((decode(&k)?, Status::parse(&s)?))))
}

/// /_node/*.
pub async fn serve(st: &State, mut req: Req) -> Result<Response> {
    let path = req.path.clone();
    match (path.as_str(), req.method.clone()) {
        ("/_node/join", Method::POST) => join(st, &mut req).await,
        ("/_node/challenge", Method::POST) => {
            let (challenge, expires_at) = st.nodes.challenge()?;
            Ok(json_ok(json!({ "challenge": challenge, "expires_at": expires_at })))
        }
        ("/_node/connect", Method::GET) => connect(st, req).await,
        ("/_node/heartbeat", Method::POST) => heartbeat(st, &mut req).await,
        ("/_node/join" | "/_node/challenge" | "/_node/connect" | "/_node/heartbeat", _) => {
            Err(Problem::new(405, "method_not_allowed", "That method does not work here."))
        }
        _ => Err(Problem::new(404, "not_found", "Nothing here.")),
    }
}

/// A node's name: printable, at most 64 characters; empty for none.
fn clean_name(s: &str) -> String {
    s.trim().chars().filter(|c| !c.is_control()).take(64).collect::<String>().trim().to_string()
}

/// POST /_node/join {token, public_key, signature, name}: bind the key to a node with a one-time join token. The
/// signature (of `join_message`) proves the caller holds the key. Joining again with a known key only renames it.
async fn join(st: &State, req: &mut Req) -> Result<Response> {
    let raw = req.bytes(16 * 1024, "The request body").await?;
    let o: Map<String, Value> = match serde_json::from_slice(&raw) {
        Ok(Value::Object(o)) => o,
        _ => return Err(Problem::new(400, "bad_json", "The request body must be a JSON object.")),
    };
    let text = |k: &str| o.get(k).and_then(Value::as_str).unwrap_or("").to_string();
    let (token, name) = (text("token"), clean_name(&text("name")));
    let key = public_key(&text("public_key"))?;
    let sig = decode(&text("signature")).unwrap_or_default();
    if !verify(&key, join_message(&token).as_bytes(), &sig) {
        return Err(Problem::new(400, "bad_signature", "signature must be the node key's signature of the join message."));
    }
    let id = node_id(&key);
    let key_text = URL_SAFE_NO_PAD.encode(&key);
    let name = if name.is_empty() { format!("node-{}", &id[5..13]) } else { name };
    let hash = sha256_hex(&token);
    let view = st
        .db
        .call(move |c| {
            tx(c, |c| {
                let t = now();
                let used = c.run(
                    "UPDATE node_join_tokens SET used_at = ? WHERE hash = ? AND used_at IS NULL AND expires_at > ?",
                    params![t, hash, t],
                )?;
                if used != 1 {
                    return Err(unauthorized("This join token is unknown, already used or expired. Ask the operator for a new one."));
                }
                if c.exists("SELECT 1 FROM nodes WHERE id = ?", [&id])? {
                    c.run("UPDATE nodes SET name = ? WHERE id = ?", params![name, id])?;
                } else {
                    c.run(
                        "INSERT INTO nodes (id, public_key, name, status, capabilities, created_at) VALUES (?,?,?,?,'{}',?)",
                        params![id, key_text, name, Status::Joining.name(), t],
                    )?;
                }
                view(c, &id, false)
            })
        })
        .await?;
    tracing::info!("node {} joined as {:?}", view["id"].as_str().unwrap_or(""), view["name"].as_str().unwrap_or(""));
    Ok(json_response(&json!({ "node": view }), 201, &[]))
}

/// GET /_node/connect with Upgrade: brod-node/1 and the node's signature of a challenge from /_node/challenge. Answers
/// 101, then speaks HTTP/2 as the client over the connection while it lasts. A new connection replaces the old one.
async fn connect(st: &State, mut req: Req) -> Result<Response> {
    if !req.header("upgrade").is_some_and(|u| u.trim().eq_ignore_ascii_case(PROTOCOL)) {
        return Err(Problem::new(426, "upgrade_required", format!("Connect with Upgrade: {PROTOCOL}.")));
    }
    let (node, challenge) = (req.header("x-brod-node").unwrap_or("").to_string(), req.header("x-brod-challenge").unwrap_or("").to_string());
    let sig = decode(req.header("x-brod-signature").unwrap_or("")).unwrap_or_default();
    if !st.nodes.take_challenge(&challenge) {
        return Err(unauthorized("The challenge is unknown, used or expired. Get a new one from /_node/challenge."));
    }
    let n = node.clone();
    let Some((key, status)) = st.db.call(move |c| find(c, &n)).await? else {
        return Err(unauthorized("This node is not known. Join it again with a join token."));
    };
    if !verify(&key, connect_message(&node, &challenge).as_bytes(), &sig) {
        return Err(unauthorized("The signature does not match this node's key."));
    }
    next(status, Change::Connect)?;
    let Some(on_upgrade) = req.upgrade.take() else {
        return Err(Problem::new(400, "upgrade_required", "This connection cannot be upgraded. Connect over HTTP/1.1."));
    };
    let address = address(st, &req);
    tokio::spawn(tunnel(st.clone(), node, address, on_upgrade));
    Ok(crate::http::response(101, Body::empty(), &[("connection", "upgrade".into()), ("upgrade", PROTOCOL.into())]))
}

/// Run one node's tunnel: HTTP/2 client over the upgraded connection, kept in the registry until it ends.
async fn tunnel(st: State, node: String, address: Option<String>, on_upgrade: hyper::upgrade::OnUpgrade) {
    let io = match on_upgrade.await {
        Ok(io) => io,
        Err(e) => return tracing::warn!("node {node}: the upgrade failed: {e}"),
    };
    let handshake = hyper::client::conn::http2::Builder::new(hyper_util::rt::TokioExecutor::new())
        .timer(hyper_util::rt::TokioTimer::new())
        // A connection that went away without closing (a lost network) is noticed within 20 s.
        .keep_alive_interval(Duration::from_secs(10))
        .keep_alive_timeout(Duration::from_secs(10))
        .keep_alive_while_idle(true)
        .handshake::<_, Body>(io)
        .await;
    let (send, conn) = match handshake {
        Ok(x) => x,
        Err(e) => return tracing::warn!("node {node}: the HTTP/2 handshake failed: {e}"),
    };
    let driver = tokio::spawn(conn);
    let serial = st.nodes.attach(&node, send, driver.abort_handle());
    let n = node.clone();
    let marked = st
        .db
        .call(move |c| {
            tx(c, |c| {
                let Some((_, status)) = find(c, &n)? else {
                    return Err(Problem::new(404, "not_found", "The node was removed."));
                };
                let to = next(status, Change::Connect)?;
                c.run("UPDATE nodes SET status = ?, last_seen_at = ?, address = ? WHERE id = ?", params![to.name(), now(), address, n])?;
                Ok(to)
            })
        })
        .await;
    match marked {
        Ok(to) => tracing::info!("node {node} connected ({})", to.name()),
        Err(e) => {
            // Disabled or removed while it was connecting.
            tracing::info!("node {node} refused after connecting: {}", e.message);
            st.nodes.close(&node);
        }
    }
    match driver.await {
        Ok(Err(e)) => tracing::info!("node {node} disconnected: {e}"),
        _ => tracing::info!("node {node} disconnected"),
    }
    st.nodes.detach(&node, serial);
}

/// Check a request a node signed (`request_message`): a known, enabled node, a timestamp within SKEW_MS, a valid
/// signature, never seen before. The node's id.
pub async fn authenticate(st: &State, req: &Req, body: &[u8]) -> Result<String> {
    let node = req.header("x-brod-node").unwrap_or("").to_string();
    let ts: i64 = req.header("x-brod-timestamp").and_then(|t| t.trim().parse().ok()).unwrap_or(0);
    let sig_text = req.header("x-brod-signature").unwrap_or("").trim().to_string();
    let sig = decode(&sig_text).unwrap_or_default();
    if (now() - ts).abs() > SKEW_MS {
        return Err(unauthorized("The request's timestamp is missing or too far from Brod's clock. Check the node's clock."));
    }
    let n = node.clone();
    let Some((key, status)) = st.db.call(move |c| find(c, &n)).await? else {
        return Err(unauthorized("This node is not known. Join it again with a join token."));
    };
    let message = request_message(req.method.as_str(), &req.path, &node, ts, body);
    if !verify(&key, message.as_bytes(), &sig) {
        return Err(unauthorized("The signature does not match this node's key."));
    }
    if !remember(&st.nodes.seen, sig_text, ts + SKEW_MS + 1)? {
        return Err(unauthorized("This request was already received."));
    }
    if status == Status::Disabled {
        return Err(Problem::new(403, "node_disabled", "This node is disabled. An operator can enable it."));
    }
    Ok(node)
}

/// POST /_node/heartbeat {version, capabilities, usage}, signed: what the node is and how busy it is.
async fn heartbeat(st: &State, req: &mut Req) -> Result<Response> {
    let raw = req.bytes(64 * 1024, "The heartbeat").await?;
    let node = authenticate(st, req, &raw).await?;
    let o: Map<String, Value> = match serde_json::from_slice(&raw) {
        Ok(Value::Object(o)) => o,
        _ => return Err(Problem::new(400, "bad_json", "The heartbeat must be a JSON object.")),
    };
    let version: Option<String> = o.get("version").and_then(Value::as_str).map(|v| v.chars().take(64).collect());
    let object = |k: &str| o.get(k).filter(|v| v.is_object()).map(Value::to_string);
    let (capabilities, usage) = (object("capabilities").unwrap_or_else(|| "{}".into()), object("usage"));
    let address = address(st, req);
    let n = node.clone();
    let status = st
        .db
        .call(move |c| {
            c.run(
                "UPDATE nodes SET capabilities = ?, resources = ?, version = ?, address = ?, last_seen_at = ? WHERE id = ?",
                params![capabilities, usage, version, address, now(), n],
            )?;
            Ok(find(c, &n)?.map(|(_, s)| s.name()).unwrap_or("removed"))
        })
        .await?;
    Ok(json_ok(json!({ "ok": true, "status": status, "connected": st.nodes.connected(&node) })))
}

/// Mark online nodes that have neither sent a heartbeat for OFFLINE_AFTER_MS nor a live tunnel as offline. For the
/// loop in main.rs. The ids it marked.
pub async fn sweep(st: &State) -> Result<Vec<String>> {
    let cutoff = now() - OFFLINE_AFTER_MS;
    let connected = st.nodes.connected_ids();
    let lost = st
        .db
        .call(move |c| {
            let stale = c.all(
                "SELECT id FROM nodes WHERE status = ? AND (last_seen_at IS NULL OR last_seen_at < ?)",
                params![Status::Online.name(), cutoff],
                |r| r.get::<_, String>(0),
            )?;
            let mut lost = Vec::new();
            for id in stale.into_iter().filter(|id| !connected.contains(id)) {
                let to = next(Status::Online, Change::Lose)?;
                if c.run("UPDATE nodes SET status = ? WHERE id = ? AND status = ?", params![to.name(), id, Status::Online.name()])? == 1 {
                    lost.push(id);
                }
            }
            Ok(lost)
        })
        .await?;
    for id in &lost {
        tracing::warn!("node {id} is offline: no heartbeat or connection for {} s", OFFLINE_AFTER_MS / 1000);
    }
    Ok(lost)
}

/// A node as the admin API shows it.
fn view(c: &Connection, id: &str, connected: bool) -> Result<Value> {
    let rows = c.rows_json(
        "SELECT id, name, status, public_key, capabilities, resources, version, address, last_seen_at, created_at FROM nodes WHERE id = ?",
        [id],
    )?;
    let Some(Value::Object(mut v)) = rows.into_iter().next() else {
        return Err(Problem::new(404, "not_found", format!("There is no node {id}.")));
    };
    for k in ["capabilities", "resources"] {
        let parsed = v.get(k).and_then(Value::as_str).and_then(|s| serde_json::from_str::<Value>(s).ok()).unwrap_or(Value::Null);
        v.insert(k.into(), parsed);
    }
    v.insert("connected".into(), json!(connected));
    Ok(Value::Object(v))
}

/// Mint a join token: kept only as its SHA-256, good once for JOIN_TOKEN_MS. The token and when it expires.
pub fn mint(c: &Connection, created_by: &str) -> Result<(String, i64)> {
    let token = format!("bnj_{}", hex::encode(random_bytes(32)));
    let expires_at = now() + JOIN_TOKEN_MS;
    c.run(
        "INSERT INTO node_join_tokens (hash, created_by, expires_at) VALUES (?,?,?)",
        params![sha256_hex(&token), created_by, expires_at],
    )?;
    Ok((token, expires_at))
}

/// /v1/admin/nodes/*, with the admin secret: join tokens, the node list, drain, disable, enable, delete, and a request
/// sent through a node's tunnel.
pub async fn admin(st: &State, req: &mut Req, seg: &[String]) -> Result<Response> {
    let given = crate::control::Credentials::of(req).bearer().unwrap_or_default();
    if st.cfg.admin_secret.is_empty() || !safe_equal(&given, &st.cfg.admin_secret) {
        return Err(Problem::new(401, "unauthorized", "The admin API needs the admin secret."));
    }
    let s = |i: usize| seg.get(i).map(String::as_str).filter(|x| !x.is_empty());
    let (a, b, extra) = (s(2).map(String::from), s(3).map(String::from), s(4).is_some());
    let m = req.method.clone();
    let origin = st.cfg.api_origin.clone();
    let st2 = st.clone();
    match (m, a.as_deref(), b.as_deref(), extra) {
        (Method::POST, Some("join-tokens"), None, false) => {
            let (token, expires_at) = st.db.call(|c| mint(c, "admin")).await?;
            let command = format!("brod-node join {origin} {token}");
            Ok(json_response(&json!({ "token": token, "expires_at": expires_at, "command": command }), 201, &[]))
        }
        (Method::GET, None, None, false) => {
            let nodes = st
                .db
                .call(move |c| {
                    let ids = c.all("SELECT id FROM nodes ORDER BY created_at, id", (), |r| r.get::<_, String>(0))?;
                    ids.iter().map(|id| view(c, id, st2.nodes.connected(id))).collect::<Result<Vec<_>>>()
                })
                .await?;
            Ok(json_ok(json!({ "nodes": nodes })))
        }
        (Method::GET, Some(id), None, false) => {
            let id = id.to_string();
            Ok(json_ok(json!({ "node": st.db.call(move |c| view(c, &id, st2.nodes.connected(&id))).await? })))
        }
        (Method::POST, Some(id), Some(action @ ("drain" | "disable" | "enable")), false) => {
            let (id, connected) = (id.to_string(), st.nodes.connected(id));
            let change = match action {
                "drain" => Change::Drain,
                "disable" => Change::Disable,
                _ => Change::Enable { connected },
            };
            let i = id.clone();
            let node = st
                .db
                .call(move |c| {
                    tx(c, |c| {
                        let Some((_, from)) = find(c, &i)? else {
                            return Err(Problem::new(404, "not_found", format!("There is no node {i}.")));
                        };
                        let to = next(from, change)?;
                        c.run("UPDATE nodes SET status = ? WHERE id = ?", params![to.name(), i])?;
                        Ok(to)
                    })
                })
                .await?;
            if node == Status::Disabled {
                st.nodes.close(&id);
            }
            tracing::info!("node {id}: {action} by the operator, now {}", node.name());
            let connected = st.nodes.connected(&id);
            Ok(json_ok(json!({ "node": st.db.call(move |c| view(c, &id, connected)).await? })))
        }
        // The operator (and the e2e tests) can send a node a request through its tunnel: /v1/admin/nodes/<id>/tunnel/<path>.
        (_, Some(id), Some("tunnel"), _) => {
            let prefix = format!("/v1/admin/nodes/{id}/tunnel");
            let rest = req.path.strip_prefix(&prefix).filter(|r| r.starts_with('/')).unwrap_or("/").to_string();
            let target = if req.query.is_empty() { rest } else { format!("{rest}?{}", req.query) };
            let mut fwd = axum::http::Request::builder().method(req.method.clone()).uri(target);
            for h in ["content-type", "content-length", "accept"] {
                if let Some(v) = req.headers.get(h) {
                    fwd = fwd.header(h, v);
                }
            }
            let fwd = fwd.body(req.take_body()).map_err(|e| Problem::new(400, "bad_request", format!("Not a request for a node: {e}")))?;
            request(st, id, fwd).await
        }
        (Method::DELETE, Some(id), None, false) => {
            let (id, connected) = (id.to_string(), st.nodes.connected(id));
            let i = id.clone();
            st.db
                .call(move |c| {
                    tx(c, |c| {
                        let Some((_, status)) = find(c, &i)? else {
                            return Err(Problem::new(404, "not_found", format!("There is no node {i}.")));
                        };
                        if connected && status != Status::Disabled {
                            return Err(Problem::new(409, "node_connected", "This node is connected. Disable it before removing it."));
                        }
                        c.run("DELETE FROM nodes WHERE id = ?", [&i])?;
                        Ok(())
                    })
                })
                .await?;
            st.nodes.close(&id);
            tracing::info!("node {id} removed by the operator");
            Ok(json_ok(json!({ "ok": true, "removed": id })))
        }
        _ => Err(Problem::new(404, "not_found", "Nothing here.")),
    }
}

/// BROD_NODE_JOIN_TOKEN_FILE: for the node next to Brod in docker-compose.yml. When no node has joined yet, write a
/// fresh join token there for it to join with once; otherwise empty the file, so no token lies around.
pub async fn write_local_join_token(st: &State) {
    let Some(path) = std::env::var("BROD_NODE_JOIN_TOKEN_FILE").ok().map(|p| p.trim().to_string()).filter(|p| !p.is_empty()) else {
        return;
    };
    let token = st.db.call(|c| if c.exists("SELECT 1 FROM nodes", ())? { Ok(None) } else { mint(c, "local").map(|(t, _)| Some(t)) }).await;
    let text = match token {
        Ok(t) => t.unwrap_or_default(),
        Err(e) => return tracing::warn!("could not make a join token for the local node: {}", e.message),
    };
    let path = std::path::PathBuf::from(path);
    let written = (|| {
        if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
            std::fs::create_dir_all(dir)?;
        }
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut opts, 0o600);
        std::io::Write::write_all(&mut opts.open(&path)?, text.as_bytes())
    })();
    match written {
        Err(e) => tracing::warn!("could not write the local node's join token to {}: {e}", path.display()),
        Ok(()) if !text.is_empty() => tracing::info!("nodes: a join token for the local node is in {}", path.display()),
        Ok(()) => {}
    }
}

#[cfg(test)]
mod tests;
