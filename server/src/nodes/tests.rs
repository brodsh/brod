// SPDX-License-Identifier: AGPL-3.0-only
// Tests for nodes.rs. The tunnel tests run Brod's real connection handling (app::serve_connection) on a local port and a
// stand-in node that does what brod-node does: challenge, signed connect, Upgrade, then an HTTP/2 server.
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use bytes::Bytes;
use futures_util::StreamExt;
use http_body_util::BodyExt;
use ring::signature::{Ed25519KeyPair, KeyPair};

use super::*;
use crate::config::Config;
use crate::state::AppState;

fn state() -> State {
    AppState::new(Config::for_tests(), crate::db::test_db())
}

/// Brod on 127.0.0.1:<port>, serving connections as main.rs does.
async fn listen(st: &State) -> String {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let st = st.clone();
    tokio::spawn(async move {
        loop {
            let Ok((s, peer)) = l.accept().await else { return };
            tokio::spawn(crate::app::serve_connection(st.clone(), s, peer.ip(), crate::http::Via::Internal));
        }
    });
    format!("http://{addr}")
}

struct TestNode {
    key: Ed25519KeyPair,
    id: String,
}

impl TestNode {
    fn new() -> TestNode {
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new()).unwrap();
        let key = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
        let id = node_id(key.public_key().as_ref());
        TestNode { key, id }
    }
    fn public(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.key.public_key().as_ref())
    }
    fn sign(&self, msg: &str) -> String {
        URL_SAFE_NO_PAD.encode(self.key.sign(msg.as_bytes()).as_ref())
    }
}

async fn join_with(base: &str, node: &TestNode, token: &str, name: &str) -> reqwest::Response {
    let body = json!({ "token": token, "public_key": node.public(), "signature": node.sign(&join_message(token)), "name": name });
    reqwest::Client::new().post(format!("{base}/_node/join")).json(&body).send().await.unwrap()
}

async fn challenge(base: &str) -> String {
    let v: Value = reqwest::Client::new().post(format!("{base}/_node/challenge")).send().await.unwrap().json().await.unwrap();
    v["challenge"].as_str().unwrap().to_string()
}

/// Released by the test to let /v1/hold read its body.
type Gate = Arc<tokio::sync::Notify>;

/// The node's side of the tunnel: /v1/ping, /v1/echo (the body streamed straight back), /v1/hold (reads nothing until
/// the gate opens, then counts the body).
async fn node_service(
    req: hyper::Request<hyper::body::Incoming>,
    gate: Gate,
) -> std::result::Result<hyper::Response<Body>, std::convert::Infallible> {
    Ok(match req.uri().path() {
        "/v1/ping" => hyper::Response::new(Body::from("pong")),
        "/v1/echo" => hyper::Response::new(Body::new(req.into_body())),
        "/v1/hold" => {
            gate.notified().await;
            let mut n = 0usize;
            let mut body = req.into_body();
            while let Some(f) = body.frame().await {
                n += f.unwrap().data_ref().map_or(0, Bytes::len);
            }
            hyper::Response::new(Body::from(n.to_string()))
        }
        _ => hyper::Response::builder().status(404).body(Body::empty()).unwrap(),
    })
}

/// Connect `node` as brod-node does and serve HTTP/2 over the upgraded connection until it closes. The 101 status, or the
/// refusal's status.
async fn dial(base: &str, node: &TestNode, challenge: &str, sig: Option<String>, gate: Gate) -> u16 {
    let addr = base.trim_start_matches("http://").to_string();
    let tcp = tokio::net::TcpStream::connect(&addr).await.unwrap();
    let (mut send, conn) = hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(tcp)).await.unwrap();
    tokio::spawn(conn.with_upgrades());
    let sig = sig.unwrap_or_else(|| node.sign(&connect_message(&node.id, challenge)));
    let req = hyper::Request::get("/_node/connect")
        .header("host", &addr)
        .header("connection", "upgrade")
        .header("upgrade", PROTOCOL)
        .header("x-brod-node", &node.id)
        .header("x-brod-challenge", challenge)
        .header("x-brod-signature", sig)
        .body(http_body_util::Empty::<Bytes>::new())
        .unwrap();
    let res = send.send_request(req).await.unwrap();
    let status = res.status().as_u16();
    if status != 101 {
        return status;
    }
    let io = hyper::upgrade::on(res).await.unwrap();
    tokio::spawn(async move {
        let svc = hyper::service::service_fn(move |r| node_service(r, gate.clone()));
        let _ = hyper::server::conn::http2::Builder::new(hyper_util::rt::TokioExecutor::new()).serve_connection(io, svc).await;
    });
    status
}

/// Wait until the node's tunnel is up and its row says online (the row is updated just after the tunnel is kept).
async fn wait_connected(st: &State, id: &str) {
    for _ in 0..200 {
        if st.nodes.connected(id) && status_of(st, id).await == "online" {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("node {id} did not connect");
}

async fn status_of(st: &State, id: &str) -> String {
    let id = id.to_string();
    st.db
        .call(move |c| c.first("SELECT status FROM nodes WHERE id = ?", [id], |r| r.get::<_, String>(0)))
        .await
        .unwrap()
        .unwrap_or_default()
}

/// A body of `chunks` chunks of `size` bytes, each byte `seed + its index`, made as it is read; `made` counts the bytes
/// handed out so far.
fn body_stream(chunks: usize, size: usize, seed: u8, made: Arc<AtomicUsize>) -> Body {
    let s = futures_util::stream::iter(0..chunks).map(move |i| {
        made.fetch_add(size, Ordering::SeqCst);
        let chunk: Vec<u8> = (0..size).map(|j| seed.wrapping_add(((i * size + j) % 251) as u8)).collect();
        Ok::<_, std::io::Error>(Bytes::from(chunk))
    });
    Body::from_stream(s)
}

async fn call(st: &State, id: &str, method: &str, path: &str, body: Body) -> Response {
    let req = axum::http::Request::builder().method(method).uri(path).body(body).unwrap();
    request(st, id, req).await.unwrap()
}

#[test]
fn id_is_the_first_half_of_the_keys_sha256() {
    use sha2::{Digest, Sha256};
    let key = [7u8; 32];
    let id = node_id(&key);
    assert_eq!(id, format!("node_{}", hex::encode(&Sha256::digest(key)[..16])));
    assert_eq!(id.len(), 5 + 32);
    assert_ne!(node_id(&[8u8; 32]), id);
}

#[test]
fn signatures_verify_only_for_the_key_and_message() {
    let (a, b) = (TestNode::new(), TestNode::new());
    let msg = connect_message(&a.id, "c1");
    let sig = URL_SAFE_NO_PAD.decode(a.sign(&msg)).unwrap();
    assert!(verify(a.key.public_key().as_ref(), msg.as_bytes(), &sig));
    assert!(!verify(b.key.public_key().as_ref(), msg.as_bytes(), &sig), "another key");
    assert!(!verify(a.key.public_key().as_ref(), connect_message(&a.id, "c2").as_bytes(), &sig), "another challenge");
    assert!(!verify(a.key.public_key().as_ref(), msg.as_bytes(), &[0u8; 64]), "a forged signature");
    let req = request_message("POST", "/_node/heartbeat", &a.id, 1, b"{}");
    assert_ne!(req, request_message("POST", "/_node/heartbeat", &a.id, 1, b"{ }"), "the body is covered");
}

#[test]
fn status_transitions() {
    use Change::*;
    use Status::*;
    let ok = |s, c| next(s, c).unwrap();
    assert_eq!(ok(Joining, Connect), Online);
    assert_eq!(ok(Offline, Connect), Online);
    assert_eq!(ok(Online, Connect), Online);
    assert_eq!(ok(Draining, Connect), Draining);
    assert_eq!(next(Disabled, Connect).unwrap_err().code, "node_disabled");
    assert_eq!(ok(Online, Lose), Offline);
    assert_eq!(ok(Joining, Lose), Joining);
    assert_eq!(ok(Draining, Lose), Draining);
    assert_eq!(ok(Disabled, Lose), Disabled);
    assert_eq!(ok(Online, Drain), Draining);
    assert_eq!(ok(Offline, Drain), Draining);
    assert_eq!(next(Disabled, Drain).unwrap_err().status, 409);
    for s in [Joining, Online, Draining, Offline, Disabled] {
        assert_eq!(ok(s, Disable), Disabled);
        assert_eq!(Status::parse(s.name()), Some(s));
    }
    assert_eq!(ok(Disabled, Enable { connected: false }), Offline);
    assert_eq!(ok(Draining, Enable { connected: true }), Online);
    assert_eq!(ok(Online, Enable { connected: true }), Online);
    assert_eq!(ok(Joining, Enable { connected: false }), Joining);
}

#[tokio::test]
async fn join_tokens_work_once_and_expire() {
    let st = state();
    let base = listen(&st).await;
    let (token, expires_at) = st.db.call(|c| mint(c, "test", None)).await.unwrap();
    assert!(expires_at > now() + JOIN_TOKEN_MS - 5_000);
    let stored = st.db.call(|c| c.all("SELECT hash FROM node_join_tokens", (), |r| r.get::<_, String>(0))).await.unwrap();
    assert_eq!(stored, vec![sha256_hex(&token)], "only the hash is kept");

    let node = TestNode::new();
    // A signature by another key is refused, and does not use the token up.
    let other = TestNode::new();
    let body = json!({ "token": token, "public_key": node.public(), "signature": other.sign(&join_message(&token)) });
    let r = reqwest::Client::new().post(format!("{base}/_node/join")).json(&body).send().await.unwrap();
    assert_eq!(r.status(), 400);

    let r = join_with(&base, &node, &token, "first").await;
    assert_eq!(r.status(), 201);
    let v: Value = r.json().await.unwrap();
    assert_eq!(v["node"]["id"], node.id.as_str());
    assert_eq!(v["node"]["status"], "joining");
    assert_eq!(join_with(&base, &TestNode::new(), &token, "again").await.status(), 401, "a token works once");

    // Joining again with the same key and a new token renames the node and keeps its status.
    let (t2, _) = st.db.call(|c| mint(c, "test", None)).await.unwrap();
    let v: Value = join_with(&base, &node, &t2, "renamed").await.json().await.unwrap();
    assert_eq!((v["node"]["id"].as_str(), v["node"]["name"].as_str()), (Some(node.id.as_str()), Some("renamed")));
    let n = st.db.call(|c| c.count("SELECT COUNT(*) FROM nodes", ())).await.unwrap();
    assert_eq!(n, 1);

    // An expired token is refused.
    let expired = "bnj_expired";
    let h = sha256_hex(expired);
    st.db
        .call(move |c| c.run("INSERT INTO node_join_tokens (hash, created_by, expires_at) VALUES (?, 'test', ?)", params![h, now() - 1]))
        .await
        .unwrap();
    assert_eq!(join_with(&base, &TestNode::new(), expired, "late").await.status(), 401);
}

/// The spike: Brod reaches a node over the reversed HTTP/2 tunnel, with bodies streaming both ways, many requests at
/// once on one connection, and backpressure that holds the sender while the node does not read.
#[tokio::test]
async fn tunnel_streams_multiplexes_and_holds_back() {
    let st = state();
    let base = listen(&st).await;
    let node = TestNode::new();
    let (token, _) = st.db.call(|c| mint(c, "test", None)).await.unwrap();
    assert_eq!(join_with(&base, &node, &token, "n1").await.status(), 201);
    let gate: Gate = Arc::new(tokio::sync::Notify::new());
    let c = challenge(&base).await;
    assert_eq!(dial(&base, &node, &c, None, gate.clone()).await, 101);
    wait_connected(&st, &node.id).await;
    assert_eq!(status_of(&st, &node.id).await, "online");

    // A small request.
    let res = call(&st, &node.id, "GET", "/v1/ping", Body::empty()).await;
    assert_eq!(res.status(), 200);
    assert_eq!(crate::http::read_capped(res.into_body(), 100, "x").await.unwrap(), b"pong");

    // 16 MB up and back, in 64 KB chunks made as they are sent, checked as they come back.
    let (chunks, size) = (256, 64 * 1024);
    let made = Arc::new(AtomicUsize::new(0));
    let res = call(&st, &node.id, "POST", "/v1/echo", body_stream(chunks, size, 3, made.clone())).await;
    let mut got = 0usize;
    let mut back = res.into_body().into_data_stream();
    while let Some(chunk) = back.next().await {
        for b in chunk.unwrap() {
            assert_eq!(b, 3u8.wrapping_add((got % 251) as u8), "byte {got}");
            got += 1;
        }
    }
    assert_eq!(got, chunks * size);

    // 32 requests at once on the one connection, each with its own body back.
    let calls = (0..32u8).map(|i| {
        let st = st.clone();
        let id = node.id.clone();
        async move {
            let res = call(&st, &id, "POST", "/v1/echo", body_stream(4, 64 * 1024, i, Arc::default())).await;
            let body = crate::http::read_capped(res.into_body(), 1 << 20, "x").await.unwrap();
            (i, body)
        }
    });
    for (i, body) in futures_util::future::join_all(calls).await {
        assert_eq!(body.len(), 4 * 64 * 1024);
        assert!(body.iter().enumerate().all(|(j, b)| *b == i.wrapping_add((j % 251) as u8)), "request {i} got another's body");
    }

    // Backpressure: while the node reads nothing, Brod stops pulling from a 64 MB body after the flow-control windows
    // fill; once the node reads, the rest flows.
    let made = Arc::new(AtomicUsize::new(0));
    let (st2, id2) = (st.clone(), node.id.clone());
    let held = tokio::spawn({
        let made = made.clone();
        async move {
            let res = call(&st2, &id2, "POST", "/v1/hold", body_stream(1024, 64 * 1024, 0, made)).await;
            crate::http::read_capped(res.into_body(), 100, "x").await.unwrap()
        }
    });
    tokio::time::sleep(Duration::from_millis(500)).await;
    let early = made.load(Ordering::SeqCst);
    assert!(early < 8 << 20, "{early} bytes were made while the node read nothing");
    // Other requests still get through while that one is held.
    let res = call(&st, &node.id, "GET", "/v1/ping", Body::empty()).await;
    assert_eq!(res.status(), 200);
    gate.notify_one();
    let total = String::from_utf8(held.await.unwrap()).unwrap();
    assert_eq!(total, (64usize << 20).to_string());
    eprintln!("backpressure: {early} bytes made before the node read; 64 MB after");

    // A new connection from the same node replaces the old one.
    let c = challenge(&base).await;
    assert_eq!(dial(&base, &node, &c, None, Arc::default()).await, 101);
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(st.nodes.tunnels.lock().unwrap().len(), 1);
    let res = call(&st, &node.id, "GET", "/v1/ping", Body::empty()).await;
    assert_eq!(res.status(), 200);

    // Disabling closes the tunnel and refuses the next connect; deleting is then allowed.
    let admin = |m: reqwest::Method, p: &str| {
        reqwest::Client::new().request(m, format!("{base}/v1/admin/nodes{p}")).bearer_auth("test-admin-secret").send()
    };
    let r = admin(reqwest::Method::DELETE, &format!("/{}", node.id)).await.unwrap();
    assert_eq!(r.status(), 409, "a connected node is not removed");
    let v: Value = admin(reqwest::Method::POST, &format!("/{}/disable", node.id)).await.unwrap().json().await.unwrap();
    assert_eq!(v["node"]["status"], "disabled");
    assert!(!st.nodes.connected(&node.id));
    let c = challenge(&base).await;
    assert_eq!(dial(&base, &node, &c, None, Arc::default()).await, 403);
    let err = call_err(&st, &node.id).await;
    assert_eq!(err.code, "node_unreachable");
    let r = admin(reqwest::Method::DELETE, &format!("/{}", node.id)).await.unwrap();
    assert_eq!(r.status(), 200);
    let c = challenge(&base).await;
    assert_eq!(dial(&base, &node, &c, None, Arc::default()).await, 401, "a removed node must join again");
}

async fn call_err(st: &State, id: &str) -> Problem {
    let req = axum::http::Request::builder().uri("/v1/ping").body(Body::empty()).unwrap();
    request(st, id, req).await.unwrap_err()
}

#[tokio::test]
async fn connect_needs_a_fresh_challenge_and_the_nodes_signature() {
    let st = state();
    let base = listen(&st).await;
    let node = TestNode::new();
    let (token, _) = st.db.call(|c| mint(c, "test", None)).await.unwrap();
    join_with(&base, &node, &token, "n").await;

    let forger = TestNode::new();
    let c = challenge(&base).await;
    let forged = forger.sign(&connect_message(&node.id, &c));
    assert_eq!(dial(&base, &node, &c, Some(forged), Arc::default()).await, 401, "another key's signature");
    assert_eq!(dial(&base, &node, &c, None, Arc::default()).await, 401, "a challenge works once, even after a failure");
    assert_eq!(dial(&base, &node, "made-up", None, Arc::default()).await, 401, "a challenge Brod never issued");
    let c = challenge(&base).await;
    assert_eq!(dial(&base, &forger, &c, None, Arc::default()).await, 401, "a node that never joined");
    let r = reqwest::get(format!("{base}/_node/connect")).await.unwrap();
    assert_eq!(r.status(), 426, "no Upgrade");
    let c = challenge(&base).await;
    assert_eq!(dial(&base, &node, &c, None, Arc::default()).await, 101);
    wait_connected(&st, &node.id).await;
}

async fn beat(base: &str, node: &TestNode, ts: i64, body: &str, signer: &TestNode) -> reqwest::Response {
    let sig = signer.sign(&request_message("POST", "/_node/heartbeat", &node.id, ts, body.as_bytes()));
    reqwest::Client::new()
        .post(format!("{base}/_node/heartbeat"))
        .header("x-brod-node", &node.id)
        .header("x-brod-timestamp", ts.to_string())
        .header("x-brod-signature", sig)
        .body(body.to_string())
        .send()
        .await
        .unwrap()
}

#[tokio::test]
async fn heartbeats_are_signed_fresh_and_used_once() {
    let st = state();
    let base = listen(&st).await;
    let node = TestNode::new();
    let (token, _) = st.db.call(|c| mint(c, "test", None)).await.unwrap();
    join_with(&base, &node, &token, "n").await;
    let body =
        r#"{"version":"0.1.0","capabilities":{"arch":"x86_64","engine":"docker","cpus":4},"usage":{"memory_used":1,"memory_total":2}}"#;
    let ts = now();
    assert_eq!(beat(&base, &node, ts, body, &node).await.status(), 200);
    assert_eq!(beat(&base, &node, ts, body, &node).await.status(), 401, "a replay");
    assert_eq!(beat(&base, &node, now() + 1, body, &TestNode::new()).await.status(), 401, "a forged signature");
    assert_eq!(beat(&base, &node, now() - SKEW_MS - 1_000, body, &node).await.status(), 401, "too old");
    assert_eq!(beat(&base, &node, now() + SKEW_MS + 1_000, body, &node).await.status(), 401, "from the future");
    let id = node.id.clone();
    let row = st
        .db
        .call(move |c| {
            c.first("SELECT capabilities, resources, version, last_seen_at, address FROM nodes WHERE id = ?", [id], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?, r.get::<_, i64>(3)?, r.get::<_, String>(4)?))
            })
        })
        .await
        .unwrap()
        .unwrap();
    assert!(
        row.0.contains("docker") && row.1.contains("memory_total") && row.2 == "0.1.0" && row.3 >= ts && row.4 == "127.0.0.1",
        "{row:?}"
    );
}

#[tokio::test]
async fn sweep_marks_silent_unconnected_nodes_offline() {
    let st = state();
    let old = now() - OFFLINE_AFTER_MS - 1_000;
    st.db
        .call(move |c| {
            for (id, status, seen) in
                [("node_a", "online", old), ("node_b", "online", now()), ("node_c", "draining", old), ("node_d", "online", old)]
            {
                c.run(
                    "INSERT INTO nodes (id, public_key, name, status, created_at, last_seen_at) VALUES (?,?,?,?,?,?)",
                    params![id, format!("k{id}"), id, status, 1, seen],
                )?;
            }
            Ok(())
        })
        .await
        .unwrap();
    // node_d has a live tunnel (a stand-in sender over an in-memory pipe).
    let (a, b) = tokio::io::duplex(1 << 16);
    tokio::spawn(async move {
        let svc = hyper::service::service_fn(|_r| async { Ok::<_, std::convert::Infallible>(hyper::Response::new(Body::empty())) });
        let _ = hyper::server::conn::http2::Builder::new(hyper_util::rt::TokioExecutor::new())
            .serve_connection(hyper_util::rt::TokioIo::new(b), svc)
            .await;
    });
    let (send, conn) =
        hyper::client::conn::http2::handshake(hyper_util::rt::TokioExecutor::new(), hyper_util::rt::TokioIo::new(a)).await.unwrap();
    let task = tokio::spawn(conn);
    st.nodes.attach("node_d", send, task.abort_handle());

    assert_eq!(sweep(&st).await.unwrap(), vec!["node_a".to_string()]);
    assert_eq!(status_of(&st, "node_a").await, "offline");
    assert_eq!(status_of(&st, "node_b").await, "online", "heard from recently");
    assert_eq!(status_of(&st, "node_c").await, "draining", "draining is kept");
    assert_eq!(status_of(&st, "node_d").await, "online", "connected");
    assert!(sweep(&st).await.unwrap().is_empty());
}

#[tokio::test]
async fn admin_api_needs_the_secret_and_drains() {
    let st = state();
    let base = listen(&st).await;
    let client = reqwest::Client::new();
    let r = client.post(format!("{base}/v1/admin/nodes/join-tokens")).send().await.unwrap();
    assert_eq!(r.status(), 401);
    let r = client.post(format!("{base}/v1/admin/nodes/join-tokens")).bearer_auth("wrong").send().await.unwrap();
    assert_eq!(r.status(), 401);
    let v: Value = client
        .post(format!("{base}/v1/admin/nodes/join-tokens"))
        .bearer_auth("test-admin-secret")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let token = v["token"].as_str().unwrap();
    assert!(v["command"].as_str().unwrap().ends_with(token));
    let node = TestNode::new();
    assert_eq!(join_with(&base, &node, token, "worker 1").await.status(), 201);
    let v: Value =
        client.get(format!("{base}/v1/admin/nodes")).bearer_auth("test-admin-secret").send().await.unwrap().json().await.unwrap();
    assert_eq!(v["nodes"][0]["name"], "worker 1");
    assert_eq!(v["nodes"][0]["connected"], false);
    let v: Value = client
        .post(format!("{base}/v1/admin/nodes/{}/drain", node.id))
        .bearer_auth("test-admin-secret")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(v["node"]["status"], "draining");
    let v: Value = client
        .post(format!("{base}/v1/admin/nodes/{}/enable", node.id))
        .bearer_auth("test-admin-secret")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(v["node"]["status"], "offline");
    let r = client.get(format!("{base}/v1/admin/nodes/node_nope")).bearer_auth("test-admin-secret").send().await.unwrap();
    assert_eq!(r.status(), 404);
}

/// A node joined with a workspace's token belongs to that workspace; joining again never moves it to another owner;
/// the operator gives it to another workspace only once no other workspace's deployment holds capacity on it.
#[tokio::test]
async fn nodes_belong_to_the_workspace_their_token_names() {
    let st = state();
    let base = listen(&st).await;
    st.db
        .call(|c| {
            c.run("INSERT INTO workspaces (id, slug, name, created_at) VALUES ('ws_a', 'acme', 'Acme', 1)", ())?;
            c.run("INSERT INTO workspaces (id, slug, name, created_at) VALUES ('ws_b', 'beta', 'Beta', 1)", ())?;
            c.run("INSERT INTO users (id, email, name, created_at) VALUES ('usr_a', 'a@a.test', 'A', 1)", ())?;
            c.run("INSERT INTO apps (id, workspace_id, owner_id, slug, name, created_at) VALUES ('app_a','ws_a','usr_a','a','A',1)", ())
        })
        .await
        .unwrap();
    let client = reqwest::Client::new();
    let admin = |m: reqwest::Method, p: &str, body: Value| {
        client.request(m, format!("{base}/v1/admin/nodes{p}")).bearer_auth("test-admin-secret").json(&body).send()
    };
    let r = admin(reqwest::Method::POST, "/join-tokens", json!({ "workspace": "nope" })).await.unwrap();
    assert_eq!(r.status(), 404, "an unknown workspace");
    let v: Value = admin(reqwest::Method::POST, "/join-tokens", json!({ "workspace": "acme" })).await.unwrap().json().await.unwrap();
    assert_eq!(v["workspace_id"], "ws_a");
    let token = v["token"].as_str().unwrap().to_string();
    let listed: Value = admin(reqwest::Method::GET, "/join-tokens", json!({})).await.unwrap().json().await.unwrap();
    assert_eq!(listed["tokens"][0]["workspace"], "acme");

    let node = TestNode::new();
    let v: Value = join_with(&base, &node, &token, "acme-1").await.json().await.unwrap();
    assert_eq!((v["node"]["workspace_id"].as_str(), v["node"]["workspace"].as_str()), (Some("ws_a"), Some("acme")));

    // Joining again with an instance token (or another workspace's) does not move the node.
    let (t2, _) = st.db.call(|c| mint(c, "test", None)).await.unwrap();
    assert_eq!(join_with(&base, &node, &t2, "taken").await.status(), 409);
    let (t3, _) = st.db.call(|c| mint(c, "test", Some("ws_b"))).await.unwrap();
    assert_eq!(join_with(&base, &node, &t3, "taken").await.status(), 409);
    let (t4, _) = st.db.call(|c| mint(c, "test", Some("ws_a"))).await.unwrap();
    assert_eq!(join_with(&base, &node, &t4, "acme-1b").await.status(), 201, "the same owner may join it again");

    // Acme's deployment holds capacity there: the node cannot go to Beta until it is evacuated.
    let id = node.id.clone();
    st.db
        .call(move |c| {
            c.run(
                "INSERT INTO deployments (id, app_id, version, environment, node_id, state, cpu, memory_mb, created_at, updated_at) VALUES ('d1','app_a',1,'live',?,'serving',0.5,256,1,1)",
                [&id],
            )
        })
        .await
        .unwrap();
    let p = format!("/{}", node.id);
    let r = admin(reqwest::Method::PATCH, &p, json!({ "workspace": "beta" })).await.unwrap();
    assert_eq!(r.status(), 409);
    let v: Value = admin(reqwest::Method::PATCH, &p, json!({ "name": "renamed" })).await.unwrap().json().await.unwrap();
    assert_eq!((v["node"]["name"].as_str(), v["node"]["workspace"].as_str()), (Some("renamed"), Some("acme")), "a rename keeps the owner");
    assert_eq!(admin(reqwest::Method::PATCH, &p, json!({})).await.unwrap().status(), 400);
    assert_eq!(admin(reqwest::Method::PATCH, &p, json!({ "workspace": 7 })).await.unwrap().status(), 400);

    st.db.call(|c| c.run("UPDATE deployments SET state = 'stopped' WHERE id = 'd1'", ())).await.unwrap();
    let v: Value = admin(reqwest::Method::PATCH, &p, json!({ "workspace": "ws_b" })).await.unwrap().json().await.unwrap();
    assert_eq!(v["node"]["workspace"], "beta");
    let v: Value = admin(reqwest::Method::PATCH, &p, json!({ "workspace": null })).await.unwrap().json().await.unwrap();
    assert!(v["node"]["workspace_id"].is_null(), "back to an instance node");
    let audit =
        st.db.call(|c| c.all("SELECT action FROM events WHERE action = 'node_owner'", (), |r| r.get::<_, String>(0))).await.unwrap();
    assert_eq!(audit.len(), 2);
}
