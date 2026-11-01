// SPDX-License-Identifier: AGPL-3.0-only
//! brod-node: a machine that will run workloads for Brod.
//!
//! It holds an Ed25519 key in its state directory (identity.rs) and dials Brod, so it needs no open port and works
//! behind NAT:
//! - `brod-node join <brod url> <join token> [--name <name>]` registers its public key with a one-time join token an
//!   operator minted (POST /v1/admin/nodes/join-tokens).
//! - `brod-node run` connects to /_node/connect, proves its key by signing Brod's challenge, and after the HTTP/1.1
//!   Upgrade serves HTTP/2 over that same connection: Brod is the client and sends the node requests (tunnel.rs). It
//!   reconnects with exponential backoff and jitter, and POSTs a signed heartbeat to /_node/heartbeat every 10 s.
//! - `brod-node id` prints the node id.
//!
//! Environment: BROD_NODE_DIR (the state directory, default /var/lib/brod-node). For `run` without a prior join (the
//! node next to Brod in docker-compose.yml): BROD_URL and BROD_NODE_JOIN_TOKEN_FILE (or BROD_NODE_JOIN_TOKEN); the node
//! waits for a token there and joins once. BROD_URL also overrides the address `join` saved. BROD_NODE_NAME names it.
mod brod;
mod db;
mod docker;
mod firewall;
mod identity;
mod sys;
mod tunnel;
mod work;

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use http_body_util::Full;
use serde_json::{Value, json};

use brod::{Brod, problem};
use identity::{Identity, Joined};

const HEARTBEAT_EVERY: Duration = Duration::from_secs(10);
const BACKOFF_FIRST: Duration = Duration::from_secs(1);
const BACKOFF_MAX: Duration = Duration::from_secs(30);
/// A connection that lasted this long resets the backoff.
const STABLE_AFTER: Duration = Duration::from_secs(30);

macro_rules! log {
    ($($t:tt)*) => { eprintln!("brod-node: {}", format!($($t)*)) };
}

/// What `run` needs: who the node is, where Brod is, and the state directory.
pub struct Node {
    pub me: Identity,
    pub brod: Brod,
    pub name: String,
    pub dir: PathBuf,
    pub work: work::Work,
    /// The database proxy's listeners and the connections waiting for Brod (db.rs).
    pub db: db::Proxy,
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let dir =
        PathBuf::from(std::env::var("BROD_NODE_DIR").ok().filter(|d| !d.trim().is_empty()).unwrap_or_else(|| "/var/lib/brod-node".into()));
    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build().expect("tokio runtime starts");
    let result = match args.first().map(String::as_str) {
        Some("join") => {
            let mut name = std::env::var("BROD_NODE_NAME").unwrap_or_default();
            let mut rest = Vec::new();
            let mut it = args[1..].iter();
            while let Some(a) = it.next() {
                match a.as_str() {
                    "--name" => name = it.next().cloned().unwrap_or_default(),
                    _ => rest.push(a.clone()),
                }
            }
            match rest.as_slice() {
                [url, token] => rt.block_on(join(&dir, url, token, &name)).map(|id| println!("joined as {id}")),
                _ => Err(usage()),
            }
        }
        Some("run") => rt.block_on(run(&dir)),
        Some("id") => Identity::load_or_create(&dir).map(|me| println!("{}", me.id)),
        Some("version" | "--version") => {
            println!("brod-node {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        _ => Err(usage()),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            log!("{e}");
            ExitCode::FAILURE
        }
    }
}

fn usage() -> String {
    "usage: brod-node join <brod url> <join token> [--name <name>] | brod-node run | brod-node id".into()
}

/// Register this node's key with Brod using a join token, and remember Brod's address. The node id.
async fn join(dir: &Path, url: &str, token: &str, name: &str) -> Result<String, String> {
    let brod = Brod::parse(url)?;
    let me = Identity::load_or_create(dir)?;
    let token = token.trim();
    let body =
        json!({ "token": token, "public_key": me.public_key(), "signature": me.sign(&identity::join_message(token)), "name": name.trim() });
    let req = brod
        .request("POST", "/_node/join")
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(body.to_string())))
        .expect("request");
    let (status, body) = brod.call(req).await?;
    if status != 201 {
        return Err(format!("Brod refused to join this node ({status}): {}", problem(&body)));
    }
    let v: Value = serde_json::from_slice(&body).unwrap_or_default();
    let name = v["node"]["name"].as_str().unwrap_or(name).to_string();
    identity::save_joined(dir, &Joined { brod: brod.url.clone(), name })?;
    Ok(me.id)
}

/// The node joined before, or join now with the token from BROD_NODE_JOIN_TOKEN(_FILE), waiting for one to appear.
async fn joined(dir: &Path) -> Result<Joined, String> {
    if let Some(j) = identity::load_joined(dir)? {
        return Ok(j);
    }
    let url = std::env::var("BROD_URL")
        .map_err(|_| format!("This node has not joined yet. Run: brod-node join <brod url> <join token> (state in {})", dir.display()))?;
    let name = std::env::var("BROD_NODE_NAME").unwrap_or_default();
    let mut said = false;
    loop {
        let token = match std::env::var("BROD_NODE_JOIN_TOKEN_FILE") {
            Ok(f) => std::fs::read_to_string(&f).unwrap_or_default(),
            Err(_) => std::env::var("BROD_NODE_JOIN_TOKEN").unwrap_or_default(),
        };
        if !token.trim().is_empty() {
            match join(dir, &url, &token, &name).await {
                Ok(id) => {
                    log!("joined {url} as {id}");
                    return identity::load_joined(dir)?.ok_or_else(|| "node.json was not written".to_string());
                }
                Err(e) if !said => log!("{e}"),
                Err(_) => {}
            }
        } else if !said {
            log!("waiting for a join token (BROD_NODE_JOIN_TOKEN_FILE or BROD_NODE_JOIN_TOKEN)");
        }
        said = true;
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
}

async fn run(dir: &Path) -> Result<(), String> {
    let j = joined(dir).await?;
    let me = Identity::load_or_create(dir)?;
    let url = std::env::var("BROD_URL").ok().filter(|u| !u.trim().is_empty()).unwrap_or(j.brod);
    let node = Arc::new(Node {
        me,
        brod: Brod::parse(&url)?,
        name: j.name,
        dir: dir.to_path_buf(),
        work: work::Work::default(),
        db: db::Proxy::default(),
    });
    log!("{} ({}) for {}; state in {}", node.me.id, node.name, node.brod.url, dir.display());
    tokio::spawn(heartbeats(node.clone()));
    tokio::spawn(db::restore(node.clone()));
    tokio::select! {
        _ = connect_loop(node) => {}
        _ = shutdown() => log!("stopping"),
    }
    Ok(())
}

/// Milliseconds since the Unix epoch.
pub fn now_ms() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0)
}

/// What the node reports: its version, capabilities and usage.
pub fn report(node: &Node) -> Value {
    json!({ "version": env!("CARGO_PKG_VERSION"), "capabilities": sys::capabilities(), "usage": sys::usage(&node.dir) })
}

async fn heartbeats(node: Arc<Node>) {
    let mut tick = tokio::time::interval(HEARTBEAT_EVERY);
    let mut failing = false;
    loop {
        tick.tick().await;
        let body = report(&node).to_string();
        let (path, ts) = ("/_node/heartbeat", now_ms());
        let sig = node.me.sign(&identity::request_message("POST", path, &node.me.id, ts, body.as_bytes()));
        let req = node
            .brod
            .request("POST", path)
            .header("content-type", "application/json")
            .header("x-brod-node", &node.me.id)
            .header("x-brod-timestamp", ts.to_string())
            .header("x-brod-signature", sig)
            .body(Full::new(Bytes::from(body)))
            .expect("request");
        let outcome = match node.brod.call(req).await {
            Ok((200, _)) => Ok(()),
            Ok((status, b)) => Err(format!("heartbeat refused ({status}): {}", problem(&b))),
            Err(e) => Err(format!("heartbeat failed: {e}")),
        };
        match outcome {
            Ok(()) if failing => {
                log!("heartbeats are getting through again");
                failing = false;
            }
            Err(e) if !failing => {
                log!("{e}");
                failing = true;
            }
            _ => {}
        }
    }
}

/// The wait before attempt `n` (from 0): doubling from BACKOFF_FIRST up to BACKOFF_MAX, then +/- 20% jitter so many
/// nodes do not reconnect in step.
fn backoff(n: u32, jitter: f64) -> Duration {
    let base = BACKOFF_FIRST.saturating_mul(1u32 << n.min(16)).min(BACKOFF_MAX);
    base.mul_f64(1.0 + 0.4 * (jitter.clamp(0.0, 1.0) - 0.5))
}

/// A random number in [0, 1).
fn random_unit() -> f64 {
    let mut b = [0u8; 8];
    let _ = ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut b);
    (u64::from_le_bytes(b) >> 11) as f64 / (1u64 << 53) as f64
}

async fn connect_loop(node: Arc<Node>) {
    let mut attempt = 0u32;
    loop {
        let started = Instant::now();
        match connect(&node).await {
            Ok(()) => log!("the connection to Brod closed"),
            Err(e) => log!("{e}"),
        }
        if started.elapsed() >= STABLE_AFTER {
            attempt = 0;
        }
        let wait = backoff(attempt, random_unit());
        attempt = attempt.saturating_add(1);
        log!("reconnecting in {:.1} s", wait.as_secs_f64());
        tokio::time::sleep(wait).await;
    }
}

/// One connection: get a challenge, sign it, upgrade, then serve Brod's HTTP/2 requests until the connection ends.
async fn connect(node: &Arc<Node>) -> Result<(), String> {
    let req = node.brod.request("POST", "/_node/challenge").body(Full::new(Bytes::new())).expect("request");
    let (status, body) = node.brod.call(req).await?;
    if status != 200 {
        return Err(format!("Brod gave no challenge ({status}): {}", problem(&body)));
    }
    let v: Value = serde_json::from_slice(&body).map_err(|e| format!("Brod's challenge is not JSON: {e}"))?;
    let challenge = v["challenge"].as_str().ok_or("Brod's answer has no challenge")?.to_string();
    let req = node
        .brod
        .request("GET", "/_node/connect")
        .header("connection", "upgrade")
        .header("upgrade", identity::PROTOCOL)
        .header("x-brod-node", &node.me.id)
        .header("x-brod-challenge", &challenge)
        .header("x-brod-signature", node.me.sign(&identity::connect_message(&node.me.id, &challenge)))
        .body(Full::new(Bytes::new()))
        .expect("request");
    let io = match node.brod.upgrade(req).await? {
        Ok(io) => io,
        Err((status, body)) => return Err(format!("Brod refused the connection ({status}): {}", problem(&body))),
    };
    log!("connected to {}", node.brod.url);
    tunnel::serve(node.clone(), io).await
}

async fn shutdown() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    let term = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut s) => {
                s.recv().await;
            }
            Err(_) => std::future::pending::<()>().await,
        }
    };
    tokio::select! { _ = ctrl_c => {}, _ = term => {} }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_doubles_to_a_ceiling_with_jitter() {
        assert_eq!(backoff(0, 0.5), Duration::from_secs(1));
        assert_eq!(backoff(1, 0.5), Duration::from_secs(2));
        assert_eq!(backoff(4, 0.5), Duration::from_secs(16));
        assert_eq!(backoff(5, 0.5), Duration::from_secs(30));
        assert_eq!(backoff(100, 0.5), Duration::from_secs(30));
        assert_eq!(backoff(0, 0.0), Duration::from_millis(800));
        assert_eq!(backoff(5, 1.0), Duration::from_secs(36));
        let r = random_unit();
        assert!((0.0..1.0).contains(&r));
    }
}
