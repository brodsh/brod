// SPDX-License-Identifier: AGPL-3.0-only
//! Workloads: what Brod asks the node to do with containers, over the tunnel.
//!
//!   POST   /v1/builds/<id>?platform=linux/arm64   body: the build context (a tar). Builds it with docker buildx into an
//!                                                  OCI image; answers NDJSON lines {"log": "..."} as the build runs,
//!                                                  then {"done": true, "ok": bool, "error": "..."}
//!   GET    /v1/builds/<id>/oci/<path>              a file of the built OCI layout (index.json, blobs/sha256/<hex>)
//!   DELETE /v1/builds/<id>                         forget the build
//!   GET    /v1/images/<image id>                   {"exists": bool}
//!   POST   /v1/images/load                         body: an image archive (docker load); {"ok", "message"}
//!   DELETE /v1/images/<image id>
//!   PUT    /v1/containers/<name>                   create it: {image, env, port, cpu, memory_mb, network, trusted, labels,
//!                                                  database (the app id: brod-db.internal reaches its database, db.rs),
//!                                                  cmd (a command instead of the image's), once (no restarts)}
//!   POST   /v1/containers/<name>/start             start it; {"address"}
//!   POST   /v1/containers/<name>/restart           restart it; {"address"}
//!   POST   /v1/containers/<name>/run               {timeout_s}: start a one-off container and wait for it to exit; its
//!                                                  {"exit_code", "timed_out", "lines"} (killed once the time is up)
//!   POST   /v1/containers/<name>/health            {path, timeout_s}: wait until it answers below 500; {"ok", "status", "error"}
//!   POST   /v1/containers/<name>/stop
//!   DELETE /v1/containers/<name>
//!   GET    /v1/containers/<name>                   {"running", "exit_code", "address"}
//!   GET    /v1/containers/<name>/logs?since=<cursor>  {"lines": [{stream, at, message}], "cursor"}
//!   *      /v1/proxy/<name>/<path>                 the request, forwarded to the container
//!   /v1/db/...                                     the database proxy (db.rs)
//!
//! Containers run hardened: read-only root file system with a small tmpfs at /tmp, every capability dropped,
//! no-new-privileges, a non-root user (10001 unless the image names a non-root USER; root only for a trusted Brod), a
//! process limit, memory and CPU limits, an init process, no volumes and no published ports, on a bridge of their own
//! (firewall.rs). How the node reaches a container (BROD_NODE_REACH):
//!   ip       the container's address on its bridge (Linux, the node running on the host)
//!   attach   the node, itself a container, joins each app's bridge (Linux, docker-compose.yml)
//!   publish  a port published on 127.0.0.1 only (macOS and Windows with Docker Desktop: development only)
use std::collections::HashMap;
use std::convert::Infallible;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use bytes::Bytes;
use http_body_util::{BodyExt, Full, combinators::BoxBody};
use hyper::body::{Frame, Incoming};
use hyper::{Method, Request, Response};
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use tokio::sync::mpsc;

use crate::Node;
use crate::docker::{Docker, demux, empty, message, q};

pub type BoxError = Box<dyn std::error::Error + Send + Sync>;
pub type Body = BoxBody<Bytes, BoxError>;

/// The largest build context the node accepts.
const CONTEXT_BYTES: u64 = 1024 * 1024 * 1024;
/// A build that takes longer is stopped (BROD_NODE_BUILD_TIMEOUT, in seconds).
const BUILD_SECS: u64 = 15 * 60;
/// The user a container runs as when its image names none.
pub const DEFAULT_USER: &str = "10001:10001";

macro_rules! log {
    ($($t:tt)*) => { eprintln!("brod-node: {}", format!($($t)*)) };
}

/// The node's workload state: the Docker client, an HTTP client for containers, and their addresses.
pub struct Work {
    docker: Docker,
    http: Client<HttpConnector, Body>,
    addresses: Mutex<HashMap<String, String>>,
    reach: Reach,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Reach {
    Ip,
    Attach,
    Publish,
}

impl Reach {
    fn from_env() -> Reach {
        match std::env::var("BROD_NODE_REACH").unwrap_or_default().trim() {
            "ip" => Reach::Ip,
            "attach" => Reach::Attach,
            "publish" => Reach::Publish,
            _ if !cfg!(target_os = "linux") => Reach::Publish,
            _ if Path::new("/.dockerenv").exists() => Reach::Attach,
            _ => Reach::Ip,
        }
    }
}

impl Default for Work {
    fn default() -> Work {
        let reach = Reach::from_env();
        if reach == Reach::Publish {
            log!("containers are reached through ports published on 127.0.0.1: for development only");
        }
        Work {
            docker: Docker::from_env(),
            http: Client::builder(hyper_util::rt::TokioExecutor::new()).build_http(),
            addresses: Mutex::new(HashMap::new()),
            reach,
        }
    }
}

impl Work {
    pub fn docker(&self) -> &Docker {
        &self.docker
    }
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

pub fn full(status: u16, content_type: &str, body: impl Into<Bytes>) -> Response<Body> {
    Response::builder()
        .status(status)
        .header("content-type", content_type)
        .body(Full::new(body.into()).map_err(|never: Infallible| match never {}).boxed())
        .expect("response")
}

pub(crate) fn reply(status: u16, v: Value) -> Response<Body> {
    full(status, "application/json", v.to_string())
}

pub(crate) fn fail(status: u16, code: &str, m: impl Into<String>) -> Response<Body> {
    reply(status, json!({ "error": { "code": code, "message": m.into() } }))
}

/// A body fed from a channel.
struct Chan(mpsc::Receiver<Bytes>);

impl http_body::Body for Chan {
    type Data = Bytes;
    type Error = BoxError;
    fn poll_frame(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        self.0.poll_recv(cx).map(|o| o.map(|b| Ok(Frame::data(b))))
    }
}

pub(crate) fn channel() -> (mpsc::Sender<Bytes>, Body) {
    let (tx, rx) = mpsc::channel(64);
    (tx, Chan(rx).boxed())
}

fn valid_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.chars().next().is_some_and(|c| c.is_ascii_alphanumeric())
        && s.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'))
}

fn query(req: &Request<Incoming>, key: &str) -> Option<String> {
    req.uri().query()?.split('&').find_map(|kv| {
        let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
        (k == key).then(|| v.replace("%2F", "/").replace("%2f", "/").replace("%3A", ":").replace("%3a", ":"))
    })
}

async fn read_json(req: Request<Incoming>) -> Result<Value, Response<Body>> {
    let bytes = http_body_util::Limited::new(req.into_body(), 1024 * 1024)
        .collect()
        .await
        .map_err(|e| fail(400, "bad_request", format!("The body did not arrive: {e}")))?
        .to_bytes();
    serde_json::from_slice(&bytes).map_err(|e| fail(400, "bad_request", format!("The body is not JSON: {e}")))
}

/// Whether the request is one work.rs answers.
pub fn handles(path: &str) -> bool {
    ["/v1/builds/", "/v1/images/", "/v1/containers/", "/v1/proxy/"].iter().any(|p| path.starts_with(p))
}

pub async fn handle(node: Arc<Node>, req: Request<Incoming>) -> Response<Body> {
    let path = req.uri().path().to_string();
    let seg: Vec<&str> = path.trim_start_matches('/').splitn(5, '/').collect();
    let m = req.method().clone();
    match (&m, &seg[1..]) {
        (&Method::POST, ["builds", id]) if valid_name(id) => build(node, id.to_string(), req).await,
        (&Method::GET, ["builds", id, "oci", rest @ ..]) if valid_name(id) => oci(&node, id, &rest.join("/")).await,
        (&Method::DELETE, ["builds", id]) if valid_name(id) => {
            let _ = tokio::fs::remove_dir_all(build_dir(&node, id)).await;
            reply(200, json!({ "ok": true }))
        }
        (&Method::POST, ["images", "load"]) => load(&node, req).await,
        (&Method::GET, ["images", id]) => match node.work.docker.call("GET", &format!("/images/{}/json", q(id)), None).await {
            Ok((200, _)) => reply(200, json!({ "exists": true })),
            Ok((404, _)) => reply(200, json!({ "exists": false })),
            Ok((s, v)) => fail(502, "docker_failed", message(s, &v)),
            Err(e) => fail(502, "docker_failed", e),
        },
        (&Method::DELETE, ["images", id]) => match node.work.docker.call("DELETE", &format!("/images/{}", q(id)), None).await {
            Ok((s, _)) if s < 300 || s == 404 => reply(200, json!({ "ok": true })),
            Ok((s, v)) => reply(200, json!({ "ok": false, "message": message(s, &v) })),
            Err(e) => fail(502, "docker_failed", e),
        },
        (_, ["containers", name, ..]) if !valid_name(name) => fail(400, "bad_name", "Not a container name."),
        (&Method::PUT, ["containers", name]) => match read_json(req).await {
            Ok(spec) => answer(create(&node, name, &spec).await),
            Err(r) => r,
        },
        (&Method::POST, ["containers", name, "start"]) => answer(start(&node, name).await),
        (&Method::POST, ["containers", name, "restart"]) => {
            lock(&node.work.addresses).remove(*name);
            let restarted = node.work.docker.call("POST", &format!("/containers/{name}/restart?t=10"), None).await;
            answer(match restarted {
                Ok((s, v)) if s >= 300 => Err(message(s, &v)),
                Ok(_) => start(&node, name).await,
                Err(e) => Err(e),
            })
        }
        (&Method::POST, ["containers", name, "run"]) => match read_json(req).await {
            Ok(v) => answer(run_once(&node, name, &v).await),
            Err(r) => r,
        },
        (&Method::POST, ["containers", name, "health"]) => match read_json(req).await {
            Ok(v) => reply(200, health(&node, name, &v).await),
            Err(r) => r,
        },
        (&Method::POST, ["containers", name, "stop"]) => {
            lock(&node.work.addresses).remove(*name);
            answer(
                node.work
                    .docker
                    .call("POST", &format!("/containers/{name}/stop?t=10"), None)
                    .await
                    .and_then(|(s, v)| if s < 300 || s == 304 || s == 404 { Ok(json!({ "ok": true })) } else { Err(message(s, &v)) }),
            )
        }
        (&Method::DELETE, ["containers", name]) => {
            lock(&node.work.addresses).remove(*name);
            answer(
                node.work
                    .docker
                    .call("DELETE", &format!("/containers/{name}?force=true&v=true"), None)
                    .await
                    .and_then(|(s, v)| if s < 300 || s == 404 { Ok(json!({ "ok": true })) } else { Err(message(s, &v)) }),
            )
        }
        (&Method::GET, ["containers", name]) => answer(inspect(&node, name).await),
        (&Method::GET, ["containers", name, "logs"]) => {
            let since = query(&req, "since");
            answer(logs(&node, name, since.as_deref()).await)
        }
        (_, ["proxy", name, ..]) if valid_name(name) => {
            let name = name.to_string();
            proxy(&node, &name, req).await
        }
        _ => fail(404, "not_found", "Nothing here."),
    }
}

fn answer(r: Result<Value, String>) -> Response<Body> {
    match r {
        Ok(v) => reply(200, v),
        Err(e) => fail(502, "container_failed", e),
    }
}

// ---------- builds ----------

fn build_dir(node: &Node, id: &str) -> PathBuf {
    node.dir.join("builds").join(id)
}

async fn build(node: Arc<Node>, id: String, req: Request<Incoming>) -> Response<Body> {
    let platform = query(&req, "platform").unwrap_or_else(|| format!("linux/{}", crate::sys::arch()));
    let dir = build_dir(&node, &id);
    let _ = tokio::fs::remove_dir_all(&dir).await;
    if let Err(e) = tokio::fs::create_dir_all(&dir).await {
        return fail(500, "build_failed", format!("Could not make {}: {e}", dir.display()));
    }
    // The context arrives first, whole; the build starts once it is on disk.
    let ctx = dir.join("context.tar");
    let mut body = req.into_body();
    let written = async {
        let mut f = tokio::fs::File::create(&ctx).await.map_err(|e| e.to_string())?;
        let mut n = 0u64;
        while let Some(frame) = body.frame().await {
            let frame = frame.map_err(|e| format!("the context did not arrive: {e}"))?;
            if let Ok(data) = frame.into_data() {
                n += data.len() as u64;
                if n > CONTEXT_BYTES {
                    return Err("the build context is larger than 1 GB".to_string());
                }
                f.write_all(&data).await.map_err(|e| e.to_string())?;
            }
        }
        f.flush().await.map_err(|e| e.to_string())?;
        Ok::<u64, String>(n)
    }
    .await;
    if let Err(e) = written {
        return fail(400, "build_failed", e);
    }
    let (tx, out) = channel();
    tokio::spawn(async move {
        let result = run_build(&dir, &platform, &tx).await;
        let _ = tokio::fs::remove_file(dir.join("context.tar")).await;
        let last = match result {
            Ok(()) => json!({ "done": true, "ok": true }),
            Err(e) => {
                let _ = tokio::fs::remove_file(dir.join("image.tar")).await;
                json!({ "done": true, "ok": false, "error": e })
            }
        };
        let _ = tx.send(Bytes::from(format!("{last}\n"))).await;
    });
    Response::builder().status(200).header("content-type", "application/x-ndjson").body(out).expect("response")
}

async fn say(tx: &mpsc::Sender<Bytes>, line: &str) {
    let _ = tx.send(Bytes::from(format!("{}\n", json!({ "log": line })))).await;
}

/// The buildx builder the node uses: a BuildKit container with memory and CPU limits, created once.
fn builder() -> String {
    std::env::var("BROD_NODE_BUILDER").ok().filter(|s| !s.trim().is_empty()).unwrap_or_else(|| "brod-builder".into())
}

async fn docker_cli(args: &[&str]) -> Result<String, String> {
    let out = tokio::process::Command::new("docker").args(args).output().await.map_err(|e| format!("docker: {e}"))?;
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    } else {
        Err(String::from_utf8_lossy(&out.stderr).trim().to_string())
    }
}

async fn ensure_builder(tx: &mpsc::Sender<Bytes>) -> Result<String, String> {
    let name = builder();
    if docker_cli(&["buildx", "inspect", &name]).await.is_ok() {
        return Ok(name);
    }
    let memory = std::env::var("BROD_NODE_BUILD_MEMORY").unwrap_or_else(|_| "2g".into());
    let cpus: f64 = std::env::var("BROD_NODE_BUILD_CPUS").ok().and_then(|c| c.parse().ok()).unwrap_or(2.0);
    let quota = format!("cpu-quota={}", (cpus * 100_000.0) as u64);
    say(tx, &format!("creating the builder {name} (memory {memory}, {cpus} CPUs)")).await;
    let mem = format!("memory={memory}");
    docker_cli(&["buildx", "create", "--name", &name, "--driver", "docker-container", "--driver-opt", &mem, "--driver-opt", &quota])
        .await
        .map_err(|e| format!("Could not create the builder: {e}"))?;
    Ok(name)
}

async fn run_build(dir: &Path, platform: &str, tx: &mpsc::Sender<Bytes>) -> Result<(), String> {
    let builder = ensure_builder(tx).await?;
    let dest = dir.join("image.tar");
    let output = format!("type=oci,dest={}", dest.display());
    let ctx = std::fs::File::open(dir.join("context.tar")).map_err(|e| e.to_string())?;
    let mut child = tokio::process::Command::new("docker")
        .args(["buildx", "build", "--builder", &builder, "--platform", platform, "--provenance=false", "--sbom=false"])
        .args(["--progress=plain", "--output", &output, "-"])
        .stdin(ctx)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| format!("Could not run docker buildx: {e}"))?;
    let pump = |r: Box<dyn tokio::io::AsyncRead + Send + Unpin>, tx: mpsc::Sender<Bytes>| async move {
        let mut lines = tokio::io::BufReader::new(r).lines();
        while let Ok(Some(l)) = lines.next_line().await {
            say(&tx, &l).await;
        }
    };
    let out = tokio::spawn(pump(Box::new(child.stdout.take().expect("stdout")), tx.clone()));
    let err = tokio::spawn(pump(Box::new(child.stderr.take().expect("stderr")), tx.clone()));
    let secs = std::env::var("BROD_NODE_BUILD_TIMEOUT").ok().and_then(|s| s.parse().ok()).unwrap_or(BUILD_SECS);
    let status = match tokio::time::timeout(Duration::from_secs(secs), child.wait()).await {
        Ok(s) => s.map_err(|e| e.to_string())?,
        Err(_) => {
            let _ = child.kill().await;
            return Err(format!("The build took longer than {} minutes and was stopped.", secs / 60));
        }
    };
    let _ = out.await;
    let _ = err.await;
    if !status.success() {
        return Err("The image did not build: see the build log.".into());
    }
    Ok(())
}

/// Where a file is in a tar: its data offset and size.
fn find_in_tar(path: &Path, want: &str) -> std::io::Result<Option<(u64, u64)>> {
    use std::io::{Read, Seek, SeekFrom};
    let mut f = std::fs::File::open(path)?;
    let mut at = 0u64;
    let mut long: Option<String> = None;
    loop {
        let mut h = [0u8; 512];
        if f.read_exact(&mut h).is_err() || h.iter().all(|b| *b == 0) {
            return Ok(None);
        }
        let text = |from: usize, len: usize| {
            let s = &h[from..from + len];
            String::from_utf8_lossy(&s[..s.iter().position(|b| *b == 0).unwrap_or(len)]).into_owned()
        };
        let size = u64::from_str_radix(text(124, 12).trim(), 8).unwrap_or(0);
        let data = at + 512;
        let next = data + size.div_ceil(512) * 512;
        match h[156] {
            b'L' | b'x' => {
                let mut d = vec![0u8; size as usize];
                f.read_exact(&mut d)?;
                let s = String::from_utf8_lossy(&d).into_owned();
                long = if h[156] == b'L' {
                    Some(s.trim_end_matches('\0').to_string())
                } else {
                    s.lines().find_map(|l| l.split_once(' ').and_then(|(_, kv)| kv.strip_prefix("path=")).map(String::from)).or(long)
                };
            }
            _ => {
                let prefix = text(345, 155);
                let name =
                    long.take().unwrap_or_else(|| if prefix.is_empty() { text(0, 100) } else { format!("{prefix}/{}", text(0, 100)) });
                if name.trim_start_matches("./") == want {
                    return Ok(Some((data, size)));
                }
            }
        }
        at = next;
        f.seek(SeekFrom::Start(at))?;
    }
}

async fn oci(node: &Node, id: &str, name: &str) -> Response<Body> {
    let ok = name == "index.json"
        || name == "oci-layout"
        || name.strip_prefix("blobs/sha256/").is_some_and(|h| h.len() == 64 && h.bytes().all(|b| b.is_ascii_hexdigit()));
    if !ok {
        return fail(404, "not_found", "Not a file of the image.");
    }
    let tar = build_dir(node, id).join("image.tar");
    let (want, t) = (name.to_string(), tar.clone());
    let found = tokio::task::spawn_blocking(move || find_in_tar(&t, &want)).await.ok().and_then(|r| r.ok()).flatten();
    let Some((offset, size)) = found else {
        return fail(404, "not_found", "The build has no such file.");
    };
    let (tx, out) = channel();
    tokio::spawn(async move {
        let Ok(mut f) = tokio::fs::File::open(&tar).await else { return };
        if f.seek(std::io::SeekFrom::Start(offset)).await.is_err() {
            return;
        }
        let mut left = size;
        let mut buf = vec![0u8; 256 * 1024];
        while left > 0 {
            let n = (buf.len() as u64).min(left) as usize;
            match f.read(&mut buf[..n]).await {
                Ok(0) | Err(_) => return,
                Ok(n) => {
                    left -= n as u64;
                    if tx.send(Bytes::copy_from_slice(&buf[..n])).await.is_err() {
                        return;
                    }
                }
            }
        }
    });
    Response::builder()
        .status(200)
        .header("content-type", "application/octet-stream")
        .header("content-length", size.to_string())
        .body(out)
        .expect("response")
}

// ---------- images ----------

async fn load(node: &Node, req: Request<Incoming>) -> Response<Body> {
    let body = req.into_body().map_err(|e| -> BoxError { Box::new(e) }).boxed();
    let res = match node.work.docker.send("POST", "/images/load?quiet=1", Some("application/x-tar"), body).await {
        Ok(r) => r,
        Err(e) => return fail(502, "docker_failed", e),
    };
    let status = res.status().as_u16();
    let bytes = match res.into_body().collect().await {
        Ok(b) => b.to_bytes(),
        Err(e) => return fail(502, "docker_failed", e.to_string()),
    };
    let text = String::from_utf8_lossy(&bytes).into_owned();
    // A stream of JSON messages; an error is one with "error".
    let error = text
        .lines()
        .filter_map(|l| serde_json::from_str::<Value>(l).ok())
        .find_map(|v| v["error"].as_str().or(v["message"].as_str().filter(|_| status >= 300)).map(String::from));
    match error {
        None if status < 300 => reply(200, json!({ "ok": true, "message": text.trim() })),
        e => reply(200, json!({ "ok": false, "message": e.unwrap_or(text) })),
    }
}

// ---------- containers ----------

/// The user to run as: the image's own unless it is root or unset. Root is refused unless Brod trusts the app.
pub fn user_for(image_user: &str, trusted: bool) -> Result<String, String> {
    let u = image_user.trim();
    let name = u.split(':').next().unwrap_or("");
    if u.is_empty() {
        return Ok(DEFAULT_USER.into());
    }
    if name == "root" || name == "0" {
        return if trusted {
            Ok(u.to_string())
        } else {
            Err("The image runs as root (USER root). Add a USER line with a non-root user, or leave USER out.".into())
        };
    }
    Ok(u.to_string())
}

/// Docker's container settings for a spec, hardened.
pub fn container_body(spec: &Value, user: &str, reach: Reach) -> Value {
    let port = spec["port"].as_u64().unwrap_or(8080);
    let network = spec["network"].as_str().unwrap_or("bridge");
    let memory = spec["memory_mb"].as_i64().unwrap_or(512).max(64) * 1024 * 1024;
    let cpus = spec["cpu"].as_f64().unwrap_or(0.5);
    let mut env: Vec<String> = match &spec["env"] {
        Value::Object(o) => o.iter().map(|(k, v)| format!("{k}={}", v.as_str().unwrap_or(""))).collect(),
        _ => vec![],
    };
    env.push(format!("PORT={port}"));
    let mut labels = spec["labels"].as_object().cloned().unwrap_or_default();
    labels.insert("brod.managed".into(), "1".into());
    labels.insert("brod.port".into(), port.to_string().into());
    labels.insert("brod.network".into(), network.into());
    let mut host = json!({
        "ReadonlyRootfs": true,
        "Tmpfs": { "/tmp": "rw,noexec,nosuid,nodev,size=256m" },
        "CapDrop": ["ALL"],
        "SecurityOpt": ["no-new-privileges:true"],
        "PidsLimit": 512,
        "Memory": memory,
        "MemorySwap": memory,
        "NanoCpus": (cpus * 1e9) as i64,
        "Init": true,
        "NetworkMode": network,
        "RestartPolicy": { "Name": "unless-stopped" },
        "LogConfig": { "Type": "json-file", "Config": { "max-size": "10m", "max-file": "3" } },
    });
    if let Some(hosts) = spec["extra_hosts"].as_array().filter(|h| !h.is_empty()) {
        host["ExtraHosts"] = Value::Array(hosts.clone());
    }
    if spec["once"].as_bool() == Some(true) {
        host["RestartPolicy"] = json!({ "Name": "no" });
    }
    let exposed = format!("{port}/tcp");
    if reach == Reach::Publish {
        host["PortBindings"] = json!({ &exposed: [{ "HostIp": "127.0.0.1", "HostPort": "" }] });
    }
    let mut body = json!({
        "Image": spec["image"],
        "User": user,
        "Env": env,
        "Labels": labels,
        "ExposedPorts": { exposed: {} },
        "HostConfig": host,
    });
    if let Some(cmd) = spec["cmd"].as_array().filter(|c| !c.is_empty()) {
        body["Cmd"] = Value::Array(cmd.clone());
    }
    body
}

/// The app's bridge, made if it is not there yet, with its network rules: a warning when the rules could not be put in
/// place, and the bridge as Docker describes it.
async fn ensure_network(node: &Node, network: &str) -> Result<(Option<String>, Value), String> {
    let d = &node.work.docker;
    let (status, mut v) = d.call("GET", &format!("/networks/{}", q(network)), None).await?;
    if status == 404 {
        let body = json!({ "Name": network, "Driver": "bridge", "Labels": { "brod.managed": "1" } });
        d.ok("POST", "/networks/create", Some(&body)).await?;
        v = d.ok("GET", &format!("/networks/{}", q(network)), None).await?;
    } else if status >= 300 {
        return Err(message(status, &v));
    }
    let config = v["IPAM"]["Config"].as_array().and_then(|c| c.iter().find(|c| c["Subnet"].as_str().is_some_and(|s| !s.contains(':'))));
    let (subnet, gateway) = (config.and_then(|c| c["Subnet"].as_str()), config.and_then(|c| c["Gateway"].as_str()));
    let warning = match subnet {
        Some(s) => crate::firewall::apply(s, gateway).await,
        None => Some("No network rules: the bridge has no IPv4 subnet.".into()),
    };
    Ok((warning, v))
}

/// Make sure the app's bridge has its database listener (db.rs). Where it listens, and what the container's
/// brod-db.internal points at.
pub async fn database_listener(
    node: &Node,
    network: &str,
    app: &str,
    port_hint: Option<u16>,
) -> Result<(std::net::SocketAddr, String), String> {
    let v = node.work.docker.ok("GET", &format!("/networks/{}", q(network)), None).await?;
    let bind = crate::db::bind_for(node, node.work.reach, &v, port_hint).await?;
    let extra = bind.extra_host.clone();
    Ok((node.db.ensure(network, app, bind)?, extra))
}

/// The node's own address on a bridge, joining it first (attach: the node is itself a container).
pub async fn own_address(node: &Node, network: &str) -> Result<std::net::Ipv4Addr, String> {
    let d = &node.work.docker;
    let me = std::fs::read_to_string("/etc/hostname").unwrap_or_default().trim().to_string();
    let (s, r) = d.call("POST", &format!("/networks/{}/connect", q(network)), Some(&json!({ "Container": me }))).await?;
    let already = r["message"].as_str().is_some_and(|m| m.contains("already exists"));
    if s >= 300 && !already {
        return Err(format!("The node could not join the app's network: {}", message(s, &r)));
    }
    let v = d.ok("GET", &format!("/containers/{}/json", q(&me)), None).await?;
    v["NetworkSettings"]["Networks"][network]["IPAddress"]
        .as_str()
        .and_then(|ip| ip.parse().ok())
        .ok_or_else(|| "The node has no address on the app's network.".to_string())
}

async fn create(node: &Node, name: &str, spec: &Value) -> Result<Value, String> {
    let d = &node.work.docker;
    let image = spec["image"].as_str().ok_or("No image.")?;
    let network = spec["network"].as_str().filter(|n| valid_name(n)).ok_or("No network.")?;
    let img = d.ok("GET", &format!("/images/{}/json", q(image)), None).await?;
    let user = user_for(img["Config"]["User"].as_str().unwrap_or(""), spec["trusted"].as_bool().unwrap_or(false))?;
    let mut warnings = vec![];
    let (warning, _) = ensure_network(node, network).await?;
    warnings.extend(warning);
    let mut spec = spec.clone();
    if let Some(app) = spec["database"].as_str().filter(|a| valid_name(a)).map(String::from) {
        // The app's database through brod-db.internal: a listener on its bridge, and the extra host pointing there.
        let (addr, extra) = database_listener(node, network, &app, None).await?;
        spec["extra_hosts"] = json!([format!("{}:{extra}", crate::db::HOST)]);
        if let Some(url) = spec["env"]["DATABASE_URL"].as_str().map(String::from) {
            spec["env"]["DATABASE_URL"] = json!(crate::db::with_port(&url, addr.port()));
        }
        if !spec["labels"].is_object() {
            spec["labels"] = json!({});
        }
        spec["labels"]["brod.db"] = json!(app);
        spec["labels"]["brod.db.port"] = json!(addr.port().to_string());
    }
    let _ = d.call("DELETE", &format!("/containers/{name}?force=true"), None).await;
    lock(&node.work.addresses).remove(name);
    let v = d.ok("POST", &format!("/containers/create?name={name}"), Some(&container_body(&spec, &user, node.work.reach))).await?;
    Ok(json!({ "id": v["Id"], "user": user, "warnings": warnings }))
}

async fn start(node: &Node, name: &str) -> Result<Value, String> {
    let d = &node.work.docker;
    let (status, v) = d.call("POST", &format!("/containers/{name}/start"), None).await?;
    if status >= 300 && status != 304 {
        return Err(message(status, &v));
    }
    let address = address(node, name).await?;
    Ok(json!({ "address": address }))
}

/// Where the node reaches the container, remembered once known.
async fn address(node: &Node, name: &str) -> Result<String, String> {
    if let Some(a) = lock(&node.work.addresses).get(name) {
        return Ok(a.clone());
    }
    let d = &node.work.docker;
    let v = d.ok("GET", &format!("/containers/{name}/json"), None).await?;
    let labels = &v["Config"]["Labels"];
    let port = labels["brod.port"].as_str().unwrap_or("8080").to_string();
    let network = labels["brod.network"].as_str().unwrap_or("bridge").to_string();
    let a = match node.work.reach {
        Reach::Publish => {
            let hp = v["NetworkSettings"]["Ports"][format!("{port}/tcp")][0]["HostPort"]
                .as_str()
                .ok_or("The container has no published port.")?;
            format!("127.0.0.1:{hp}")
        }
        reach => {
            if reach == Reach::Attach {
                let me = std::fs::read_to_string("/etc/hostname").unwrap_or_default().trim().to_string();
                let (s, r) = d.call("POST", &format!("/networks/{}/connect", q(&network)), Some(&json!({ "Container": me }))).await?;
                let already = r["message"].as_str().is_some_and(|m| m.contains("already exists"));
                if s >= 300 && !already {
                    return Err(format!("The node could not join the app's network: {}", message(s, &r)));
                }
            }
            let ip = v["NetworkSettings"]["Networks"][&network]["IPAddress"]
                .as_str()
                .filter(|s| !s.is_empty())
                .ok_or("The container has no address.")?;
            format!("{ip}:{port}")
        }
    };
    lock(&node.work.addresses).insert(name.to_string(), a.clone());
    Ok(a)
}

async fn inspect(node: &Node, name: &str) -> Result<Value, String> {
    let (s, v) = node.work.docker.call("GET", &format!("/containers/{name}/json"), None).await?;
    if s == 404 {
        return Ok(json!({ "exists": false, "running": false }));
    }
    if s >= 300 {
        return Err(message(s, &v));
    }
    let running = v["State"]["Running"].as_bool().unwrap_or(false);
    Ok(json!({ "exists": true, "running": running, "exit_code": v["State"]["ExitCode"], "oom": v["State"]["OOMKilled"] }))
}

/// Start a one-off container (a migration) and wait for it to exit, killing it after timeout_s. Its exit code and output.
async fn run_once(node: &Node, name: &str, v: &Value) -> Result<Value, String> {
    let d = &node.work.docker;
    let secs = v["timeout_s"].as_u64().unwrap_or(600).clamp(1, 3600);
    let (status, r) = d.call("POST", &format!("/containers/{name}/start"), None).await?;
    if status >= 300 && status != 304 {
        return Err(message(status, &r));
    }
    let wait = async {
        let res = d.send("POST", &format!("/containers/{name}/wait"), None, empty()).await?;
        let bytes = res.into_body().collect().await.map_err(|e| e.to_string())?.to_bytes();
        let v: Value = serde_json::from_slice(&bytes).map_err(|_| format!("Docker's wait answered {}", String::from_utf8_lossy(&bytes)))?;
        v["StatusCode"].as_i64().ok_or_else(|| format!("Docker's wait answered {v}"))
    };
    let (exit_code, timed_out) = match tokio::time::timeout(Duration::from_secs(secs), wait).await {
        Ok(code) => (Some(code?), false),
        Err(_) => {
            let _ = d.call("POST", &format!("/containers/{name}/kill"), None).await;
            (None, true)
        }
    };
    let lines = logs(node, name, None).await.map(|l| l["lines"].clone()).unwrap_or(json!([]));
    Ok(json!({ "exit_code": exit_code, "timed_out": timed_out, "lines": lines }))
}

async fn health(node: &Node, name: &str, v: &Value) -> Value {
    let path = v["path"].as_str().filter(|p| p.starts_with('/')).unwrap_or("/").to_string();
    let deadline = Instant::now() + Duration::from_secs(v["timeout_s"].as_u64().unwrap_or(60).min(600));
    let mut last: String;
    loop {
        match inspect(node, name).await {
            Ok(i) if !i["running"].as_bool().unwrap_or(false) => {
                let oom = if i["oom"].as_bool() == Some(true) { " after running out of memory" } else { "" };
                return json!({ "ok": false, "error": format!("The container stopped (exit code {}){oom}.", i["exit_code"]) });
            }
            Err(e) => return json!({ "ok": false, "error": e }),
            Ok(_) => {}
        }
        match address(node, name).await {
            Ok(a) => {
                let req = Request::get(format!("http://{a}{path}")).header("user-agent", "brod-health").body(empty()).expect("request");
                match tokio::time::timeout(Duration::from_secs(3), node.work.http.request(req)).await {
                    Ok(Ok(res)) if res.status().as_u16() < 500 => return json!({ "ok": true, "status": res.status().as_u16() }),
                    Ok(Ok(res)) => last = format!("{path} answered {}.", res.status().as_u16()),
                    Ok(Err(e)) => last = format!("{path} did not answer: {e}"),
                    Err(_) => last = format!("{path} took longer than 3 s to answer."),
                }
            }
            Err(e) => last = e,
        }
        if Instant::now() >= deadline {
            return json!({ "ok": false, "error": last });
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

/// Seconds and nanoseconds since the epoch of an RFC 3339 UTC timestamp as Docker writes it.
pub fn timestamp(s: &str) -> Option<(i64, u32)> {
    let s = s.strip_suffix('Z')?;
    let (date, time) = s.split_once('T')?;
    let mut d = date.split('-').map(|p| p.parse::<i64>());
    let (y, mo, da) = (d.next()?.ok()?, d.next()?.ok()?, d.next()?.ok()?);
    let (hms, frac) = time.split_once('.').unwrap_or((time, "0"));
    let mut t = hms.split(':').map(|p| p.parse::<i64>());
    let (h, mi, se) = (t.next()?.ok()?, t.next()?.ok()?, t.next()?.ok()?);
    let nanos: u32 = format!("{:0<9}", &frac[..frac.len().min(9)]).parse().ok()?;
    // Days from civil (Howard Hinnant's algorithm).
    let y = if mo <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * (if mo > 2 { mo - 3 } else { mo + 9 }) + 2) / 5 + da - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146097 + doe - 719468;
    Some((days * 86400 + h * 3600 + mi * 60 + se, nanos))
}

fn cursor((s, n): (i64, u32)) -> String {
    format!("{s}.{n:09}")
}

fn parse_cursor(c: &str) -> Option<(i64, u32)> {
    let (s, n) = c.split_once('.').unwrap_or((c, "0"));
    Some((s.parse().ok()?, format!("{:0<9}", &n[..n.len().min(9)]).parse().ok()?))
}

async fn logs(node: &Node, name: &str, since: Option<&str>) -> Result<Value, String> {
    let after = since.and_then(parse_cursor);
    let since_q = after.map(|(s, _)| s.to_string()).unwrap_or_else(|| "0".into());
    let res = node
        .work
        .docker
        .send("GET", &format!("/containers/{name}/logs?stdout=1&stderr=1&timestamps=1&since={since_q}&tail=2000"), None, empty())
        .await?;
    let status = res.status().as_u16();
    let bytes = res.into_body().collect().await.map_err(|e| e.to_string())?.to_bytes();
    if status == 404 {
        return Ok(json!({ "lines": [], "cursor": since, "gone": true }));
    }
    if status >= 300 {
        return Err(message(status, &serde_json::from_slice(&bytes).unwrap_or_default()));
    }
    let mut last = after;
    let mut lines = vec![];
    for (stream, l) in demux(&bytes) {
        let (ts, text) = l.split_once(' ').unwrap_or((&l, ""));
        let Some(t) = timestamp(ts) else { continue };
        if after.is_some_and(|a| t <= a) {
            continue;
        }
        last = Some(t);
        lines.push(json!({ "stream": stream, "at": t.0 * 1000 + (t.1 / 1_000_000) as i64, "message": text }));
    }
    Ok(json!({ "lines": lines, "cursor": last.map(cursor) }))
}

// ---------- the proxy ----------

/// Mark an answer as the node's own, so Brod can tell it from the app's.
fn node_error(mut r: Response<Body>) -> Response<Body> {
    r.headers_mut().insert("x-brod-node-error", hyper::header::HeaderValue::from_static("1"));
    r
}

async fn proxy(node: &Node, name: &str, req: Request<Incoming>) -> Response<Body> {
    let a = match address(node, name).await {
        Ok(a) => a,
        Err(e) => return node_error(fail(502, "container_unreachable", e)),
    };
    let (mut parts, body) = req.into_parts();
    let prefix = format!("/v1/proxy/{name}");
    let rest = parts.uri.path().strip_prefix(&prefix).unwrap_or("/");
    let rest = if rest.is_empty() { "/" } else { rest };
    let pq = match parts.uri.query() {
        Some(q) => format!("{rest}?{q}"),
        None => rest.to_string(),
    };
    parts.uri = match format!("http://{a}{pq}").parse() {
        Ok(u) => u,
        Err(e) => return fail(400, "bad_path", e.to_string()),
    };
    parts.version = hyper::Version::HTTP_11;
    let host = parts.headers.get("x-forwarded-host").cloned();
    if let Some(h) = host {
        parts.headers.insert("host", h);
    }
    let req = Request::from_parts(parts, body.map_err(|e| -> BoxError { Box::new(e) }).boxed());
    match node.work.http.request(req).await {
        Ok(res) => res.map(|b| b.map_err(|e| -> BoxError { Box::new(e) }).boxed()),
        Err(e) => {
            lock(&node.work.addresses).remove(name);
            node_error(fail(502, "container_unreachable", format!("The app's container did not answer: {e}")))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runs_as_a_non_root_user() {
        assert_eq!(user_for("", false).unwrap(), DEFAULT_USER);
        assert_eq!(user_for("node", false).unwrap(), "node");
        assert_eq!(user_for("1000:1000", false).unwrap(), "1000:1000");
        assert!(user_for("root", false).is_err());
        assert!(user_for("0:0", false).is_err());
        assert_eq!(user_for("root", true).unwrap(), "root");
    }

    #[test]
    fn hardens_the_container() {
        let spec =
            json!({ "image": "sha256:ab", "port": 3000, "cpu": 0.5, "memory_mb": 256, "network": "brod-app-x", "env": { "A": "1" } });
        let b = container_body(&spec, DEFAULT_USER, Reach::Ip);
        let h = &b["HostConfig"];
        assert_eq!(h["ReadonlyRootfs"], true);
        assert_eq!(h["CapDrop"], json!(["ALL"]));
        assert_eq!(h["SecurityOpt"], json!(["no-new-privileges:true"]));
        assert_eq!(h["Init"], true);
        assert_eq!(h["Memory"], 256 * 1024 * 1024);
        assert_eq!(h["NanoCpus"], 500_000_000);
        assert_eq!(h["NetworkMode"], "brod-app-x");
        assert!(h.get("Binds").is_none() && h.get("PortBindings").is_none());
        assert_eq!(b["User"], DEFAULT_USER);
        assert_eq!(b["Env"], json!(["A=1", "PORT=3000"]));
        let p = container_body(&spec, DEFAULT_USER, Reach::Publish);
        assert_eq!(p["HostConfig"]["PortBindings"]["3000/tcp"][0]["HostIp"], "127.0.0.1");
    }

    #[test]
    fn reads_docker_timestamps() {
        assert_eq!(timestamp("1970-01-01T00:00:01.5Z"), Some((1, 500_000_000)));
        assert_eq!(timestamp("2026-10-31T19:08:39.123456789Z"), Some((1793473719, 123456789)));
        assert_eq!(parse_cursor(&cursor((5, 7))), Some((5, 7)));
        assert!(timestamp("nope").is_none());
    }
}
