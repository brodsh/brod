// SPDX-License-Identifier: AGPL-3.0-only
// Container apps: from a source bundle with a Dockerfile to a container serving the app's address.
//
// deploy_app records the version (runtime "container"), picks a node (scheduler.rs) and returns at once with the
// deployment's id and state; the rest runs in the background, step by step:
//   scheduled -> building   the node builds the context with docker buildx (15 minutes at most)
//             -> pulling    Brod copies the image into its registry as apps/<app id>:v<n> and records its digest, then
//                           has the node load it (skipped when the node has it already)
//             -> starting   the node creates the container, hardened (node/src/work.rs), with BROD_ISSUER,
//                           BROD_APP_ID, BROD_IDENTITY_JWKS and the app's secrets in its environment, and starts it
//             -> healthy    it answered its health path below 500 within 60 s
//             -> serving    the app's live (or staging) pointer moves to the version: visitors get it from now on
// The deployment it replaced drains for 30 s, then its container stops (draining -> stopped). Stopped containers of an
// app's last 2 versions are kept for 24 h, the rest removed. A failure at any step ends in failed with the reason in
// error and the log kept; what is live stays as it was. A rollback to a container version, and publishing staging,
// reuse the image by its digest: nothing is rebuilt.
//
// Every step's lines, the build output among them, go to the deployment's log and to the app's logs (get_logs); while
// a container serves, its stdout and stderr follow into the app's logs too. get_deployment reads a deployment.
//
// Containers are on only when BROD_CONTAINERS is "trusted" (self-hosted default: images may run as root) or "on"
// (never as root; the hosted default is off), and only with a registry (BROD_REGISTRY_URL).
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use axum::body::Body;
use axum::http::Method;
use axum::response::Response;
use bytes::Bytes;
use futures_util::StreamExt;
use http_body_util::BodyExt;
use serde_json::{Map, Value, json};

use crate::config::Containers;
use crate::containers::{self, Spec};
use crate::control::{self, DeployTarget};
use crate::db::{Connection, Row, Sql, event, params, tx};
use crate::http::{Req, notice, response};
use crate::model::{AppRow, Caller};
use crate::people::require_role;
use crate::problem::{Problem, Result};
use crate::registry::{self, Registry};
use crate::state::State;
use crate::util::{iso, js_slice, js_trim, now, random_id, staging_url};

/// How long a container has to answer its health path.
const HEALTH_SECS: u64 = 60;
/// How long the deployment a new one replaced keeps its container running for requests in flight.
const DRAIN_MS: i64 = 30_000;
/// Stopped containers of an app's last versions are kept this long, for a quick rollback and for their logs.
const KEEP_STOPPED_MS: i64 = 24 * 3600 * 1000;
const KEEP_STOPPED_VERSIONS: usize = 2;
/// Images in the registry: the live and staging versions' and the newest of the rest.
const KEEP_IMAGES: usize = 5;
/// A deployment's own log, at most (the newest lines are kept).
const LOG_BYTES: usize = 256 * 1024;
/// A request to a container: its body at most, and how long its answer may take to start.
pub const REQUEST_BYTES: usize = 32 * 1024 * 1024;
const REQUEST_SECS: u64 = 60;

/// The states in order, and what may follow each.
pub fn allowed(from: &str, to: &str) -> bool {
    matches!(
        (from, to),
        ("scheduled", "building" | "pulling")
            | ("building", "pulling")
            | ("pulling", "starting")
            | ("starting", "healthy")
            | ("healthy", "serving" | "stopped")
            | ("serving", "draining")
            | ("draining", "stopped")
    ) || (to == "failed" && matches!(from, "scheduled" | "building" | "pulling" | "starting" | "healthy"))
}

/// Not finished yet: scheduled to healthy.
pub const IN_PROGRESS: [&str; 5] = ["scheduled", "building", "pulling", "starting", "healthy"];

/// The prefix of the containers, networks and images Brod makes on nodes (BROD_CONTAINER_PREFIX, default "brod").
pub fn prefix() -> &'static str {
    static P: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    P.get_or_init(|| {
        std::env::var("BROD_CONTAINER_PREFIX")
            .ok()
            .map(|p| p.trim().to_lowercase())
            .filter(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'))
            .unwrap_or_else(|| "brod".into())
    })
}

pub fn network_of(app_id: &str) -> String {
    format!("{}-app-{}", prefix(), app_id.replace('_', "-"))
}

fn container_of(id: &str) -> String {
    format!("{}-{}", prefix(), id.replace('_', "-"))
}

/// A deployment row.
#[derive(Clone, Debug)]
pub struct Deployment {
    pub id: String,
    pub app_id: String,
    pub version: i64,
    pub environment: String,
    pub node_id: Option<String>,
    pub state: String,
    pub error: Option<String>,
    pub error_code: Option<String>,
    pub container_ref: Option<String>,
    pub log: String,
    pub cpu: f64,
    pub memory_mb: i64,
    pub built: bool,
    pub actor: String,
    pub created_at: i64,
    pub updated_at: i64,
    pub ready_at: Option<i64>,
    pub stopped_at: Option<i64>,
    pub log_cursor: Option<String>,
}

impl Deployment {
    pub fn from_row(r: &Row) -> Result<Deployment> {
        Ok(Deployment {
            id: r.get("id")?,
            app_id: r.get("app_id")?,
            version: r.get("version")?,
            environment: r.get("environment")?,
            node_id: r.get("node_id")?,
            state: r.get("state")?,
            error: r.get("error")?,
            error_code: r.get("error_code")?,
            container_ref: r.get("container_ref")?,
            log: r.get("log")?,
            cpu: r.get("cpu")?,
            memory_mb: r.get("memory_mb")?,
            built: r.get::<_, i64>("built")? != 0,
            actor: r.get("actor")?,
            created_at: r.get("created_at")?,
            updated_at: r.get("updated_at")?,
            ready_at: r.get("ready_at")?,
            stopped_at: r.get("stopped_at")?,
            log_cursor: r.get("log_cursor")?,
        })
    }

    /// The last `n` lines of its log.
    pub fn tail(&self, n: usize) -> Vec<&str> {
        let lines: Vec<&str> = self.log.lines().collect();
        lines[lines.len().saturating_sub(n)..].to_vec()
    }

    pub fn view(&self, lines: usize) -> Value {
        json!({
            "id": self.id, "version": self.version, "environment": if self.environment == "live" { "production" } else { "staging" },
            "state": self.state, "node": self.node_id, "error": self.error, "error_code": self.error_code,
            "created_at": iso(self.created_at), "updated_at": iso(self.updated_at), "ready_at": self.ready_at.map(iso),
            "log": self.tail(lines),
        })
    }
}

pub fn get(conn: &Connection, id: &str) -> Result<Option<Deployment>> {
    conn.first("SELECT * FROM deployments WHERE id = ?", [id], Deployment::from_row)
}

/// Why containers cannot run here, or None when they can.
pub fn unavailable(st: &State) -> Option<Problem> {
    let why = if st.cfg.containers == Containers::Off {
        "Container apps are off on this Brod (BROD_CONTAINERS). Deploy static files or server code instead, or ask the operator to turn containers on."
    } else if st.registry.is_none() {
        "Container apps need an image registry, and this Brod has none (BROD_REGISTRY_URL)."
    } else {
        return None;
    };
    Some(Problem::new(403, "containers_unavailable", why))
}

/// Change a deployment's state if it is still in `from`. False when it was not (it moved on, or was taken over).
fn transition(conn: &Connection, id: &str, from: &str, to: &str) -> Result<bool> {
    if !allowed(from, to) {
        return Err(Problem::internal(format!("deployment {id}: {from} -> {to}")));
    }
    let at = now();
    let n = conn.run(
        "UPDATE deployments SET state = ?, updated_at = ?,
           ready_at = CASE WHEN ? = 'serving' THEN ? ELSE ready_at END,
           stopped_at = CASE WHEN ? = 'stopped' THEN ? ELSE stopped_at END
         WHERE id = ? AND state = ?",
        params![to, at, to, at, to, at, id, from],
    )?;
    Ok(n == 1)
}

// ---------- deploying ----------

/// deploy_app for a container source (an archive with a Dockerfile at its top): record the version, schedule the
/// deployment and start it. Returns at once.
pub async fn deploy(st: &State, c: &Caller, o: DeployTarget, archive: Vec<u8>) -> Result<Value> {
    if let Some(p) = unavailable(st) {
        return Err(p);
    }
    {
        let (c, o) = (c.clone(), o.clone());
        st.db
            .call(move |conn| {
                require_role(&c, "builder", "deploy apps")?;
                control::check_rate(conn, &c)?;
                crate::abuse::check_workspace_up(conn, &c)?;
                match o.app_slug() {
                    Some(slug) => crate::abuse::check_up(conn, &control::get_app(conn, &c, slug)?),
                    None => Ok(()),
                }
            })
            .await?;
    }
    o.check_environment()?;
    let base = o.base()?;
    let options = o.options.clone();
    // Read the source once for its settings, then write the filtered build context to disk.
    let id = random_id("dep_", 10);
    let dir = st.cfg.data_dir.join("builds");
    std::fs::create_dir_all(&dir).map_err(Problem::internal)?;
    let context = dir.join(format!("{id}.tar"));
    let ctx_path = context.clone();
    let (spec, ctx, declared_open) = tokio::task::spawn_blocking(move || -> Result<(Spec, containers::Context, Option<String>)> {
        let survey = containers::survey(&archive)?
            .filter(|s| s.dockerfile)
            .ok_or_else(|| Problem::new(400, "bad_container", "A container app's source needs a Dockerfile at the top of the archive."))?;
        let spec = containers::spec_of(survey.manifest.as_deref(), options.as_ref())?;
        // brod.json's open_paths work as for any app (open_paths.rs).
        let manifest = survey.manifest.clone().map(|bytes| crate::tar::BundleFile { path: crate::settings::MANIFEST.to_string(), bytes });
        let declared_open = crate::open_paths::from_bundle(manifest.as_slice())?;
        let ignore = containers::Ignore::parse(survey.dockerignore.as_deref().unwrap_or(""));
        let ctx = containers::write_context(&archive, &ignore, &ctx_path)?;
        Ok((spec, ctx, declared_open))
    })
    .await
    .map_err(Problem::internal)?
    .inspect_err(|_| {
        let _ = std::fs::remove_file(&context);
    })?;
    let connected = st.nodes.connected_ids();
    let (c2, o2, cfg, spec2, id2) = (c.clone(), o.clone(), st.cfg.clone(), spec.clone(), id.clone());
    let out = st
        .db
        .call(move |conn| {
            let (app, created) = control::target_app(conn, &cfg, &c2, &o2)?;
            if let Some(b) = base
                && control::current_version(&app) != Some(b)
            {
                return Err(control::stale_base(conn, &app.id, b)?);
            }
            let prefer = live_node(conn, &app.id)?;
            let node = crate::scheduler::choose(
                conn,
                &connected,
                &crate::scheduler::Need { cpu: spec2.cpu, memory_mb: spec2.memory_mb, arch: None, prefer },
            )?;
            let staging = control::deploy_to_staging(&c2, &app, created, &o2);
            let note = js_slice(js_trim(o2.note.as_deref().unwrap_or("")), 200);
            let note = if note.is_empty() { if created { "First version".to_string() } else { "Update".to_string() } } else { note };
            let n: i64 = conn
                .first("UPDATE apps SET last_version = COALESCE(last_version, 0) + 1 WHERE id = ? RETURNING last_version", [&app.id], |r| {
                    r.get(0)
                })?
                .ok_or_else(|| Problem::new(404, "not_found", "The app was deleted during the deploy."))?;
            let environment = if staging { "staging" } else { "live" };
            tx(conn, |x| {
                x.run(
                    "INSERT INTO versions (app_id, n, note, actor, file_count, bytes, created_at, scan, based_on, runtime, spec, open_paths) VALUES (?,?,?,?,?,?,?,'[]',?,'container',?,?)",
                    params![app.id, n, note, c2.actor, ctx.files as i64, ctx.bytes as i64, now(), base, spec2.to_json(), declared_open],
                )?;
                x.run(
                    "INSERT INTO deployments (id, app_id, version, environment, node_id, state, cpu, memory_mb, actor, created_at, updated_at) VALUES (?,?,?,?,?,'scheduled',?,?,?,?,?)",
                    params![id2, app.id, n, environment, node, spec2.cpu, spec2.memory_mb, c2.actor, now(), now()],
                )?;
                let to = if staging { " to staging" } else { "" };
                event(x, &c2.workspace.id, &c2.actor, Some(&app.id), "deploy", &format!("v{n}{to} (container, building): {note} ({} files)", ctx.files))?;
                Ok(())
            })?;
            control::mark_editing(conn, &c2, &app.id, Some(n))?;
            let open = control::deployed_open_paths(conn, &cfg, &c2, &app, n)?;
            let mut m = control::described(conn, &cfg, &c2, &app)?;
            if let Some(open) = open {
                if let Some(url) = open.get("confirm_url") {
                    m.insert("confirm_url".into(), url.clone());
                }
                m.insert("open_paths".into(), open);
            }
            m.insert("version".into(), json!(n));
            m.insert("based_on".into(), json!(base));
            m.extend(control::editing_notice(conn, &c2, &app)?);
            m.insert("environment".into(), json!(if staging { "staging" } else { "production" }));
            m.insert("files".into(), json!(ctx.files));
            m.insert("bytes".into(), json!(ctx.bytes));
            m.insert("created".into(), json!(created));
            m.insert("kind".into(), json!("container"));
            m.insert("container".into(), containers::spec_view(&spec2));
            m.insert("deployment".into(), json!({ "id": id2, "state": "scheduled", "node": node }));
            let address = if staging { staging_url(&cfg, &c2.workspace.slug, &app.slug) } else { m["url"].as_str().unwrap_or("").to_string() };
            if staging {
                m.insert("staging_url".into(), json!(address));
            }
            let current = if staging { app.staging_version } else { app.live_version };
            m.insert(
                "next_step".into(),
                json!(format!(
                    "v{n} is building on a node; it is not serving yet{}. Call get_deployment with \"deployment\": \"{id2}\" every 10-20 s until its state is \"serving\" \
                     (then {address} serves v{n}) or \"failed\" (its error and log say why; {} keeps serving).",
                    current.map(|v| format!(": {address} still serves v{v}")).unwrap_or_default(),
                    current.map(|v| format!("v{v}")).unwrap_or_else(|| "nothing".into())
                )),
            );
            Ok(Value::Object(m))
        })
        .await;
    match out {
        Ok(v) => {
            let st = st.clone();
            tokio::spawn(async move { run(st, id).await });
            Ok(v)
        }
        Err(e) => {
            let _ = std::fs::remove_file(&context);
            Err(e)
        }
    }
}

/// The node serving the app's live version, to keep an update there.
fn live_node(conn: &Connection, app_id: &str) -> Result<Option<String>> {
    Ok(conn
        .first(
            "SELECT node_id FROM deployments WHERE app_id = ? AND state = 'serving' AND environment = 'live' ORDER BY created_at DESC LIMIT 1",
            [app_id],
            |r| r.get::<_, Option<String>>(0),
        )?
        .flatten())
}

/// Start a deployment of an existing container version, reusing its image (rollback, or redeploying a version).
pub fn redeploy(conn: &Connection, connected: &[String], app: &AppRow, n: i64, environment: &str, actor: &str) -> Result<Deployment> {
    let spec: Option<String> = conn
        .first("SELECT spec FROM versions WHERE app_id = ? AND n = ? AND runtime = 'container'", params![app.id, n], |r| r.get(0))?
        .flatten();
    let spec = Spec::parse(spec.as_deref());
    if spec.digest.is_none() || spec.pruned {
        let why = if spec.pruned {
            "its image was removed from the registry (only the newest versions' images are kept)"
        } else {
            "it was never built"
        };
        return Err(Problem::new(409, "no_image", format!("v{n} cannot run again: {why}. Deploy its source again instead.")));
    }
    let arch = spec.platform.as_deref().and_then(|p| p.strip_prefix("linux/")).map(String::from);
    let node = crate::scheduler::choose(
        conn,
        connected,
        &crate::scheduler::Need { cpu: spec.cpu, memory_mb: spec.memory_mb, arch, prefer: live_node(conn, &app.id)? },
    )?;
    let id = random_id("dep_", 10);
    conn.run(
        "INSERT INTO deployments (id, app_id, version, environment, node_id, state, cpu, memory_mb, actor, created_at, updated_at) VALUES (?,?,?,?,?,'scheduled',?,?,?,?,?)",
        params![id, app.id, n, environment, node, spec.cpu, spec.memory_mb, actor, now(), now()],
    )?;
    get(conn, &id)?.ok_or_else(|| Problem::internal("the deployment was not saved"))
}

/// Start the background work for a deployment created by `redeploy`.
pub fn start(st: &State, id: &str) {
    let (st, id) = (st.clone(), id.to_string());
    tokio::spawn(async move { run(st, id).await });
}

/// A deployment's log: kept in its row (the newest LOG_BYTES) and copied to the app's logs about once a second.
struct Log {
    st: State,
    id: String,
    app_id: String,
    version: i64,
    text: String,
    pending: Vec<String>,
    flushed: Instant,
}

impl Log {
    async fn line(&mut self, line: impl Into<String>) {
        let line: String = line.into();
        let line = js_slice(&line, 2000);
        self.text.push_str(&line);
        self.text.push('\n');
        if self.text.len() > LOG_BYTES {
            let mut cut = self.text.len() - LOG_BYTES;
            while !self.text.is_char_boundary(cut) {
                cut += 1;
            }
            let start = self.text[cut..].find('\n').map(|i| cut + i + 1).unwrap_or(cut);
            self.text.drain(..start);
        }
        self.pending.push(line);
        if self.flushed.elapsed() > Duration::from_secs(1) {
            self.flush().await;
        }
    }

    async fn flush(&mut self) {
        self.flushed = Instant::now();
        let lines = std::mem::take(&mut self.pending);
        let (id, app, version, text) = (self.id.clone(), self.app_id.clone(), self.version, self.text.clone());
        let r = self
            .st
            .db
            .call(move |c| {
                c.run("UPDATE deployments SET log = ?, updated_at = ? WHERE id = ?", params![text, now(), id])?;
                if !lines.is_empty() {
                    let logs: Vec<Value> = lines.iter().map(|l| json!({ "level": "info", "message": l })).collect();
                    c.run(
                        "INSERT INTO app_logs (app_id, at, version, method, path, status, outcome, logs, exceptions) VALUES (?,?,?,'DEPLOY',?,NULL,'deploy',?,'[]')",
                        params![app, now(), version, id, Value::Array(logs).to_string()],
                    )?;
                }
                Ok(())
            })
            .await;
        if let Err(e) = r {
            tracing::warn!("could not save a deployment's log: {}", e.message);
        }
    }
}

/// Run a deployment to serving, or to failed.
pub async fn run(st: State, id: String) {
    let d = match st
        .db
        .call({
            let id = id.clone();
            move |c| get(c, &id)
        })
        .await
    {
        Ok(Some(d)) => d,
        Ok(None) => return,
        Err(e) => {
            tracing::error!("deployment {id}: {}", e.message);
            return;
        }
    };
    let mut log = Log {
        st: st.clone(),
        id: d.id.clone(),
        app_id: d.app_id.clone(),
        version: d.version,
        text: d.log.clone(),
        pending: vec![],
        flushed: Instant::now(),
    };
    let result = steps(&st, &d, &mut log).await;
    let context = st.cfg.data_dir.join("builds").join(format!("{}.tar", d.id));
    let _ = tokio::fs::remove_file(&context).await;
    if let Err((code, p)) = result {
        log.line(format!("failed: {}", p.message)).await;
        log.flush().await;
        let (id, code2, msg) = (d.id.clone(), code.to_string(), p.message.clone());
        let r = st
            .db
            .call(move |c| {
                let state: Option<String> = c.first("SELECT state FROM deployments WHERE id = ?", [&id], |r| r.get(0))?;
                if state.as_deref().is_some_and(|s| IN_PROGRESS.contains(&s)) {
                    c.run(
                        "UPDATE deployments SET state = 'failed', error = ?, error_code = ?, updated_at = ?, stopped_at = ? WHERE id = ?",
                        params![msg, code2, now(), now(), id],
                    )?;
                }
                Ok(())
            })
            .await;
        if let Err(e) = r {
            tracing::error!("deployment {}: {}", d.id, e.message);
        }
        tracing::warn!(deployment = %d.id, "deployment failed ({code}): {}", p.message);
        // The container of a failed deployment goes; its output is in the log.
        if let (Some(node), Some(_)) = (&d.node_id, container_ref(&st, &d.id).await) {
            let _ = node_call(&st, node, Method::DELETE, &format!("/v1/containers/{}", container_of(&d.id)), None, 30).await;
            let id = d.id.clone();
            let _ = st.db.call(move |c| c.run("UPDATE deployments SET removed_at = ? WHERE id = ?", params![now(), id])).await;
        }
    } else {
        log.flush().await;
    }
}

async fn container_ref(st: &State, id: &str) -> Option<String> {
    let id = id.to_string();
    st.db
        .call(move |c| c.first("SELECT container_ref FROM deployments WHERE id = ?", [&id], |r| r.get::<_, Option<String>>(0)))
        .await
        .ok()
        .flatten()
        .flatten()
}

type Step<T> = std::result::Result<T, (&'static str, Problem)>;

fn failed(code: &'static str) -> impl Fn(Problem) -> (&'static str, Problem) {
    move |p| (code, p)
}

async fn move_to(st: &State, d: &Deployment, from: &str, to: &str) -> Result<bool> {
    let (id, from, to) = (d.id.clone(), from.to_string(), to.to_string());
    st.db.call(move |c| transition(c, &id, &from, &to)).await
}

/// A JSON call to a node over its tunnel, with a time limit.
async fn node_call(st: &State, node: &str, method: Method, path: &str, body: Option<Value>, secs: u64) -> Result<Value> {
    let mut req = axum::http::Request::builder().method(method).uri(path);
    let body = match body {
        Some(b) => {
            req = req.header("content-type", "application/json");
            Body::from(b.to_string())
        }
        None => Body::empty(),
    };
    let req = req.body(body).map_err(Problem::internal)?;
    let work = async {
        let res = crate::nodes::request(st, node, req).await?;
        let status = res.status().as_u16();
        let bytes = res.into_body().collect().await.map_err(|e| node_failed(&e.to_string()))?.to_bytes();
        let v: Value = serde_json::from_slice(&bytes).unwrap_or_else(|_| json!({ "text": String::from_utf8_lossy(&bytes) }));
        if status >= 300 {
            let m = v["error"]["message"].as_str().map(String::from).unwrap_or_else(|| format!("the node answered {status}"));
            return Err(node_failed(&m));
        }
        Ok(v)
    };
    tokio::time::timeout(Duration::from_secs(secs), work).await.map_err(|_| node_failed("the node took too long to answer"))?
}

fn node_failed(m: &str) -> Problem {
    Problem::new(502, "node_failed", format!("The node failed: {m}"))
}

async fn steps(st: &State, d: &Deployment, log: &mut Log) -> Step<()> {
    let node = d.node_id.clone().ok_or_else(|| ("deployment_failed", Problem::internal("no node")))?;
    let registry =
        st.registry.clone().ok_or_else(|| ("deployment_failed", unavailable(st).unwrap_or_else(|| Problem::internal("no registry"))))?;
    let (app_id, n) = (d.app_id.clone(), d.version);
    let mut spec = {
        let app_id = app_id.clone();
        let s: Option<String> = st
            .db
            .call(move |c| Ok(c.first("SELECT spec FROM versions WHERE app_id = ? AND n = ?", params![app_id, n], |r| r.get(0))?.flatten()))
            .await
            .map_err(failed("deployment_failed"))?;
        Spec::parse(s.as_deref())
    };
    log.line(format!("deployment {} of v{n} on node {node}", d.id)).await;
    if spec.digest.is_none() {
        if !move_to(st, d, "scheduled", "building").await.map_err(failed("build_failed"))? {
            return Ok(());
        }
        build(st, d, &node, log).await.map_err(failed("build_failed"))?;
        log.line("pushing the image to Brod's registry").await;
        spec = push(st, &registry, d, &node, spec, log).await.map_err(failed("build_failed"))?;
        let _ = node_call(st, &node, Method::DELETE, &format!("/v1/builds/{}", d.id), None, 30).await;
        let (app_id, json, id) = (app_id.clone(), spec.to_json(), d.id.clone());
        st.db
            .call(move |c| {
                c.run("UPDATE versions SET spec = ? WHERE app_id = ? AND n = ?", params![json, app_id, n])?;
                c.run("UPDATE deployments SET built = 1 WHERE id = ?", [&id])?;
                Ok(())
            })
            .await
            .map_err(failed("build_failed"))?;
        if !move_to(st, d, "building", "pulling").await.map_err(failed("deployment_failed"))? {
            return Ok(());
        }
    } else {
        log.line(format!("reusing the image {} of v{n}: no build", spec.digest.as_deref().unwrap_or(""))).await;
        if !move_to(st, d, "scheduled", "pulling").await.map_err(failed("deployment_failed"))? {
            return Ok(());
        }
    }
    let fail = failed("deployment_failed");
    let image = spec.image_id.clone().ok_or_else(|| fail(Problem::internal("the version has no image id")))?;
    pull(st, &registry, &node, &app_id, n, &spec, log).await.map_err(&fail)?;
    if !move_to(st, d, "pulling", "starting").await.map_err(&fail)? {
        return Ok(());
    }
    let name = container_of(&d.id);
    let env = environment(st, &app_id).await.map_err(&fail)?;
    let body = json!({
        "image": image, "env": env, "port": spec.port, "cpu": spec.cpu, "memory_mb": spec.memory_mb,
        "network": network_of(&app_id), "trusted": st.cfg.containers == Containers::Trusted,
        "labels": { "brod.app": app_id, "brod.deployment": d.id, "brod.version": n.to_string() },
    });
    let made = node_call(st, &node, Method::PUT, &format!("/v1/containers/{name}"), Some(body), 120).await.map_err(&fail)?;
    {
        let (id, name) = (d.id.clone(), name.clone());
        st.db.call(move |c| c.run("UPDATE deployments SET container_ref = ? WHERE id = ?", params![name, id])).await.map_err(&fail)?;
    }
    log.line(format!("created the container {name} (user {})", made["user"].as_str().unwrap_or("?"))).await;
    for w in made["warnings"].as_array().into_iter().flatten() {
        log.line(format!("warning: {}", w.as_str().unwrap_or(""))).await;
    }
    node_call(st, &node, Method::POST, &format!("/v1/containers/{name}/start"), None, 60).await.map_err(&fail)?;
    log.line(format!("started; waiting for {} to answer below 500 (up to {HEALTH_SECS} s)", spec.health)).await;
    let h = node_call(
        st,
        &node,
        Method::POST,
        &format!("/v1/containers/{name}/health"),
        Some(json!({ "path": spec.health, "timeout_s": HEALTH_SECS })),
        HEALTH_SECS + 30,
    )
    .await
    .map_err(&fail)?;
    if h["ok"].as_bool() != Some(true) {
        let why = h["error"].as_str().unwrap_or("it did not answer").to_string();
        if let Ok(l) = node_call(st, &node, Method::GET, &format!("/v1/containers/{name}/logs"), None, 30).await {
            log.line("the container's output:").await;
            for line in l["lines"].as_array().into_iter().flatten().rev().take(50).collect::<Vec<_>>().into_iter().rev() {
                log.line(format!("  {}", line["message"].as_str().unwrap_or(""))).await;
            }
        }
        return Err(fail(Problem::new(502, "deployment_failed", format!("The health check failed: {why}"))));
    }
    log.line(format!("healthy: {} answered {}", spec.health, h["status"])).await;
    if !move_to(st, d, "starting", "healthy").await.map_err(&fail)? {
        return Ok(());
    }
    let served = serve(st, d).await.map_err(&fail)?;
    log.line(served).await;
    Ok(())
}

/// Send the build context to the node and follow the build's output.
async fn build(st: &State, d: &Deployment, node: &str, log: &mut Log) -> Result<()> {
    let context: PathBuf = st.cfg.data_dir.join("builds").join(format!("{}.tar", d.id));
    let file = tokio::fs::File::open(&context)
        .await
        .map_err(|e| Problem::new(500, "build_failed", format!("The build context is gone ({e}): Brod restarted? Deploy again.")))?;
    let len = file.metadata().await.map(|m| m.len()).unwrap_or(0);
    let arch = node_arch(st, node).await.unwrap_or_else(|| "amd64".into());
    log.line(format!("building for linux/{arch} ({} KB of context)", len / 1024)).await;
    let req = axum::http::Request::builder()
        .method(Method::POST)
        .uri(format!("/v1/builds/{}?platform=linux%2F{arch}", d.id))
        .header("content-type", "application/x-tar")
        .body(Body::from_stream(tokio_util::io::ReaderStream::new(file)))
        .map_err(Problem::internal)?;
    let res = crate::nodes::request(st, node, req).await?;
    if res.status().as_u16() != 200 {
        let b = res.into_body().collect().await.map(|b| b.to_bytes()).unwrap_or_default();
        let v: Value = serde_json::from_slice(&b).unwrap_or_default();
        return Err(Problem::new(502, "build_failed", v["error"]["message"].as_str().unwrap_or("The node refused the build.").to_string()));
    }
    let mut stream = res.into_body().into_data_stream();
    let mut buf: Vec<u8> = Vec::new();
    let mut done: Option<Value> = None;
    // The node stops a build after 15 minutes; this only guards against a node that goes silent.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(17 * 60);
    loop {
        let next = match tokio::time::timeout_at(deadline, stream.next()).await {
            Ok(n) => n,
            Err(_) => return Err(Problem::new(504, "build_failed", "The build took longer than 15 minutes.")),
        };
        let Some(chunk) = next else { break };
        let chunk =
            chunk.map_err(|e| Problem::new(502, "build_failed", format!("The connection to the node broke during the build: {e}")))?;
        buf.extend_from_slice(&chunk);
        while let Some(i) = buf.iter().position(|b| *b == b'\n') {
            let line: Vec<u8> = buf.drain(..=i).collect();
            let Ok(v) = serde_json::from_slice::<Value>(&line) else { continue };
            if v["done"].as_bool() == Some(true) {
                done = Some(v);
            } else if let Some(l) = v["log"].as_str() {
                log.line(l).await;
            }
        }
    }
    match done {
        Some(v) if v["ok"].as_bool() == Some(true) => Ok(()),
        Some(v) => Err(Problem::new(422, "build_failed", v["error"].as_str().unwrap_or("The image did not build.").to_string())),
        None => Err(Problem::new(502, "build_failed", "The node stopped answering during the build.")),
    }
}

async fn node_arch(st: &State, node: &str) -> Option<String> {
    let node = node.to_string();
    let caps: Option<String> =
        st.db.call(move |c| c.first("SELECT capabilities FROM nodes WHERE id = ?", [&node], |r| r.get(0))).await.ok().flatten();
    caps.and_then(|c| serde_json::from_str::<Value>(&c).ok()).and_then(|v| v["arch"].as_str().map(String::from))
}

/// A file of the build's OCI layout from the node.
async fn oci_file(st: &State, node: &str, id: &str, path: &str) -> Result<axum::http::Response<Body>> {
    let req = axum::http::Request::builder()
        .method(Method::GET)
        .uri(format!("/v1/builds/{id}/oci/{path}"))
        .body(Body::empty())
        .map_err(Problem::internal)?;
    let res = crate::nodes::request(st, node, req).await?;
    if res.status().as_u16() != 200 {
        return Err(Problem::new(502, "build_failed", format!("The node has no {path} for the build.")));
    }
    Ok(res)
}

async fn oci_bytes(st: &State, node: &str, id: &str, path: &str) -> Result<Bytes> {
    let res = oci_file(st, node, id, path).await?;
    Ok(res.into_body().collect().await.map_err(|e| node_failed(&e.to_string()))?.to_bytes())
}

/// The image manifest of an OCI layout's index.json: its digest and media type, following one nested index.
fn manifest_of(index: &Value) -> Option<(String, String)> {
    let m = index["manifests"].as_array()?.first()?;
    Some((m["digest"].as_str()?.to_string(), m["mediaType"].as_str().unwrap_or("application/vnd.oci.image.manifest.v1+json").to_string()))
}

/// Copy the built image from the node into the registry, as apps/<app id>:v<n>. The spec with its digests.
async fn push(st: &State, registry: &Registry, d: &Deployment, node: &str, mut spec: Spec, log: &mut Log) -> Result<Spec> {
    let repo = registry::repository(&d.app_id);
    let index: Value = serde_json::from_slice(&oci_bytes(st, node, &d.id, "index.json").await?).map_err(Problem::internal)?;
    let (mut digest, mut media) = manifest_of(&index).ok_or_else(|| Problem::new(502, "build_failed", "The build produced no image."))?;
    let mut manifest = oci_bytes(st, node, &d.id, &format!("blobs/{}", digest.replace(':', "/"))).await?;
    let mut parsed: Value = serde_json::from_slice(&manifest).map_err(Problem::internal)?;
    if parsed["manifests"].is_array() {
        // An index (several platforms): take its first image.
        (digest, media) = manifest_of(&parsed).ok_or_else(|| Problem::new(502, "build_failed", "The build produced an empty index."))?;
        manifest = oci_bytes(st, node, &d.id, &format!("blobs/{}", digest.replace(':', "/"))).await?;
        parsed = serde_json::from_slice(&manifest).map_err(Problem::internal)?;
    }
    let mut blobs: Vec<(String, u64)> = vec![];
    let desc = |v: &Value| Some((v["digest"].as_str()?.to_string(), v["size"].as_u64().unwrap_or(0)));
    blobs.extend(desc(&parsed["config"]));
    blobs.extend(parsed["layers"].as_array().into_iter().flatten().filter_map(desc));
    let config_digest = blobs.first().map(|b| b.0.clone()).ok_or_else(|| Problem::new(502, "build_failed", "The image has no config."))?;
    let config: Value = serde_json::from_slice(&oci_bytes(st, node, &d.id, &format!("blobs/{}", config_digest.replace(':', "/"))).await?)
        .map_err(Problem::internal)?;
    for (digest, size) in &blobs {
        if registry.has_blob(&st.http, &repo, digest).await? {
            continue;
        }
        let res = oci_file(st, node, &d.id, &format!("blobs/{}", digest.replace(':', "/"))).await?;
        let body = reqwest::Body::wrap_stream(res.into_body().into_data_stream());
        registry.push_blob(&st.http, &repo, digest, body, Some(*size)).await?;
    }
    let tag = format!("v{}", d.version);
    let pushed = registry.put_manifest(&st.http, &repo, &tag, &media, manifest.clone()).await?;
    let digest =
        if pushed.is_empty() { format!("sha256:{}", hex::encode(ring::digest::digest(&ring::digest::SHA256, &manifest))) } else { pushed };
    let size: u64 = blobs.iter().map(|b| b.1).sum();
    log.line(format!("pushed {repo}:{tag} ({digest}, {} MB)", size / 1024 / 1024)).await;
    spec.digest = Some(digest);
    spec.image_id = Some(config_digest);
    spec.platform = Some(format!("{}/{}", config["os"].as_str().unwrap_or("linux"), config["architecture"].as_str().unwrap_or("amd64")));
    Ok(spec)
}

/// One tar header (ustar); names here are short.
fn tar_header(name: &str, size: u64) -> [u8; 512] {
    let mut h = [0u8; 512];
    let put = |h: &mut [u8; 512], s: &[u8], at: usize| h[at..at + s.len()].copy_from_slice(s);
    put(&mut h, name.as_bytes(), 0);
    put(&mut h, b"0000644\0", 100);
    put(&mut h, b"0000000\0", 108);
    put(&mut h, b"0000000\0", 116);
    put(&mut h, format!("{size:011o}\0").as_bytes(), 124);
    put(&mut h, b"00000000000\0", 136);
    h[156] = b'0';
    put(&mut h, b"ustar\0", 257);
    put(&mut h, b"00", 263);
    put(&mut h, b"        ", 148);
    let sum: u32 = h.iter().map(|x| *x as u32).sum();
    put(&mut h, format!("{sum:06o}\0 ").as_bytes(), 148);
    h
}

fn pad(size: u64) -> Bytes {
    Bytes::from(vec![0u8; ((512 - size % 512) % 512) as usize])
}

/// The small files of an image archive `docker load` takes (Docker's manifest.json next to an OCI layout), for a
/// manifest, its config digest and layers.
pub fn load_files(
    manifest_digest: &str,
    media: &str,
    manifest_len: usize,
    config: &str,
    layers: &[String],
    tag: &str,
) -> Vec<(String, Vec<u8>)> {
    let path = |d: &str| format!("blobs/{}", d.replace(':', "/"));
    let docker = json!([{ "Config": path(config), "RepoTags": [tag], "Layers": layers.iter().map(|l| path(l)).collect::<Vec<_>>() }]);
    let index = json!({
        "schemaVersion": 2, "mediaType": "application/vnd.oci.image.index.v1+json",
        "manifests": [{ "mediaType": media, "digest": manifest_digest, "size": manifest_len, "annotations": { "io.containerd.image.name": tag, "org.opencontainers.image.ref.name": tag.rsplit(':').next().unwrap_or("") } }],
    });
    vec![
        ("oci-layout".into(), br#"{"imageLayoutVersion":"1.0.0"}"#.to_vec()),
        ("index.json".into(), index.to_string().into_bytes()),
        ("manifest.json".into(), docker.to_string().into_bytes()),
    ]
}

/// Make sure the node has the image: it loads it from the registry when it does not.
async fn pull(st: &State, registry: &std::sync::Arc<Registry>, node: &str, app_id: &str, n: i64, spec: &Spec, log: &mut Log) -> Result<()> {
    let image = spec.image_id.clone().unwrap_or_default();
    let have = node_call(st, node, Method::GET, &format!("/v1/images/{image}"), None, 30).await?;
    if have["exists"].as_bool() == Some(true) {
        log.line("the node has the image already").await;
        return Ok(());
    }
    let repo = registry::repository(app_id);
    let digest = spec.digest.clone().unwrap_or_default();
    let (media, manifest) = registry
        .manifest(&st.http, &repo, &digest)
        .await?
        .ok_or_else(|| Problem::new(404, "no_image", format!("The registry no longer has {repo}@{digest}.")))?;
    let parsed: Value = serde_json::from_slice(&manifest).map_err(Problem::internal)?;
    let config = parsed["config"]["digest"].as_str().unwrap_or("").to_string();
    let layers: Vec<(String, u64)> = parsed["layers"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|l| Some((l["digest"].as_str()?.to_string(), l["size"].as_u64()?)))
        .collect();
    let tag = format!("{}-apps/{}:v{n}", prefix(), app_id.replace('_', "-"));
    let names: Vec<String> = layers.iter().map(|l| l.0.clone()).collect();
    let small = load_files(&digest, &media, manifest.len(), &config, &names, &tag);
    let config_len = parsed["config"]["size"].as_u64().unwrap_or(0);
    log.line(format!("sending the image to the node ({} MB)", layers.iter().map(|l| l.1).sum::<u64>() / 1024 / 1024)).await;
    // The archive is streamed: the small files, the manifest, then each blob straight from the registry.
    let (tx, rx) = tokio::sync::mpsc::channel::<std::result::Result<Bytes, std::io::Error>>(8);
    let (http, reg, repo2) = (st.http.clone(), registry.clone(), repo.clone());
    let manifest_path = format!("blobs/{}", digest.replace(':', "/"));
    let mut blobs: Vec<(String, u64)> = vec![(config.clone(), config_len)];
    blobs.extend(layers.clone());
    tokio::spawn(async move {
        let send = |b: Bytes| {
            let tx = tx.clone();
            async move { tx.send(Ok(b)).await.is_ok() }
        };
        for (name, bytes) in &small {
            if !send(Bytes::copy_from_slice(&tar_header(name, bytes.len() as u64))).await
                || !send(Bytes::from(bytes.clone())).await
                || !send(pad(bytes.len() as u64)).await
            {
                return;
            }
        }
        if !send(Bytes::copy_from_slice(&tar_header(&manifest_path, manifest.len() as u64))).await
            || !send(manifest.clone()).await
            || !send(pad(manifest.len() as u64)).await
        {
            return;
        }
        let mut seen = std::collections::HashSet::new();
        for (digest, size) in blobs {
            if !seen.insert(digest.clone()) {
                continue;
            }
            let res = match reg.blob(&http, &repo2, &digest).await {
                Ok(r) => r,
                Err(e) => {
                    let _ = tx.send(Err(std::io::Error::other(e.message))).await;
                    return;
                }
            };
            if !send(Bytes::copy_from_slice(&tar_header(&format!("blobs/{}", digest.replace(':', "/")), size))).await {
                return;
            }
            let mut s = res.bytes_stream();
            while let Some(chunk) = s.next().await {
                match chunk {
                    Ok(c) => {
                        if !send(c).await {
                            return;
                        }
                    }
                    Err(e) => {
                        let _ = tx.send(Err(std::io::Error::other(e))).await;
                        return;
                    }
                }
            }
            if !send(pad(size)).await {
                return;
            }
        }
        let _ = send(Bytes::from(vec![0u8; 1024])).await;
    });
    let stream = futures_util::stream::unfold(rx, |mut rx| async move { rx.recv().await.map(|x| (x, rx)) });
    let req = axum::http::Request::builder()
        .method(Method::POST)
        .uri("/v1/images/load")
        .header("content-type", "application/x-tar")
        .body(Body::from_stream(stream))
        .map_err(Problem::internal)?;
    let work = async {
        let res = crate::nodes::request(st, node, req).await?;
        let b = res.into_body().collect().await.map_err(|e| node_failed(&e.to_string()))?.to_bytes();
        Ok::<Value, Problem>(serde_json::from_slice(&b).unwrap_or_default())
    };
    let v = tokio::time::timeout(Duration::from_secs(1800), work).await.map_err(|_| node_failed("loading the image took too long"))??;
    if v["ok"].as_bool() != Some(true) {
        return Err(Problem::new(
            502,
            "deployment_failed",
            format!("The node could not load the image: {}", v["message"].as_str().unwrap_or("?")),
        ));
    }
    log.line(format!("the node loaded the image ({tag})")).await;
    Ok(())
}

/// What the container gets in its environment: Brod's identity settings and the app's secrets.
async fn environment(st: &State, app_id: &str) -> Result<Map<String, Value>> {
    let (key, id) = (st.cfg.secrets_key.clone(), app_id.to_string());
    let secrets = st.db.call(move |c| crate::secrets::read_all(c, &key, &id)).await?;
    let mut env: Map<String, Value> = secrets.into_iter().map(|(k, v)| (k, json!(v))).collect();
    // Secret names starting with BROD_ are reserved (secrets.rs), so these are never shadowed.
    env.insert("BROD_ISSUER".into(), json!(st.cfg.api_origin));
    env.insert("BROD_APP_ID".into(), json!(app_id));
    env.insert("BROD_IDENTITY_JWKS".into(), json!(st.cfg.identity_key.jwks().to_string()));
    Ok(env)
}

/// Move the app's pointer to a healthy deployment's version, unless a newer deployment got there first.
async fn serve(st: &State, d: &Deployment) -> Result<String> {
    let d = d.clone();
    st.db
        .call(move |c| {
            tx(c, |x| {
                let app = x.first("SELECT * FROM apps WHERE id = ?", [&d.app_id], AppRow::from_row)?;
                let newer = x.count(
                    "SELECT COUNT(*) FROM deployments WHERE app_id = ? AND environment = ? AND state = 'serving' AND created_at > ?",
                    params![d.app_id, d.environment, d.created_at],
                )?;
                let Some(app) = app.filter(|_| newer == 0) else {
                    transition(x, &d.id, "healthy", "stopped")?;
                    return Ok("a newer deployment is serving already: this one stops".to_string());
                };
                let column = if d.environment == "live" { "live_version" } else { "staging_version" };
                x.run(&format!("UPDATE apps SET {column} = ? WHERE id = ?"), params![d.version, app.id])?;
                if !transition(x, &d.id, "healthy", "serving")? {
                    return Err(Problem::new(409, "deployment_failed", "The deployment was stopped before it could serve."));
                }
                // The deployment serving before drains; the reconciler stops it.
                x.run(
                    "UPDATE deployments SET state = 'draining', updated_at = ? WHERE app_id = ? AND environment = ? AND state = 'serving' AND id <> ?",
                    params![now(), d.app_id, d.environment, d.id],
                )?;
                let to = if d.environment == "live" { "" } else { " on staging" };
                event(x, &app.workspace_id, &d.actor, Some(&app.id), "deployed", &format!("v{} is serving{to} (container on {})", d.version, d.node_id.as_deref().unwrap_or("?")))?;
                Ok(format!("serving: v{} is {}", d.version, if d.environment == "live" { "live" } else { "on staging" }))
            })
        })
        .await
}

// ---------- reading deployments ----------

/// get_deployment: one deployment of an app (the newest when no id is given). A failed one is a problem
/// (build_failed or deployment_failed) carrying the last 50 lines of its log.
pub fn get_deployment(conn: &Connection, c: &Caller, slug: &str, id: Option<&str>) -> Result<Value> {
    require_role(c, "builder", "see app deployments")?;
    let app = control::get_app(conn, c, slug)?;
    let d = match id.filter(|i| !i.is_empty()) {
        Some(id) => conn.first("SELECT * FROM deployments WHERE id = ? AND app_id = ?", params![id, app.id], Deployment::from_row)?,
        None => {
            conn.first("SELECT * FROM deployments WHERE app_id = ? ORDER BY created_at DESC LIMIT 1", [&app.id], Deployment::from_row)?
        }
    };
    let d = d.ok_or_else(|| Problem::new(404, "not_found", format!("{} has no such deployment.", app.slug)))?;
    if d.state == "failed" {
        let code = d.error_code.clone().unwrap_or_else(|| "deployment_failed".into());
        let what = if code == "build_failed" { "did not build" } else { "did not start" };
        let live = app.live_version.map(|v| format!("v{v} is still live")).unwrap_or_else(|| "nothing is live".into());
        return Err(Problem::new(
            422,
            &code,
            format!(
                "v{} {what}: {} Nothing changed for visitors ({live}). Fix the cause the log shows and deploy again.",
                d.version,
                d.error.clone().unwrap_or_default()
            ),
        )
        .with("deployment", d.view(0))
        .with("log", json!(d.tail(50))));
    }
    let mut v = d.view(50);
    v["app"] = json!(app.slug);
    v["next_step"] = json!(match d.state.as_str() {
        s if IN_PROGRESS.contains(&s) => "Still going: call get_deployment again in 10-20 s.".to_string(),
        "serving" => format!("v{} is serving.", d.version),
        _ => format!("This deployment is {}: another one replaced it.", d.state),
    });
    Ok(v)
}

/// The app's recent deployments, for get_status.
pub fn recent(conn: &Connection, app_id: &str) -> Result<Value> {
    let list = conn.all("SELECT * FROM deployments WHERE app_id = ? ORDER BY created_at DESC LIMIT 10", [app_id], |r| {
        let d = Deployment::from_row(r)?;
        Ok(json!({ "id": d.id, "version": d.version, "environment": if d.environment == "live" { "production" } else { "staging" },
            "state": d.state, "node": d.node_id, "error": d.error, "at": iso(d.created_at), "ready_at": d.ready_at.map(iso) }))
    })?;
    Ok(Value::Array(list))
}

// ---------- rollback ----------

/// rollback: to a container version through a new deployment (rollback_container), else by moving the pointer.
pub async fn rollback(st: &State, c: &Caller, slug: &str, version: Option<f64>) -> Result<Value> {
    let n = version.filter(|v| v.fract() == 0.0).map(|v| v as i64);
    let (c2, slug2) = (c.clone(), slug.to_string());
    let container = match n {
        Some(n) => {
            st.db
                .call(move |conn| {
                    let app = control::get_app(conn, &c2, &slug2)?;
                    Ok(app.live_version != Some(n) && runtime_of(conn, &app.id, n)?.as_deref() == Some("container"))
                })
                .await?
        }
        None => false,
    };
    match n {
        Some(n) if container => rollback_container(st, c, slug, n).await,
        _ => {
            let (c, slug, cfg) = (c.clone(), slug.to_string(), st.cfg.clone());
            st.db.call(move |conn| control::rollback(conn, &cfg, &c, &slug, version)).await
        }
    }
}

/// Roll back to a container version: a new deployment of its image, no build. The pointer moves once it is healthy.
pub async fn rollback_container(st: &State, c: &Caller, slug: &str, n: i64) -> Result<Value> {
    if let Some(p) = unavailable(st) {
        return Err(p);
    }
    let connected = st.nodes.connected_ids();
    let (c2, slug2, cfg) = (c.clone(), slug.to_string(), st.cfg.clone());
    let (d, mut m) = st
        .db
        .call(move |conn| {
            require_role(&c2, "builder", "roll back apps")?;
            let app = control::get_app(conn, &c2, &slug2)?;
            if app.live_version == Some(n) {
                return Err(Problem::new(400, "already_live", format!("v{n} is already live.")));
            }
            let d = redeploy(conn, &connected, &app, n, "live", &c2.actor)?;
            event(
                conn,
                &c2.workspace.id,
                &c2.actor,
                Some(&app.id),
                "rollback",
                &format!("to v{n} (container: reusing its image, no build)"),
            )?;
            let mut m = control::described(conn, &cfg, &c2, &app)?;
            m.insert("version".into(), json!(n));
            Ok((d, m))
        })
        .await?;
    start(st, &d.id);
    m.insert("kind".into(), json!("container"));
    m.insert("deployment".into(), json!({ "id": d.id, "state": d.state, "node": d.node_id }));
    m.insert(
        "next_step".into(),
        json!(format!(
            "v{n} is starting again from its stored image (no rebuild); what is live keeps serving until it is healthy. Call get_deployment with \"deployment\": \"{}\" until it is \"serving\".",
            d.id
        )),
    );
    Ok(Value::Object(m))
}

/// The runtime of an app's version: "container" or "auto".
pub fn runtime_of(conn: &Connection, app_id: &str, n: i64) -> Result<Option<String>> {
    conn.first("SELECT runtime FROM versions WHERE app_id = ? AND n = ?", params![app_id, n], |r| r.get(0))
}

// ---------- serving requests ----------

/// Hand a request to the container serving a version, over its node's tunnel, with the same header rules as server
/// code (runtime.rs): the client's x-brod-* headers and Brod's session cookie are dropped, and who is signed in added.
pub async fn dispatch(
    st: &State,
    mut req: Req,
    app: &AppRow,
    origin: &str,
    version: i64,
    serving: Option<(String, String)>,
    identity: Option<(Value, String)>,
) -> Result<Response> {
    let Some((node, container)) = serving else {
        return Ok(notice(
            503,
            "Starting",
            "This app's container is not running yet. Try again in a moment; if it stays like this, its owner can see why in get_status.",
            "",
        ));
    };
    if !st.nodes.connected(&node) {
        return Ok(notice(
            503,
            "This app is offline",
            "The machine that runs this app is not connected to Brod right now. Try again in a minute.",
            "",
        ));
    }
    if let Some(len) = req.header("content-length").and_then(|l| l.parse::<usize>().ok())
        && len > REQUEST_BYTES
    {
        return Ok(notice(413, "Too large", "The request is larger than this app accepts.", ""));
    }
    let mut headers = crate::runtime::forward_headers(&req, identity);
    let host = origin.split("://").nth(1).unwrap_or(origin).to_string();
    let proto = if origin.starts_with("https://") { "https" } else { "http" };
    for (k, v) in [("x-forwarded-host", host), ("x-forwarded-proto", proto.to_string())] {
        if let Ok(v) = axum::http::HeaderValue::try_from(v) {
            headers.insert(k, v);
        }
    }
    if let Some(peer) = req.peer
        && let Ok(v) = axum::http::HeaderValue::try_from(peer.to_string())
    {
        headers.insert("x-forwarded-for", v);
    }
    let path = if req.query.is_empty() { req.path.clone() } else { format!("{}?{}", req.path, req.query) };
    let has_body = req.method != Method::GET && req.method != Method::HEAD;
    let body = if has_body {
        Body::new(http_body_util::Limited::new(req.take_body(), REQUEST_BYTES).map_err(std::io::Error::other))
    } else {
        Body::empty()
    };
    let mut out = axum::http::Request::builder().method(req.method.clone()).uri(format!("/v1/proxy/{container}{path}"));
    if let Some(h) = out.headers_mut() {
        *h = headers;
    }
    let out = out.body(body).map_err(Problem::internal)?;
    let res = match tokio::time::timeout(Duration::from_secs(REQUEST_SECS), crate::nodes::request(st, &node, out)).await {
        Ok(Ok(r)) => r,
        Ok(Err(e)) => {
            tracing::warn!(app = %app.slug, "container request failed: {}", e.message);
            return Ok(notice(503, "This app is offline", "The machine that runs this app did not answer. Try again in a minute.", ""));
        }
        Err(_) => return Ok(notice(504, "This app is slow", "The app took too long to answer.", "")),
    };
    if res.headers().contains_key("x-brod-node-error") {
        return Ok(notice(502, "This app failed", "The app's container did not answer. Its owner can see why in the app's logs.", ""));
    }
    let status = res.status().as_u16();
    let (h, html) = crate::runtime::answer_headers(app, version, res.headers());
    let pairs: Vec<(&str, String)> = h.iter().map(|(k, v)| (k.as_str(), v.clone())).collect();
    if req.method == Method::HEAD {
        return Ok(response(status, Body::empty(), &pairs));
    }
    if app.access == "public" && html && st.cfg.abuse_checks {
        let page = crate::http::read_capped(res.into_body(), crate::tar::FILE_BYTES * 2, "The page").await?;
        return Ok(response(status, crate::http::bytes_body(crate::gateway::append_to_body(&page, crate::gateway::REPORT_LINK)), &pairs));
    }
    Ok(response(status, res.into_body(), &pairs))
}

// ---------- the reconciler ----------

/// Brod restarted: what was in progress cannot continue (its build context and step are gone).
pub async fn recover(st: &State) -> Result<()> {
    st.db
        .call(|c| {
            let states = IN_PROGRESS.map(|s| format!("'{s}'")).join(",");
            c.run(
                &format!(
                    "UPDATE deployments SET state = 'failed', error_code = 'deployment_failed', error = 'Brod restarted during this deployment. Deploy again.', updated_at = ?, stopped_at = ? WHERE state IN ({states})"
                ),
                params![now(), now()],
            )?;
            Ok(())
        })
        .await?;
    let _ = tokio::fs::remove_dir_all(st.cfg.data_dir.join("builds")).await;
    Ok(())
}

/// Keep deployments in step with the apps' pointers, every few seconds: a serving deployment whose version is no
/// longer pointed to (rollback, publish, discard, a newer deploy) drains; drained ones stop; old stopped containers go;
/// serving containers' output goes to the app's logs.
pub async fn reconcile(st: &State) -> Result<()> {
    let rows = st
        .db
        .call(|c| {
            c.all(
                "SELECT d.*, a.live_version AS live, a.staging_version AS staging, a.id AS still FROM deployments d LEFT JOIN apps a ON a.id = d.app_id
                 WHERE d.state IN ('serving','draining') OR (d.state IN ('stopped','failed') AND d.removed_at IS NULL AND d.container_ref IS NOT NULL)",
                (),
                |r| Ok((Deployment::from_row(r)?, r.get::<_, Option<i64>>("live")?, r.get::<_, Option<i64>>("staging")?, r.get::<_, Option<String>>("still")?)),
            )
        })
        .await?;
    let t = now();
    let mut stopped: HashMap<String, Vec<Deployment>> = HashMap::new();
    for (d, live, staging, still) in rows {
        match d.state.as_str() {
            "serving" => {
                let want = if still.is_none() {
                    None
                } else if live == Some(d.version) {
                    Some("live")
                } else if staging == Some(d.version) {
                    Some("staging")
                } else {
                    None
                };
                let id = d.id.clone();
                match want {
                    Some(env) if env != d.environment => {
                        let env = env.to_string();
                        st.db
                            .call(move |c| {
                                c.run("UPDATE deployments SET environment = ?, updated_at = ? WHERE id = ?", params![env, now(), id])
                            })
                            .await?;
                    }
                    Some(_) => pump_logs(st, &d).await,
                    None => {
                        st.db.call(move |c| transition(c, &id, "serving", "draining")).await?;
                    }
                }
            }
            "draining" if d.updated_at < t - DRAIN_MS => {
                if let Some(node) = &d.node_id {
                    pump_logs(st, &d).await;
                    let r = node_call(st, node, Method::POST, &format!("/v1/containers/{}/stop", container_of(&d.id)), None, 30).await;
                    if let Err(e) = r
                        && st.nodes.connected(node)
                    {
                        tracing::warn!(deployment = %d.id, "could not stop a container: {}", e.message);
                        continue;
                    }
                }
                let id = d.id.clone();
                st.db.call(move |c| transition(c, &id, "draining", "stopped")).await?;
            }
            "stopped" | "failed" => stopped.entry(d.app_id.clone()).or_default().push(d),
            _ => {}
        }
    }
    // Stopped containers: an app's last KEEP_STOPPED_VERSIONS versions stay for a day; the rest go.
    for (_, mut list) in stopped {
        list.sort_by(|a, b| b.version.cmp(&a.version).then(b.created_at.cmp(&a.created_at)));
        let mut versions: Vec<i64> = vec![];
        for d in list {
            if !versions.contains(&d.version) {
                versions.push(d.version);
            }
            let keep = d.state == "stopped" && versions.len() <= KEEP_STOPPED_VERSIONS && d.stopped_at.unwrap_or(t) > t - KEEP_STOPPED_MS;
            if keep {
                continue;
            }
            let Some(node) = &d.node_id else { continue };
            if !st.nodes.connected(node) {
                continue;
            }
            if node_call(st, node, Method::DELETE, &format!("/v1/containers/{}", container_of(&d.id)), None, 60).await.is_ok() {
                let id = d.id.clone();
                st.db.call(move |c| c.run("UPDATE deployments SET removed_at = ? WHERE id = ?", params![now(), id])).await?;
            }
        }
    }
    Ok(())
}

/// Bring a serving container's new output into the app's logs.
async fn pump_logs(st: &State, d: &Deployment) {
    let Some(node) = &d.node_id else { return };
    if !st.nodes.connected(node) {
        return;
    }
    let since = d.log_cursor.as_deref().map(|c| format!("?since={c}")).unwrap_or_default();
    let Ok(v) = node_call(st, node, Method::GET, &format!("/v1/containers/{}/logs{since}", container_of(&d.id)), None, 20).await else {
        return;
    };
    let lines: Vec<Value> = v["lines"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|l| json!({ "level": if l["stream"] == "stderr" { "error" } else { "info" }, "message": js_slice(l["message"].as_str().unwrap_or(""), 2000) }))
        .collect();
    let Some(cursor) = v["cursor"].as_str().map(String::from) else { return };
    if lines.is_empty() && d.log_cursor.as_deref() == Some(cursor.as_str()) {
        return;
    }
    let (id, app, version) = (d.id.clone(), d.app_id.clone(), d.version);
    let r = st
        .db
        .call(move |c| {
            tx(c, |x| {
                for chunk in lines.chunks(200) {
                    x.run(
                        "INSERT INTO app_logs (app_id, at, version, method, path, status, outcome, logs, exceptions) VALUES (?,?,?,'CONTAINER','',NULL,'output',?,'[]')",
                        params![app, now(), version, Value::Array(chunk.to_vec()).to_string()],
                    )?;
                }
                x.run("UPDATE deployments SET log_cursor = ? WHERE id = ?", params![cursor, id])?;
                Ok(())
            })
        })
        .await;
    if let Err(e) = r {
        tracing::warn!("could not save a container's output: {}", e.message);
    }
}

/// Registry retention, nightly: every app keeps the images of its live and staging versions and of its newest
/// KEEP_IMAGES container versions. Older manifests are deleted (and their versions marked pruned); the registry's own
/// garbage collection (`registry garbage-collect`, see docs/self-hosting.md) then frees their layers.
pub async fn prune_images(st: &State) -> Result<usize> {
    let Some(registry) = st.registry.clone() else { return Ok(0) };
    let rows = st
        .db
        .call(|c| {
            c.all(
                "SELECT v.app_id, v.n, v.spec, a.live_version, a.staging_version FROM versions v JOIN apps a ON a.id = v.app_id WHERE v.runtime = 'container' ORDER BY v.app_id, v.n DESC",
                (),
                |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?, r.get::<_, Option<String>>(2)?, r.get::<_, Option<i64>>(3)?, r.get::<_, Option<i64>>(4)?)),
            )
        })
        .await?;
    let mut seen: HashMap<String, usize> = HashMap::new();
    let mut pruned = 0;
    for (app_id, n, spec, live, staging) in rows {
        let mut spec = Spec::parse(spec.as_deref());
        let Some(digest) = spec.digest.clone().filter(|_| !spec.pruned) else { continue };
        let rank = seen.entry(app_id.clone()).or_default();
        *rank += 1;
        if *rank <= KEEP_IMAGES || live == Some(n) || staging == Some(n) {
            continue;
        }
        // A version still running somewhere keeps its image.
        let (a, running) = (app_id.clone(), {
            let a = app_id.clone();
            st.db
                .call(move |c| c.count("SELECT COUNT(*) FROM deployments WHERE app_id = ? AND version = ? AND state IN ('scheduled','building','pulling','starting','healthy','serving','draining')", params![a, n]))
                .await?
        });
        if running > 0 {
            continue;
        }
        registry.delete_manifest(&st.http, &registry::repository(&a), &digest).await?;
        spec.pruned = true;
        let json = spec.to_json();
        st.db.call(move |c| c.run("UPDATE versions SET spec = ? WHERE app_id = ? AND n = ?", params![json, a, n])).await?;
        pruned += 1;
    }
    Ok(pruned)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn states_only_move_forward() {
        let path = ["scheduled", "building", "pulling", "starting", "healthy", "serving", "draining", "stopped"];
        for w in path.windows(2) {
            assert!(allowed(w[0], w[1]), "{} -> {}", w[0], w[1]);
        }
        assert!(allowed("scheduled", "pulling"), "a rollback skips the build");
        for s in IN_PROGRESS {
            assert!(allowed(s, "failed"), "{s} can fail");
        }
        for (from, to) in [
            ("serving", "failed"),
            ("failed", "serving"),
            ("stopped", "serving"),
            ("building", "serving"),
            ("serving", "building"),
            ("draining", "serving"),
        ] {
            assert!(!allowed(from, to), "{from} -> {to}");
        }
        assert!(allowed("healthy", "stopped"), "superseded before serving");
    }

    #[tokio::test]
    async fn transitions_need_the_expected_state() {
        crate::db::test_db()
            .call(|db| {
                check_transitions(db);
                Ok(())
            })
            .await
            .unwrap();
    }

    fn check_transitions(db: &Connection) {
        db.run(
            "INSERT INTO deployments (id, app_id, version, environment, state, created_at, updated_at) VALUES ('d1','a',1,'live','scheduled',1,1)",
            (),
        )
        .unwrap();
        assert!(transition(db, "d1", "scheduled", "building").unwrap());
        assert!(!transition(db, "d1", "scheduled", "building").unwrap(), "only from the state it is in");
        assert!(transition(db, "d1", "building", "failed").unwrap());
        assert!(transition(db, "d1", "failed", "serving").is_err(), "never out of failed");
        for s in ["pulling", "starting", "healthy"] {
            db.run("UPDATE deployments SET state = ? WHERE id = 'd1'", [s]).unwrap();
            assert!(transition(db, "d1", s, "failed").unwrap());
        }
        db.run("UPDATE deployments SET state = 'healthy' WHERE id = 'd1'", ()).unwrap();
        assert!(transition(db, "d1", "healthy", "serving").unwrap());
        let d = get(db, "d1").unwrap().unwrap();
        assert!(d.ready_at.is_some() && d.stopped_at.is_none());
    }

    #[test]
    fn image_archives_carry_dockers_manifest() {
        let files = load_files(
            "sha256:m",
            "application/vnd.oci.image.manifest.v1+json",
            400,
            "sha256:c",
            &["sha256:l1".into()],
            "brod-apps/app-x:v3",
        );
        let names: Vec<&str> = files.iter().map(|f| f.0.as_str()).collect();
        assert_eq!(names, ["oci-layout", "index.json", "manifest.json"]);
        let m: Value = serde_json::from_slice(&files[2].1).unwrap();
        assert_eq!(m[0]["Config"], "blobs/sha256/c");
        assert_eq!(m[0]["Layers"], json!(["blobs/sha256/l1"]));
        assert_eq!(m[0]["RepoTags"], json!(["brod-apps/app-x:v3"]));
        let h = tar_header("blobs/sha256/c", 1000);
        assert_eq!(&h[124..135], b"00000001750");
        assert_eq!(pad(1000).len(), 24);
        assert_eq!(pad(1024).len(), 0);
        assert!(container_of("dep_ab").ends_with("-dep-ab") && network_of("app_1").ends_with("-app-app-1"));
    }
}
