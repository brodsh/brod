// SPDX-License-Identifier: AGPL-3.0-only
// Managed Postgres for container apps (plan D5). Apps' databases live in apps-postgres, a Postgres server of its own
// (never Brod's database) that only Brod reaches, as an admin (BROD_APPS_DATABASE_URL). Without it, request_database
// answers database_unavailable.
//
// request_database gives an app one database, idempotently: a role and a database both named after the app's id
// (app_<hex>), the role a plain login (no superuser, createdb, createrole, replication or inherit; 20 connections at
// most) with a random password (SCRAM), the database owned by it. PUBLIC loses CONNECT on every app database (and on
// postgres and template1) and CREATE on the public schema, so one app's role cannot even connect to another's database.
// The password is kept as the app's secret DATABASE_URL (postgres://<role>:<password>@brod-db.internal:5432/<db>), which
// Brod manages: set_secret refuses to change it while the database exists. An app that sets DATABASE_URL itself
// (an external database) cannot also have a managed one.
//
// Containers reach it at brod-db.internal:5432. Nodes never have network access to Postgres: the node listens on the
// app's bridge only (node/src/db.rs) and announces each connection on its accept stream (GET /v1/db/accept, kept open
// here for as long as the tunnel lasts); Brod takes it with a full-duplex POST /v1/db/conns/<id> stream through the
// tunnel and pipes it to apps-postgres. Before piping, Brod reads the Postgres startup packet and lets it through only
// when the app whose listener accepted it has a managed database and a deployment on that node, and the packet names
// exactly that app's role and database; anything else gets a Postgres error and is closed. Postgres then checks the
// password as usual. backups.rs dumps, restores and drills the databases.
use std::collections::HashMap;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use axum::body::Body;
use bytes::Bytes;
use futures_util::StreamExt;
use http_body_util::StreamBody;
use hyper::body::Frame;
use serde_json::{Map, Value, json};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;

use crate::config::Config;
use crate::control;
use crate::db::{Connection, Sql, event, params, tx};
use crate::model::Caller;
use crate::people::require_role;
use crate::problem::{Problem, Result};
use crate::state::State;
use crate::util::{iso, now, random_id};

/// The name containers reach their database by, and its port.
pub const HOST: &str = "brod-db.internal";
pub const PORT: u16 = 5432;
/// Connections one app's role may hold at once.
const CONNECTION_LIMIT: u32 = 20;
/// The secret that carries the connection URL.
pub const SECRET: &str = "DATABASE_URL";
/// How long a database replaced by a restore is kept, and how long a restore or drill's scratch database may linger.
pub const KEEP_REPLACED_MS: i64 = 24 * 3600 * 1000;
const STALE_SCRATCH_MS: i64 = 6 * 3600 * 1000;

pub fn unavailable() -> Problem {
    Problem::new(
        503,
        "database_unavailable",
        "Managed databases are not set up on this Brod (BROD_APPS_DATABASE_URL). Use an external database instead: set its URL as the secret DATABASE_URL.",
    )
}

// ---------- names ----------

/// The database and role name of an app: its id, "app_" and lowercase hex. Anything else is refused, so the identifiers
/// built from it are plain even before quoting, and an app id can never smuggle SQL in.
pub fn name_of(app_id: &str) -> Result<String> {
    let ok = app_id.len() <= 44
        && app_id
            .strip_prefix("app_")
            .is_some_and(|h| !h.is_empty() && h.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)));
    if !ok {
        return Err(Problem::internal(format!("not an app id a database can be named after: {app_id:?}")));
    }
    Ok(app_id.to_string())
}

/// A quoted SQL identifier.
pub fn ident(s: &str) -> String {
    format!("\"{}\"", s.replace('\0', "").replace('"', "\"\""))
}

/// A quoted SQL string literal (standard_conforming_strings is on: backslashes are plain characters).
pub fn literal(s: &str) -> String {
    format!("'{}'", s.replace('\0', "").replace('\'', "''"))
}

/// What a scratch or replaced database left behind by backups.rs is: the app database it belongs to, its kind
/// ("before", "restore" or "drill") and when it was made (ms).
pub fn leftover(name: &str) -> Option<(&str, &str, i64)> {
    for kind in ["before", "restore", "drill"] {
        let marker = format!("_{kind}_");
        if let Some(i) = name.find(&marker) {
            let (base, ts) = (&name[..i], &name[i + marker.len()..]);
            if name_of(base).is_ok() && !ts.is_empty() && ts.len() <= 16 && ts.bytes().all(|b| b.is_ascii_digit()) {
                return Some((base, kind, ts.parse().ok()?));
            }
        }
    }
    None
}

/// Whether a leftover database should go: a replaced one after a day, scratch ones after six hours.
pub fn expired(kind: &str, made: i64, t: i64) -> bool {
    match kind {
        "before" => made < t - KEEP_REPLACED_MS,
        _ => made < t - STALE_SCRATCH_MS,
    }
}

/// The URL the app's containers get as DATABASE_URL.
pub fn url_for(name: &str, password: &str) -> String {
    format!("postgres://{name}:{password}@{HOST}:{PORT}/{name}?sslmode=disable")
}

// ---------- the admin connection ----------

/// The admin connection's settings, for `dbname` (default: the URL's).
pub fn admin_config(cfg: &Config, dbname: Option<&str>) -> Result<postgres::Config> {
    let a = cfg.apps_db.as_ref().ok_or_else(unavailable)?;
    let mut c: postgres::Config = a.url.parse().map_err(Problem::internal)?;
    if c.get_password().is_none()
        && let Some(p) = &a.password
    {
        c.password(p);
    }
    if let Some(d) = dbname {
        c.dbname(d);
    }
    c.connect_timeout(Duration::from_secs(10));
    c.application_name("brod");
    Ok(c)
}

/// Connect as the admin. Only on a blocking thread.
pub fn connect(c: &postgres::Config) -> Result<postgres::Client> {
    c.connect(postgres::NoTls).map_err(|e| {
        tracing::error!("apps-postgres: {e}");
        Problem::new(503, "database_unavailable", "The apps' database server is not reachable right now. Try again shortly.")
    })
}

/// Run blocking work (the Postgres client, pg_dump) off the async threads.
pub async fn blocking<T: Send + 'static>(f: impl FnOnce() -> Result<T> + Send + 'static) -> Result<T> {
    tokio::task::spawn_blocking(f).await.map_err(Problem::internal)?
}

pub fn pg_error(e: postgres::Error) -> Problem {
    Problem::internal(format!("apps-postgres: {e}"))
}

/// Create (or bring back in line) the app's role and database. Safe to repeat: an existing role gets the new password.
fn provision(admin: &postgres::Config, name: &str, password: &str) -> Result<()> {
    let mut c = connect(admin)?;
    let role = ident(name);
    let exists = c.query_opt("SELECT 1 FROM pg_roles WHERE rolname = $1", &[&name]).map_err(pg_error)?.is_some();
    let options = format!(
        "LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS CONNECTION LIMIT {CONNECTION_LIMIT} PASSWORD {}",
        literal(password)
    );
    let verb = if exists { "ALTER" } else { "CREATE" };
    c.batch_execute(&format!("SET password_encryption = 'scram-sha-256'; {verb} ROLE {role} WITH {options}")).map_err(pg_error)?;
    if c.query_opt("SELECT 1 FROM pg_database WHERE datname = $1", &[&name]).map_err(pg_error)?.is_none() {
        c.batch_execute(&format!("CREATE DATABASE {role} OWNER {role}")).map_err(pg_error)?;
    }
    c.batch_execute(&format!("REVOKE ALL ON DATABASE {role} FROM PUBLIC; GRANT CONNECT, TEMPORARY ON DATABASE {role} TO {role}"))
        .map_err(pg_error)?;
    lock_down(&mut c)?;
    drop(c);
    let mut d = connect(&{
        let mut x = admin.clone();
        x.dbname(name);
        x
    })?;
    d.batch_execute(&format!("REVOKE CREATE ON SCHEMA public FROM PUBLIC; ALTER SCHEMA public OWNER TO {role}")).map_err(pg_error)?;
    Ok(())
}

/// PUBLIC may connect to no database on the server: every role reaches only what it owns or was granted.
pub fn lock_down(c: &mut postgres::Client) -> Result<()> {
    let names: Vec<String> =
        c.query("SELECT datname FROM pg_database WHERE datallowconn", &[]).map_err(pg_error)?.iter().map(|r| r.get(0)).collect();
    let sql: String = names.iter().map(|n| format!("REVOKE CONNECT, TEMPORARY ON DATABASE {} FROM PUBLIC;", ident(n))).collect();
    c.batch_execute(&sql).map_err(pg_error)
}

/// Drop the app's database and role (deleting the app; its final backup is taken first, in backups.rs).
pub fn drop_all(admin: &postgres::Config, name: &str) -> Result<()> {
    let mut c = connect(admin)?;
    let n = ident(name);
    c.batch_execute(&format!("DROP DATABASE IF EXISTS {n} WITH (FORCE)")).map_err(pg_error)?;
    let leftovers: Vec<String> = c
        .query("SELECT datname FROM pg_database WHERE datname LIKE $1", &[&format!("{name}\\_%")])
        .map_err(pg_error)?
        .iter()
        .map(|r| r.get(0))
        .filter(|d: &String| leftover(d).is_some_and(|(base, _, _)| base == name))
        .collect();
    for d in leftovers {
        c.batch_execute(&format!("DROP DATABASE IF EXISTS {} WITH (FORCE)", ident(&d))).map_err(pg_error)?;
    }
    c.batch_execute(&format!("DROP ROLE IF EXISTS {n}")).map_err(pg_error)?;
    Ok(())
}

// ---------- rows ----------

#[derive(Clone, Debug)]
pub struct Database {
    pub id: String,
    pub app_id: String,
    pub name: String,
    pub role: String,
    pub created_at: i64,
    pub bytes: Option<i64>,
    pub measured_at: Option<i64>,
    pub drilled_at: Option<i64>,
}

const COLUMNS: &str = "id, app_id, name, role, created_at, bytes, measured_at, drilled_at";

fn from_row(r: &crate::db::Row) -> Result<Database> {
    Ok(Database {
        id: r.get("id")?,
        app_id: r.get("app_id")?,
        name: r.get("name")?,
        role: r.get("role")?,
        created_at: r.get("created_at")?,
        bytes: r.get("bytes")?,
        measured_at: r.get("measured_at")?,
        drilled_at: r.get("drilled_at")?,
    })
}

pub fn of_app(conn: &Connection, app_id: &str) -> Result<Option<Database>> {
    conn.first(&format!("SELECT {COLUMNS} FROM databases WHERE app_id = ?"), [app_id], from_row)
}

pub fn all(conn: &Connection) -> Result<Vec<Database>> {
    conn.all(&format!("SELECT {COLUMNS} FROM databases ORDER BY created_at"), (), from_row)
}

/// Whether DATABASE_URL is Brod's to manage for this app (set_secret refuses to touch it then).
pub fn manages_url(conn: &Connection, app_id: &str) -> Result<bool> {
    conn.exists("SELECT 1 FROM databases WHERE app_id = ?", [app_id])
}

pub fn managed_url_problem() -> Problem {
    Problem::new(
        409,
        "database_managed",
        "DATABASE_URL belongs to this app's managed database (request_database), so Brod sets it and it cannot be changed or removed by hand. Deploy the app and read DATABASE_URL from its environment.",
    )
}

/// The database as get_status shows it: never its password.
pub fn view(conn: &Connection, cfg: &Config, app_id: &str) -> Result<Option<Value>> {
    let Some(d) = of_app(conn, app_id)? else { return Ok(None) };
    let backups = conn.all(
        "SELECT id, kind, state, bytes, error, created_at, finished_at, restored_test_at, drill_error FROM backups WHERE database_id = ? ORDER BY created_at DESC LIMIT 10",
        [&d.id],
        |r| {
            let mut m = Map::new();
            m.insert("id".into(), json!(r.get::<_, String>(0)?));
            m.insert("kind".into(), json!(r.get::<_, String>(1)?));
            m.insert("state".into(), json!(r.get::<_, String>(2)?));
            m.insert("bytes".into(), json!(r.get::<_, Option<i64>>(3)?));
            if let Some(e) = r.get::<_, Option<String>>(4)? {
                m.insert("error".into(), json!(e));
            }
            m.insert("at".into(), json!(iso(r.get(5)?)));
            if let Some(t) = r.get::<_, Option<i64>>(7)? {
                m.insert("restore_tested".into(), json!(iso(t)));
            }
            if let Some(e) = r.get::<_, Option<String>>(8)? {
                m.insert("restore_test_error".into(), json!(e));
            }
            Ok(Value::Object(m))
        },
    )?;
    let mut v = json!({
        "engine": "postgres", "name": d.name, "host": HOST, "port": PORT, "env": SECRET,
        "size_bytes": d.bytes, "measured": d.measured_at.map(iso), "created": iso(d.created_at),
        "last_restore_drill": d.drilled_at.map(iso), "backups": backups,
    });
    if let Some(w) = crate::backups::storage_warning(cfg) {
        v["warning"] = json!(w);
    }
    Ok(Some(v))
}

// ---------- request_database ----------

fn provisioning() -> &'static tokio::sync::Mutex<()> {
    static M: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();
    M.get_or_init(Default::default)
}

/// One lock per database: a backup, a restore, a drill and a delete never overlap.
pub fn lock(id: &str) -> Arc<tokio::sync::Mutex<()>> {
    static LOCKS: OnceLock<std::sync::Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>> = OnceLock::new();
    let mut m = LOCKS.get_or_init(Default::default).lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    m.retain(|_, l| Arc::strong_count(l) > 1);
    m.entry(id.to_string()).or_default().clone()
}

/// request_database: the app's managed database, made the first time. No confirmation: it only adds.
pub async fn request(st: &State, c: &Caller, slug: &str) -> Result<Value> {
    if st.cfg.apps_db.is_none() {
        return Err(unavailable());
    }
    let (c2, s) = (c.clone(), slug.to_string());
    let app = st
        .db
        .call(move |conn| {
            require_role(&c2, "builder", "add a database to an app")?;
            control::get_app(conn, &c2, &s)
        })
        .await?;
    let _held = provisioning().lock().await;
    let (cfg, id) = (st.cfg.clone(), app.id.clone());
    let (existing, external) = st
        .db
        .call(move |conn| {
            Ok((view(conn, &cfg, &id)?, conn.exists("SELECT 1 FROM secrets WHERE app_id = ? AND name = ?", params![id, SECRET])?))
        })
        .await?;
    if let Some(v) = existing {
        return Ok(
            json!({ "app": app.slug, "database": v, "created": false, "note": "The app already has its database; nothing changed." }),
        );
    }
    if external {
        return Err(Problem::new(
            409,
            "database_url_set",
            "This app already sets DATABASE_URL itself (an external database). Remove that secret with set_secret first to use a managed database instead.",
        ));
    }
    let name = name_of(&app.id)?;
    let password = random_id("", 24);
    let admin = admin_config(&st.cfg, None)?;
    {
        let (name, password) = (name.clone(), password.clone());
        blocking(move || provision(&admin, &name, &password)).await?;
    }
    let sealed = crate::secrets::seal(&st.cfg.secrets_key, &app.id, &url_for(&name, &password))?;
    let (cfg, c2, a2) = (st.cfg.clone(), c.clone(), app.clone());
    let v = st
        .db
        .call(move |conn| {
            tx(conn, |x| {
                let id = random_id("db_", 12);
                let t = now();
                x.run(
                    "INSERT INTO databases (id, app_id, engine, name, role, secret_ref, created_at) VALUES (?,?,'postgres',?,?,?,?)",
                    params![id, a2.id, name, name, format!("secret:{SECRET}"), t],
                )?;
                x.run("UPDATE apps SET database_id = ? WHERE id = ?", params![id, a2.id])?;
                x.run(
                    "INSERT INTO secrets (app_id, name, value, updated_at, updated_by) VALUES (?,?,?,?,'brod') ON CONFLICT(app_id, name) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at, updated_by = excluded.updated_by",
                    params![a2.id, SECRET, sealed, t],
                )?;
                x.run("UPDATE apps SET secrets_rev = secrets_rev + 1 WHERE id = ?", [&a2.id])?;
                event(x, &c2.workspace.id, &c2.actor, Some(&a2.id), "database_created", &format!("Postgres database {name}"))
            })?;
            view(conn, &cfg, &a2.id)
        })
        .await?;
    let _ = measure(st).await;
    Ok(json!({
        "app": app.slug, "database": v, "created": true,
        "note": "The app's containers get DATABASE_URL (postgres://...@brod-db.internal:5432/...) from their next deployment: deploy the app again to use it. Only this app can reach this database. It is backed up nightly; backup_database takes one now.",
    }))
}

/// Refresh every managed database's size.
pub async fn measure(st: &State) -> Result<()> {
    if st.cfg.apps_db.is_none() {
        return Ok(());
    }
    let admin = admin_config(&st.cfg, None)?;
    let sizes: Vec<(String, i64)> = blocking(move || {
        let mut c = connect(&admin)?;
        Ok(c.query("SELECT datname, pg_database_size(datname) FROM pg_database WHERE datname LIKE 'app\\_%'", &[])
            .map_err(pg_error)?
            .iter()
            .map(|r| (r.get(0), r.get(1)))
            .collect())
    })
    .await?;
    st.db
        .call(move |conn| {
            let t = now();
            for (name, bytes) in sizes {
                conn.run("UPDATE databases SET bytes = ?, measured_at = ? WHERE name = ?", params![bytes, t, name])?;
            }
            Ok(())
        })
        .await
}

/// Drop what restores and drills left behind: replaced databases after a day, scratch ones after six hours.
pub async fn sweep(st: &State) -> Result<usize> {
    if st.cfg.apps_db.is_none() {
        return Ok(0);
    }
    let admin = admin_config(&st.cfg, None)?;
    blocking(move || {
        let mut c = connect(&admin)?;
        let names: Vec<String> = c
            .query("SELECT datname FROM pg_database WHERE datname LIKE 'app\\_%'", &[])
            .map_err(pg_error)?
            .iter()
            .map(|r| r.get(0))
            .collect();
        let t = now();
        let mut dropped = 0;
        for n in names {
            if let Some((_, kind, made)) = leftover(&n)
                && expired(kind, made, t)
            {
                c.batch_execute(&format!("DROP DATABASE IF EXISTS {} WITH (FORCE)", ident(&n))).map_err(pg_error)?;
                tracing::info!("dropped the leftover database {n}");
                dropped += 1;
            }
        }
        Ok(dropped)
    })
    .await
}

// ---------- the proxy: brod-db.internal through the tunnel ----------

/// Keep the node's accept stream open for as long as its tunnel `serial` lasts, taking each connection it announces.
pub async fn accept_loop(st: State, node: String, serial: u64) {
    if st.cfg.apps_db.is_none() {
        return;
    }
    while st.nodes.is_current(&node, serial) {
        match accept_once(&st, &node, serial).await {
            Ok(()) => {}
            Err(e) if e.code == "not_found" => {
                return tracing::info!("node {node} has no database proxy (an older brod-node): managed databases are not reachable there");
            }
            Err(e) => tracing::debug!("node {node}: database accept stream: {e}"),
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

async fn accept_once(st: &State, node: &str, serial: u64) -> Result<()> {
    let req = axum::http::Request::get("/v1/db/accept").body(Body::empty()).map_err(Problem::internal)?;
    let res = crate::nodes::request(st, node, req).await?;
    if res.status().as_u16() == 404 {
        return Err(Problem::new(404, "not_found", "no accept stream"));
    }
    if !res.status().is_success() {
        return Err(Problem::internal(format!("the accept stream answered {}", res.status())));
    }
    let mut stream = res.into_body().into_data_stream();
    let mut buf: Vec<u8> = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(Problem::internal)?;
        buf.extend_from_slice(&chunk);
        while let Some(i) = buf.iter().position(|b| *b == b'\n') {
            let line: Vec<u8> = buf.drain(..=i).collect();
            let Ok(v) = serde_json::from_slice::<Value>(&line) else { continue };
            if let (Some(conn), Some(app)) = (v["conn"].as_str(), v["app"].as_str()) {
                tokio::spawn(take(st.clone(), node.to_string(), conn.to_string(), app.to_string()));
            }
        }
        if buf.len() > 64 * 1024 {
            return Err(Problem::internal("an accept stream line is too long"));
        }
        if !st.nodes.is_current(node, serial) {
            break;
        }
    }
    Ok(())
}

/// The app's database name and role when its listener on `node` may reach it: the app has a managed database and a
/// deployment there (migrating to draining).
async fn allowed(st: &State, node: &str, app: &str) -> Result<Option<(String, String)>> {
    let (node, app) = (node.to_string(), app.to_string());
    st.db
        .call(move |c| {
            c.first(
                "SELECT d.name, d.role FROM databases d WHERE d.app_id = ? AND EXISTS (SELECT 1 FROM deployments x WHERE x.app_id = d.app_id AND x.node_id = ?
                   AND x.state IN ('migrating','starting','healthy','serving','draining'))",
                params![app, node],
                |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)),
            )
        })
        .await
}

async fn take(st: State, node: String, conn: String, app: String) {
    if conn.is_empty() || conn.len() > 64 || !conn.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_') {
        return;
    }
    let target = match allowed(&st, &node, &app).await {
        Ok(t) => t,
        Err(e) => {
            tracing::warn!("node {node}: database connection for {app}: {}", e.message);
            None
        }
    };
    let Some((name, role)) = target else {
        tracing::warn!("node {node}: refused a database connection for {app}: no managed database or no deployment of it there");
        if let Ok(req) = axum::http::Request::delete(format!("/v1/db/conns/{conn}")).body(Body::empty()) {
            let _ = crate::nodes::request(&st, &node, req).await;
        }
        return;
    };
    if let Err(e) = pipe(&st, &node, &conn, &name, &role).await {
        tracing::debug!("node {node}: database connection for {app} ended: {e}");
    }
}

/// What a client sent first.
#[derive(Debug, PartialEq)]
pub enum Startup {
    /// A CancelRequest, passed on as it is.
    Cancel(Vec<u8>),
    /// A StartupMessage (protocol 3.0): the whole packet, the user and the database.
    Connect { packet: Vec<u8>, user: String, database: String },
}

const SSL_REQUEST: u32 = 80877103;
const GSSENC_REQUEST: u32 = 80877104;
const CANCEL_REQUEST: u32 = 80877102;
const PROTOCOL_3: u32 = 196608;

/// A StartupMessage's parameters (after its length and protocol version): user and database (default: the user).
pub fn parameters(b: &[u8]) -> Option<(String, String)> {
    let mut fields = b.split(|x| *x == 0);
    let mut m: HashMap<String, String> = HashMap::new();
    loop {
        let k = fields.next()?;
        if k.is_empty() {
            break;
        }
        let v = fields.next()?;
        m.insert(String::from_utf8(k.to_vec()).ok()?, String::from_utf8(v.to_vec()).ok()?);
    }
    let user = m.get("user").filter(|u| !u.is_empty())?.clone();
    let database = m.get("database").filter(|d| !d.is_empty()).cloned().unwrap_or_else(|| user.clone());
    Some((user, database))
}

/// Read the client's first packet, answering SSL and GSS encryption requests with "N" (the tunnel is the encryption).
pub async fn startup<R: AsyncRead + Unpin>(r: &mut R, reply: &mpsc::Sender<Bytes>) -> std::io::Result<Startup> {
    let bad = |m: &str| std::io::Error::new(std::io::ErrorKind::InvalidData, m.to_string());
    for _ in 0..3 {
        let mut len = [0u8; 4];
        r.read_exact(&mut len).await?;
        let n = u32::from_be_bytes(len) as usize;
        if !(8..=10_000).contains(&n) {
            return Err(bad("not a Postgres startup packet"));
        }
        let mut rest = vec![0u8; n - 4];
        r.read_exact(&mut rest).await?;
        let code = u32::from_be_bytes([rest[0], rest[1], rest[2], rest[3]]);
        match code {
            SSL_REQUEST | GSSENC_REQUEST => {
                reply.send(Bytes::from_static(b"N")).await.map_err(|_| bad("closed"))?;
            }
            CANCEL_REQUEST => return Ok(Startup::Cancel([&len[..], &rest[..]].concat())),
            PROTOCOL_3 => {
                let (user, database) = parameters(&rest[4..]).ok_or_else(|| bad("a startup packet without a user"))?;
                return Ok(Startup::Connect { packet: [&len[..], &rest[..]].concat(), user, database });
            }
            _ => return Err(bad("an unsupported Postgres protocol version")),
        }
    }
    Err(bad("too many encryption requests"))
}

/// A Postgres ErrorResponse (severity FATAL).
pub fn error_response(code: &str, message: &str) -> Bytes {
    let mut body = Vec::new();
    for (t, v) in [(b'S', "FATAL"), (b'V', "FATAL"), (b'C', code), (b'M', message)] {
        body.push(t);
        body.extend_from_slice(v.as_bytes());
        body.push(0);
    }
    body.push(0);
    let mut out = vec![b'E'];
    out.extend_from_slice(&((body.len() + 4) as u32).to_be_bytes());
    out.extend_from_slice(&body);
    Bytes::from(out)
}

trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}

/// A raw connection to apps-postgres, as the admin URL locates it (TCP, or a Unix socket folder).
async fn upstream(cfg: &Config) -> Result<Box<dyn Io>> {
    let c = admin_config(cfg, None)?;
    let port = c.get_ports().first().copied().unwrap_or(5432);
    let io: Box<dyn Io> = match c.get_hosts().first() {
        Some(postgres::config::Host::Tcp(h)) => Box::new(tokio::net::TcpStream::connect((h.as_str(), port)).await?),
        #[cfg(unix)]
        Some(postgres::config::Host::Unix(dir)) => Box::new(tokio::net::UnixStream::connect(dir.join(format!(".s.PGSQL.{port}"))).await?),
        _ => return Err(Problem::internal("BROD_APPS_DATABASE_URL names no host")),
    };
    Ok(io)
}

/// Take a connection: check its startup packet against the app's database, then pipe it to apps-postgres.
async fn pipe(st: &State, node: &str, conn: &str, name: &str, role: &str) -> Result<()> {
    let (tx, rx) = mpsc::channel::<Bytes>(16);
    let to_node =
        futures_util::stream::unfold(rx, |mut rx| async move { rx.recv().await.map(|b| (Ok::<_, std::io::Error>(Frame::data(b)), rx)) });
    let req =
        axum::http::Request::post(format!("/v1/db/conns/{conn}")).body(Body::new(StreamBody::new(to_node))).map_err(Problem::internal)?;
    let res = crate::nodes::request(st, node, req).await?;
    if !res.status().is_success() {
        return Err(Problem::internal(format!("the node answered {} for connection {conn}", res.status())));
    }
    let mut client = tokio_util::io::StreamReader::new(res.into_body().into_data_stream().map(|r| r.map_err(std::io::Error::other)));
    let first = startup(&mut client, &tx).await?;
    let packet = match first {
        Startup::Cancel(packet) => {
            let mut up = upstream(&st.cfg).await?;
            up.write_all(&packet).await?;
            return Ok(());
        }
        Startup::Connect { packet, user, database } => {
            if user != role || database != name {
                let m = format!(
                    "This app's database is {name}, reached as {role}: use DATABASE_URL. No other database or role is reachable from here."
                );
                let _ = tx.send(error_response("28000", &m)).await;
                return Err(Problem::new(403, "forbidden", format!("asked for {database} as {user}")));
            }
            packet
        }
    };
    let up = match upstream(&st.cfg).await {
        Ok(u) => u,
        Err(e) => {
            let _ = tx.send(error_response("57P03", "The database server is not reachable right now.")).await;
            return Err(e);
        }
    };
    let (mut ur, mut uw) = tokio::io::split(up);
    uw.write_all(&packet).await?;
    let down = async {
        let mut buf = vec![0u8; 32 * 1024];
        loop {
            let n = ur.read(&mut buf).await?;
            if n == 0 || tx.send(Bytes::copy_from_slice(&buf[..n])).await.is_err() {
                return Ok::<_, std::io::Error>(());
            }
        }
    };
    let up = async {
        tokio::io::copy(&mut client, &mut uw).await?;
        uw.shutdown().await
    };
    tokio::select! {
        r = down => r?,
        r = up => r?,
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_come_only_from_app_ids() {
        assert_eq!(name_of("app_0123456789abcdef01234567").unwrap(), "app_0123456789abcdef01234567");
        for bad in [
            "",
            "app_",
            "app_XYZ",
            "app_12\"; DROP ROLE x; --",
            "app_ab cd",
            "APP_abc",
            "postgres",
            "app_abc'",
            &format!("app_{}", "a".repeat(41)),
            "app_abc\0",
        ] {
            assert!(name_of(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn quotes_identifiers_and_literals() {
        assert_eq!(ident("app_1"), "\"app_1\"");
        assert_eq!(ident("a\"b"), "\"a\"\"b\"");
        assert_eq!(ident("x\0y"), "\"xy\"");
        assert_eq!(literal("it's"), "'it''s'");
        assert_eq!(literal("a\\b"), "'a\\b'");
        assert_eq!(literal("'; DROP DATABASE x; --"), "'''; DROP DATABASE x; --'");
    }

    #[test]
    fn builds_the_url_the_app_gets() {
        assert_eq!(url_for("app_ab", "pw"), "postgres://app_ab:pw@brod-db.internal:5432/app_ab?sslmode=disable");
    }

    #[test]
    fn recognises_what_restores_and_drills_leave() {
        assert_eq!(leftover("app_ab_before_1700000000000"), Some(("app_ab", "before", 1_700_000_000_000)));
        assert_eq!(leftover("app_ab_drill_17"), Some(("app_ab", "drill", 17)));
        assert_eq!(leftover("app_ab_restore_5"), Some(("app_ab", "restore", 5)));
        for no in ["app_ab", "app_ab_before_", "app_ab_before_12x", "postgres", "app_XY_before_1", "app_ab_other_1"] {
            assert_eq!(leftover(no), None, "{no}");
        }
        let t = 100 * KEEP_REPLACED_MS;
        assert!(!expired("before", t - KEEP_REPLACED_MS + 1, t));
        assert!(expired("before", t - KEEP_REPLACED_MS - 1, t));
        assert!(expired("drill", t - STALE_SCRATCH_MS - 1, t));
        assert!(!expired("restore", t - 1000, t));
    }

    #[test]
    fn reads_startup_parameters() {
        let p = b"user\0app_ab\0database\0app_ab\0application_name\0psql\0\0";
        assert_eq!(parameters(p), Some(("app_ab".into(), "app_ab".into())));
        assert_eq!(parameters(b"user\0app_ab\0\0"), Some(("app_ab".into(), "app_ab".into())), "the database defaults to the user");
        assert_eq!(parameters(b"database\0x\0\0"), None, "a user is required");
        assert_eq!(parameters(b"user\0app_ab"), None, "truncated");
    }

    fn packet(code: u32, rest: &[u8]) -> Vec<u8> {
        let mut p = ((rest.len() + 8) as u32).to_be_bytes().to_vec();
        p.extend_from_slice(&code.to_be_bytes());
        p.extend_from_slice(rest);
        p
    }

    #[tokio::test]
    async fn answers_ssl_requests_then_reads_the_startup_packet() {
        let (tx, mut rx) = mpsc::channel(4);
        let start = packet(PROTOCOL_3, b"user\0app_ab\0database\0app_cd\0\0");
        let mut input: Vec<u8> = packet(SSL_REQUEST, b"");
        input.extend_from_slice(&start);
        let got = startup(&mut &input[..], &tx).await.unwrap();
        assert_eq!(got, Startup::Connect { packet: start, user: "app_ab".into(), database: "app_cd".into() });
        assert_eq!(rx.recv().await.unwrap(), Bytes::from_static(b"N"));
        let cancel = packet(CANCEL_REQUEST, &[0, 0, 0, 1, 0, 0, 0, 2]);
        assert_eq!(startup(&mut &cancel[..], &tx).await.unwrap(), Startup::Cancel(cancel.clone()));
        assert!(startup(&mut &packet(1234, b"")[..], &tx).await.is_err());
        assert!(startup(&mut &[0u8, 0, 0xff, 0xff][..], &tx).await.is_err(), "too long");
    }

    #[test]
    fn writes_postgres_errors() {
        let e = error_response("28000", "no");
        assert_eq!(e[0], b'E');
        assert_eq!(u32::from_be_bytes([e[1], e[2], e[3], e[4]]) as usize, e.len() - 1);
        assert!(e.ends_with(b"Mno\0\0"));
    }
}
