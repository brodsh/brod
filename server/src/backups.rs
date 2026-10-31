// SPDX-License-Identifier: AGPL-3.0-only
// Backups of apps' managed databases (databases.rs): pg_dump in custom format, as the admin, encrypted and kept in
// Brod's storage at backups/<database id>/<timestamp>.dump.enc.
//
//   nightly    every managed database whose last backup is a day old (checked every 10 minutes)
//   manual     backup_database, and POST /v1/admin/backups/run (every database, now)
//   final      deleting an app takes one before its database and role are dropped; kept 30 days
// Kept: the newest backup of each of the 7 most recent days that have one, and of each of the 4 most recent weeks.
//
// The dump runs in a REPEATABLE READ snapshot of its own, exported to pg_dump (--snapshot), after each table's rows are
// counted in it: the counts (row_counts) are exactly what the dump holds. The restore drill restores the latest backup of
// every database once a week into a scratch database, compares the counts, sets restored_test_at, and drops the scratch
// (POST /v1/admin/backups/drill runs it now). A failed drill is logged as an error.
//
// restore_database needs a person (control.rs NEEDS_A_PERSON). Confirmed, it restores into a fresh database, checks
// pg_restore succeeded and the row counts match, then swaps names (connections to the old one are refused and ended
// first), keeps the old database as <name>_before_<ms> for 24 hours, and restarts the app's serving containers.
//
// Encryption: AES-256-GCM under a key derived from SECRETS_KEY with HKDF-SHA256 (info "brod db backups v1"), in
// chunks so neither side holds a dump in memory: "BRODBK\0\1", an 8-byte random nonce prefix, then chunks of
// [final flag: 1 byte][length: u32 BE][ciphertext and tag] holding up to 1 MiB each. A chunk's nonce is the prefix and
// its counter (u32 BE); its associated data is the magic, the database id, the counter and the flag, so chunks cannot
// be reordered, dropped, cut short or moved to another database's backup unnoticed. Plain dumps never touch disk.
use std::collections::HashSet;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use hkdf::Hkdf;
use serde_json::{Map, Value, json};
use sha2::Sha256;

use crate::config::Config;
use crate::control;
use crate::databases::{self, Database, admin_config, blocking, connect, ident, pg_error};
use crate::db::{Sql, event, params};
use crate::model::Caller;
use crate::people::require_role;
use crate::problem::{Problem, Result};
use crate::state::State;
use crate::util::{iso, now, random_bytes, random_id};

const MAGIC: &[u8; 8] = b"BRODBK\x00\x01";
const CHUNK: usize = 1 << 20;
const DAY_MS: i64 = 24 * 3600 * 1000;
/// How long a deleted app's final backup is kept.
pub const FINAL_KEEP_MS: i64 = 30 * DAY_MS;
const KEEP_DAILY: usize = 7;
const KEEP_WEEKLY: usize = 4;
/// How often each database's restore is drilled.
const DRILL_EVERY_MS: i64 = 7 * DAY_MS;

// ---------- encryption ----------

/// The backup key: HKDF-SHA256 of SECRETS_KEY.
pub fn key(secrets_key: &str) -> Result<[u8; 32]> {
    if secrets_key.encode_utf16().count() < 16 {
        return Err(Problem::new(503, "secrets_unavailable", "Backups need SECRETS_KEY to encrypt them, and it is not configured."));
    }
    let mut okm = [0u8; 32];
    Hkdf::<Sha256>::new(Some(&[]), secrets_key.as_bytes()).expand(b"brod db backups v1", &mut okm).map_err(Problem::internal)?;
    Ok(okm)
}

fn nonce(prefix: &[u8], counter: u32) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[..8].copy_from_slice(prefix);
    n[8..].copy_from_slice(&counter.to_be_bytes());
    n
}

fn aad(database: &str, counter: u32, last: bool) -> Vec<u8> {
    let mut a = MAGIC.to_vec();
    a.extend_from_slice(database.as_bytes());
    a.extend_from_slice(&counter.to_be_bytes());
    a.push(last as u8);
    a
}

/// Read until `buf` is full or the input ends; the bytes read.
fn fill(r: &mut impl Read, buf: &mut [u8]) -> std::io::Result<usize> {
    let mut n = 0;
    while n < buf.len() {
        match r.read(&mut buf[n..]) {
            Ok(0) => break,
            Ok(k) => n += k,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(n)
}

/// Encrypt everything `r` yields into `w`. The bytes written.
pub fn encrypt(key: &[u8; 32], database: &str, mut r: impl Read, mut w: impl Write) -> std::io::Result<u64> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(std::io::Error::other)?;
    let prefix = random_bytes(8);
    w.write_all(MAGIC)?;
    w.write_all(&prefix)?;
    let mut written = 16u64;
    let mut cur = vec![0u8; CHUNK];
    let mut cur_len = fill(&mut r, &mut cur)?;
    let mut next = vec![0u8; CHUNK];
    let mut counter = 0u32;
    loop {
        let next_len = if cur_len == CHUNK { fill(&mut r, &mut next)? } else { 0 };
        let last = next_len == 0;
        let ct = cipher
            .encrypt(Nonce::from_slice(&nonce(&prefix, counter)), Payload { msg: &cur[..cur_len], aad: &aad(database, counter, last) })
            .map_err(|_| std::io::Error::other("encrypt"))?;
        w.write_all(&[last as u8])?;
        w.write_all(&(ct.len() as u32).to_be_bytes())?;
        w.write_all(&ct)?;
        written += 5 + ct.len() as u64;
        if last {
            w.flush()?;
            return Ok(written);
        }
        std::mem::swap(&mut cur, &mut next);
        cur_len = next_len;
        counter = counter.checked_add(1).ok_or_else(|| std::io::Error::other("the backup is too large"))?;
    }
}

/// Decrypt a backup from `r` into `w`, checking every chunk and that it ends where it should. The bytes written.
pub fn decrypt(key: &[u8; 32], database: &str, mut r: impl Read, mut w: impl Write) -> std::io::Result<u64> {
    let bad = |m: &str| std::io::Error::new(std::io::ErrorKind::InvalidData, m.to_string());
    let cipher = Aes256Gcm::new_from_slice(key).map_err(std::io::Error::other)?;
    let mut head = [0u8; 16];
    if fill(&mut r, &mut head)? != 16 || &head[..8] != MAGIC {
        return Err(bad("not a Brod database backup"));
    }
    let prefix = head[8..].to_vec();
    let (mut counter, mut written) = (0u32, 0u64);
    loop {
        let mut h = [0u8; 5];
        if fill(&mut r, &mut h)? != 5 {
            return Err(bad("the backup is cut short"));
        }
        let last = match h[0] {
            0 => false,
            1 => true,
            _ => return Err(bad("the backup is damaged")),
        };
        let len = u32::from_be_bytes([h[1], h[2], h[3], h[4]]) as usize;
        if len > CHUNK + 16 {
            return Err(bad("the backup is damaged"));
        }
        let mut ct = vec![0u8; len];
        if fill(&mut r, &mut ct)? != len {
            return Err(bad("the backup is cut short"));
        }
        let plain = cipher
            .decrypt(Nonce::from_slice(&nonce(&prefix, counter)), Payload { msg: &ct, aad: &aad(database, counter, last) })
            .map_err(|_| bad("the backup could not be decrypted (damaged, another database's, or another SECRETS_KEY)"))?;
        w.write_all(&plain)?;
        written += plain.len() as u64;
        if last {
            if fill(&mut r, &mut [0u8; 1])? != 0 {
                return Err(bad("the backup has data after its end"));
            }
            w.flush()?;
            return Ok(written);
        }
        counter = counter.checked_add(1).ok_or_else(|| bad("the backup is damaged"))?;
    }
}

// ---------- retention ----------

/// Which finished backups to keep, given (id, created_at) of each: the newest of each of the KEEP_DAILY most recent
/// days that have one, and of each of the KEEP_WEEKLY most recent weeks (Monday to Sunday, UTC).
pub fn keep(backups: &[(String, i64)]) -> HashSet<String> {
    let mut sorted: Vec<&(String, i64)> = backups.iter().collect();
    sorted.sort_by(|a, b| b.1.cmp(&a.1).then(b.0.cmp(&a.0)));
    let mut out = HashSet::new();
    let (mut days, mut weeks): (Vec<i64>, Vec<i64>) = (vec![], vec![]);
    for (id, at) in sorted {
        let day = at.div_euclid(DAY_MS);
        // 1970-01-01 was a Thursday: shifting by 3 days starts weeks on Monday.
        let week = (day + 3).div_euclid(7);
        if !days.contains(&day) && days.len() < KEEP_DAILY {
            days.push(day);
            out.insert(id.clone());
        }
        if !weeks.contains(&week) && weeks.len() < KEEP_WEEKLY {
            weeks.push(week);
            out.insert(id.clone());
        }
    }
    out
}

/// Apply retention to one database's nightly and manual backups, delete failed ones after a week, and every backup
/// past its expires_at (final backups, and the rest of a deleted app's).
pub async fn prune(st: &State) -> Result<usize> {
    let t = now();
    type Row = (String, String, String, String, i64, Option<i64>, String);
    let rows: Vec<Row> = st
        .db
        .call(|c| {
            c.all(
                "SELECT b.id, b.database_id, b.key, b.state, b.created_at, b.expires_at, b.kind FROM backups b WHERE b.state <> 'running'",
                (),
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?, r.get(6)?)),
            )
        })
        .await?;
    let mut by_db: std::collections::HashMap<&str, Vec<(String, i64)>> = Default::default();
    for (id, db, _, state, at, expires, kind) in &rows {
        if state == "done" && expires.is_none() && kind != "final" {
            by_db.entry(db.as_str()).or_default().push((id.clone(), *at));
        }
    }
    let kept: HashSet<String> = by_db.values().flat_map(|l| keep(l)).collect();
    let mut gone = 0;
    for (id, _, key, state, at, expires, kind) in &rows {
        let drop = match expires {
            Some(e) => *e < t,
            None if state == "failed" => *at < t - KEEP_DAILY as i64 * DAY_MS,
            None => kind != "final" && !kept.contains(id),
        };
        if !drop {
            continue;
        }
        if state == "done" {
            st.store.delete(key).await?;
        }
        let id = id.clone();
        st.db.call(move |c| c.run("DELETE FROM backups WHERE id = ?", [&id]).map(|_| ())).await?;
        gone += 1;
    }
    Ok(gone)
}

// ---------- pg_dump and pg_restore ----------

/// A pg tool (pg_dump, pg_restore) with the admin's connection in its environment, never on its command line.
fn tool(cfg: &Config, name: &str) -> Result<Command> {
    let a = cfg.apps_db.as_ref().ok_or_else(databases::unavailable)?;
    let c = admin_config(cfg, None)?;
    let mut cmd = Command::new(a.bin_dir.as_ref().map(|d| d.join(name)).unwrap_or_else(|| PathBuf::from(name)));
    match c.get_hosts().first() {
        Some(postgres::config::Host::Tcp(h)) => {
            cmd.env("PGHOST", h);
        }
        #[cfg(unix)]
        Some(postgres::config::Host::Unix(p)) => {
            cmd.env("PGHOST", p);
        }
        _ => {}
    }
    if let Some(p) = c.get_ports().first() {
        cmd.env("PGPORT", p.to_string());
    }
    if let Some(u) = c.get_user() {
        cmd.env("PGUSER", u);
    }
    if let Some(p) = c.get_password() {
        cmd.env("PGPASSWORD", String::from_utf8_lossy(p).into_owned());
    }
    cmd.env("PGCONNECT_TIMEOUT", "10").env_remove("PGDATABASE").env_remove("PGSERVICE");
    Ok(cmd)
}

/// The last lines of a tool's error output.
fn tail(text: &str) -> String {
    let lines: Vec<&str> = text.lines().filter(|l| !l.trim().is_empty()).collect();
    lines[lines.len().saturating_sub(10)..].join("\n")
}

/// Collect a child's stderr on a thread of its own, so a full pipe never stalls it.
fn drain(child: &mut std::process::Child) -> std::thread::JoinHandle<String> {
    let err = child.stderr.take();
    std::thread::spawn(move || {
        let mut s = String::new();
        if let Some(mut e) = err {
            let _ = e.read_to_string(&mut s);
        }
        s
    })
}

/// Rows of every ordinary table, by "schema.table", in the transaction's snapshot.
fn count_rows(c: &mut impl postgres::GenericClient) -> Result<Map<String, Value>> {
    let tables: Vec<(String, String)> = c
        .query(
            "SELECT n.nspname::text, c.relname::text FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
             WHERE c.relkind = 'r' AND n.nspname NOT IN ('pg_catalog', 'information_schema') AND n.nspname NOT LIKE 'pg\\_%' ORDER BY 1, 2",
            &[],
        )
        .map_err(pg_error)?
        .iter()
        .map(|r| (r.get(0), r.get(1)))
        .collect();
    let mut out = Map::new();
    for (schema, table) in tables {
        let n: i64 = c.query_one(&format!("SELECT count(*) FROM {}.{}", ident(&schema), ident(&table)), &[]).map_err(pg_error)?.get(0);
        out.insert(format!("{schema}.{table}"), json!(n));
    }
    Ok(out)
}

/// Dump `name` into the encrypted file `to`, in one snapshot with its row counts. The file's size and the counts.
fn dump(cfg: &Config, key: &[u8; 32], database_id: &str, name: &str, to: &Path) -> Result<(u64, Map<String, Value>)> {
    let mut c = connect(&admin_config(cfg, Some(name))?)?;
    let mut t =
        c.build_transaction().isolation_level(postgres::IsolationLevel::RepeatableRead).read_only(true).start().map_err(pg_error)?;
    let snapshot: String = t.query_one("SELECT pg_export_snapshot()", &[]).map_err(pg_error)?.get(0);
    let counts = count_rows(&mut t)?;
    let mut child = tool(cfg, "pg_dump")?
        .args(["--format=custom", "--snapshot", &snapshot, "--dbname", name])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| Problem::new(500, "backup_failed", format!("pg_dump could not start: {e}")))?;
    let errors = drain(&mut child);
    let out = private_file(to)?;
    let stdout = child.stdout.take().ok_or_else(|| Problem::internal("pg_dump has no output"))?;
    let written = encrypt(key, database_id, stdout, std::io::BufWriter::new(out));
    let status = child.wait()?;
    let errors = errors.join().unwrap_or_default();
    let _ = t.commit();
    if !status.success() {
        return Err(Problem::new(500, "backup_failed", format!("pg_dump failed ({status}): {}", tail(&errors))));
    }
    let written = written.map_err(|e| Problem::new(500, "backup_failed", format!("Writing the backup failed: {e}")))?;
    Ok((written, counts))
}

fn private_file(path: &Path) -> Result<std::fs::File> {
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create(true).truncate(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut o, 0o600);
    Ok(o.open(path)?)
}

/// Restore the encrypted backup `from` into the existing, empty database `into` (as `role`, when given, so it owns
/// what is made). Its row counts afterwards.
fn restore_into(
    cfg: &Config,
    key: &[u8; 32],
    database_id: &str,
    from: &Path,
    into: &str,
    role: Option<&str>,
) -> Result<Map<String, Value>> {
    let mut cmd = tool(cfg, "pg_restore")?;
    cmd.args(["--no-owner", "--no-acl", "--exit-on-error", "--dbname", into]);
    if let Some(r) = role {
        cmd.arg(format!("--role={r}"));
    }
    let mut child = cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| Problem::new(500, "restore_failed", format!("pg_restore could not start: {e}")))?;
    let errors = drain(&mut child);
    let stdin = child.stdin.take().ok_or_else(|| Problem::internal("pg_restore has no input"))?;
    let (key, id, file) = (*key, database_id.to_string(), std::fs::File::open(from)?);
    let feeder = std::thread::spawn(move || decrypt(&key, &id, std::io::BufReader::new(file), std::io::BufWriter::new(stdin)));
    let status = child.wait()?;
    let fed = feeder.join().map_err(|_| Problem::internal("the backup reader panicked"))?;
    let errors = errors.join().unwrap_or_default();
    if let Err(e) = fed {
        return Err(Problem::new(500, "restore_failed", format!("The backup could not be read: {e}")));
    }
    if !status.success() {
        return Err(Problem::new(500, "restore_failed", format!("pg_restore failed ({status}): {}", tail(&errors))));
    }
    let mut c = connect(&admin_config(cfg, Some(into))?)?;
    count_rows(&mut c)
}

/// Whether the counts a restore produced match the ones recorded at dump time; what differs, when not.
pub fn compare(expected: &Map<String, Value>, got: &Map<String, Value>) -> std::result::Result<(), String> {
    let mut diff = vec![];
    for (t, n) in expected {
        if got.get(t) != Some(n) {
            diff.push(format!("{t}: {n} expected, {} restored", got.get(t).map(|v| v.to_string()).unwrap_or_else(|| "none".into())));
        }
    }
    for t in got.keys().filter(|t| !expected.contains_key(*t)) {
        diff.push(format!("{t}: not in the backup"));
    }
    if diff.is_empty() { Ok(()) } else { Err(diff.join("; ")) }
}

fn create_scratch(cfg: &Config, scratch: &str, owner: Option<&str>) -> Result<()> {
    let mut c = connect(&admin_config(cfg, None)?)?;
    let owner = owner.map(|o| format!(" OWNER {}", ident(o))).unwrap_or_default();
    c.batch_execute(&format!("CREATE DATABASE {}{owner}; REVOKE ALL ON DATABASE {} FROM PUBLIC", ident(scratch), ident(scratch)))
        .map_err(pg_error)
}

fn drop_db(cfg: &Config, name: &str) -> Result<()> {
    let mut c = connect(&admin_config(cfg, None)?)?;
    c.batch_execute(&format!("DROP DATABASE IF EXISTS {} WITH (FORCE)", ident(name))).map_err(pg_error)
}

/// Swap the restored database in: refuse and end connections to the live one, rename it to `old` and `scratch` to its
/// name in one transaction, and give the role back its rights.
fn swap(cfg: &Config, live: &str, scratch: &str, old: &str, role: &str) -> Result<()> {
    let mut c = connect(&admin_config(cfg, None)?)?;
    let (l, s, o, r) = (ident(live), ident(scratch), ident(old), ident(role));
    c.batch_execute(&format!("ALTER DATABASE {l} WITH ALLOW_CONNECTIONS false")).map_err(pg_error)?;
    let result = (|| {
        for _ in 0..40 {
            let left: i64 = c
                .query_one(
                    "SELECT count(*) FROM (SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = ANY($1) AND pid <> pg_backend_pid()) t",
                    &[&vec![live.to_string(), scratch.to_string()]],
                )
                .map_err(pg_error)?
                .get(0);
            if left == 0 {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(250));
        }
        c.batch_execute(&format!("BEGIN; ALTER DATABASE {l} RENAME TO {o}; ALTER DATABASE {s} RENAME TO {l}; COMMIT")).map_err(pg_error)
    })();
    if let Err(e) = result {
        let _ = c.batch_execute("ROLLBACK");
        let _ = c.batch_execute(&format!("ALTER DATABASE {l} WITH ALLOW_CONNECTIONS true"));
        return Err(e);
    }
    c.batch_execute(&format!(
        "ALTER DATABASE {l} OWNER TO {r}; REVOKE ALL ON DATABASE {l} FROM PUBLIC; GRANT CONNECT, TEMPORARY ON DATABASE {l} TO {r}"
    ))
    .map_err(pg_error)?;
    let mut d = connect(&admin_config(cfg, Some(live))?)?;
    d.batch_execute(&format!("REVOKE CREATE ON SCHEMA public FROM PUBLIC; ALTER SCHEMA public OWNER TO {r}")).map_err(pg_error)
}

// ---------- backups ----------

fn spool(cfg: &Config) -> Result<PathBuf> {
    let dir = cfg.data_dir.join("spool");
    std::fs::create_dir_all(&dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700));
    }
    Ok(dir)
}

/// A timestamp for object keys: 20261031T201000123Z.
fn stamp(ms: i64) -> String {
    let s = iso(ms);
    let digits: String = s.chars().filter(|c| c.is_ascii_digit()).collect();
    format!("{}T{}Z", &digits[..8], &digits[8..digits.len().min(17)])
}

/// Off-machine or not: a warning when backups stay in the server's own folder.
pub fn storage_warning(cfg: &Config) -> Option<&'static str> {
    matches!(cfg.storage, crate::config::StorageConfig::Fs { .. }).then_some(
        "Backups are kept in this server's own folder storage, on the same machine as the database, so they do not survive losing the machine. Configure S3-compatible storage to keep them off it.",
    )
}

/// One backup of the database, now. The backup's row.
pub async fn backup(st: &State, d: &Database, kind: &str, actor: &str) -> Result<Value> {
    let lock = databases::lock(&d.id);
    let _held = lock.lock().await;
    backup_locked(st, d, kind, actor).await
}

async fn backup_locked(st: &State, d: &Database, kind: &str, actor: &str) -> Result<Value> {
    let k = key(&st.cfg.secrets_key)?;
    let (id, t) = (random_id("bk_", 12), now());
    let object = format!("backups/{}/{}.dump.enc", d.id, stamp(t));
    {
        let (id, db, app, object, kind) = (id.clone(), d.id.clone(), d.app_id.clone(), object.clone(), kind.to_string());
        let expires = (kind == "final").then_some(t + FINAL_KEEP_MS);
        st.db
            .call(move |c| {
                c.run(
                    "INSERT INTO backups (id, database_id, app_id, key, state, kind, created_at, expires_at) VALUES (?,?,?,?,'running',?,?,?)",
                    params![id, db, app, object, kind, t, expires],
                )
                .map(|_| ())
            })
            .await?;
    }
    let file = spool(&st.cfg)?.join(format!("{id}.enc"));
    let result = async {
        let (cfg, db, name, f) = (st.cfg.clone(), d.id.clone(), d.name.clone(), file.clone());
        let (bytes, counts) = blocking(move || dump(&cfg, &k, &db, &name, &f)).await?;
        st.store.put_file(&object, &file, Some("application/octet-stream")).await?;
        Ok::<_, Problem>((bytes, counts))
    }
    .await;
    let _ = tokio::fs::remove_file(&file).await;
    let (id2, finished) = (id.clone(), now());
    match result {
        Ok((bytes, counts)) => {
            let counts = Value::Object(counts).to_string();
            st.db
                .call(move |c| {
                    c.run(
                        "UPDATE backups SET state = 'done', bytes = ?, row_counts = ?, finished_at = ? WHERE id = ?",
                        params![bytes as i64, counts, finished, id2],
                    )
                    .map(|_| ())
                })
                .await?;
            tracing::info!(database = %d.name, "backed up ({kind}, {bytes} bytes) by {actor}");
            Ok(json!({ "id": id, "kind": kind, "state": "done", "bytes": bytes, "at": iso(t) }))
        }
        Err(e) => {
            let msg = e.internal.as_deref().map(String::from).unwrap_or_else(|| e.message.clone());
            st.db
                .call(move |c| {
                    c.run("UPDATE backups SET state = 'failed', error = ?, finished_at = ? WHERE id = ?", params![msg, finished, id2])
                        .map(|_| ())
                })
                .await?;
            tracing::error!(database = %d.name, "a backup failed: {e}");
            Err(if e.is_internal() { Problem::new(500, "backup_failed", "The backup failed. The operator's logs say why.") } else { e })
        }
    }
}

async fn database_of(st: &State, c: &Caller, slug: &str, verb: &str) -> Result<(crate::model::AppRow, Database)> {
    if st.cfg.apps_db.is_none() {
        return Err(databases::unavailable());
    }
    let (c2, s, verb) = (c.clone(), slug.to_string(), verb.to_string());
    st.db
        .call(move |conn| {
            require_role(&c2, "builder", &verb)?;
            let app = control::get_app(conn, &c2, &s)?;
            let d = databases::of_app(conn, &app.id)?.ok_or_else(|| {
                Problem::new(404, "no_database", format!("{} has no managed database. request_database adds one.", app.slug))
            })?;
            Ok((app, d))
        })
        .await
}

/// backup_database: back the app's database up now.
pub async fn backup_now(st: &State, c: &Caller, slug: &str) -> Result<Value> {
    let (app, d) = database_of(st, c, slug, "back up app databases").await?;
    let b = backup(st, &d, "manual", &c.actor).await?;
    let (ws, actor, app_id, id) = (c.workspace.id.clone(), c.actor.clone(), app.id.clone(), b["id"].as_str().unwrap_or("").to_string());
    st.db.call(move |x| event(x, &ws, &actor, Some(&app_id), "database_backed_up", &id)).await?;
    let mut out = json!({ "app": app.slug, "backup": b });
    if let Some(w) = storage_warning(&st.cfg) {
        out["warning"] = json!(w);
    }
    Ok(out)
}

// ---------- restore ----------

/// A finished backup of the database: `id`, or the newest. Its id, key and row counts.
async fn pick(st: &State, d: &Database, id: Option<&str>) -> Result<(String, String, Map<String, Value>)> {
    let (db, id) = (d.id.clone(), id.map(String::from).filter(|i| !i.is_empty()));
    let row: Option<(String, String, Option<String>)> = st
        .db
        .call(move |c| {
            let f = |r: &crate::db::Row| Ok((r.get(0)?, r.get(1)?, r.get(2)?));
            match id {
                Some(id) => c.first(
                    "SELECT id, key, row_counts FROM backups WHERE database_id = ? AND id = ? AND state = 'done'",
                    params![db, id],
                    f,
                ),
                None => c.first(
                    "SELECT id, key, row_counts FROM backups WHERE database_id = ? AND state = 'done' ORDER BY created_at DESC LIMIT 1",
                    [&db],
                    f,
                ),
            }
        })
        .await?;
    let (id, key, counts) =
        row.ok_or_else(|| Problem::new(404, "no_backup", "There is no such finished backup of this database. get_status lists them."))?;
    let counts = match counts.and_then(|c| serde_json::from_str::<Value>(&c).ok()) {
        Some(Value::Object(m)) => m,
        _ => Map::new(),
    };
    Ok((id, key, counts))
}

/// Download a backup to the spool.
async fn fetch(st: &State, key: &str, file: &Path) -> Result<()> {
    if !st.store.save_to(key, file).await? {
        return Err(Problem::new(410, "backup_missing", "The backup's file is no longer in storage."));
    }
    Ok(())
}

/// restore_database: replace the app's database with a backup. Asked for by an agent, it waits for a person.
pub async fn restore(st: &State, c: &Caller, slug: &str, backup_id: Option<&str>) -> Result<Value> {
    let (app, d) = database_of(st, c, slug, "restore app databases").await?;
    let lock = databases::lock(&d.id);
    let _held = lock.lock().await;
    let (id, object, counts) = pick(st, &d, backup_id).await?;
    if control::needs_a_person(c, "restore_database") {
        let (c2, cfg, app2, id2) = (c.clone(), st.cfg.clone(), app.clone(), id.clone());
        let summary = format!("Restore {}'s database from backup {id}, replacing its current data", app.slug);
        return st
            .db
            .call(move |conn| {
                control::needs_confirmation(conn, &cfg, &c2, Some(&app2), "restore_database", &json!({ "backup": id2 }), &summary)
            })
            .await;
    }
    let k = key(&st.cfg.secrets_key)?;
    let file = spool(&st.cfg)?.join(format!("{id}-restore.enc"));
    let t = now();
    let (scratch, old) = (format!("{}_restore_{t}", d.name), format!("{}_before_{t}", d.name));
    let result = async {
        fetch(st, &object, &file).await?;
        let (cfg, db, f, scratch, old, live, role) =
            (st.cfg.clone(), d.id.clone(), file.clone(), scratch.clone(), old.clone(), d.name.clone(), d.role.clone());
        blocking(move || {
            create_scratch(&cfg, &scratch, Some(&role))?;
            let done = (|| {
                let got = restore_into(&cfg, &k, &db, &f, &scratch, Some(&role))?;
                if !counts.is_empty() {
                    compare(&counts, &got)
                        .map_err(|m| Problem::new(500, "restore_failed", format!("The restored rows do not match the backup: {m}")))?;
                }
                swap(&cfg, &live, &scratch, &old, &role)
            })();
            if done.is_err() {
                let _ = drop_db(&cfg, &scratch);
            }
            done
        })
        .await
    }
    .await;
    let _ = tokio::fs::remove_file(&file).await;
    if let Err(e) = result {
        tracing::error!(database = %d.name, "a restore failed: {e}");
        return Err(if e.is_internal() {
            Problem::new(500, "restore_failed", "The restore failed and nothing changed. The operator's logs say why.")
        } else {
            e
        });
    }
    let restarted = crate::deployments::restart(st, &app.id).await;
    let (ws, actor, app_id, detail) = (
        c.workspace.id.clone(),
        c.actor.clone(),
        app.id.clone(),
        format!("from backup {id}; the replaced data is kept for 24 hours as {old}"),
    );
    st.db.call(move |x| event(x, &ws, &actor, Some(&app_id), "database_restored", &detail)).await?;
    Ok(json!({
        "app": app.slug, "restored": true, "backup": id, "replaced_kept_as": old, "replaced_kept_until": iso(t + databases::KEEP_REPLACED_MS),
        "restarted": restarted,
        "note": "The database now holds the backup's data. The data it replaced is kept for 24 hours, then dropped.",
    }))
}

// ---------- the restore drill ----------

/// Restore the database's latest backup into a scratch database and compare its row counts with the dump's.
pub async fn drill(st: &State, d: &Database) -> Result<Value> {
    let lock = databases::lock(&d.id);
    let _held = lock.lock().await;
    let (id, object, counts) = pick(st, d, None).await?;
    let k = key(&st.cfg.secrets_key)?;
    let t = now();
    let file = spool(&st.cfg)?.join(format!("{id}-drill.enc"));
    let scratch = format!("{}_drill_{t}", d.name);
    let result = async {
        fetch(st, &object, &file).await?;
        let (cfg, db, f, scratch) = (st.cfg.clone(), d.id.clone(), file.clone(), scratch.clone());
        blocking(move || {
            create_scratch(&cfg, &scratch, None)?;
            let got = restore_into(&cfg, &k, &db, &f, &scratch, None);
            let dropped = drop_db(&cfg, &scratch);
            let got = got?;
            dropped?;
            compare(&counts, &got)
                .map_err(|m| Problem::new(500, "drill_failed", format!("The restored rows do not match the backup: {m}")))?;
            Ok(got.len())
        })
        .await
    }
    .await;
    let _ = tokio::fs::remove_file(&file).await;
    let (db_id, bid, done) = (d.id.clone(), id.clone(), now());
    let error = result.as_ref().err().map(|e| e.internal.as_deref().map(String::from).unwrap_or_else(|| e.message.clone()));
    {
        let error = error.clone();
        st.db
            .call(move |c| {
                c.run("UPDATE databases SET drilled_at = ? WHERE id = ?", params![done, db_id])?;
                match error {
                    None => c.run("UPDATE backups SET restored_test_at = ?, drill_error = NULL WHERE id = ?", params![done, bid])?,
                    Some(e) => c.run("UPDATE backups SET drill_error = ? WHERE id = ?", params![e, bid])?,
                };
                Ok(())
            })
            .await?;
    }
    match result {
        Ok(tables) => {
            tracing::info!(database = %d.name, "restore drill passed: backup {id}, {tables} tables match");
            Ok(json!({ "database": d.name, "backup": id, "ok": true, "tables": tables }))
        }
        Err(e) => {
            tracing::error!(database = %d.name, "RESTORE DRILL FAILED for backup {id}: {e}");
            Ok(json!({ "database": d.name, "backup": id, "ok": false, "error": error }))
        }
    }
}

// ---------- deleting an app ----------

/// Before an app is deleted: a final backup (kept 30 days, as are its other backups), then its database and role go.
/// A failed backup stops the delete, so data is never lost unbacked.
pub async fn retire(st: &State, app_id: &str, actor: &str) -> Result<()> {
    let id = app_id.to_string();
    let Some(d) = st.db.call(move |c| databases::of_app(c, &id)).await? else { return Ok(()) };
    if st.cfg.apps_db.is_none() {
        return Err(databases::unavailable());
    }
    let lock = databases::lock(&d.id);
    let _held = lock.lock().await;
    backup_locked(st, &d, "final", actor).await.map_err(|e| {
        Problem::new(
            500,
            "backup_failed",
            format!("The app was not deleted: its database's final backup failed ({}). Try again.", e.message),
        )
    })?;
    let (admin, name) = (admin_config(&st.cfg, None)?, d.name.clone());
    blocking(move || databases::drop_all(&admin, &name)).await?;
    let (db, until) = (d.id.clone(), now() + FINAL_KEEP_MS);
    st.db
        .call(move |c| {
            c.run(
                "UPDATE backups SET expires_at = ? WHERE database_id = ? AND (expires_at IS NULL OR expires_at > ?)",
                params![until, db, until],
            )?;
            c.run("DELETE FROM databases WHERE id = ?", [&db])?;
            Ok(())
        })
        .await?;
    tracing::info!(database = %d.name, "dropped with its app; the final backup is kept 30 days");
    Ok(())
}

// ---------- the schedule ----------

/// Every 10 minutes: sizes, leftovers, a backup of each database whose last one is a day old, a drill of each one not
/// drilled for a week, and retention.
pub async fn tick(st: &State) -> Result<()> {
    if st.cfg.apps_db.is_none() {
        return Ok(());
    }
    if let Err(e) = databases::measure(st).await {
        tracing::warn!("could not measure app databases: {}", e.message);
    }
    if let Err(e) = databases::sweep(st).await {
        tracing::warn!("could not drop leftover app databases: {}", e.message);
    }
    let t = now();
    let due: Vec<(Database, bool, bool)> = st
        .db
        .call(move |c| {
            let mut out = vec![];
            for d in databases::all(c)? {
                let last: Option<i64> = c.first(
                    "SELECT MAX(created_at) FROM backups WHERE database_id = ? AND kind IN ('nightly','manual') AND state IN ('done','running')",
                    [&d.id],
                    |r| r.get(0),
                )?.flatten();
                let backup = last.is_none_or(|l| l < t - DAY_MS);
                let drill = d.drilled_at.is_none_or(|x| x < t - DRILL_EVERY_MS);
                out.push((d, backup, drill));
            }
            Ok(out)
        })
        .await?;
    for (d, backup_due, drill_due) in due {
        if backup_due && let Err(e) = backup(st, &d, "nightly", "brod").await {
            tracing::warn!(database = %d.name, "nightly backup: {}", e.message);
        }
        if drill_due && let Err(e) = drill(st, &d).await {
            tracing::warn!(database = %d.name, "restore drill: {}", e.message);
        }
    }
    prune(st).await?;
    Ok(())
}

/// POST /v1/admin/backups/run and /v1/admin/backups/drill (ADMIN_SECRET): back up, or drill, every database now.
pub async fn admin(st: &State, req: &mut crate::http::Req, seg: &[String]) -> Result<axum::response::Response> {
    let given = control::Credentials::of(req).bearer().unwrap_or_default();
    if st.cfg.admin_secret.is_empty() || !crate::util::safe_equal(&given, &st.cfg.admin_secret) {
        return Err(Problem::new(401, "unauthorized", "The admin API needs the admin secret."));
    }
    if req.method != axum::http::Method::POST {
        return Err(Problem::new(405, "method_not_allowed", "POST it."));
    }
    if st.cfg.apps_db.is_none() {
        return Err(databases::unavailable());
    }
    let what = seg.get(2).map(String::as_str).unwrap_or("");
    if seg.len() > 3 || !matches!(what, "run" | "drill") {
        return Err(Problem::new(404, "not_found", "Nothing here."));
    }
    let list = st.db.call(|c| databases::all(c)).await?;
    let mut out = vec![];
    for d in list {
        let r = if what == "run" { backup(st, &d, "nightly", "admin").await } else { drill(st, &d).await };
        out.push(match r {
            Ok(v) => json!({ "database": d.name, "app_id": d.app_id, "result": v }),
            Err(e) => json!({ "database": d.name, "app_id": d.app_id, "error": e.body()["error"] }),
        });
    }
    if what == "run" {
        prune(st).await?;
    }
    Ok(crate::http::json(json!({ if what == "run" { "backups" } else { "drills" }: out })))
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; 32] = [7u8; 32];

    fn round(plain: &[u8]) {
        let mut enc = vec![];
        encrypt(&KEY, "db_1", plain, &mut enc).unwrap();
        let mut out = vec![];
        assert_eq!(decrypt(&KEY, "db_1", &enc[..], &mut out).unwrap(), plain.len() as u64);
        assert_eq!(out, plain);
    }

    #[test]
    fn encrypts_in_chunks_and_round_trips() {
        round(b"");
        round(b"hello");
        let big: Vec<u8> = (0..(2 * CHUNK + 1234)).map(|i| (i % 251) as u8).collect();
        round(&big);
        round(&big[..CHUNK]);
        round(&big[..2 * CHUNK]);
    }

    #[test]
    fn refuses_tampering_truncation_and_the_wrong_key_or_database() {
        let plain: Vec<u8> = (0..(CHUNK + 10)).map(|i| (i % 13) as u8).collect();
        let mut enc = vec![];
        encrypt(&KEY, "db_1", &plain[..], &mut enc).unwrap();
        let mut sink = vec![];
        assert!(decrypt(&KEY, "db_2", &enc[..], &mut sink).is_err(), "another database's");
        assert!(decrypt(&[8u8; 32], "db_1", &enc[..], &mut sink).is_err(), "another key");
        let first_chunk = 16 + 5 + CHUNK + 16;
        assert!(decrypt(&KEY, "db_1", &enc[..first_chunk], &mut sink).is_err(), "the last chunk dropped");
        assert!(decrypt(&KEY, "db_1", &enc[..enc.len() - 1], &mut sink).is_err(), "cut short");
        let mut flipped = enc.clone();
        flipped[40] ^= 1;
        assert!(decrypt(&KEY, "db_1", &flipped[..], &mut sink).is_err(), "a changed byte");
        let mut early_end = enc.clone();
        early_end[16] = 1; // the first chunk claims to be the last
        assert!(decrypt(&KEY, "db_1", &early_end[..], &mut sink).is_err(), "a moved end");
        let mut extra = enc.clone();
        extra.push(0);
        assert!(decrypt(&KEY, "db_1", &extra[..], &mut sink).is_err(), "data after the end");
        assert!(decrypt(&KEY, "db_1", &b"not a backup at all"[..], &mut sink).is_err());
    }

    #[test]
    fn derives_the_key_from_secrets_key() {
        assert_eq!(key("a-long-enough-secrets-key").unwrap(), key("a-long-enough-secrets-key").unwrap());
        assert_ne!(key("a-long-enough-secrets-key").unwrap(), key("another-long-secrets-key").unwrap());
        assert_eq!(key("short").unwrap_err().code, "secrets_unavailable");
    }

    #[test]
    fn keeps_seven_daily_and_four_weekly() {
        // 2026-10-05 was a Monday. Two backups a day for 40 days, from then on.
        let monday = 1_791_158_400_000i64;
        let list: Vec<(String, i64)> =
            (0..80).map(|i| (format!("b{i:02}"), monday + (i / 2) as i64 * DAY_MS + (i % 2) as i64 * 3_600_000)).collect();
        let kept = keep(&list);
        // Days 33..39: the later backup of each (odd indexes 67..79).
        for day in 33..40 {
            assert!(kept.contains(&format!("b{:02}", day * 2 + 1)), "day {day}");
        }
        // Weeks: day 39 is in week 5 (days 35-41); weeks 4, 3 and 2 end on days 34, 27 and 20.
        for day in [34, 27, 20] {
            assert!(kept.contains(&format!("b{:02}", day * 2 + 1)), "week ending on day {day}");
        }
        assert_eq!(kept.len(), 7 + 2, "the newest two weeks' newest are daily ones already");
        assert!(!kept.contains("b00"));
        assert_eq!(keep(&[("only".into(), 5)]).len(), 1, "a lone backup is kept");
    }

    #[test]
    fn compares_row_counts() {
        let a = json!({ "public.notes": 3, "public.users": 1 });
        let a = a.as_object().unwrap();
        assert!(compare(a, a).is_ok());
        let b = json!({ "public.notes": 2, "public.users": 1, "public.extra": 0 });
        let err = compare(a, b.as_object().unwrap()).unwrap_err();
        assert!(err.contains("public.notes: 3 expected, 2 restored") && err.contains("public.extra"), "{err}");
    }

    #[test]
    fn stamps_keys() {
        assert_eq!(stamp(1_793_485_800_123), "20261031T223000123Z");
    }
}
