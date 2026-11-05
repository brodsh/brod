// SPDX-License-Identifier: AGPL-3.0-only
// The content-addressed version store. A version is a manifest (path, sha256, size, mode for every file, sorted by
// path) in the database; each distinct file content is stored once in Storage at "blobs/<sha256>", whatever backend
// (a folder or S3) Storage is. Deploying a new version writes only the blobs the store does not have yet, and every
// way of reading a version's files (serving, get_files, downloads, publishing to the marketplace, server modules) goes
// through its manifest.
//
// Versions deployed before this layout exist as one object per file under "<app>/<n>/<path>". They are converted the
// first time they are read (`manifest`): the files become blobs, the manifest row is committed, and only then are the
// old objects deleted. Nothing happens at startup, so a large instance never waits on it.
//
// Blobs nothing refers to any more are removed by `gc`, which runs hourly and after a version or app is deleted. It
// leaves a blob alone until it is `GC_GRACE_MS` old (or last reused), so a deploy that has stored its blobs but not yet
// committed its manifest never loses them.
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, OnceLock};

use bytes::Bytes;
use serde_json::{Value, json};

use crate::db::{Connection, Sql, params, tx};
use crate::market::read_tree;
use crate::problem::{Problem, Result};
use crate::state::State;
use crate::storage::Object;
use crate::tar::{BundleFile, FILE_BYTES};
use crate::util::{content_type, now};

/// A blob is deleted only once nothing refers to it and it is older than this (or was last reused this long ago).
pub const GC_GRACE_MS: i64 = 3_600_000;

/// Manifests kept in memory for serving. They never change once written, so the cache needs no expiry.
const CACHE_MAX: usize = 512;

#[derive(Clone, Debug, PartialEq)]
pub struct Entry {
    pub path: String,
    pub sha256: String,
    pub size: i64,
    /// 0o644, or 0o755 for a file that starts with a shebang.
    pub mode: i64,
}

#[derive(Clone, Debug)]
pub struct Manifest {
    pub app_id: String,
    pub version: i64,
    pub parent: Option<i64>,
    /// The user who deployed it; None for a version converted from the old layout.
    pub author: Option<String>,
    pub note: String,
    pub created_at: i64,
    /// Sorted by path.
    pub entries: Vec<Entry>,
}

impl Manifest {
    pub fn get(&self, path: &str) -> Option<&Entry> {
        self.entries.binary_search_by(|e| e.path.as_str().cmp(path)).ok().map(|i| &self.entries[i])
    }
    pub fn bytes(&self) -> i64 {
        self.entries.iter().map(|e| e.size).sum()
    }
}

pub fn blob_key(sha256: &str) -> String {
    format!("blobs/{sha256}")
}

pub fn is_sha256(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

pub fn sha256_bytes(b: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(b))
}

fn mode_of(bytes: &[u8]) -> i64 {
    if bytes.starts_with(b"#!") { 0o755 } else { 0o644 }
}

/// A file ready to store: its manifest entry and its bytes.
pub type Prepared = Vec<(Entry, Bytes)>;

/// Hash the files and sort them by path. A path given twice keeps its last content, as unpacking an archive always did.
pub fn prepare(files: Vec<BundleFile>) -> Prepared {
    let mut by_path: HashMap<String, Bytes> = HashMap::with_capacity(files.len());
    for f in files {
        by_path.insert(f.path, Bytes::from(f.bytes));
    }
    let mut out: Prepared = by_path
        .into_iter()
        .map(|(path, bytes)| (Entry { sha256: sha256_bytes(&bytes), size: bytes.len() as i64, mode: mode_of(&bytes), path }, bytes))
        .collect();
    out.sort_by(|a, b| a.0.path.cmp(&b.0.path));
    out
}

// ---------- the manifest cache ----------

type Key = (String, i64);

fn cache() -> &'static Mutex<HashMap<Key, Arc<Manifest>>> {
    static CACHE: OnceLock<Mutex<HashMap<Key, Arc<Manifest>>>> = OnceLock::new();
    CACHE.get_or_init(Default::default)
}

fn cached(app_id: &str, n: i64) -> Option<Arc<Manifest>> {
    cache().lock().ok()?.get(&(app_id.to_string(), n)).cloned()
}

fn remember(m: Manifest) -> Arc<Manifest> {
    let m = Arc::new(m);
    if let Ok(mut c) = cache().lock() {
        if c.len() >= CACHE_MAX {
            c.clear();
        }
        c.insert((m.app_id.clone(), m.version), m.clone());
    }
    m
}

fn forget(app_id: &str, version: Option<i64>) {
    if let Ok(mut c) = cache().lock() {
        c.retain(|(a, n), _| !(a == app_id && version.is_none_or(|v| v == *n)));
    }
}

// ---------- the database side ----------

pub fn load_manifest(conn: &Connection, app_id: &str, n: i64) -> Result<Option<Manifest>> {
    let head = conn.first(
        "SELECT parent, author, note, created_at FROM version_manifests WHERE app_id = ? AND version = ?",
        params![app_id, n],
        |r| Ok((r.get::<_, Option<i64>>(0)?, r.get::<_, Option<String>>(1)?, r.get::<_, String>(2)?, r.get::<_, i64>(3)?)),
    )?;
    let Some((parent, author, note, created_at)) = head else { return Ok(None) };
    let entries = conn.all(
        "SELECT path, sha256, size, mode FROM manifest_entries WHERE app_id = ? AND version = ? ORDER BY path",
        params![app_id, n],
        |r| Ok(Entry { path: r.get(0)?, sha256: r.get(1)?, size: r.get(2)?, mode: r.get(3)? }),
    )?;
    let mut m = Manifest { app_id: app_id.into(), version: n, parent, author, note, created_at, entries };
    // The database sorts text its own way; lookups by path need byte order.
    m.entries.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(Some(m))
}

/// Record a version's manifest. Call it in the transaction that inserts the `versions` row. A manifest that already
/// exists (two readers converting one old version at once) is left as it is.
pub fn insert_manifest(conn: &Connection, m: &Manifest) -> Result<()> {
    let added = conn.run(
        "INSERT INTO version_manifests (app_id, version, parent, author, note, created_at, file_count, bytes) VALUES (?,?,?,?,?,?,?,?) \
         ON CONFLICT (app_id, version) DO NOTHING",
        params![m.app_id, m.version, m.parent, m.author, m.note, m.created_at, m.entries.len() as i64, m.bytes()],
    )?;
    if added == 0 {
        return Ok(());
    }
    for e in &m.entries {
        conn.run(
            "INSERT INTO manifest_entries (app_id, version, path, sha256, size, mode) VALUES (?,?,?,?,?,?)",
            params![m.app_id, m.version, e.path, e.sha256, e.size, e.mode],
        )?;
    }
    Ok(())
}

/// What storing these files would add to the app's storage: the bytes of the contents it does not hold in any version.
pub fn new_bytes(conn: &Connection, app_id: &str, entries: &[Entry]) -> Result<i64> {
    let have: HashSet<String> = conn
        .all("SELECT DISTINCT sha256 FROM manifest_entries WHERE app_id = ?", [app_id], |r| r.get::<_, String>(0))?
        .into_iter()
        .collect();
    let mut seen = HashSet::new();
    Ok(entries.iter().filter(|e| !have.contains(&e.sha256) && seen.insert(e.sha256.as_str())).map(|e| e.size).sum())
}

/// What an app's versions use: each distinct content once, plus the full size of versions not converted yet.
pub fn app_bytes(conn: &Connection, app_id: &str) -> Result<i64> {
    Ok(conn
        .count("SELECT COALESCE(SUM(size), 0) FROM (SELECT DISTINCT sha256, size FROM manifest_entries WHERE app_id = ?) t", [app_id])?
        + conn.count(
            "SELECT COALESCE(SUM(v.bytes), 0) FROM versions v WHERE v.app_id = ? \
         AND NOT EXISTS (SELECT 1 FROM version_manifests m WHERE m.app_id = v.app_id AND m.version = v.n)",
            [app_id],
        )?)
}

/// Forget a version's manifest (its blobs go when `gc` finds nothing refers to them).
pub fn delete_manifest(conn: &Connection, app_id: &str, n: i64) -> Result<()> {
    conn.run("DELETE FROM manifest_entries WHERE app_id = ? AND version = ?", params![app_id, n])?;
    conn.run("DELETE FROM version_manifests WHERE app_id = ? AND version = ?", params![app_id, n])?;
    forget(app_id, Some(n));
    Ok(())
}

/// Drop an app's manifests from the in-memory cache (its rows go with the app).
pub fn forget_app(app_id: &str) {
    forget(app_id, None);
}

// ---------- blobs ----------

/// Store the blobs of these files that the store does not have, then record (or refresh) them in `blobs`.
pub async fn store_blobs(st: &State, files: &Prepared) -> Result<()> {
    let mut seen = HashSet::new();
    let unique: Vec<(&Entry, &Bytes)> = files.iter().filter(|(e, _)| seen.insert(e.sha256.as_str())).map(|(e, b)| (e, b)).collect();
    for chunk in unique.chunks(20) {
        futures_util::future::try_join_all(chunk.iter().map(|(e, bytes)| async move {
            let key = blob_key(&e.sha256);
            if st.store.head(&key).await?.is_none() {
                st.store.put(&key, (*bytes).clone(), Some("application/octet-stream")).await?;
            }
            Ok::<_, Problem>(())
        }))
        .await?;
    }
    let rows: Vec<(String, i64)> = unique.iter().map(|(e, _)| (e.sha256.clone(), e.size)).collect();
    st.db
        .call(move |conn| {
            tx(conn, |x| {
                let t = now();
                for (sha, size) in &rows {
                    // Reusing a blob restarts its grace period; see `gc`.
                    if x.run("UPDATE blobs SET created_at = ? WHERE sha256 = ?", params![t, sha])? == 0 {
                        x.run(
                            "INSERT INTO blobs (sha256, size, created_at) VALUES (?,?,?) ON CONFLICT (sha256) DO UPDATE SET created_at = excluded.created_at",
                            params![sha, size, t],
                        )?;
                    }
                }
                Ok(())
            })
        })
        .await
}

pub async fn read_blob(st: &State, sha256: &str, cap: usize) -> Result<Vec<u8>> {
    let key = blob_key(sha256);
    st.store.read(&key, cap).await?.ok_or_else(|| Problem::internal(format!("{key} is missing from the store")))
}

/// Delete the blobs nothing refers to that are older than `grace_ms`. The row goes first, in one statement that checks
/// again that nothing refers to it, then the object. Returns how many blobs were deleted.
pub async fn gc(st: &State, grace_ms: i64) -> Result<usize> {
    let mut deleted = 0;
    loop {
        let before = now() - grace_ms;
        let batch: Vec<String> = st
            .db
            .call(move |conn| {
                conn.all(
                    "SELECT b.sha256 FROM blobs b WHERE b.created_at < ? AND NOT EXISTS (SELECT 1 FROM manifest_entries e WHERE e.sha256 = b.sha256) \
                     ORDER BY b.created_at LIMIT 500",
                    [before],
                    |r| r.get::<_, String>(0),
                )
            })
            .await?;
        let full = batch.len() == 500;
        for sha in batch {
            let s2 = sha.clone();
            let claimed = st
                .db
                .call(move |conn| {
                    conn.run(
                        "DELETE FROM blobs WHERE sha256 = ? AND created_at < ? AND NOT EXISTS (SELECT 1 FROM manifest_entries e WHERE e.sha256 = blobs.sha256)",
                        params![s2, before],
                    )
                })
                .await?;
            if claimed == 1 {
                st.store.delete(&blob_key(&sha)).await?;
                deleted += 1;
            }
        }
        if !full {
            return Ok(deleted);
        }
    }
}

// ---------- reading a version ----------

/// A version's manifest, converting a version stored the old way on the way. None when there is no such version, or it
/// has no files here (a container app's version, whose source lives with its image).
pub async fn manifest(st: &State, app_id: &str, n: i64) -> Result<Option<Arc<Manifest>>> {
    if let Some(m) = cached(app_id, n) {
        return Ok(Some(m));
    }
    // A marketplace preview sandbox serves a release from "<listing>/<n>/" (preview.rs); it has no versions.
    if app_id.starts_with("lst_") {
        return Ok(None);
    }
    let a = app_id.to_string();
    let loaded = st.db.call(move |conn| load_manifest(conn, &a, n)).await?;
    if let Some(m) = loaded {
        return Ok(Some(remember(m)));
    }
    convert(st, app_id, n).await
}

/// Turn a version stored the old way (one object per file) into a manifest and blobs. The old objects are deleted only
/// after the manifest is committed.
async fn convert(st: &State, app_id: &str, n: i64) -> Result<Option<Arc<Manifest>>> {
    let a = app_id.to_string();
    let row = st
        .db
        .call(move |conn| {
            conn.first("SELECT note, created_at, based_on FROM versions WHERE app_id = ? AND n = ?", params![a, n], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?, r.get::<_, Option<i64>>(2)?))
            })
        })
        .await?;
    let Some((note, created_at, parent)) = row else { return Ok(None) };
    let prefix = format!("{app_id}/{n}/");
    let files = read_tree(st, &prefix).await?;
    if files.is_empty() {
        // Another request may have converted it, and deleted the old objects, between our two looks.
        let a = app_id.to_string();
        return Ok(st.db.call(move |conn| load_manifest(conn, &a, n)).await?.map(remember));
    }
    let prepared = prepare(files);
    store_blobs(st, &prepared).await?;
    let m = Manifest {
        app_id: app_id.into(),
        version: n,
        parent,
        author: None,
        note,
        created_at,
        entries: prepared.iter().map(|(e, _)| e.clone()).collect(),
    };
    let a = app_id.to_string();
    let stored = st
        .db
        .call(move |conn| {
            tx(conn, |x| {
                // Not for a version deleted while we were reading it.
                if x.exists("SELECT 1 FROM versions WHERE app_id = ? AND n = ?", params![m.app_id, n])? {
                    insert_manifest(x, &m)?;
                }
                Ok(())
            })?;
            load_manifest(conn, &a, n)
        })
        .await?;
    let Some(stored) = stored else { return Ok(None) };
    st.store.delete_prefix(&prefix).await?;
    Ok(Some(remember(stored)))
}

/// One file of a version, ready to serve: content type from its path, ETag from its content.
pub async fn open_file(st: &State, app_id: &str, n: i64, path: &str) -> Result<Option<Object>> {
    match manifest(st, app_id, n).await? {
        Some(m) => {
            let Some(e) = m.get(path) else { return Ok(None) };
            let Some(mut obj) = st.store.get(&blob_key(&e.sha256)).await? else {
                return Err(Problem::internal(format!("{} is missing from the store", blob_key(&e.sha256))));
            };
            obj.meta.content_type = Some(content_type(path).to_string());
            obj.meta.etag = e.sha256.clone();
            Ok(Some(obj))
        }
        None => st.store.get(&format!("{app_id}/{n}/{path}")).await,
    }
}

/// One file of a version into memory (a server app's code modules).
pub async fn read_file(st: &State, app_id: &str, n: i64, path: &str, cap: usize) -> Result<Option<Vec<u8>>> {
    match open_file(st, app_id, n, path).await? {
        Some(o) => Ok(Some(crate::http::read_capped(o.body, cap, "The file").await?)),
        None => Ok(None),
    }
}

/// Every file of a version, in path order.
pub async fn read_files(st: &State, app_id: &str, n: i64) -> Result<Vec<BundleFile>> {
    let Some(m) = manifest(st, app_id, n).await? else {
        let mut files = read_tree(st, &format!("{app_id}/{n}/")).await?;
        files.sort_by(|a, b| a.path.cmp(&b.path));
        return Ok(files);
    };
    let mut out = Vec::with_capacity(m.entries.len());
    for chunk in m.entries.chunks(20) {
        let got = futures_util::future::try_join_all(chunk.iter().map(|e| async move {
            Ok::<_, Problem>(BundleFile { path: e.path.clone(), bytes: read_blob(st, &e.sha256, FILE_BYTES).await? })
        }))
        .await?;
        out.extend(got);
    }
    Ok(out)
}

/// How two versions differ.
#[derive(Clone, Debug, PartialEq)]
pub struct Change<'a> {
    pub path: &'a str,
    /// "added", "modified" or "deleted".
    pub status: &'static str,
    pub from: Option<&'a Entry>,
    pub to: Option<&'a Entry>,
}

/// The paths that differ between two manifests, in path order.
pub fn changes<'a>(from: &'a Manifest, to: &'a Manifest) -> Vec<Change<'a>> {
    let mut out = Vec::new();
    for e in &to.entries {
        match from.get(&e.path) {
            None => out.push(Change { path: &e.path, status: "added", from: None, to: Some(e) }),
            Some(f) if f.sha256 != e.sha256 => out.push(Change { path: &e.path, status: "modified", from: Some(f), to: Some(e) }),
            Some(_) => {}
        }
    }
    for f in &from.entries {
        if to.get(&f.path).is_none() {
            out.push(Change { path: &f.path, status: "deleted", from: Some(f), to: None });
        }
    }
    out.sort_by(|a, b| a.path.cmp(b.path));
    out
}

/// A manifest as JSON, for answers that list a version's files without their content.
pub fn entries_json(entries: &[Entry]) -> Value {
    Value::Array(entries.iter().map(|e| json!({ "path": e.path, "sha256": e.sha256, "size": e.size, "mode": e.mode })).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::StorageConfig;

    fn file(path: &str, text: &str) -> BundleFile {
        BundleFile { path: path.into(), bytes: text.as_bytes().to_vec() }
    }

    async fn state() -> (State, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!("brod-versions-{}", crate::util::random_id("", 8)));
        let mut cfg = crate::config::Config::for_tests();
        cfg.storage = StorageConfig::Fs { dir: dir.clone() };
        (crate::state::AppState::new(cfg, crate::db::test_db()), dir)
    }

    #[test]
    fn manifests_are_sorted_deduplicated_and_hashed() {
        let p = prepare(vec![file("b.txt", "B"), file("a.txt", "A"), file("b.txt", "B2"), file("run.sh", "#!/bin/sh\n")]);
        let paths: Vec<&str> = p.iter().map(|(e, _)| e.path.as_str()).collect();
        assert_eq!(paths, ["a.txt", "b.txt", "run.sh"]);
        assert_eq!(p[1].0.sha256, sha256_bytes(b"B2"));
        assert_eq!((p[0].0.mode, p[2].0.mode), (0o644, 0o755));
        assert!(is_sha256(&p[0].0.sha256) && !is_sha256("ABC"));
    }

    #[test]
    fn changes_between_manifests() {
        let m = |files: Vec<BundleFile>| Manifest {
            app_id: "a".into(),
            version: 1,
            parent: None,
            author: None,
            note: String::new(),
            created_at: 0,
            entries: prepare(files).into_iter().map(|(e, _)| e).collect(),
        };
        let a = m(vec![file("index.html", "1"), file("old.css", "x"), file("same.js", "s")]);
        let b = m(vec![file("index.html", "2"), file("new.js", "n"), file("same.js", "s")]);
        let got: Vec<(&str, &str)> = changes(&a, &b).iter().map(|c| (c.path, c.status)).collect();
        assert_eq!(got, [("index.html", "modified"), ("new.js", "added"), ("old.css", "deleted")]);
    }

    #[tokio::test]
    async fn identical_content_is_stored_once_and_collected_when_unused() {
        let (st, dir) = state().await;
        let one = prepare(vec![file("index.html", "<h1>hi</h1>"), file("copy.html", "<h1>hi</h1>"), file("a.js", "a")]);
        store_blobs(&st, &one).await.unwrap();
        // The same content again, in another version: no new blobs.
        store_blobs(&st, &one).await.unwrap();
        let (n, _) = st.store.list("blobs/", None, 100).await.unwrap();
        assert_eq!(n.len(), 2, "two distinct contents");
        assert_eq!(st.db.call(|c| c.count("SELECT COUNT(*) FROM blobs", ())).await.unwrap(), 2);

        // Reference one blob from a manifest; collect the rest once they are past the grace period.
        let m = Manifest {
            app_id: "app_g".into(),
            version: 1,
            parent: None,
            author: Some("usr_x".into()),
            note: "n".into(),
            created_at: 1,
            entries: vec![one[0].0.clone()],
        };
        let m2 = m.clone();
        st.db.call(move |c| insert_manifest(c, &m2)).await.unwrap();
        assert_eq!(gc(&st, GC_GRACE_MS).await.unwrap(), 0, "nothing is old enough");
        assert_eq!(gc(&st, -1).await.unwrap(), 1, "the unreferenced blob goes, the referenced one stays");
        let loaded = st.db.call(|c| load_manifest(c, "app_g", 1)).await.unwrap().unwrap();
        assert_eq!(loaded.entries, m.entries);
        assert!(st.store.head(&blob_key(&m.entries[0].sha256)).await.unwrap().is_some());
        // Deleting the manifest frees the last blob.
        st.db.call(|c| delete_manifest(c, "app_g", 1)).await.unwrap();
        assert_eq!(gc(&st, -1).await.unwrap(), 1);
        assert!(st.store.list("blobs/", None, 100).await.unwrap().0.is_empty());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn an_old_bundle_is_converted_on_first_read_and_its_objects_removed() {
        let (st, dir) = state().await;
        st.db
            .call(|c| {
                c.run("INSERT INTO workspaces (id, slug, name, created_at) VALUES ('ws_m','m','M',1)", ())?;
                c.run("INSERT INTO users (id, email, created_at) VALUES ('usr_m','m@e.test',1)", ())?;
                c.run("INSERT INTO apps (id, workspace_id, owner_id, slug, name, created_at) VALUES ('app_m','ws_m','usr_m','m','M',1)", ())?;
                c.run(
                    "INSERT INTO versions (app_id, n, note, actor, file_count, bytes, created_at) VALUES ('app_m', 1, 'old', 'm@e.test', 2, 5, 77)",
                    (),
                )?;
                Ok(())
            })
            .await
            .unwrap();
        for (p, t) in [("index.html", "<p>old</p>"), ("css/app.css", "body{}")] {
            st.store.put(&format!("app_m/1/{p}"), Bytes::from(t.as_bytes().to_vec()), Some("text/plain")).await.unwrap();
        }
        let m = manifest(&st, "app_m", 1).await.unwrap().expect("converted");
        assert_eq!(m.entries.iter().map(|e| e.path.as_str()).collect::<Vec<_>>(), ["css/app.css", "index.html"]);
        assert_eq!((m.created_at, m.note.as_str(), m.author.clone()), (77, "old", None));
        assert!(st.store.list("app_m/1/", None, 10).await.unwrap().0.is_empty(), "old objects deleted after conversion");
        let files = read_files(&st, "app_m", 1).await.unwrap();
        assert_eq!(files[1].bytes, b"<p>old</p>");
        let served = open_file(&st, "app_m", 1, "index.html").await.unwrap().unwrap();
        assert_eq!(served.meta.content_type.as_deref(), Some("text/html; charset=utf-8"));
        assert!(open_file(&st, "app_m", 1, "missing").await.unwrap().is_none());
        // A version that does not exist has no manifest.
        assert!(manifest(&st, "app_m", 2).await.unwrap().is_none());
        // What the app now uses counts unique blob bytes.
        let added = st
            .db
            .call(|c| {
                new_bytes(
                    c,
                    "app_m",
                    &prepare(vec![file("x", "<p>old</p>"), file("y", "zz")]).iter().map(|p| p.0.clone()).collect::<Vec<_>>(),
                )
            })
            .await
            .unwrap();
        assert_eq!(added, 2);
        let _ = std::fs::remove_dir_all(dir);
    }
}
