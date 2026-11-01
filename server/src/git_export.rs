// SPDX-License-Identifier: AGPL-3.0-only
// Git export: an app's versions as a git repository, built from the version manifests (versions.rs) and never stored.
//
// The mapping is deterministic, so exporting twice gives the same commit ids and a person who clones, works and pushes
// back through an import is talking about the same history:
//   * a manifest becomes nested trees: entries sorted by name with a directory compared as "name/", modes 100644,
//     100755 (an executable file) and 40000;
//   * a version becomes a commit whose parent is the commit of the version it was built on (the manifest's parent; none
//     if that version has no files any more), authored and committed by the person who deployed it at the version's
//     creation time in UTC, with the version's note (or "Version N") and a "Brod-Version: N" trailer;
//   * refs: HEAD and refs/heads/main are the live version, refs/heads/staging the version waiting on staging, and
//     refs/tags/vN every version.
// Commit authors carry a noreply address (`<user id>@users.noreply.<apps domain>`) unless the operator turned on
// git.real_emails: an export can be shared outside the workspace, and an email address should not travel with it.
// Secrets are not files of a version, so they are not in an export (the code here never reads them).
//
// `plan` computes the history and the refs; `Plan::pack` writes the objects. Both a bundle download and the read-only
// smart HTTP endpoints (git clone https://...) are built on them.
use std::collections::{BTreeMap, HashMap, HashSet};

use axum::response::Response;
use futures_util::future::try_join_all;
use serde_json::{Value, json};

use crate::control::{self, Credentials};
use crate::db::{Sql, params, tx};
use crate::git::{self, Ident, Kind, MODE_DIR, MODE_EXEC, MODE_FILE, Oid, PackWriter, TreeEntry};
use crate::http::{Req, response};
use crate::model::{Caller, limits};
use crate::people::require_role;
use crate::problem::{Problem, Result};
use crate::state::State;
use crate::tar::FILE_BYTES;
use crate::util::{now, random_id};
use crate::versions;

/// The most file content (before compression) one export holds in memory.
pub const EXPORT_BYTES: i64 = 256 * 1024 * 1024;

// ---------- the pure mapping ----------

pub struct FileIn {
    pub path: String,
    pub oid: Oid,
    /// 0o755 for an executable, anything else is a plain file.
    pub mode: i64,
}

pub struct VersionIn {
    pub n: i64,
    pub parent: Option<i64>,
    /// Name and address for the commit; None for a version converted from the old layout.
    pub author: Option<(String, String)>,
    /// Milliseconds since the epoch.
    pub created_at: i64,
    pub note: String,
    pub files: Vec<FileIn>,
}

#[derive(Clone, Copy, Debug)]
pub struct CommitOut {
    pub commit: Oid,
    pub tree: Oid,
}

type Object = (Oid, Kind, Vec<u8>);

#[derive(Default)]
pub struct History {
    pub commits: BTreeMap<i64, CommitOut>,
    /// Trees and commits, each once.
    pub objects: Vec<Object>,
}

enum Node {
    File(u32, Oid),
    Dir(BTreeMap<String, Node>),
}

fn insert(dir: &mut BTreeMap<String, Node>, parts: &[&str], mode: u32, oid: Oid, whole: &str) -> Result<()> {
    let clash = || Problem::new(409, "path_conflict", format!("\"{whole}\" is both a file and a folder, which git cannot represent."));
    match parts {
        [] => Ok(()),
        [name] => match dir.get(*name) {
            Some(Node::Dir(_)) => Err(clash()),
            _ => {
                dir.insert((*name).to_string(), Node::File(mode, oid));
                Ok(())
            }
        },
        [name, rest @ ..] => {
            let sub = dir.entry((*name).to_string()).or_insert_with(|| Node::Dir(BTreeMap::new()));
            match sub {
                Node::Dir(d) => insert(d, rest, mode, oid, whole),
                Node::File(..) => Err(clash()),
            }
        }
    }
}

fn write_tree(dir: &BTreeMap<String, Node>, seen: &mut HashSet<Oid>, out: &mut Vec<Object>) -> Oid {
    let mut entries: Vec<TreeEntry> = dir
        .iter()
        .map(|(name, node)| match node {
            Node::File(mode, oid) => TreeEntry { mode: *mode, name: name.clone(), oid: *oid },
            Node::Dir(d) => TreeEntry { mode: MODE_DIR, name: name.clone(), oid: write_tree(d, seen, out) },
        })
        .collect();
    let data = git::encode_tree(&mut entries);
    let oid = git::object_oid(Kind::Tree, &data);
    if seen.insert(oid) {
        out.push((oid, Kind::Tree, data));
    }
    oid
}

/// The tree of a set of files; returns its id and adds the trees it needs to `out`.
pub fn tree_of(files: &[FileIn], seen: &mut HashSet<Oid>, out: &mut Vec<Object>) -> Result<Oid> {
    let mut root = BTreeMap::new();
    for f in files {
        let parts: Vec<&str> = f.path.split('/').collect();
        let mode = if f.mode & 0o111 != 0 { MODE_EXEC } else { MODE_FILE };
        insert(&mut root, &parts, mode, f.oid, &f.path)?;
    }
    Ok(write_tree(&root, seen, out))
}

/// A version's commit message: its note, then the trailer that says which version it is.
pub fn message(n: i64, note: &str) -> String {
    let note = note.trim();
    let subject = if note.is_empty() { format!("Version {n}") } else { note.to_string() };
    format!("{subject}\n\nBrod-Version: {n}\n")
}

/// Commits for versions given in ascending order. A version's parent commit is its manifest parent's, when that
/// version is in the list; otherwise the commit is a root.
pub fn build(versions: &[VersionIn]) -> Result<History> {
    let mut h = History::default();
    let mut seen = HashSet::new();
    for v in versions {
        let tree = tree_of(&v.files, &mut seen, &mut h.objects)?;
        let parents: Vec<Oid> = v.parent.and_then(|p| h.commits.get(&p)).map(|c| vec![c.commit]).unwrap_or_default();
        let (name, email) = v.author.clone().unwrap_or_else(|| ("Brod".to_string(), "brod@users.noreply.invalid".to_string()));
        let who = Ident { name, email, time: v.created_at.div_euclid(1000) };
        let data = git::encode_commit(&tree, &parents, &who, &who, &message(v.n, &v.note));
        let commit = git::object_oid(Kind::Commit, &data);
        if seen.insert(commit) {
            h.objects.push((commit, Kind::Commit, data));
        }
        h.commits.insert(v.n, CommitOut { commit, tree });
    }
    Ok(h)
}

/// The refs of an export, HEAD first and the rest sorted by name.
pub fn refs_of(h: &History, live: Option<i64>, staging: Option<i64>) -> Vec<(String, Oid)> {
    let commit = |n: Option<i64>| n.and_then(|n| h.commits.get(&n)).map(|c| c.commit);
    let newest = h.commits.keys().next_back().copied();
    let Some(main) = commit(live).or_else(|| commit(staging)).or_else(|| commit(newest)) else { return Vec::new() };
    let mut refs: Vec<(String, Oid)> = vec![("refs/heads/main".into(), main)];
    if let Some(s) = commit(staging) {
        refs.push(("refs/heads/staging".into(), s));
    }
    for (n, c) in &h.commits {
        refs.push((format!("refs/tags/v{n}"), c.commit));
    }
    refs.sort_by(|a, b| a.0.cmp(&b.0));
    refs.insert(0, ("HEAD".into(), main));
    refs
}

// ---------- the plan ----------

pub struct Plan {
    pub slug: String,
    /// HEAD first.
    pub refs: Vec<(String, Oid)>,
    pub history: History,
    /// Each distinct file once: its git id, the sha256 it is stored under and its size.
    blobs: Vec<(Oid, String, i64)>,
}

impl Plan {
    /// Every commit of the export.
    pub fn commit_ids(&self) -> HashSet<Oid> {
        self.history.commits.values().map(|c| c.commit).collect()
    }

    /// The pack of every object.
    pub async fn pack(&self, st: &State) -> Result<Vec<u8>> {
        let mut w = PackWriter::new();
        for (_, kind, data) in &self.history.objects {
            w.add(*kind, data);
        }
        for chunk in self.blobs.chunks(16) {
            let got = try_join_all(chunk.iter().map(|(_, sha, _)| versions::read_blob(st, sha, FILE_BYTES))).await?;
            for data in got {
                w.add(Kind::Blob, &data);
            }
        }
        Ok(w.finish())
    }

    /// The commits reachable from `from` (itself included) that this export holds, following parents.
    pub fn ancestors_of(&self, from: Oid) -> HashSet<Oid> {
        let parents: HashMap<Oid, Vec<Oid>> = self
            .history
            .objects
            .iter()
            .filter(|(_, k, _)| *k == Kind::Commit)
            .filter_map(|(o, _, d)| git::parse_commit(d).ok().map(|c| (*o, c.parents)))
            .collect();
        let mut seen = HashSet::new();
        let mut todo = vec![from];
        while let Some(o) = todo.pop() {
            if seen.insert(o) {
                todo.extend(parents.get(&o).into_iter().flatten().copied());
            }
        }
        seen
    }

    /// A pack of the objects reachable from the `want` commits that are not reachable from the `have` commits (what the
    /// other side already holds). `extra` are objects that are not part of the history, such as a commit that continues a
    /// remote branch.
    pub async fn pack_for(&self, st: &State, want: &[Oid], have: &[Oid], extra: &[Object]) -> Result<Vec<u8>> {
        let mut by_oid: HashMap<Oid, (Kind, &[u8])> = self.history.objects.iter().map(|(o, k, d)| (*o, (*k, d.as_slice()))).collect();
        for (o, k, d) in extra {
            by_oid.insert(*o, (*k, d.as_slice()));
        }
        let held = reachable(&by_oid, have);
        let mut need = reachable(&by_oid, want);
        need.retain(|o| !held.contains(o));
        let mut w = PackWriter::new();
        for (o, k, d) in self.history.objects.iter().chain(extra.iter()) {
            if need.contains(o) {
                w.add(*k, d);
            }
        }
        let blobs: Vec<&(Oid, String, i64)> = self.blobs.iter().filter(|(o, _, _)| need.contains(o)).collect();
        for chunk in blobs.chunks(16) {
            let got = try_join_all(chunk.iter().map(|(_, sha, _)| versions::read_blob(st, sha, FILE_BYTES))).await?;
            for data in got {
                w.add(Kind::Blob, &data);
            }
        }
        Ok(w.finish())
    }

    pub async fn bundle(&self, st: &State) -> Result<Vec<u8>> {
        Ok(git::bundle(&self.refs, &self.pack(st).await?))
    }
}

/// Every object reachable from the roots: commits to their parents and tree, trees to their entries. Objects not in
/// `objs` (a blob, or something the other side holds) are counted but not followed.
fn reachable(objs: &HashMap<Oid, (Kind, &[u8])>, roots: &[Oid]) -> HashSet<Oid> {
    let mut seen = HashSet::new();
    let mut todo: Vec<Oid> = roots.to_vec();
    while let Some(o) = todo.pop() {
        if !seen.insert(o) {
            continue;
        }
        match objs.get(&o) {
            Some((Kind::Commit, d)) => {
                if let Ok(c) = git::parse_commit(d) {
                    todo.push(c.tree);
                    todo.extend(c.parents);
                }
            }
            Some((Kind::Tree, d)) => {
                if let Ok(entries) = git::parse_tree(d) {
                    todo.extend(entries.into_iter().filter(|e| e.mode != git::MODE_GITLINK).map(|e| e.oid));
                }
            }
            _ => {}
        }
    }
    seen
}

/// The part of an apps domain that names a host: "brod.example:9000" becomes "brod.example".
fn noreply_domain(apps_domain: &str) -> &str {
    apps_domain.split(':').next().unwrap_or(apps_domain)
}

pub fn noreply_email(user_id: &str, apps_domain: &str) -> String {
    format!("{user_id}@users.noreply.{}", noreply_domain(apps_domain))
}

/// Compute the git history of an app the caller can read the files of. Records the ids in version_git_commits (the
/// index an import uses to find a merge base) and the blobs' git ids.
pub async fn plan(st: &State, c: &Caller, slug: &str) -> Result<Plan> {
    let (c2, slug2) = (c.clone(), slug.to_string());
    let app = st
        .db
        .call(move |conn| {
            require_role(&c2, "builder", "export an app")?;
            control::get_app(conn, &c2, &slug2)
        })
        .await?;
    plan_app(st, app).await
}

/// `plan` for an app whose access was checked already (a download address is its own credential).
pub async fn plan_app(st: &State, app: crate::model::AppRow) -> Result<Plan> {
    let slug = app.slug.clone();
    let slug = slug.as_str();
    let aid = app.id.clone();
    let (ns, known) = st
        .db
        .call(move |conn| {
            let ns: Vec<i64> = conn.all("SELECT n FROM versions WHERE app_id = ? ORDER BY n", params![aid], |r| r.get::<_, i64>("n"))?;
            let known: HashMap<String, Oid> = conn
                .all(
                    "SELECT sha256, git_oid FROM blobs WHERE git_oid IS NOT NULL AND sha256 IN (SELECT sha256 FROM manifest_entries WHERE app_id = ?)",
                    params![aid],
                    |r| Ok((r.get::<_, String>("sha256")?, r.get::<_, String>("git_oid")?)),
                )?
                .into_iter()
                .filter_map(|(s, o)| git::parse_oid(&o).map(|o| (s, o)))
                .collect();
            Ok((ns, known))
        })
        .await?;

    let mut manifests = Vec::new();
    for n in ns {
        if let Some(m) = versions::manifest(st, &app.id, n).await? {
            manifests.push(m);
        }
    }
    if manifests.is_empty() {
        return Err(Problem::new(409, "no_files", format!("{slug} has no versions with files to export.")));
    }

    // Git ids of the blobs the database does not know yet: read each once.
    let mut oids = known;
    let missing: Vec<String> = {
        let mut seen = HashSet::new();
        manifests
            .iter()
            .flat_map(|m| m.entries.iter())
            .filter(|e| !oids.contains_key(&e.sha256) && seen.insert(e.sha256.clone()))
            .map(|e| e.sha256.clone())
            .collect()
    };
    let mut learned: Vec<(String, Oid)> = Vec::new();
    for chunk in missing.chunks(16) {
        let got = try_join_all(chunk.iter().map(|sha| async move {
            let data = versions::read_blob(st, sha, FILE_BYTES).await?;
            Ok::<_, Problem>((sha.clone(), git::blob_oid(&data)))
        }))
        .await?;
        for (sha, oid) in got {
            oids.insert(sha.clone(), oid);
            learned.push((sha, oid));
        }
    }

    // Who wrote each version.
    let real_emails = crate::instance::current(st).await.flag("git.real_emails");
    let wanted: HashSet<String> = manifests.iter().filter_map(|m| m.author.clone()).collect();
    let mut people: HashMap<String, (String, String)> = HashMap::new();
    if !wanted.is_empty() {
        let domain = st.cfg.apps_domain.clone();
        people = st
            .db
            .call(move |conn| {
                let mut out = HashMap::new();
                for id in wanted {
                    let row = conn.first("SELECT name, email FROM users WHERE id = ?", params![id], |r| {
                        Ok((r.get::<_, String>("name")?, r.get::<_, String>("email")?))
                    })?;
                    let (name, email) = row.unwrap_or_default();
                    let shown = if !name.trim().is_empty() {
                        name.trim().to_string()
                    } else if let Some((local, _)) = email.split_once('@') {
                        local.to_string()
                    } else {
                        "Brod".to_string()
                    };
                    let address = if real_emails && email.contains('@') { email } else { noreply_email(&id, &domain) };
                    out.insert(id, (shown, address));
                }
                Ok(out)
            })
            .await?;
    }

    let inputs: Vec<VersionIn> = manifests
        .iter()
        .map(|m| VersionIn {
            n: m.version,
            parent: m.parent,
            author: m
                .author
                .as_ref()
                .map(|a| people.get(a).cloned().unwrap_or_else(|| ("Brod".to_string(), noreply_email(a, &st.cfg.apps_domain)))),
            created_at: m.created_at,
            note: m.note.clone(),
            files: m.entries.iter().map(|e| FileIn { path: e.path.clone(), oid: oids[&e.sha256], mode: e.mode }).collect(),
        })
        .collect();
    let history = build(&inputs)?;

    let mut blobs: Vec<(Oid, String, i64)> = Vec::new();
    let mut seen = HashSet::new();
    let mut total = 0i64;
    for m in &manifests {
        for e in &m.entries {
            if seen.insert(e.sha256.clone()) {
                total += e.size;
                blobs.push((oids[&e.sha256], e.sha256.clone(), e.size));
            }
        }
    }
    if total > EXPORT_BYTES {
        return Err(Problem::new(
            413,
            "too_large",
            format!("{slug}'s history is larger than {} MB, which is more than Brod exports at once.", EXPORT_BYTES / 1024 / 1024),
        ));
    }
    let refs = refs_of(&history, app.live_version, app.staging_version);

    // Remember the ids. Rewriting only what changed keeps a repeated export from writing to the database.
    let rows: Vec<(i64, String, String)> = history.commits.iter().map(|(n, c)| (*n, git::hex(&c.commit), git::hex(&c.tree))).collect();
    let app_id = app.id.clone();
    st.db
        .call(move |conn| {
            let have: HashMap<i64, String> = conn
                .all("SELECT version, commit_oid FROM version_git_commits WHERE app_id = ?", params![app_id], |r| {
                    Ok((r.get::<_, i64>("version")?, r.get::<_, String>("commit_oid")?))
                })?
                .into_iter()
                .collect();
            let stale: Vec<&(i64, String, String)> = rows.iter().filter(|(n, c, _)| have.get(n) != Some(c)).collect();
            if stale.is_empty() && learned.is_empty() {
                return Ok(());
            }
            tx(conn, |x| {
                for (n, commit, tree) in &stale {
                    // source_commit_oid is left alone: it records where an imported version came from.
                    x.run(
                        "INSERT INTO version_git_commits (app_id, version, commit_oid, tree_oid) VALUES (?,?,?,?) \
                         ON CONFLICT (app_id, version) DO UPDATE SET commit_oid = excluded.commit_oid, tree_oid = excluded.tree_oid",
                        params![app_id, *n, commit, tree],
                    )?;
                }
                for (sha, oid) in &learned {
                    x.run("UPDATE blobs SET git_oid = ? WHERE sha256 = ? AND git_oid IS NULL", params![git::hex(oid), sha])?;
                }
                Ok(())
            })
        })
        .await?;

    Ok(Plan { slug: app.slug, refs, history, blobs })
}

// ---------- the bundle download ----------

/// The app as a git bundle, and a file name for it.
pub async fn export_bundle(st: &State, c: &Caller, slug: &str) -> Result<(String, Vec<u8>)> {
    let p = plan(st, c, slug).await?;
    let body = p.bundle(st).await?;
    Ok((format!("{}.bundle", p.slug), body))
}

/// export_app: a short-lived download address for the bundle (a bundle is binary, so it always comes by address).
pub async fn export_app(st: &State, c: &Caller, slug: &str) -> Result<Value> {
    let (c2, slug2) = (c.clone(), slug.to_string());
    let (app_id, slug) = st
        .db
        .call(move |conn| {
            require_role(&c2, "builder", "export an app")?;
            let app = control::get_app(conn, &c2, &slug2)?;
            Ok((app.id, app.slug))
        })
        .await?;
    let id = random_id("dl_", 20);
    let (c3, id2) = (c.clone(), id.clone());
    st.db
        .call(move |conn| {
            conn.run(
                "INSERT INTO downloads (id, workspace_id, app_id, version, user_id, expires_at, kind) VALUES (?,?,?,?,?,?,'bundle')",
                params![id2, c3.workspace.id, app_id, 0i64, c3.user.id, now() + limits::DOWNLOAD_TTL_MS],
            )?;
            Ok(())
        })
        .await?;
    let url = format!("{}/v1/downloads/{id}", st.cfg.api_origin);
    let clone_url = format!("{}/v1/apps/{slug}.git", st.cfg.api_origin);
    Ok(json!({
        "app": slug,
        "format": "git-bundle",
        "download_url": url,
        "expires_in_seconds": limits::DOWNLOAD_TTL_MS / 1000,
        "clone_url": clone_url,
        "next_step": format!(
            "Fetch it with one command and clone it:\n  curl -sS --fail -o {slug}.bundle \"{url}\" && git clone {slug}.bundle {slug}\n\
             main is the live version, staging the version waiting on staging, and every version is a tag (v1, v2, ...). \
             Or clone directly: git clone {clone_url} (user name anything, password a Brod token). \
             Change the files, then bring the work back with import_app."
        ),
    }))
}

// ---------- read-only smart HTTP ----------

const ADVERTISEMENT: &str = "application/x-git-upload-pack-advertisement";
const RESULT: &str = "application/x-git-upload-pack-result";
const MAX_REQUEST: usize = 256 * 1024;

/// The pkt-line advertisement for `git-upload-pack`: HEAD with the capabilities, then the other refs.
pub fn advertisement(refs: &[(String, Oid)]) -> Vec<u8> {
    let mut out = git::pkt(b"# service=git-upload-pack\n");
    out.extend_from_slice(git::FLUSH);
    let caps = "ofs-delta agent=brod symref=HEAD:refs/heads/main";
    for (i, (name, oid)) in refs.iter().enumerate() {
        let line = if i == 0 { format!("{} {name}\0{caps}\n", git::hex(oid)) } else { format!("{} {name}\n", git::hex(oid)) };
        out.extend_from_slice(&git::pkt(line.as_bytes()));
    }
    if refs.is_empty() {
        out.extend_from_slice(&git::pkt(format!("{} capabilities^{{}}\0{caps}\n", "0".repeat(40)).as_bytes()));
    }
    out.extend_from_slice(git::FLUSH);
    out
}

pub struct UploadRequest {
    pub wants: Vec<Oid>,
    pub haves: Vec<Oid>,
    pub done: bool,
}

/// Read a (protocol v0/v1) upload-pack request: want lines, a flush, have lines and "done".
pub fn parse_upload_request(body: &[u8]) -> Result<UploadRequest> {
    let bad = |m: &str| Problem::new(400, "bad_request", m.to_string());
    let (mut wants, mut haves, mut done) = (Vec::new(), Vec::new(), false);
    let mut pos = 0;
    while let Some(p) = git::read_pkt(body, &mut pos).map_err(|e| bad(&e))? {
        let git::Pkt::Data(line) = p else { continue };
        let line = String::from_utf8_lossy(line);
        let line = line.trim_end_matches('\n');
        if let Some(rest) = line.strip_prefix("want ") {
            let oid = rest.split(' ').next().and_then(git::parse_oid).ok_or_else(|| bad("a want line has a bad object id"))?;
            wants.push(oid);
        } else if let Some(rest) = line.strip_prefix("have ") {
            haves.push(git::parse_oid(rest.trim()).ok_or_else(|| bad("a have line has a bad object id"))?);
        } else if line == "done" {
            done = true;
        } else if line.starts_with("deepen") || line.starts_with("shallow") || line.starts_with("filter") {
            return Err(bad("Brod does not support shallow or partial fetches; fetch the whole history"));
        }
    }
    Ok(UploadRequest { wants, haves, done })
}

/// Git's HTTP clients send the token as the password of Basic authentication (any user name); accept that and a
/// Bearer header alike.
fn git_credentials(req: &Req) -> Credentials {
    let mut cr = Credentials::of(req);
    if let Some(a) = cr.authorization.clone()
        && let Some((scheme, rest)) = a.split_once(' ')
        && scheme.eq_ignore_ascii_case("basic")
    {
        use base64::Engine;
        let decoded = base64::engine::general_purpose::STANDARD.decode(rest.trim()).ok().and_then(|b| String::from_utf8(b).ok());
        if let Some((_, pw)) = decoded.as_deref().and_then(|d| d.split_once(':')) {
            cr.authorization = Some(format!("Bearer {pw}"));
        }
    }
    cr
}

fn challenge() -> Response {
    response(
        401,
        "Sign in with a Brod token: use any user name and the token as the password.\n",
        &[("www-authenticate", "Basic realm=\"Brod\", charset=\"UTF-8\"".into()), ("content-type", "text/plain; charset=utf-8".into())],
    )
}

fn text(status: u16, msg: &str) -> Response {
    response(status, format!("{msg}\n"), &[("content-type", "text/plain; charset=utf-8".into()), ("cache-control", "no-store".into())])
}

/// `/v1/apps/<slug>.git/...`: the read-only half of git's smart HTTP protocol. Cloning and fetching work; pushing is
/// refused, because changes come back through import_app, which merges them.
pub async fn smart_http(st: &State, req: &mut Req, slug: &str, rest: &[&str]) -> Result<Response> {
    let service = req.param("service");
    // Pushing is refused before anything else, for a signed-in caller or not.
    if rest == ["git-receive-pack"] || service.as_deref() == Some("git-receive-pack") {
        return Ok(text(
            403,
            "Brod does not accept pushes. Send changes back with import_app (a git bundle or a url) so they merge with what others deployed.",
        ));
    }
    let cr = git_credentials(req);
    if cr.authorization.is_none() && cr.cookie.is_none() {
        return Ok(challenge());
    }
    let c = match control::authenticate_async(st, cr).await {
        Ok(c) => c,
        Err(e) if e.status == 401 => return Ok(challenge()),
        Err(e) => return Err(e),
    };
    st.calls.check(&c, crate::instance::current(st).await.int("rate.calls_per_minute"))?;
    match (req.method.as_str(), rest) {
        ("GET", ["info", "refs"]) => {
            if service.as_deref() != Some("git-upload-pack") {
                return Ok(text(403, "Only git-upload-pack (clone and fetch) is available; Brod has no dumb HTTP protocol."));
            }
            let p = plan(st, &c, slug).await?;
            Ok(response(200, advertisement(&p.refs), &[("content-type", ADVERTISEMENT.into()), ("cache-control", "no-cache".into())]))
        }
        ("POST", ["git-upload-pack"]) => {
            let body = req.bytes(MAX_REQUEST, "The request").await?;
            let want = parse_upload_request(&body)?;
            if want.wants.is_empty() {
                return Err(Problem::new(400, "bad_request", "The request wants nothing."));
            }
            let p = plan(st, &c, slug).await?;
            let known = p.commit_ids();
            if let Some(bad) = want.wants.iter().find(|w| !known.contains(*w)) {
                return Err(Problem::new(400, "bad_request", format!("not our ref {}", git::hex(bad))));
            }
            let mut out = git::pkt(b"NAK\n");
            if want.done {
                // The whole history is sent whatever the client already has: it is small, and git ignores objects it holds.
                out.extend_from_slice(&p.pack(st).await?);
            }
            Ok(response(200, out, &[("content-type", RESULT.into()), ("cache-control", "no-cache".into())]))
        }
        _ => Ok(text(404, "Not found.")),
    }
}

/// The app slug of a "<slug>.git" path segment.
pub fn git_slug(segment: &str) -> Option<&str> {
    segment.strip_suffix(".git").filter(|s| !s.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn f(path: &str, content: &[u8], mode: i64) -> FileIn {
        FileIn { path: path.into(), oid: git::blob_oid(content), mode }
    }

    fn fixture() -> Vec<VersionIn> {
        let v1 = vec![
            f("index.html", b"<h1>hi</h1>\n", 0o644),
            f("css/app.css", b"body{}\n", 0o644),
            f("bin/run", b"#!/bin/sh\necho hi\n", 0o755),
        ];
        let v2 = vec![
            f("index.html", b"<h1>hello</h1>\n", 0o644),
            f("css/app.css", b"body{}\n", 0o644),
            f("bin/run", b"#!/bin/sh\necho hi\n", 0o755),
        ];
        vec![
            VersionIn {
                n: 1,
                parent: None,
                author: Some(("Ada Lovelace".into(), "u_ada@users.noreply.brod.test".into())),
                created_at: 1_700_000_000_000,
                note: "First version".into(),
                files: v1,
            },
            VersionIn {
                n: 2,
                parent: Some(1),
                author: Some(("Brod".into(), "brod@users.noreply.brod.test".into())),
                created_at: 1_700_000_600_000,
                note: "".into(),
                files: v2,
            },
        ]
    }

    // These ids were computed with git itself (git write-tree and git commit-tree on the same files, author and date),
    // so they pin the format: tree ordering, modes, the commit header and the message.
    #[test]
    fn a_fixed_history_has_the_ids_real_git_gives_it() {
        let h = build(&fixture()).unwrap();
        assert_eq!(git::hex(&h.commits[&1].tree), "a5953fb17356130420dae9a83199eeb17682432c");
        assert_eq!(git::hex(&h.commits[&1].commit), "e88d4b63f45232b4f68c770495cd6b932cca07b0");
        assert_eq!(git::hex(&h.commits[&2].tree), "b1a779d81bf01bb8438d16dadde8f722cbbd91bc");
        assert_eq!(git::hex(&h.commits[&2].commit), "5761e131fcf69f4cfeed97fb68ac7bab7d6f75d2");
    }

    #[test]
    fn exporting_twice_gives_the_same_ids_and_objects_are_not_repeated() {
        let (a, b) = (build(&fixture()).unwrap(), build(&fixture()).unwrap());
        assert_eq!(a.commits[&2].commit, b.commits[&2].commit);
        let ids: Vec<Oid> = a.objects.iter().map(|o| o.0).collect();
        assert_eq!(ids.len(), ids.iter().collect::<HashSet<_>>().len());
        // 2 commits, 2 root trees, and the css/ and bin/ trees (shared by both versions): 6.
        assert_eq!(a.objects.len(), 6);
    }

    #[test]
    fn a_version_whose_parent_is_missing_is_a_root() {
        let mut v = fixture();
        v[1].parent = Some(7);
        let h = build(&v).unwrap();
        let data = &h.objects.iter().find(|o| o.0 == h.commits[&2].commit).unwrap().2;
        assert!(!String::from_utf8_lossy(data).contains("\nparent "));
    }

    #[test]
    fn refs_point_main_at_live_staging_at_staging_and_tag_every_version() {
        let h = build(&fixture()).unwrap();
        let r = refs_of(&h, Some(1), Some(2));
        let names: Vec<&str> = r.iter().map(|x| x.0.as_str()).collect();
        assert_eq!(names, ["HEAD", "refs/heads/main", "refs/heads/staging", "refs/tags/v1", "refs/tags/v2"]);
        assert_eq!(r[0].1, h.commits[&1].commit);
        assert_eq!(r[1].1, h.commits[&1].commit);
        assert_eq!(r[2].1, h.commits[&2].commit);
        // Nothing live: main follows staging.
        assert_eq!(refs_of(&h, None, Some(2))[1].1, h.commits[&2].commit);
        assert!(refs_of(&History::default(), Some(1), None).is_empty());
    }

    #[test]
    fn a_file_and_a_folder_with_one_name_cannot_be_exported() {
        let v = vec![VersionIn {
            n: 1,
            parent: None,
            author: None,
            created_at: 0,
            note: String::new(),
            files: vec![f("a", b"x", 0o644), f("a/b", b"y", 0o644)],
        }];
        assert_eq!(build(&v).err().map(|p| p.code), Some("path_conflict".to_string()));
    }

    #[test]
    fn emails_are_noreply_addresses_on_the_host_without_its_port() {
        assert_eq!(noreply_email("u_1", "localhost:9000"), "u_1@users.noreply.localhost");
        assert_eq!(noreply_email("u_1", "brod.example"), "u_1@users.noreply.brod.example");
    }

    #[test]
    fn the_advertisement_and_requests_follow_the_protocol() {
        let h = build(&fixture()).unwrap();
        let refs = refs_of(&h, Some(2), None);
        let adv = advertisement(&refs);
        let text = String::from_utf8_lossy(&adv).into_owned();
        assert!(text.starts_with("001e# service=git-upload-pack\n0000"));
        assert!(text.contains(" HEAD\0ofs-delta agent=brod symref=HEAD:refs/heads/main\n"));
        assert!(text.contains(" refs/tags/v1\n"));
        assert!(text.ends_with("0000"));
        assert!(String::from_utf8_lossy(&advertisement(&[])).contains("capabilities^{}"));

        let oid = git::hex(&refs[0].1);
        let mut body = git::pkt(format!("want {oid} ofs-delta agent=git/2\n").as_bytes());
        body.extend_from_slice(git::FLUSH);
        body.extend_from_slice(&git::pkt(format!("have {oid}\n").as_bytes()));
        body.extend_from_slice(&git::pkt(b"done\n"));
        let r = parse_upload_request(&body).unwrap();
        assert_eq!((r.wants.len(), r.haves.len(), r.done), (1, 1, true));
        let mut shallow = git::pkt(format!("want {oid}\n").as_bytes());
        shallow.extend_from_slice(&git::pkt(b"deepen 1\n"));
        assert!(parse_upload_request(&shallow).is_err());
        assert_eq!(git_slug("notes.git"), Some("notes"));
        assert_eq!(git_slug("notes"), None);
    }

    #[test]
    fn basic_credentials_become_a_bearer_token() {
        use base64::Engine;
        let b64 = base64::engine::general_purpose::STANDARD.encode("anything:tok_123");
        let req = Req::for_tests("GET", "/v1/apps/x.git/info/refs", &[("authorization", &format!("Basic {b64}"))]);
        assert_eq!(git_credentials(&req).bearer().as_deref(), Some("tok_123"));
        let req = Req::for_tests("GET", "/v1/apps/x.git/info/refs", &[("authorization", "Bearer tok_9")]);
        assert_eq!(git_credentials(&req).bearer().as_deref(), Some("tok_9"));
    }

    /// An export is built from version manifests only. This pins that the production code never reads the secrets
    /// store, and that a bundle built from the objects holds no such value.
    #[test]
    fn a_bundle_holds_only_the_files_of_the_versions() {
        let secret = "sk_live_super_secret_value";
        let h = build(&fixture()).unwrap();
        let mut w = PackWriter::new();
        for (_, k, d) in &h.objects {
            w.add(*k, d);
        }
        w.add(Kind::Blob, b"<h1>hi</h1>\n");
        let b = git::bundle(&refs_of(&h, Some(2), None), &w.finish());
        assert!(!b.windows(secret.len()).any(|x| x == secret.as_bytes()));
        assert!(h.objects.iter().all(|(_, _, d)| !d.windows(secret.len()).any(|x| x == secret.as_bytes())));
        let src = include_str!("git_export.rs");
        let production = src.split("#[cfg(test)]").next().unwrap();
        assert!(!production.contains("secrets::") && !production.contains("FROM secrets"), "an export must not read secrets");
    }
}
