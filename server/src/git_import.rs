// SPDX-License-Identifier: AGPL-3.0-only
// Git import: the files of a git commit (from a bundle or a repository address) become a new version of an app,
// through the same deploy pipeline as any other deploy.
//
// Where the commit sits in the app's history decides how it lands:
//   * if the commit, or an ancestor of it, is one Brod knows (version_git_commits), that version is the merge base:
//     the difference between it and the commit is applied as a patch, so what others deployed since is merged and
//     never undone;
//   * otherwise the commit has no common ancestor with the app, and its files replace the app's (with a warning).
// Everything goes to staging unless the caller asks for production.
//
// Only plain files are imported. Symlinks, submodules, Git LFS pointers, `.git` folders, paths with `..` and files
// over the deploy limits are refused with the path named, because deploying them would silently deploy something else
// than what the person sees in the repository.
//
// Recording the mapping (version_git_commits): an imported version's own commit id is the commit that was imported
// (source_commit_oid), but the id a later export gives that version is a different commit (its parent is the version's
// manifest parent, its author the person who ran the import, its time the import's). commit_oid always holds what an
// export gives, so a clone made from an export finds its base; source_commit_oid is kept in addition, so the repository
// the work came from (for example the person's own clone of GitHub) is found as a base the next time it is imported.
// If the two happen to be equal, source_commit_oid stays empty.
use std::collections::{HashMap, HashSet};

use serde_json::{Map, Value, json};

use crate::control::{self, DeployTarget};
use crate::db::{Sql, params};
use crate::git::{self, Kind, MODE_DIR, MODE_EXEC, MODE_FILE, MODE_GITLINK, MODE_SYMLINK, Objects, Oid, PackLimits, ParsedCommit};
use crate::model::Caller;
use crate::outbound::{self, Policy};
use crate::patch::{self, Change, PatchRequest};
use crate::people::require_role;
use crate::problem::{Problem, Result};
use crate::state::State;
use crate::tar::{BundleFile, FILE_BYTES, MAX_FILES, UNPACKED_BYTES};
use crate::versions;

/// Commits one import may create with history "all".
pub const MAX_HISTORY: usize = 50;
/// How far back to look for a commit Brod knows.
const CHAIN_SCAN: usize = 1000;
const LFS_PREFIX: &[u8] = b"version https://git-lfs.github.com/spec/";

pub enum Source {
    Bundle(Vec<u8>),
    Url(String),
}

pub struct ImportRequest {
    pub app: String,
    pub source: Source,
    pub git_ref: Option<String>,
    pub base_version: Option<Value>,
    pub history_all: bool,
    /// "staging" (the default) or "production".
    pub environment: Option<String>,
    pub note: Option<String>,
}

impl ImportRequest {
    /// The options common to the MCP tool, the JSON body and the query string of an import.
    pub fn from_json(app: &str, o: &Map<String, Value>, source: Source) -> Result<ImportRequest> {
        let text = |k: &str| match o.get(k) {
            Some(Value::String(s)) if !s.trim().is_empty() => Some(s.trim().to_string()),
            _ => None,
        };
        let history = text("history").unwrap_or_else(|| "tip".into());
        if history != "tip" && history != "all" {
            return Err(Problem::new(
                400,
                "bad_history",
                "\"history\" is \"tip\" (import the commit as one version) or \"all\" (one version per commit).",
            ));
        }
        let environment = match text("target").or_else(|| text("environment")).as_deref() {
            None | Some("staging") => "staging".to_string(),
            Some("production") | Some("live") => "production".to_string(),
            Some(_) => return Err(Problem::new(400, "bad_target", "\"target\" is \"staging\" (the default) or \"production\".")),
        };
        Ok(ImportRequest {
            app: app.to_string(),
            source,
            git_ref: text("ref"),
            base_version: o.get("base_version").filter(|v| !v.is_null() && !matches!(v, Value::String(s) if s.is_empty())).cloned(),
            history_all: history == "all",
            environment: Some(environment),
            note: text("note"),
        })
    }
}

// ---------- reading a repository ----------

/// The refs of a smart HTTP advertisement and what the server can do.
#[derive(Debug, Default)]
pub struct Advert {
    pub refs: Vec<(String, Oid)>,
    pub caps: Vec<String>,
}

pub fn parse_advert(body: &[u8]) -> Result<Advert> {
    let bad = |m: &str| Problem::new(502, "fetch_failed", format!("That address is not a git repository over smart HTTP: {m}."));
    let mut pos = 0;
    let mut advert = Advert::default();
    let mut first = true;
    let mut seen_service = false;
    while let Some(p) = git::read_pkt(body, &mut pos).map_err(|e| bad(&e))? {
        let git::Pkt::Data(line) = p else { continue };
        let line = String::from_utf8_lossy(line).into_owned();
        let line = line.trim_end_matches('\n');
        if line.starts_with("# service=") {
            seen_service = true;
            continue;
        }
        if line.starts_with("version ") {
            continue;
        }
        let (head, caps) = match line.split_once('\0') {
            Some((h, c)) => (h, Some(c)),
            None => (line, None),
        };
        if first {
            if let Some(c) = caps {
                advert.caps = c.split(' ').map(String::from).collect();
            }
            first = false;
        }
        let Some((oid, name)) = head.split_once(' ') else { return Err(bad("a ref line is malformed")) };
        let Some(oid) = git::parse_oid(oid) else { return Err(bad("a ref has a bad object id")) };
        if name.ends_with("^{}") {
            continue;
        }
        advert.refs.push((name.to_string(), oid));
    }
    if !seen_service && advert.refs.is_empty() && advert.caps.is_empty() {
        return Err(bad("the answer is not a git advertisement"));
    }
    Ok(advert)
}

/// Choose the commit to import: the ref asked for, or else HEAD, main, master, or the only branch.
pub fn pick_ref(refs: &[(String, Oid)], wanted: Option<&str>) -> Result<(String, Oid)> {
    let find = |n: &str| refs.iter().find(|(name, _)| name == n).cloned();
    let list = || refs.iter().map(|(n, _)| n.as_str()).collect::<Vec<_>>().join(", ");
    if let Some(w) = wanted {
        for cand in [w.to_string(), format!("refs/{w}"), format!("refs/heads/{w}"), format!("refs/tags/{w}")] {
            if let Some(r) = find(&cand) {
                return Ok(r);
            }
        }
        return Err(Problem::new(400, "unknown_ref", format!("The repository has no ref \"{w}\". It has: {}.", list())));
    }
    for cand in ["HEAD", "refs/heads/main", "refs/heads/master"] {
        if let Some(r) = find(cand) {
            return Ok(r);
        }
    }
    let branches: Vec<_> = refs.iter().filter(|(n, _)| n.starts_with("refs/heads/")).collect();
    if branches.len() == 1 {
        return Ok(branches[0].clone());
    }
    if refs.len() == 1 {
        return Ok(refs[0].clone());
    }
    Err(Problem::new(400, "need_ref", format!("Say which ref to import with \"ref\". The repository has: {}.", list())))
}

/// The upload-pack request for one commit.
pub fn upload_request(want: &Oid, shallow: bool) -> Vec<u8> {
    let mut out = git::pkt(format!("want {} side-band-64k ofs-delta agent=brod\n", git::hex(want)).as_bytes());
    if shallow {
        out.extend_from_slice(&git::pkt(b"deepen 1\n"));
    }
    out.extend_from_slice(git::FLUSH);
    out.extend_from_slice(&git::pkt(b"done\n"));
    out
}

/// The pack inside an upload-pack answer: pkt-lines (NAK, shallow lines) and then side-band data, or a bare pack.
pub fn demux(body: &[u8]) -> Result<Vec<u8>> {
    let bad = |m: String| Problem::new(502, "fetch_failed", format!("The repository's answer could not be read: {m}."));
    let mut pos = 0;
    let mut pack = Vec::new();
    while pos < body.len() {
        if body[pos..].starts_with(b"PACK") {
            pack.extend_from_slice(&body[pos..]);
            break;
        }
        match git::read_pkt(body, &mut pos).map_err(bad)? {
            None => break,
            Some(git::Pkt::Flush) => {}
            Some(git::Pkt::Data(line)) => match line.first() {
                Some(1) => pack.extend_from_slice(&line[1..]),
                Some(3) => {
                    return Err(Problem::new(
                        502,
                        "fetch_failed",
                        format!("The repository refused: {}", String::from_utf8_lossy(&line[1..]).trim()),
                    ));
                }
                _ => {}
            },
        }
    }
    if pack.is_empty() {
        return Err(bad("it sent no objects".into()));
    }
    Ok(pack)
}

pub fn git_url(url: &str, tail: &str) -> Result<String> {
    let trimmed = url.trim().trim_end_matches('/');
    if trimmed.contains('?') || trimmed.contains('#') {
        return Err(Problem::new(
            400,
            "bad_url",
            "Give the repository address without a query or fragment, such as https://github.com/owner/repo.git.",
        ));
    }
    Ok(format!("{trimmed}{tail}"))
}

/// The HTTP Basic header git hosting services accept for a token: GitHub, GitLab and Gitea take any user name.
pub fn basic_auth(token: &str) -> String {
    use base64::Engine;
    format!("Basic {}", base64::engine::general_purpose::STANDARD.encode(format!("x-access-token:{token}")))
}

fn headers_with(auth: Option<&str>, mut h: Vec<(&'static str, String)>) -> Vec<(&'static str, String)> {
    if let Some(a) = auth {
        h.push(("authorization", a.to_string()));
    }
    h
}

/// The refs a repository advertises for a git service ("git-upload-pack" or "git-receive-pack"), with the optional
/// Authorization header value for a private one.
pub async fn advertise(policy: Policy, url: &str, service: &str, auth: Option<&str>) -> Result<Advert> {
    let reply = outbound::send(
        policy,
        &outbound::Request {
            post: false,
            url: git_url(url, &format!("/info/refs?service={service}"))?,
            headers: headers_with(auth, vec![("accept", "*/*".into()), ("pragma", "no-cache".into())]),
            body: Vec::new(),
        },
        2 * 1024 * 1024,
    )
    .await?;
    if reply.status == 401 || reply.status == 403 {
        return Err(Problem::new(
            502,
            if auth.is_some() { "auth_refused" } else { "fetch_failed" },
            if auth.is_some() {
                "The repository refused the access token.".to_string()
            } else {
                "The repository needs a login. Brod can only import public repositories by address; export a bundle (git bundle create) and import that instead.".to_string()
            },
        ));
    }
    if reply.status != 200 {
        let code = if reply.status >= 500 || reply.status == 429 { "fetch_failed" } else { "remote_refused" };
        return Err(Problem::new(502, code, format!("The repository answered {} to the request for its refs.", reply.status)));
    }
    parse_advert(&reply.body)
}

/// Ask a repository for one commit's objects (with its history unless `shallow`).
async fn upload_pack(policy: Policy, url: &str, want: &Oid, shallow: bool, max_pack: usize, auth: Option<&str>) -> Result<Vec<u8>> {
    let reply = outbound::send(
        policy,
        &outbound::Request {
            post: true,
            url: git_url(url, "/git-upload-pack")?,
            headers: headers_with(
                auth,
                vec![
                    ("content-type", "application/x-git-upload-pack-request".into()),
                    ("accept", "application/x-git-upload-pack-result".into()),
                ],
            ),
            body: upload_request(want, shallow),
        },
        max_pack + 64 * 1024,
    )
    .await?;
    if reply.status != 200 {
        return Err(Problem::new(502, "fetch_failed", format!("The repository answered {} to the request for its files.", reply.status)));
    }
    demux(&reply.body)
}

/// Fetch one commit's objects from a repository over smart HTTP, as the commit chosen and a pack.
pub async fn fetch(policy: Policy, url: &str, git_ref: Option<&str>, shallow: bool, max_pack: usize) -> Result<(Oid, Vec<u8>)> {
    let advert = advertise(policy, url, "git-upload-pack", None).await?;
    let (_, want) = pick_ref(&advert.refs, git_ref)?;
    let can_shallow = shallow && advert.caps.iter().any(|c| c == "shallow");
    Ok((want, upload_pack(policy, url, &want, can_shallow, max_pack, None).await?))
}

/// Fetch a commit and all its history, to a private repository too (`auth` is an Authorization header value).
pub async fn fetch_commit(policy: Policy, url: &str, want: &Oid, max_pack: usize, auth: Option<&str>) -> Result<Vec<u8>> {
    upload_pack(policy, url, want, false, max_pack, auth).await
}

// ---------- reading the objects ----------

fn limits() -> PackLimits {
    PackLimits { max_objects: 200_000, max_object_bytes: FILE_BYTES, max_total_bytes: UNPACKED_BYTES * 2 }
}

fn unreadable(e: String) -> Problem {
    Problem::new(422, "bad_repository", format!("The repository could not be read: {e}."))
}

pub fn parse_pack(pack: &[u8]) -> Result<Objects> {
    git::read_pack(pack, &limits()).map_err(unreadable)
}

/// Follow annotated tags to the commit.
pub fn peel(objs: &Objects, mut oid: Oid) -> Result<Oid> {
    for _ in 0..8 {
        let Some((kind, data)) = objs.get(&oid) else {
            return Err(unreadable(format!("object {} is missing", git::hex(&oid))));
        };
        match kind {
            Kind::Commit => return Ok(oid),
            Kind::Tag => {
                let text = String::from_utf8_lossy(data);
                oid = text
                    .lines()
                    .find_map(|l| l.strip_prefix("object "))
                    .and_then(git::parse_oid)
                    .ok_or_else(|| unreadable("a tag has no object".into()))?;
            }
            _ => return Err(Problem::new(400, "not_a_commit", "That ref does not point to a commit.")),
        }
    }
    Err(unreadable("tags nest too deeply".into()))
}

/// The commit and its first-parent ancestors that the pack holds, newest first.
pub fn first_parent_chain(objs: &Objects, tip: Oid, max: usize) -> Result<Vec<(Oid, ParsedCommit)>> {
    let mut out = Vec::new();
    let mut at = Some(tip);
    while let Some(oid) = at {
        if out.len() >= max {
            break;
        }
        let Some((Kind::Commit, data)) = objs.get(&oid) else {
            if out.is_empty() {
                return Err(unreadable(format!("commit {} is missing", git::hex(&oid))));
            }
            break;
        };
        let c = git::parse_commit(data).map_err(unreadable)?;
        at = c.parents.first().copied();
        out.push((oid, c));
    }
    Ok(out)
}

fn refuse(code: &str, msg: String) -> Problem {
    Problem::new(422, code, msg)
}

/// Whether a name in a tree may become a path of an app.
fn check_name(name: &str, path: &str) -> Result<()> {
    if name.is_empty() || name == "." || name == ".." {
        return Err(refuse("bad_path", format!("\"{path}\" is not allowed: a path may not contain \"..\" or empty parts.")));
    }
    if name.eq_ignore_ascii_case(".git") {
        return Err(refuse("bad_path", format!("\"{path}\" is not allowed: a \".git\" folder cannot be part of an app.")));
    }
    if name.contains('\\') || name.contains('\0') || name.contains('/') {
        return Err(refuse("bad_path", format!("\"{path}\" is not allowed: it has a slash, backslash or null character in a name.")));
    }
    Ok(())
}

pub struct TreeLimits {
    pub file_bytes: usize,
    pub total_bytes: usize,
    pub files: usize,
}

impl Default for TreeLimits {
    fn default() -> Self {
        TreeLimits { file_bytes: FILE_BYTES, total_bytes: UNPACKED_BYTES, files: MAX_FILES }
    }
}

type Files = Vec<(String, Vec<u8>, bool)>;

/// Every file of a tree as (path, content, executable), refusing what Brod cannot deploy faithfully.
pub fn walk_files(objs: &Objects, tree: &Oid, lim: &TreeLimits) -> Result<Files> {
    let mut out = Vec::new();
    let mut total = 0usize;
    walk(objs, tree, "", 0, lim, &mut total, &mut out)?;
    Ok(out)
}

fn walk(objs: &Objects, tree: &Oid, prefix: &str, depth: usize, lim: &TreeLimits, total: &mut usize, out: &mut Files) -> Result<()> {
    if depth > 64 {
        return Err(refuse("bad_path", format!("\"{prefix}\" is nested more than 64 folders deep.")));
    }
    let Some((Kind::Tree, data)) = objs.get(tree) else {
        return Err(unreadable(format!("tree {} is missing", git::hex(tree))));
    };
    for e in git::parse_tree(data).map_err(unreadable)? {
        let path = if prefix.is_empty() { e.name.clone() } else { format!("{prefix}/{}", e.name) };
        check_name(&e.name, &path)?;
        match e.mode {
            MODE_DIR => walk(objs, &e.oid, &path, depth + 1, lim, total, out)?,
            MODE_SYMLINK => {
                return Err(refuse(
                    "git_symlink",
                    format!(
                        "\"{path}\" is a symbolic link. Brod apps are plain files: replace the link with the file (or a copy) and import again."
                    ),
                ));
            }
            MODE_GITLINK => {
                return Err(refuse(
                    "git_submodule",
                    format!(
                        "\"{path}\" is a git submodule. Brod does not fetch submodules: add their files to the repository itself and import again."
                    ),
                ));
            }
            m if m == MODE_FILE || m == MODE_EXEC || m == 0o100664 => {
                let Some((Kind::Blob, bytes)) = objs.get(&e.oid) else {
                    return Err(unreadable(format!("file {path} is missing from the repository (a partial or shallow clone?)")));
                };
                if bytes.starts_with(LFS_PREFIX) {
                    return Err(refuse(
                        "git_lfs",
                        format!(
                            "\"{path}\" is a Git LFS pointer, not the file itself. Brod does not fetch LFS files: check the real file in (or deploy it without git) and import again."
                        ),
                    ));
                }
                if bytes.len() > lim.file_bytes {
                    return Err(Problem::new(413, "too_large", format!("{path} is larger than {} MB.", lim.file_bytes / 1_048_576)));
                }
                *total += bytes.len();
                if *total > lim.total_bytes {
                    return Err(Problem::new(
                        413,
                        "too_large",
                        format!("The files are larger than {} MB together.", lim.total_bytes / 1_048_576),
                    ));
                }
                if out.len() >= lim.files {
                    return Err(Problem::new(413, "too_many_files", format!("The repository has more than {} files.", lim.files)));
                }
                out.push((path, bytes.clone(), m == MODE_EXEC));
            }
            m => return Err(refuse("bad_path", format!("\"{path}\" has the unsupported file mode {m:o}."))),
        }
    }
    Ok(())
}

fn short(oid: &Oid) -> String {
    git::hex(oid)[..8].to_string()
}

fn note_of(oid: &Oid, c: &ParsedCommit) -> String {
    let subject = c.message.lines().next().unwrap_or("").trim();
    let full = format!("Imported from git {}: {subject}", short(oid));
    full.chars().take(200).collect()
}

// ---------- the import ----------

/// For each commit of a chain, the version it is (or was imported as), if the app still has that version's files.
async fn known_versions(st: &State, app_id: &str, chain: &[Oid]) -> Result<Vec<Option<i64>>> {
    let a = app_id.to_string();
    let rows: Vec<(i64, String, Option<String>)> = st
        .db
        .call(move |conn| {
            // Commits a git mirror pushed to continue a remote branch count too (git_mirror.rs).
            conn.all(
                "SELECT version, commit_oid, source_commit_oid FROM version_git_commits WHERE app_id = ? \
                 UNION ALL SELECT version, remote_oid, NULL FROM git_sync_events WHERE app_id = ? AND result = 'pushed' AND version IS NOT NULL",
                params![a, a],
                |r| {
                Ok((r.get::<_, i64>("version")?, r.get::<_, String>("commit_oid")?, r.get::<_, Option<String>>("source_commit_oid")?))
            })
        })
        .await?;
    let mut by_oid: HashMap<&str, i64> = HashMap::new();
    for (v, commit, source) in &rows {
        for oid in std::iter::once(commit).chain(source.iter()) {
            let e = by_oid.entry(oid.as_str()).or_insert(*v);
            *e = (*e).max(*v);
        }
    }
    let mut out = Vec::new();
    for oid in chain {
        let v = by_oid.get(git::hex(oid).as_str()).copied();
        let usable = match v {
            Some(n) => versions::manifest(st, app_id, n).await?.is_some(),
            None => false,
        };
        out.push(if usable { v } else { None });
    }
    Ok(out)
}

struct Step {
    oid: Oid,
    commit: ParsedCommit,
    files: Files,
}

/// Import a bundle or repository as new versions of an app. See the module comment for how it lands.
pub async fn run(st: &State, c: &Caller, req: ImportRequest) -> Result<Value> {
    run_with(st, c, req, Policy::from_config(&st.cfg)).await
}

pub async fn run_with(st: &State, c: &Caller, req: ImportRequest, policy: Policy) -> Result<Value> {
    let (c2, slug2) = (c.clone(), req.app.clone());
    let app = st
        .db
        .call(move |conn| {
            require_role(&c2, "builder", "deploy apps")?;
            control::get_app(conn, &c2, &slug2)
        })
        .await?;
    let max_pack = (crate::instance::current(st).await.int("git.max_import_mb").max(1) as usize) * 1024 * 1024;

    // 1. The objects and the commit to import.
    let (objs, tip, ref_name) = match req.source {
        Source::Bundle(data) => {
            if data.len() > max_pack {
                return Err(Problem::new(413, "too_large", format!("The bundle is larger than {} MB.", max_pack / 1024 / 1024)));
            }
            let wanted = req.git_ref.clone();
            tokio::task::spawn_blocking(move || {
                let b = git::parse_bundle(&data).map_err(|e| Problem::new(400, "bad_bundle", e))?;
                let objs = parse_pack(b.pack)?;
                let (name, oid) = pick_ref(&b.refs, wanted.as_deref())?;
                let tip = peel(&objs, oid)?;
                Ok::<_, Problem>((objs, tip, name))
            })
            .await
            .map_err(Problem::internal)??
        }
        Source::Url(url) => {
            let (oid, pack) = fetch(policy, &url, req.git_ref.as_deref(), !req.history_all, max_pack).await?;
            let name = req.git_ref.clone().unwrap_or_else(|| "HEAD".into());
            tokio::task::spawn_blocking(move || {
                let objs = parse_pack(&pack)?;
                let tip = peel(&objs, oid)?;
                Ok::<_, Problem>((objs, tip, name))
            })
            .await
            .map_err(Problem::internal)??
        }
    };

    let landing = Landing { base_version: req.base_version, history_all: req.history_all, environment: req.environment, note: req.note };
    apply(st, c, &app, &objs, tip, &ref_name, landing).await
}

/// How the commit lands: the options of an import that do not say where the objects come from.
pub struct Landing {
    pub base_version: Option<Value>,
    pub history_all: bool,
    pub environment: Option<String>,
    pub note: Option<String>,
}

/// Turn the commit `tip` of a set of objects into versions of the app, merging with what is there. The chain of commits the
/// objects hold is searched for one Brod knows, which becomes the merge base.
pub async fn apply(
    st: &State,
    c: &Caller,
    app: &crate::model::AppRow,
    objs: &Objects,
    tip: Oid,
    ref_name: &str,
    req: Landing,
) -> Result<Value> {
    // 2. Which commits Brod knows.
    let chain = first_parent_chain(objs, tip, CHAIN_SCAN)?;
    let oids: Vec<Oid> = chain.iter().map(|(o, _)| *o).collect();
    let known = known_versions(st, &app.id, &oids).await?;
    let explicit_base = match &req.base_version {
        Some(v) => DeployTarget { app: Some(app.slug.clone()), base_version: Some(v.clone()), ..Default::default() }.base()?,
        None => None,
    };
    let first_known = known.iter().position(Option::is_some);
    if first_known == Some(0) && explicit_base.is_none() {
        let v = known[0].unwrap_or_default();
        return Ok(json!({
            "app": app.slug,
            "unchanged": true,
            "version": v,
            "imported_commit": git::hex(&tip),
            "message": format!("Commit {} is already version {v} of {}, so there is nothing to import.", short(&tip), app.slug),
        }));
    }

    // 3. The commits to turn into versions, oldest first.
    let lim = TreeLimits::default();
    let fresh = first_known.unwrap_or(chain.len());
    let picks: Vec<usize> = if req.history_all {
        if fresh > MAX_HISTORY {
            return Err(Problem::new(
                400,
                "too_much_history",
                format!(
                    "{fresh} commits are not in {} yet, which is more than the {MAX_HISTORY} one import creates. Import with \"history\": \"tip\" for the latest state as one version.",
                    app.slug
                ),
            ));
        }
        (0..fresh).rev().collect()
    } else {
        vec![0]
    };
    let mut steps = Vec::new();
    for i in picks {
        let (oid, commit) = &chain[i];
        let files = walk_files(objs, &commit.tree, &lim)?;
        steps.push(Step {
            oid: *oid,
            commit: ParsedCommit { tree: commit.tree, parents: commit.parents.clone(), message: commit.message.clone() },
            files,
        });
    }

    // 4. Deploy them.
    let mut base = explicit_base.or_else(|| first_known.and_then(|i| known[i]));
    let warning = if base.is_none() { Some("no common ancestor; replaced all files".to_string()) } else { None };
    let mut created: Vec<(i64, Oid)> = Vec::new();
    let mut last = Value::Null;
    for step in steps {
        let note = req.note.clone().filter(|_| !req.history_all).unwrap_or_else(|| note_of(&step.oid, &step.commit));
        let out = deploy_step(st, c, &app.slug, &app.id, step.files, base, note, req.environment.clone()).await?;
        if let Some(v) = out.get("version").and_then(Value::as_i64) {
            base = Some(v);
            created.push((v, step.oid));
        }
        last = out;
    }
    record(st, c, &app.slug, &created).await?;

    let mut result = match last {
        Value::Object(m) => m,
        other => {
            let mut m = Map::new();
            m.insert("result".into(), other);
            m
        }
    };
    result.insert("imported_commit".into(), json!(git::hex(&tip)));
    result.insert("imported_ref".into(), json!(ref_name));
    if let Some(i) = first_known {
        result.insert("merge_base".into(), json!({ "commit": git::hex(&chain[i].0), "version": known[i] }));
    }
    if created.len() > 1 {
        result.insert("versions_created".into(), json!(created.iter().map(|(v, _)| *v).collect::<Vec<_>>()));
    }
    if let Some(w) = warning {
        result.insert("warning".into(), json!(w));
    }
    Ok(Value::Object(result))
}

#[allow(clippy::too_many_arguments)]
async fn deploy_step(
    st: &State,
    c: &Caller,
    slug: &str,
    app_id: &str,
    files: Files,
    base: Option<i64>,
    note: String,
    environment: Option<String>,
) -> Result<Value> {
    let target = DeployTarget {
        app: Some(slug.to_string()),
        note: Some(note),
        environment,
        base_version: base.map(|b| json!(b)),
        ..Default::default()
    };
    if let Some(base) = base {
        let m = versions::manifest(st, app_id, base)
            .await?
            .ok_or_else(|| Problem::new(404, "no_version", format!("{slug} has no files for version {base} to merge with.")))?;
        let mut req = PatchRequest::default();
        let mut keep = HashSet::new();
        for (path, bytes, _) in files {
            keep.insert(path.clone());
            if m.get(&path).map(|e| e.sha256.as_str()) != Some(versions::sha256_bytes(&bytes).as_str()) {
                req.changes.insert(path, Change::Bytes(bytes));
            }
        }
        req.deletes = m.entries.iter().filter(|e| !keep.contains(&e.path)).map(|e| e.path.clone()).collect();
        return patch::deploy_patch(st, c, target, req).await;
    }
    let files = files.into_iter().map(|(path, bytes, _)| BundleFile { path, bytes }).collect();
    control::deploy(st, c, target, files).await
}

/// Record where the new versions came from. Their exported commit ids are computed first (git_export::plan stores
/// them as commit_oid); the commit imported is kept as source_commit_oid when it differs. See the module comment.
async fn record(st: &State, c: &Caller, slug: &str, created: &[(i64, Oid)]) -> Result<()> {
    if created.is_empty() {
        return Ok(());
    }
    let plan = crate::git_export::plan(st, c, slug).await?;
    let rows: Vec<(i64, String)> = created
        .iter()
        .filter(|(v, oid)| plan.history.commits.get(v).is_none_or(|x| x.commit != *oid))
        .map(|(v, oid)| (*v, git::hex(oid)))
        .collect();
    if rows.is_empty() {
        return Ok(());
    }
    let (c2, slug2) = (c.clone(), slug.to_string());
    st.db
        .call(move |conn| {
            let app = control::get_app(conn, &c2, &slug2)?;
            for (v, oid) in &rows {
                conn.run(
                    "UPDATE version_git_commits SET source_commit_oid = ? WHERE app_id = ? AND version = ?",
                    params![oid, app.id, *v],
                )?;
            }
            Ok(())
        })
        .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::git::{PackWriter, TreeEntry};

    fn repo(files: &[(&str, u32, &[u8])]) -> (Objects, Oid) {
        let mut objs = Objects::new();
        let mut put = |kind: Kind, data: Vec<u8>| {
            let oid = git::object_oid(kind, &data);
            objs.insert(oid, (kind, data));
            oid
        };
        let mut top: Vec<TreeEntry> = Vec::new();
        let mut sub: HashMap<String, Vec<TreeEntry>> = HashMap::new();
        for (path, mode, content) in files {
            let blob = put(Kind::Blob, content.to_vec());
            match path.split_once('/') {
                Some((d, rest)) => sub.entry(d.to_string()).or_default().push(TreeEntry { mode: *mode, name: rest.to_string(), oid: blob }),
                None => top.push(TreeEntry { mode: *mode, name: (*path).to_string(), oid: blob }),
            }
        }
        for (d, mut entries) in sub {
            let t = put(Kind::Tree, git::encode_tree(&mut entries));
            top.push(TreeEntry { mode: MODE_DIR, name: d, oid: t });
        }
        let root = put(Kind::Tree, git::encode_tree(&mut top));
        (objs, root)
    }

    fn code<T>(r: Result<T>) -> String {
        r.err().map(|e| e.code).unwrap_or_default()
    }

    #[test]
    fn plain_files_are_read_with_their_paths_and_exec_bit() {
        let (objs, root) =
            repo(&[("index.html", MODE_FILE, b"<h1>x</h1>"), ("css/app.css", MODE_FILE, b"a{}"), ("bin/run", MODE_EXEC, b"#!/bin/sh\n")]);
        let mut files = walk_files(&objs, &root, &TreeLimits::default()).unwrap();
        files.sort();
        let got: Vec<(&str, bool)> = files.iter().map(|f| (f.0.as_str(), f.2)).collect();
        assert_eq!(got, [("bin/run", true), ("css/app.css", false), ("index.html", false)]);
    }

    #[test]
    fn symlinks_submodules_and_lfs_pointers_are_refused_naming_the_path() {
        let (o, r) = repo(&[("index.html", MODE_FILE, b"x"), ("link", MODE_SYMLINK, b"index.html")]);
        let e = walk_files(&o, &r, &TreeLimits::default()).unwrap_err();
        assert_eq!((e.code.as_str(), e.status), ("git_symlink", 422));
        assert!(e.message.contains("\"link\""));

        let mut entries = vec![TreeEntry { mode: MODE_GITLINK, name: "vendor".into(), oid: [7; 20] }];
        let mut objs = Objects::new();
        let data = git::encode_tree(&mut entries);
        let root = git::object_oid(Kind::Tree, &data);
        objs.insert(root, (Kind::Tree, data));
        assert_eq!(code(walk_files(&objs, &root, &TreeLimits::default())), "git_submodule");

        let pointer = b"version https://git-lfs.github.com/spec/v1\noid sha256:abc\nsize 10\n";
        let (o, r) = repo(&[("big.bin", MODE_FILE, pointer)]);
        assert_eq!(code(walk_files(&o, &r, &TreeLimits::default())), "git_lfs");
    }

    #[test]
    fn dangerous_names_are_refused() {
        for name in ["..", ".", ".git", ".GIT", "a\\b", "a/b", ""] {
            assert_eq!(code(check_name(name, name)), "bad_path", "{name}");
        }
        assert!(check_name(".gitignore", ".gitignore").is_ok());
        assert!(check_name(".github", ".github").is_ok());
        let (o, r) = repo(&[("index.html", MODE_FILE, b"x"), (".git/config", MODE_FILE, b"[core]")]);
        let e = walk_files(&o, &r, &TreeLimits::default()).unwrap_err();
        assert!(e.message.contains(".git"));
    }

    #[test]
    fn size_and_count_limits_apply() {
        let (o, r) = repo(&[("a", MODE_FILE, b"12345"), ("b", MODE_FILE, b"12345")]);
        let small = |file_bytes, total_bytes, files| TreeLimits { file_bytes, total_bytes, files };
        assert_eq!(code(walk_files(&o, &r, &small(4, 100, 10))), "too_large");
        assert_eq!(code(walk_files(&o, &r, &small(10, 9, 10))), "too_large");
        assert_eq!(code(walk_files(&o, &r, &small(10, 100, 1))), "too_many_files");
        assert!(walk_files(&o, &r, &small(10, 100, 2)).is_ok());
    }

    #[test]
    fn a_missing_object_is_a_clear_error() {
        let (mut o, r) = repo(&[("a", MODE_FILE, b"hello")]);
        o.remove(&git::blob_oid(b"hello"));
        let e = walk_files(&o, &r, &TreeLimits::default()).unwrap_err();
        assert_eq!(e.code, "bad_repository");
    }

    fn fixture(name: &str) -> Vec<u8> {
        std::fs::read(format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"))).unwrap()
    }

    // Packs written by real git, with and without offset deltas: three commits whose later versions of big.txt are
    // stored as deltas. Only a correctly applied delta hashes to the blob id git gave the file.
    #[test]
    fn packs_with_ofs_and_ref_deltas_are_read_by_real_git_ids() {
        for name in ["git-ofs-delta.pack", "git-ref-delta.pack"] {
            let objs = parse_pack(&fixture(name)).unwrap();
            let tip = git::parse_oid("f8a27d10d549f4386e183e018bebe3d5c0ea1c41").unwrap();
            let chain = first_parent_chain(&objs, tip, 10).unwrap();
            let ids: Vec<String> = chain.iter().map(|c| git::hex(&c.0)).collect();
            assert_eq!(
                ids,
                [
                    "f8a27d10d549f4386e183e018bebe3d5c0ea1c41",
                    "1db06542473cecf636c65a3b09a1f840ad81739e",
                    "e2b4d33eb93fe7cb42739353851d6bc2e54f7831"
                ],
                "{name}"
            );
            let files = walk_files(&objs, &chain[0].1.tree, &TreeLimits::default()).unwrap();
            let names: Vec<&str> = files.iter().map(|f| f.0.as_str()).collect();
            assert_eq!(names, ["big.txt", "index.html", "more.txt"], "{name}");
            assert_eq!(git::hex(&git::blob_oid(&files[0].1)), "47fcd5cba434ee6a2b1025a5306bfb9a0f1f6fb4", "{name}");
            assert_eq!(files[2].1, b"extra\n");
            assert_eq!(chain[0].1.message.trim(), "three");
        }
    }

    #[test]
    fn refs_are_picked_by_name_head_or_the_only_branch() {
        let o = |b: u8| [b; 20];
        let refs = vec![
            ("HEAD".to_string(), o(1)),
            ("refs/heads/main".to_string(), o(1)),
            ("refs/heads/dev".to_string(), o(2)),
            ("refs/tags/v1".to_string(), o(3)),
        ];
        assert_eq!(pick_ref(&refs, None).unwrap().1, o(1));
        assert_eq!(pick_ref(&refs, Some("dev")).unwrap().1, o(2));
        assert_eq!(pick_ref(&refs, Some("v1")).unwrap().1, o(3));
        assert_eq!(code(pick_ref(&refs, Some("nope"))), "unknown_ref");
        let two = vec![("refs/heads/a".to_string(), o(1)), ("refs/heads/b".to_string(), o(2))];
        assert_eq!(code(pick_ref(&two, None)), "need_ref");
        assert_eq!(pick_ref(&two[..1], None).unwrap().1, o(1));
    }

    #[test]
    fn advertisements_and_answers_are_parsed() {
        let id = "f8a27d10d549f4386e183e018bebe3d5c0ea1c41";
        let mut adv = git::pkt(b"# service=git-upload-pack\n");
        adv.extend_from_slice(git::FLUSH);
        adv.extend_from_slice(&git::pkt(format!("{id} HEAD\0multi_ack shallow side-band-64k symref=HEAD:refs/heads/main\n").as_bytes()));
        adv.extend_from_slice(&git::pkt(format!("{id} refs/heads/main\n").as_bytes()));
        adv.extend_from_slice(&git::pkt(format!("{id} refs/tags/v1^{{}}\n").as_bytes()));
        adv.extend_from_slice(git::FLUSH);
        let a = parse_advert(&adv).unwrap();
        assert_eq!(a.refs.len(), 2);
        assert!(a.caps.contains(&"shallow".to_string()));
        assert_eq!(code(parse_advert(b"<html>not git</html>")), "fetch_failed");

        let pack = fixture("git-ofs-delta.pack");
        let mut body = git::pkt(b"NAK\n");
        for chunk in pack.chunks(1000) {
            let mut line = vec![1u8];
            line.extend_from_slice(chunk);
            body.extend_from_slice(&git::pkt(&line));
            body.extend_from_slice(&git::pkt(b"\x02Counting objects\n"));
        }
        body.extend_from_slice(git::FLUSH);
        assert_eq!(demux(&body).unwrap(), pack);
        let mut bare = git::pkt(b"NAK\n");
        bare.extend_from_slice(&pack);
        assert_eq!(demux(&bare).unwrap(), pack);
        assert!(demux(&git::pkt(b"\x03fatal: nope\n")).unwrap_err().message.contains("fatal: nope"));

        let want = upload_request(&git::parse_oid(id).unwrap(), true);
        let text = String::from_utf8_lossy(&want).into_owned();
        assert!(text.contains("want f8a27d10") && text.contains("deepen 1") && text.ends_with("0009done\n"));
    }

    #[test]
    fn a_commit_is_noted_from_its_subject() {
        let c = ParsedCommit { tree: [0; 20], parents: vec![], message: "Fix the header\n\nlong body".into() };
        assert_eq!(note_of(&[0xab; 20], &c), "Imported from git abababab: Fix the header");
        let long = ParsedCommit { tree: [0; 20], parents: vec![], message: "x".repeat(500) };
        assert_eq!(note_of(&[0; 20], &long).chars().count(), 200);
    }

    #[test]
    fn request_options_are_checked() {
        let o = |v: Value| v.as_object().unwrap().clone();
        let url = || Source::Url("https://x".into());
        let r = ImportRequest::from_json("a", &o(json!({"history": "all", "target": "production", "ref": "dev"})), url()).unwrap();
        assert!(r.history_all);
        assert_eq!((r.environment.as_deref(), r.git_ref.as_deref()), (Some("production"), Some("dev")));
        let d = ImportRequest::from_json("a", &o(json!({})), url()).unwrap();
        assert_eq!((d.history_all, d.environment.as_deref()), (false, Some("staging")));
        assert!(ImportRequest::from_json("a", &o(json!({"history": "some"})), url()).is_err());
        assert!(ImportRequest::from_json("a", &o(json!({"target": "moon"})), url()).is_err());
    }

    #[tokio::test]
    async fn the_outbound_guard_applies_to_a_repository_address() {
        for url in [
            "http://127.0.0.1:1/repo.git",
            "http://169.254.169.254/latest",
            "http://localhost/x.git",
            "file:///etc/passwd",
            "ftp://example.com/x.git",
        ] {
            let e = fetch(Policy::strict(), url, None, true, 1024).await.unwrap_err();
            assert_eq!(e.code, "blocked_url", "{url}");
        }
        assert_eq!(fetch(Policy::strict(), "https://example.com/r.git?x=1", None, true, 1024).await.unwrap_err().code, "bad_url");
    }

    #[test]
    fn a_pack_made_by_brod_round_trips_through_the_reader() {
        let mut w = PackWriter::new();
        w.add(Kind::Blob, b"hello");
        let objs = parse_pack(&w.finish()).unwrap();
        assert!(objs.contains_key(&git::blob_oid(b"hello")));
    }
}
