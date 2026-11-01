// SPDX-License-Identifier: AGPL-3.0-only
// Patch deploys: a deploy that sends only what changed. The request names the version its changes start from
// ("base_version"), the files it adds or changes ("changes", path -> content, content_base64 or the sha256 of a file the
// app already has) and the paths it removes ("deletes"). The new version is that base with the patch applied.
//
// When the app has moved on since the base, the patch is merged onto what is current instead of being refused: per
// file, where only one side changed it that side wins, where both changed a text file the lines are merged (merge.rs),
// and a real conflict refuses the whole deploy with a 409 that lists the conflicting paths and hunks, deploying
// nothing. The merged file set then goes through the same pipeline as a full upload (control::deploy_files): the same
// checks, scan, limits, staging rules and version bookkeeping.
use std::collections::{BTreeMap, BTreeSet, HashSet};

use base64::Engine;
use serde_json::{Map, Value, json};

use crate::control::{self, DeployTarget};
use crate::db::{Connection, Sql, params};
use crate::merge::{self, Outcome};
use crate::model::{Caller, js_string, limits};
use crate::people::require_role;
use crate::problem::{Problem, Result};
use crate::state::State;
use crate::tar::{BundleFile, FILE_BYTES, MAX_FILES};
use crate::versions::{self, Manifest};

/// What a patch does to one path.
#[derive(Clone, Debug, PartialEq)]
pub enum Change {
    /// New content, sent with the request.
    Bytes(Vec<u8>),
    /// Content the app already stores, by hash.
    Blob(String),
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct PatchRequest {
    pub changes: BTreeMap<String, Change>,
    pub deletes: BTreeSet<String>,
}

/// The cap on content sent inline in one patch, as for a full upload.
const INLINE_CAP: usize = limits::INLINE_BYTES;

/// Diff text returned by diff_versions, at most.
const DIFF_CAP: usize = 100_000;

/// Whether a deploy request is a patch (it has "changes" or "deletes"), and if so what it asks for.
pub fn parse(b: &Map<String, Value>) -> Result<Option<PatchRequest>> {
    let given = |k: &str| b.get(k).filter(|v| !v.is_null());
    let (changes, deletes) = (given("changes"), given("deletes"));
    if changes.is_none() && deletes.is_none() {
        return Ok(None);
    }
    if given("files").is_some() {
        return Err(Problem::new(
            400,
            "bad_patch",
            "Send either \"files\" (a full upload) or \"changes\" and \"deletes\" (a patch to \"base_version\"), not both.",
        ));
    }
    let mut req = PatchRequest::default();
    let mut inline = 0usize;
    if let Some(changes) = changes {
        let Value::Object(map) = changes else {
            return Err(Problem::new(400, "bad_patch", "\"changes\" maps each path to { content }, { content_base64 } or { sha256 }."));
        };
        for (raw, spec) in map {
            let path = clean_path(raw)?;
            let Value::Object(spec) = spec else {
                return Err(Problem::new(
                    400,
                    "bad_patch",
                    format!("The change for {path} must be an object: {{ \"content\": \"...\" }}."),
                ));
            };
            let which = ["content", "content_base64", "sha256"].iter().filter(|k| spec.get(**k).is_some_and(|v| !v.is_null())).count();
            if which != 1 {
                return Err(Problem::new(
                    400,
                    "bad_patch",
                    format!("The change for {path} needs exactly one of \"content\", \"content_base64\" or \"sha256\"."),
                ));
            }
            let text = |k: &str| match spec.get(k) {
                Some(Value::String(s)) => Ok(s.clone()),
                _ => Err(Problem::new(400, "bad_patch", format!("\"{k}\" for {path} must be a string."))),
            };
            let change = if spec.get("sha256").is_some_and(|v| !v.is_null()) {
                let sha = text("sha256")?.to_lowercase();
                if !versions::is_sha256(&sha) {
                    return Err(Problem::new(400, "bad_patch", format!("\"sha256\" for {path} must be 64 hexadecimal characters.")));
                }
                Change::Blob(sha)
            } else if spec.get("content_base64").is_some_and(|v| !v.is_null()) {
                let s = text("content_base64")?;
                let clean: String = s.chars().filter(|c| !c.is_ascii_whitespace()).collect();
                let bytes = base64::engine::general_purpose::STANDARD
                    .decode(clean.trim_end_matches('='))
                    .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(clean.trim_end_matches('=')))
                    .map_err(|_| Problem::new(400, "bad_patch", format!("\"content_base64\" for {path} is not valid base64.")))?;
                inline += bytes.len();
                Change::Bytes(bytes)
            } else {
                let bytes = text("content")?.into_bytes();
                inline += bytes.len();
                Change::Bytes(bytes)
            };
            if req.changes.insert(path.clone(), change).is_some() {
                return Err(Problem::new(400, "bad_patch", format!("{path} is given twice in \"changes\".")));
            }
        }
    }
    if let Some(deletes) = deletes {
        let Value::Array(list) = deletes else {
            return Err(Problem::new(400, "bad_patch", "\"deletes\" is a list of paths."));
        };
        for p in list {
            let Value::String(p) = p else {
                return Err(Problem::new(400, "bad_patch", "\"deletes\" is a list of paths."));
            };
            req.deletes.insert(clean_path(p)?);
        }
    }
    if let Some(p) = req.changes.keys().find(|p| req.deletes.contains(*p)) {
        return Err(Problem::new(400, "bad_patch", format!("{p} is both changed and deleted.")));
    }
    if req.changes.len() + req.deletes.len() > MAX_FILES {
        return Err(Problem::new(413, "too_many_files", format!("A patch can touch at most {MAX_FILES} files.")));
    }
    if inline > INLINE_CAP {
        return Err(Problem::new(
            413,
            "too_large",
            "Content sent inline in a patch can total 1 MB. Larger files: upload the whole bundle instead.",
        ));
    }
    Ok(Some(req))
}

/// A patch path, cleaned as a bundle's paths are (control::normalise) and refused if it could not be one.
fn clean_path(raw: &str) -> Result<String> {
    let mut p = raw.replace('\\', "/");
    while let Some(rest) = p.strip_prefix("./") {
        p = rest.to_string();
    }
    let p = p.trim_start_matches('/').to_string();
    if p.is_empty() || p.split('/').any(|s| s == ".." || s == "." || s.is_empty()) {
        return Err(Problem::new(400, "bad_path", format!("File path \"{raw}\" is not allowed.")));
    }
    if p.encode_utf16().count() > 400 {
        return Err(Problem::new(400, "bad_path", "A file path is longer than 400 characters."));
    }
    if p.starts_with("_brod/") {
        return Err(Problem::new(400, "bad_path", "Paths under _brod/ are reserved for the platform."));
    }
    Ok(p)
}

/// Where one file of the new version comes from.
enum Source {
    /// Stored already: by hash.
    Blob(String),
    Bytes(Vec<u8>),
}

async fn blob(st: &State, sha: Option<&str>) -> Result<Option<Vec<u8>>> {
    match sha {
        Some(s) => versions::read_blob(st, s, FILE_BYTES).await.map(Some),
        None => Ok(None),
    }
}

/// Deploy a patch. `o.base_version` is required; see the module comment.
pub async fn deploy_patch(st: &State, c: &Caller, mut o: DeployTarget, req: PatchRequest) -> Result<Value> {
    control::preflight(st, c, &o).await?;
    let Some(slug) = o.app_slug().map(String::from) else {
        return Err(Problem::new(400, "need_app", "A patch changes an existing app: give \"app\" and \"base_version\"."));
    };
    if o.base_version.as_ref().is_none_or(|v| v.is_null() || matches!(v, Value::String(s) if s.is_empty())) {
        return Err(Problem::new(
            400,
            "need_base_version",
            "A patch needs \"base_version\", the version its changes start from (get_files returns it as \"version\"). It is what lets Brod merge with changes made since.",
        ));
    }
    let base = o.base()?.ok_or_else(|| Problem::new(400, "need_base_version", "A patch needs \"base_version\"."))?;
    let (c2, slug2) = (c.clone(), slug.clone());
    let wanted: Vec<String> = req.changes.values().filter_map(|c| if let Change::Blob(s) = c { Some(s.clone()) } else { None }).collect();
    let (app, current, missing) = st
        .db
        .call(move |conn| {
            let app = control::get_app(conn, &c2, &slug2)?;
            let current = control::current_version(&app);
            Ok((app.clone(), current, unknown_blobs(conn, &app.id, &wanted)?))
        })
        .await?;
    if !missing.is_empty() {
        return Err(Problem::new(
            422,
            "unknown_blobs",
            format!(
                "{} of the sha256 values in \"changes\" are not files of {slug}: {}. Send their content instead, or take the hashes from get_files.",
                missing.len(),
                missing.join(", ")
            ),
        )
        .with("missing", json!(missing)));
    }
    let Some(current) = current else {
        return Err(Problem::new(409, "no_version", format!("{slug} has no version yet to patch. Deploy its files first.")));
    };
    let base_m = versions::manifest(st, &app.id, base).await?.ok_or_else(|| {
        Problem::new(
            404,
            "no_version",
            format!("{slug} has no files for version {base} to patch (it was deleted, or it is a container version). Get the current files with get_files and deploy them in full."),
        )
    })?;
    let cur_m = if current == base {
        base_m.clone()
    } else {
        versions::manifest(st, &app.id, current).await?.ok_or_else(|| {
            Problem::new(409, "stale_base", format!("The current version v{current} of {slug} has no files to merge with."))
        })?
    };

    // Decide every path touched by the base, the current version or the patch.
    let mut paths: BTreeSet<&str> = BTreeSet::new();
    paths.extend(base_m.entries.iter().map(|e| e.path.as_str()));
    paths.extend(cur_m.entries.iter().map(|e| e.path.as_str()));
    paths.extend(req.changes.keys().map(String::as_str));
    paths.extend(req.deletes.iter().map(String::as_str));

    let mut result: BTreeMap<String, Source> = BTreeMap::new();
    let mut conflicts = Vec::new();
    let (mut applied, mut merged_files) = (0usize, Vec::<String>::new());
    for path in paths {
        let b = base_m.get(path).map(|e| e.sha256.clone());
        let cur = cur_m.get(path).map(|e| e.sha256.clone());
        // What the patch makes of this path: its own change, a delete, or the base left alone.
        let (inc, inc_change) = match (req.changes.get(path), req.deletes.contains(path)) {
            (Some(Change::Blob(s)), _) => (Some(s.clone()), Some(Change::Blob(s.clone()))),
            (Some(Change::Bytes(bytes)), _) => (Some(versions::sha256_bytes(bytes)), Some(Change::Bytes(bytes.clone()))),
            (None, true) => (None, None),
            (None, false) => (b.clone(), None),
        };
        let touched = req.changes.contains_key(path) || req.deletes.contains(path);
        if inc == cur || inc == b {
            // Nothing for the patch to do here, or the current version already has it.
            if let Some(s) = cur {
                result.insert(path.to_string(), Source::Blob(s));
            }
            continue;
        }
        if cur == b {
            // Only the patch changed it.
            if touched {
                applied += 1;
            }
            match (inc, inc_change) {
                (Some(_), Some(Change::Bytes(bytes))) => {
                    result.insert(path.to_string(), Source::Bytes(bytes));
                }
                (Some(s), _) => {
                    result.insert(path.to_string(), Source::Blob(s));
                }
                (None, _) => {}
            }
            continue;
        }
        // Both changed it, differently: look at the contents.
        let bb = blob(st, b.as_deref()).await?;
        let cb = blob(st, cur.as_deref()).await?;
        let ib = match &inc_change {
            Some(Change::Bytes(x)) => Some(x.clone()),
            _ => blob(st, inc.as_deref()).await?,
        };
        match merge::three_way(path, bb.as_deref(), cb.as_deref(), ib.as_deref()) {
            Outcome::Resolved(Some(bytes)) => {
                applied += 1;
                merged_files.push(path.to_string());
                result.insert(path.to_string(), Source::Bytes(bytes));
            }
            Outcome::Resolved(None) => {
                applied += 1;
            }
            Outcome::Conflict(x) => conflicts.push(x),
        }
    }
    if !conflicts.is_empty() {
        let list: Vec<&str> = conflicts.iter().map(|c| c.path.as_str()).collect();
        return Err(Problem::new(
            409,
            "merge_conflict",
            format!(
                "Nothing was deployed: your changes to {} overlap with changes made to {slug} since v{base} (it is now v{current}). \
                 Get the current files (get_files, or get_files with \"since\": {base}), resolve these files by hand, and deploy again with \"base_version\": {current}.",
                list.join(", ")
            ),
        )
        .with("your_base", json!(base))
        .with("current_version", json!(current))
        .with("conflicts", Value::Array(conflicts.iter().map(|c| c.to_json()).collect())));
    }

    let files = materialise(st, result).await?;
    // The new version follows the current one: the patch has been merged onto it.
    o.base_version = Some(json!(current));
    let mut out = control::deploy_files(st, c, o, files).await?;
    if let Value::Object(m) = &mut out {
        m.insert(
            "patch".into(),
            json!({
                "base_version": base,
                "merged_onto": current,
                "stale_base": base != current,
                "changed": applied,
                "merged": merged_files,
            }),
        );
    }
    Ok(out)
}

/// The hashes among `wanted` that no version of the app has. A hash can only name a file of the same app, so a patch
/// cannot be used to probe for (or take) another workspace's files.
fn unknown_blobs(conn: &Connection, app_id: &str, wanted: &[String]) -> Result<Vec<String>> {
    let mut seen = HashSet::new();
    let mut missing = Vec::new();
    for sha in wanted {
        if seen.insert(sha)
            && !conn.exists("SELECT 1 FROM manifest_entries WHERE app_id = ? AND sha256 = ? LIMIT 1", params![app_id, sha])?
        {
            missing.push(sha.clone());
        }
    }
    Ok(missing)
}

async fn materialise(st: &State, result: BTreeMap<String, Source>) -> Result<Vec<BundleFile>> {
    let items: Vec<(String, Source)> = result.into_iter().collect();
    let mut out = Vec::with_capacity(items.len());
    for chunk in items.chunks(20) {
        let got = futures_util::future::try_join_all(chunk.iter().map(|(path, src)| async move {
            let bytes = match src {
                Source::Bytes(b) => b.clone(),
                Source::Blob(s) => versions::read_blob(st, s, FILE_BYTES).await?,
            };
            Ok::<_, Problem>(BundleFile { path: path.clone(), bytes })
        }))
        .await?;
        out.extend(got);
    }
    Ok(out)
}

// ---------- diff_versions ----------

fn version_arg(v: &Value) -> Option<i64> {
    match v {
        Value::Number(x) => x.as_f64(),
        Value::String(x) => x.trim().parse::<f64>().ok(),
        _ => None,
    }
    .filter(|f| f.fract() == 0.0 && *f >= 1.0 && *f < 9e15)
    .map(|f| f as i64)
}

/// A unified diff between two versions of an app (`to` defaults to the current version), cut off at about 100 KB.
pub async fn diff_versions(st: &State, c: &Caller, slug: &str, from: Option<&Value>, to: Option<&Value>) -> Result<Value> {
    require_role(c, "builder", "compare versions")?;
    let (c2, slug2) = (c.clone(), slug.to_string());
    let app = st.db.call(move |conn| control::get_app(conn, &c2, &slug2)).await?;
    fn given(v: Option<&Value>) -> Option<&Value> {
        v.filter(|v| !v.is_null() && !matches!(v, Value::String(s) if s.is_empty()))
    }
    let from_n =
        given(from).ok_or_else(|| Problem::new(400, "need_version", "Give \"from\", the version to compare from.")).and_then(|v| {
            version_arg(v).ok_or_else(|| Problem::new(404, "no_version", format!("{} is not a version number.", js_string(v))))
        })?;
    let to_n = match given(to) {
        Some(v) => version_arg(v).ok_or_else(|| Problem::new(404, "no_version", format!("{} is not a version number.", js_string(v))))?,
        None => {
            control::current_version(&app).ok_or_else(|| Problem::new(409, "no_version", format!("{} has no version yet.", app.slug)))?
        }
    };
    let (a, b) = (version_files(st, &app, from_n).await?, version_files(st, &app, to_n).await?);
    diff_manifests(st, &app.slug, &a, &b).await
}

async fn version_files(st: &State, app: &crate::model::AppRow, n: i64) -> Result<std::sync::Arc<Manifest>> {
    versions::manifest(st, &app.id, n).await?.ok_or_else(|| {
        Problem::new(404, "no_version", format!("{} has no version {n} with files. Use get_status to see its versions.", app.slug))
    })
}

async fn diff_manifests(st: &State, slug: &str, a: &Manifest, b: &Manifest) -> Result<Value> {
    let changes = versions::changes(a, b);
    let (mut added, mut modified, mut deleted) = (0, 0, 0);
    let mut diff = String::new();
    let mut truncated = false;
    let mut listed = Vec::new();
    for ch in &changes {
        match ch.status {
            "added" => added += 1,
            "deleted" => deleted += 1,
            _ => modified += 1,
        }
        listed.push(json!({ "path": ch.path, "status": ch.status }));
        if truncated {
            continue;
        }
        let (x, y) = (blob(st, ch.from.map(|e| e.sha256.as_str())).await?, blob(st, ch.to.map(|e| e.sha256.as_str())).await?);
        let piece = merge::unified(ch.path, x.as_deref(), y.as_deref());
        if diff.len() + piece.len() > DIFF_CAP {
            let room = DIFF_CAP.saturating_sub(diff.len());
            let mut end = room.min(piece.len());
            while !piece.is_char_boundary(end) {
                end -= 1;
            }
            diff.push_str(&piece[..end]);
            diff.push_str("\n... diff truncated\n");
            truncated = true;
        } else {
            diff.push_str(&piece);
        }
    }
    Ok(json!({
        "app": slug,
        "from": a.version,
        "to": b.version,
        "changes": { "added": added, "modified": modified, "deleted": deleted },
        "files": listed,
        "diff": diff,
        "truncated": truncated,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn obj(v: Value) -> Map<String, Value> {
        v.as_object().unwrap().clone()
    }

    #[test]
    fn a_request_is_a_patch_only_with_changes_or_deletes() {
        assert!(parse(&obj(json!({ "app": "x", "files": [] }))).unwrap().is_none());
        assert!(parse(&obj(json!({ "app": "x" }))).unwrap().is_none());
        let p = parse(&obj(json!({
            "changes": {
                "./a.txt": { "content": "hi" },
                "b.bin": { "content_base64": "AAEC" },
                "c.txt": { "sha256": "A".repeat(64) },
            },
            "deletes": ["old.js"],
        })))
        .unwrap()
        .unwrap();
        assert_eq!(p.changes["a.txt"], Change::Bytes(b"hi".to_vec()));
        assert_eq!(p.changes["b.bin"], Change::Bytes(vec![0, 1, 2]));
        assert_eq!(p.changes["c.txt"], Change::Blob("a".repeat(64)));
        assert!(p.deletes.contains("old.js"));
    }

    #[test]
    fn bad_patches_are_refused() {
        let err = |v: Value| parse(&obj(v)).unwrap_err().code;
        assert_eq!(err(json!({ "changes": {}, "files": [] })), "bad_patch");
        assert_eq!(err(json!({ "changes": { "a": { "content": "x", "sha256": "0" } } })), "bad_patch");
        assert_eq!(err(json!({ "changes": { "a": { "sha256": "xyz" } } })), "bad_patch");
        assert_eq!(err(json!({ "changes": { "../a": { "content": "x" } } })), "bad_path");
        assert_eq!(err(json!({ "deletes": ["_brod/x"] })), "bad_path");
        assert_eq!(err(json!({ "changes": { "a": { "content": "x" } }, "deletes": ["a"] })), "bad_patch");
        assert_eq!(err(json!({ "deletes": "a" })), "bad_patch");
    }
}
