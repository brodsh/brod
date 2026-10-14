// SPDX-License-Identifier: AGPL-3.0-only
// App files in a folder: the object under objects/<key> and its metadata in meta/<key>.json. The layout is the
// same as src/node/fs-bucket.ts, so a FILES_DIR written by the Node build is read here unchanged.
use axum::body::Body;
use bytes::Bytes;
use md5::{Digest, Md5};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use tokio_util::io::ReaderStream;

use super::{Object, ObjectMeta};
use crate::problem::{Problem, Result};

#[derive(Clone)]
pub struct FsStore {
    root: PathBuf,
}

#[derive(Serialize, Deserialize)]
struct Meta {
    etag: String,
    #[serde(rename = "contentType", skip_serializing_if = "Option::is_none")]
    content_type: Option<String>,
    uploaded: String,
}

fn parts(key: &str) -> Result<Vec<&str>> {
    let p: Vec<&str> = key.split('/').collect();
    if p.iter().any(|x| x.is_empty() || *x == "." || *x == ".." || x.contains('\\') || x.contains('\0')) {
        return Err(Problem::internal(format!("bad object key: {key}")));
    }
    Ok(p)
}

impl FsStore {
    pub fn new(root: PathBuf) -> FsStore {
        FsStore { root }
    }
    fn data(&self, key: &str) -> Result<PathBuf> {
        Ok(parts(key)?.iter().fold(self.root.join("objects"), |p, x| p.join(x)))
    }
    fn meta_file(&self, key: &str) -> Result<PathBuf> {
        let p = parts(key)?;
        let (last, dirs) = p.split_last().ok_or_else(|| Problem::internal("empty key"))?;
        Ok(dirs.iter().fold(self.root.join("meta"), |p, x| p.join(x)).join(format!("{last}.json")))
    }

    pub async fn put(&self, key: &str, bytes: Bytes, content_type: Option<&str>) -> Result<ObjectMeta> {
        let etag = hex::encode(Md5::digest(&bytes));
        let (data, meta) = (self.data(key)?, self.meta_file(key)?);
        let uploaded = crate::util::iso(crate::util::now());
        let m = Meta { etag: etag.clone(), content_type: content_type.map(String::from), uploaded: uploaded.clone() };
        write_atomic(&data, &bytes).await?;
        write_atomic(&meta, serde_json::to_string(&m)?.as_bytes()).await?;
        Ok(ObjectMeta {
            key: key.to_string(),
            size: bytes.len() as u64,
            etag,
            content_type: content_type.map(String::from),
            uploaded: Some(uploaded),
        })
    }

    pub async fn head(&self, key: &str) -> Result<Option<ObjectMeta>> {
        let Ok(raw) = tokio::fs::read(self.meta_file(key)?).await else {
            return Ok(None);
        };
        let Ok(m) = serde_json::from_slice::<Meta>(&raw) else {
            return Ok(None);
        };
        let Ok(stat) = tokio::fs::metadata(self.data(key)?).await else {
            return Ok(None);
        };
        Ok(Some(ObjectMeta {
            key: key.to_string(),
            size: stat.len(),
            etag: m.etag,
            content_type: m.content_type,
            uploaded: Some(m.uploaded),
        }))
    }

    pub async fn get(&self, key: &str) -> Result<Option<Object>> {
        let Some(meta) = self.head(key).await? else {
            return Ok(None);
        };
        let Ok(file) = tokio::fs::File::open(self.data(key)?).await else {
            return Ok(None);
        };
        Ok(Some(Object { meta, body: Body::from_stream(ReaderStream::with_capacity(file, 64 * 1024)) }))
    }

    pub async fn list(&self, prefix: &str, cursor: Option<String>, limit: usize) -> Result<(Vec<ObjectMeta>, Option<String>)> {
        let base = self.root.join("objects");
        // Only walk the folder the prefix points into, not the whole store.
        let dir_part = prefix.rsplit_once('/').map(|(d, _)| d).unwrap_or("");
        let start = if dir_part.is_empty() { base.clone() } else { parts(dir_part)?.iter().fold(base.clone(), |p, x| p.join(x)) };
        let all = tokio::task::spawn_blocking(move || {
            let mut out = Vec::new();
            walk(&start, &base, &mut out);
            out
        })
        .await
        .map_err(Problem::internal)?;
        let mut keys: Vec<String> = all.into_iter().filter(|k| k.starts_with(prefix) && cursor.as_ref().is_none_or(|c| k > c)).collect();
        keys.sort();
        let more = keys.len() > limit;
        keys.truncate(limit);
        let mut objects = Vec::with_capacity(keys.len());
        for k in &keys {
            if let Some(m) = self.head(k).await? {
                objects.push(m);
            }
        }
        Ok((objects, if more { keys.last().cloned() } else { None }))
    }

    pub async fn delete(&self, key: &str) -> Result<()> {
        for p in [self.data(key)?, self.meta_file(key)?] {
            match tokio::fs::remove_file(&p).await {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(e.into()),
            }
        }
        Ok(())
    }
}

fn walk(dir: &Path, base: &Path, out: &mut Vec<String>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for e in entries.flatten() {
        let p = e.path();
        if e.file_type().map(|t| t.is_dir()).unwrap_or(false) {
            walk(&p, base, out);
        } else if let Ok(rel) = p.strip_prefix(base) {
            let key: Vec<String> = rel.components().map(|c| c.as_os_str().to_string_lossy().into_owned()).collect();
            if !key.last().is_some_and(|n| n.starts_with(".tmp-")) {
                out.push(key.join("/"));
            }
        }
    }
}

/// Write to a temporary file next to the target, then rename, so a reader never sees half a file.
async fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let dir = path.parent().ok_or_else(|| Problem::internal("no parent folder"))?;
    tokio::fs::create_dir_all(dir).await?;
    let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    let tmp = dir.join(format!(".tmp-{}-{name}", crate::util::random_id("", 6)));
    tokio::fs::write(&tmp, bytes).await?;
    tokio::fs::rename(&tmp, path).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn stores_lists_and_deletes() {
        let s = FsStore::new(std::env::temp_dir().join(format!("brod-fs-{}", crate::util::random_id("", 6))));
        let m = s.put("app_1/1/index.html", Bytes::from_static(b"<h1>hi</h1>"), Some("text/html; charset=utf-8")).await.unwrap();
        assert_eq!(m.etag, hex::encode(Md5::digest(b"<h1>hi</h1>")));
        assert_eq!(m.http_etag(), format!("\"{}\"", m.etag));
        s.put("app_1/1/a/b.js", Bytes::from_static(b"x"), None).await.unwrap();
        s.put("app_2/1/index.html", Bytes::from_static(b"y"), None).await.unwrap();
        let got = s.get("app_1/1/index.html").await.unwrap().unwrap();
        assert_eq!(got.meta.size, 11);
        assert_eq!(got.meta.content_type.as_deref(), Some("text/html; charset=utf-8"));
        let body = crate::http::read_capped(got.body, 100, "x").await.unwrap();
        assert_eq!(body, b"<h1>hi</h1>");
        let (page, cursor) = s.list("app_1/", None, 1).await.unwrap();
        assert_eq!(page.len(), 1);
        let (rest, none) = s.list("app_1/", cursor, 10).await.unwrap();
        assert_eq!((rest.len(), none), (1, None));
        assert!(s.get("app_1/1/missing").await.unwrap().is_none());
        assert!(s.get("../x").await.is_err());
        s.delete("app_1/1/index.html").await.unwrap();
        assert!(s.head("app_1/1/index.html").await.unwrap().is_none());
    }
}
