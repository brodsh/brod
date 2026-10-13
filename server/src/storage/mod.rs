// SPDX-License-Identifier: AGPL-3.0-only
// Where app files live: under "<app id>/<version>/<path>", in a local folder or an S3-compatible bucket.
// Five calls (put, get, head, list, delete); bodies are streamed on the way out.
use axum::body::Body;
use bytes::Bytes;

use crate::config::StorageConfig;
use crate::problem::Result;

pub mod fs;
pub mod s3;

#[derive(Clone, Debug, PartialEq)]
pub struct ObjectMeta {
    pub key: String,
    pub size: u64,
    /// Without quotes.
    pub etag: String,
    pub content_type: Option<String>,
    /// When it was stored, as an ISO date, where the store says.
    pub uploaded: Option<String>,
}

impl ObjectMeta {
    /// The ETag header value, in quotes.
    pub fn http_etag(&self) -> String {
        format!("\"{}\"", self.etag)
    }
}

pub struct Object {
    pub meta: ObjectMeta,
    pub body: Body,
}

#[derive(Clone)]
pub enum Storage {
    Fs(fs::FsStore),
    S3(s3::S3Store),
}

impl Storage {
    pub fn from_config(c: &StorageConfig) -> Storage {
        match c {
            StorageConfig::Fs { dir } => Storage::Fs(fs::FsStore::new(dir.clone())),
            StorageConfig::S3 { endpoint, bucket, access_key_id, secret_access_key, region, virtual_hosted } => {
                Storage::S3(s3::S3Store::new(endpoint, bucket, access_key_id, secret_access_key, region, *virtual_hosted))
            }
        }
    }
    pub async fn put(&self, key: &str, bytes: Bytes, content_type: Option<&str>) -> Result<ObjectMeta> {
        match self {
            Storage::Fs(s) => s.put(key, bytes, content_type).await,
            Storage::S3(s) => s.put(key, bytes, content_type).await,
        }
    }
    pub async fn get(&self, key: &str) -> Result<Option<Object>> {
        match self {
            Storage::Fs(s) => s.get(key).await,
            Storage::S3(s) => s.get(key).await,
        }
    }
    pub async fn head(&self, key: &str) -> Result<Option<ObjectMeta>> {
        match self {
            Storage::Fs(s) => s.head(key).await,
            Storage::S3(s) => s.head(key).await,
        }
    }
    /// One page of keys under `prefix`, in key order, and a cursor for the next page.
    pub async fn list(&self, prefix: &str, cursor: Option<String>, limit: usize) -> Result<(Vec<ObjectMeta>, Option<String>)> {
        match self {
            Storage::Fs(s) => s.list(prefix, cursor, limit).await,
            Storage::S3(s) => s.list(prefix, cursor, limit).await,
        }
    }
    pub async fn delete(&self, key: &str) -> Result<()> {
        match self {
            Storage::Fs(s) => s.delete(key).await,
            Storage::S3(s) => s.delete(key).await,
        }
    }

    /// Read a whole object into memory (server code modules, which are small).
    pub async fn read(&self, key: &str, cap: usize) -> Result<Option<Vec<u8>>> {
        match self.get(key).await? {
            Some(o) => Ok(Some(crate::http::read_capped(o.body, cap, "The file").await?)),
            None => Ok(None),
        }
    }

    /// Delete every object under a prefix.
    pub async fn delete_prefix(&self, prefix: &str) -> Result<()> {
        let mut cursor = None;
        loop {
            let (objects, next) = self.list(prefix, cursor, 1000).await?;
            for chunk in objects.chunks(20) {
                futures_util::future::try_join_all(chunk.iter().map(|o| self.delete(&o.key))).await?;
            }
            match next {
                Some(c) => cursor = Some(c),
                None => return Ok(()),
            }
        }
    }
}
