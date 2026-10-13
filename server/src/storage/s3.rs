// SPDX-License-Identifier: AGPL-3.0-only
// App files in any S3-compatible bucket: Cloudflare R2's S3 endpoint, MinIO, AWS S3, Backblaze B2 and others.
// Requests are signed with AWS Signature Version 4, written out here rather than pulling in an SDK.
use axum::body::Body;
use bytes::Bytes;
use hmac::{Hmac, Mac};
use reqwest::Method;
use sha2::{Digest, Sha256};
use std::time::Duration;

use super::{Object, ObjectMeta};
use crate::problem::{Problem, Result};

#[derive(Clone)]
pub struct S3Store {
    client: reqwest::Client,
    /// scheme://host[:port]
    origin: String,
    host: String,
    /// The path before the key: "/<bucket>" (path style) or "" (virtual-hosted), plus any endpoint path.
    base_path: String,
    access_key_id: String,
    secret_access_key: String,
    region: String,
}

/// RFC 3986 encoding, as SigV4 canonical requests need it: everything but A-Z a-z 0-9 - _ . ~
const RFC3986: &percent_encoding::AsciiSet = &percent_encoding::NON_ALPHANUMERIC.remove(b'-').remove(b'_').remove(b'.').remove(b'~');
fn enc(s: &str) -> String {
    percent_encoding::utf8_percent_encode(s, RFC3986).to_string()
}
fn hmac(key: &[u8], data: &str) -> Vec<u8> {
    let mut m = Hmac::<Sha256>::new_from_slice(key).expect("HMAC takes a key of any length");
    m.update(data.as_bytes());
    m.finalize().into_bytes().to_vec()
}
fn sha_hex(b: &[u8]) -> String {
    hex::encode(Sha256::digest(b))
}

fn unxml(s: &str) -> String {
    s.replace("&lt;", "<").replace("&gt;", ">").replace("&quot;", "\"").replace("&apos;", "'").replace("&amp;", "&")
}
fn tag<'a>(xml: &'a str, name: &str) -> Option<&'a str> {
    let open = format!("<{name}>");
    let close = format!("</{name}>");
    let start = xml.find(&open)? + open.len();
    let end = xml[start..].find(&close)? + start;
    Some(&xml[start..end])
}

impl S3Store {
    pub fn new(endpoint: &str, bucket: &str, access_key_id: &str, secret_access_key: &str, region: &str, virtual_hosted: bool) -> S3Store {
        let endpoint = endpoint.trim_end_matches('/');
        let (scheme, rest) = endpoint.split_once("://").unwrap_or(("https", endpoint));
        let (host, path) = match rest.find('/') {
            Some(i) => (&rest[..i], rest[i..].trim_end_matches('/')),
            None => (rest, ""),
        };
        let (host, base_path) = if virtual_hosted {
            (format!("{bucket}.{host}"), path.to_string())
        } else {
            (host.to_string(), format!("{path}/{}", enc(bucket)))
        };
        S3Store {
            client: reqwest::Client::builder()
                .connect_timeout(Duration::from_secs(10))
                .timeout(Duration::from_secs(120))
                .build()
                .expect("HTTP client builds"),
            origin: format!("{scheme}://{host}"),
            host,
            base_path,
            access_key_id: access_key_id.into(),
            secret_access_key: secret_access_key.into(),
            region: if region.is_empty() { "auto".into() } else { region.into() },
        }
    }

    fn key_path(&self, key: &str) -> String {
        format!("{}/{}", self.base_path, key.split('/').map(enc).collect::<Vec<_>>().join("/"))
    }

    /// Send one signed request. `query` is (name, value) pairs, unencoded.
    async fn send(
        &self,
        method: Method,
        path: &str,
        query: &[(&str, String)],
        body: Bytes,
        content_type: Option<&str>,
    ) -> Result<reqwest::Response> {
        let stamp = crate::util::iso(crate::util::now());
        let amz_date = format!("{}{}{}T{}{}{}Z", &stamp[0..4], &stamp[5..7], &stamp[8..10], &stamp[11..13], &stamp[14..16], &stamp[17..19]);
        let date = &amz_date[..8];
        let payload = sha_hex(&body);
        let mut q: Vec<(String, String)> = query.iter().map(|(k, v)| (enc(k), enc(v))).collect();
        q.sort();
        let canonical_query = q.iter().map(|(k, v)| format!("{k}={v}")).collect::<Vec<_>>().join("&");
        let mut headers: Vec<(&str, String)> =
            vec![("host", self.host.clone()), ("x-amz-content-sha256", payload.clone()), ("x-amz-date", amz_date.clone())];
        if let Some(ct) = content_type {
            headers.push(("content-type", ct.to_string()));
        }
        headers.sort_by(|a, b| a.0.cmp(b.0));
        let signed = headers.iter().map(|(k, _)| *k).collect::<Vec<_>>().join(";");
        let canonical_headers: String = headers.iter().map(|(k, v)| format!("{k}:{}\n", v.trim())).collect();
        let canonical = format!("{}\n{path}\n{canonical_query}\n{canonical_headers}\n{signed}\n{payload}", method.as_str());
        let scope = format!("{date}/{}/s3/aws4_request", self.region);
        let to_sign = format!("AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}", sha_hex(canonical.as_bytes()));
        let k = hmac(&hmac(&hmac(&hmac(format!("AWS4{}", self.secret_access_key).as_bytes(), date), &self.region), "s3"), "aws4_request");
        let signature = hex::encode(hmac(&k, &to_sign));
        let auth = format!("AWS4-HMAC-SHA256 Credential={}/{scope}, SignedHeaders={signed}, Signature={signature}", self.access_key_id);
        let url =
            if canonical_query.is_empty() { format!("{}{path}", self.origin) } else { format!("{}{path}?{canonical_query}", self.origin) };
        let mut req = self.client.request(method.clone(), url).header("authorization", auth);
        for (k, v) in &headers {
            if *k != "host" {
                req = req.header(*k, v);
            }
        }
        if !body.is_empty() || method == Method::PUT {
            req = req.body(body);
        }
        req.send().await.map_err(|e| Problem::internal(format!("S3 {method} {path}: {e}")))
    }

    async fn check(&self, res: reqwest::Response, what: &str, ok404: bool) -> Result<Option<reqwest::Response>> {
        if res.status().is_success() {
            return Ok(Some(res));
        }
        if ok404 && res.status().as_u16() == 404 {
            return Ok(None);
        }
        let status = res.status().as_u16();
        let text = res.text().await.unwrap_or_default();
        Err(Problem::internal(format!(
            "S3 {what} failed: {status} {} {}",
            tag(&text, "Code").unwrap_or(""),
            tag(&text, "Message").map(String::from).unwrap_or_else(|| text.chars().take(200).collect())
        )))
    }

    fn meta(key: &str, res: &reqwest::Response) -> ObjectMeta {
        let h = |n: &str| res.headers().get(n).and_then(|v| v.to_str().ok()).map(String::from);
        ObjectMeta {
            key: key.to_string(),
            size: h("content-length").and_then(|v| v.parse().ok()).unwrap_or(0),
            etag: h("etag").unwrap_or_default().trim_start_matches("W/").trim_matches('"').to_string(),
            content_type: h("content-type"),
            uploaded: None,
        }
    }

    pub async fn put(&self, key: &str, bytes: Bytes, content_type: Option<&str>) -> Result<ObjectMeta> {
        let size = bytes.len() as u64;
        let res = self.send(Method::PUT, &self.key_path(key), &[], bytes, content_type).await?;
        let res = self.check(res, &format!("PUT {key}"), false).await?.ok_or_else(|| Problem::internal("S3 PUT"))?;
        let etag = res.headers().get("etag").and_then(|v| v.to_str().ok()).unwrap_or("").trim_matches('"').to_string();
        Ok(ObjectMeta {
            key: key.to_string(),
            size,
            etag,
            content_type: content_type.map(String::from),
            uploaded: Some(crate::util::iso(crate::util::now())),
        })
    }

    pub async fn get(&self, key: &str) -> Result<Option<Object>> {
        let res = self.send(Method::GET, &self.key_path(key), &[], Bytes::new(), None).await?;
        let Some(res) = self.check(res, &format!("GET {key}"), true).await? else {
            return Ok(None);
        };
        let meta = S3Store::meta(key, &res);
        Ok(Some(Object { meta, body: Body::from_stream(res.bytes_stream()) }))
    }

    pub async fn head(&self, key: &str) -> Result<Option<ObjectMeta>> {
        let res = self.send(Method::HEAD, &self.key_path(key), &[], Bytes::new(), None).await?;
        Ok(self.check(res, &format!("HEAD {key}"), true).await?.map(|r| S3Store::meta(key, &r)))
    }

    pub async fn list(&self, prefix: &str, cursor: Option<String>, limit: usize) -> Result<(Vec<ObjectMeta>, Option<String>)> {
        let mut q = vec![("list-type", "2".to_string()), ("prefix", prefix.to_string()), ("max-keys", limit.to_string())];
        if let Some(c) = cursor {
            q.push(("continuation-token", c));
        }
        let res = self.send(Method::GET, &format!("{}/", self.base_path), &q, Bytes::new(), None).await?;
        let res = self.check(res, "LIST", false).await?.ok_or_else(|| Problem::internal("S3 LIST"))?;
        let xml = res.text().await.map_err(Problem::internal)?;
        let mut objects = Vec::new();
        let mut rest = xml.as_str();
        while let Some(c) = tag(rest, "Contents") {
            objects.push(ObjectMeta {
                key: unxml(tag(c, "Key").unwrap_or("")),
                size: tag(c, "Size").and_then(|s| s.parse().ok()).unwrap_or(0),
                etag: unxml(tag(c, "ETag").unwrap_or("")).trim_matches('"').to_string(),
                content_type: None,
                uploaded: tag(c, "LastModified").map(String::from),
            });
            let end = rest.find("</Contents>").map(|i| i + "</Contents>".len()).unwrap_or(rest.len());
            rest = &rest[end..];
        }
        let next = if tag(&xml, "IsTruncated") == Some("true") { tag(&xml, "NextContinuationToken").map(unxml) } else { None };
        Ok((objects, next))
    }

    pub async fn delete(&self, key: &str) -> Result<()> {
        let res = self.send(Method::DELETE, &self.key_path(key), &[], Bytes::new(), None).await?;
        self.check(res, &format!("DELETE {key}"), true).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_paths_for_both_addressing_styles() {
        let p = S3Store::new("http://127.0.0.1:9000/", "brod-bundles", "k", "s", "", false);
        assert_eq!(p.origin, "http://127.0.0.1:9000");
        assert_eq!(p.key_path("app_1/1/a b+c.html"), "/brod-bundles/app_1/1/a%20b%2Bc.html");
        assert_eq!(p.region, "auto");
        let v = S3Store::new("https://r2.example.com", "b", "k", "s", "auto", true);
        assert_eq!(v.origin, "https://b.r2.example.com");
        assert_eq!(v.key_path("x/y"), "/x/y");
    }

    #[test]
    fn reads_list_results() {
        let xml = "<ListBucketResult><IsTruncated>true</IsTruncated><NextContinuationToken>a&amp;b</NextContinuationToken><Contents><Key>a/1</Key><Size>3</Size><ETag>&quot;e&quot;</ETag></Contents></ListBucketResult>";
        assert_eq!(tag(xml, "IsTruncated"), Some("true"));
        assert_eq!(unxml(tag(xml, "NextContinuationToken").unwrap()), "a&b");
    }
}
