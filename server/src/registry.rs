// SPDX-License-Identifier: AGPL-3.0-only
// Brod's image registry: a CNCF Distribution (`registry:2`) service with no published port, configured for token auth
// (REGISTRY_AUTH=token). Only Brod talks to it. Images move between it and the nodes through Brod over each node's
// tunnel (deployments.rs): after a build Brod reads the image's OCI layout from the node and pushes it here; to run a
// version it pulls the image from here and loads it into the node's Docker. So a node needs no route to the registry,
// no credentials and no insecure-registry setting in its Docker daemon.
//
// Tokens are JWTs signed with ES256 by REGISTRY_SIGNING_KEY (generated into secrets.env when self-hosted). Their header
// carries the key's self-signed certificate (x5c), and Brod writes the same certificate to BROD_REGISTRY_CERT_FILE,
// which the registry reads as its rootcertbundle. Each token is good for 5 minutes and for one repository,
// apps/<app id>, with only the actions asked for (pull, push, delete).
//
// Images are apps/<app id>:v<n>; the manifest digest is recorded on the version (versions.spec).
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use bytes::Bytes;
use ring::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair};
use serde_json::{Value, json};

use crate::config::RegistryConfig;
use crate::problem::{Problem, Result};
use crate::util::{now, random_id};

/// The issuer and service the registry is configured with (docker-compose.yml).
pub const ISSUER: &str = "brod";
pub const SERVICE: &str = "brod-registry";
/// How long a registry token works.
pub const TOKEN_SECS: i64 = 300;

/// The media types a manifest may have.
pub const MANIFEST_TYPES: [&str; 4] = [
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.docker.distribution.manifest.v2+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
];

/// A fresh ECDSA P-256 key, PKCS#8 in base64, for REGISTRY_SIGNING_KEY.
pub fn new_key() -> String {
    let rng = ring::rand::SystemRandom::new();
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).expect("the system has randomness");
    STANDARD.encode(pkcs8.as_ref())
}

/// Whether `pkcs8` is an ECDSA P-256 key ring can sign with.
pub fn check_key(pkcs8: &[u8]) -> bool {
    EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8, &ring::rand::SystemRandom::new()).is_ok()
}

/// The repository of an app's images.
pub fn repository(app_id: &str) -> String {
    format!("apps/{app_id}")
}

/// What Brod needs to reach the registry: its address, the signing key and its certificate.
pub struct Registry {
    pub url: String,
    key: EcdsaKeyPair,
    cert_der: Vec<u8>,
}

impl Registry {
    /// Load the key and make sure the registry's certificate file holds its certificate: an existing one for the same
    /// key is kept (the registry reads the file only when it starts), anything else is replaced.
    pub fn open(cfg: &RegistryConfig) -> std::result::Result<Registry, String> {
        let rng = ring::rand::SystemRandom::new();
        let key = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &cfg.key_pkcs8, &rng)
            .map_err(|_| "REGISTRY_SIGNING_KEY is not an ECDSA P-256 key".to_string())?;
        let existing = std::fs::read_to_string(&cfg.cert_file).ok().and_then(|pem| cert_for(&pem, key.public_key().as_ref()));
        let cert_der = match existing {
            Some(der) => der,
            None => {
                let (der, pem) = make_cert(&cfg.key_pkcs8)?;
                if let Some(dir) = cfg.cert_file.parent().filter(|d| !d.as_os_str().is_empty()) {
                    std::fs::create_dir_all(dir).map_err(|e| format!("could not create {}: {e}", dir.display()))?;
                }
                std::fs::write(&cfg.cert_file, pem).map_err(|e| format!("could not write {}: {e}", cfg.cert_file.display()))?;
                der
            }
        };
        Ok(Registry { url: cfg.url.clone(), key, cert_der })
    }

    /// A bearer token for one repository and these actions (pull, push, delete), good for TOKEN_SECS.
    pub fn token(&self, repository: &str, actions: &[&str]) -> String {
        let t = now() / 1000;
        let header = json!({ "typ": "JWT", "alg": "ES256", "x5c": [STANDARD.encode(&self.cert_der)] });
        let claims = json!({
            "iss": ISSUER, "sub": "brod", "aud": SERVICE, "iat": t, "nbf": t - 10, "exp": t + TOKEN_SECS, "jti": random_id("", 16),
            "access": [{ "type": "repository", "name": repository, "actions": actions }],
        });
        let input = format!("{}.{}", URL_SAFE_NO_PAD.encode(header.to_string()), URL_SAFE_NO_PAD.encode(claims.to_string()));
        let sig = self.key.sign(&ring::rand::SystemRandom::new(), input.as_bytes()).expect("ECDSA signs");
        format!("{input}.{}", URL_SAFE_NO_PAD.encode(sig.as_ref()))
    }

    fn url(&self, repository: &str, rest: &str) -> String {
        format!("{}/v2/{repository}/{rest}", self.url)
    }

    /// Whether the repository already has this blob.
    pub async fn has_blob(&self, http: &reqwest::Client, repository: &str, digest: &str) -> Result<bool> {
        let res = http
            .head(self.url(repository, &format!("blobs/{digest}")))
            .bearer_auth(self.token(repository, &["pull"]))
            .send()
            .await
            .map_err(unreachable)?;
        match res.status().as_u16() {
            200 => Ok(true),
            404 => Ok(false),
            s => Err(refused("check a blob", s, "")),
        }
    }

    /// Upload a blob in one request (a monolithic upload), streaming `body`.
    pub async fn push_blob(
        &self,
        http: &reqwest::Client,
        repository: &str,
        digest: &str,
        body: reqwest::Body,
        len: Option<u64>,
    ) -> Result<()> {
        let token = self.token(repository, &["pull", "push"]);
        let res = http.post(self.url(repository, "blobs/uploads/")).bearer_auth(&token).send().await.map_err(unreachable)?;
        if res.status().as_u16() != 202 {
            let s = res.status().as_u16();
            return Err(refused("start an upload", s, &res.text().await.unwrap_or_default()));
        }
        let location = res.headers().get("location").and_then(|l| l.to_str().ok()).unwrap_or("").to_string();
        let location =
            if location.starts_with("http://") || location.starts_with("https://") { location } else { format!("{}{location}", self.url) };
        let sep = if location.contains('?') { '&' } else { '?' };
        let mut put = http
            .put(format!("{location}{sep}digest={digest}"))
            .bearer_auth(&token)
            .header("content-type", "application/octet-stream")
            .timeout(Duration::from_secs(3600))
            .body(body);
        if let Some(len) = len {
            put = put.header("content-length", len);
        }
        let res = put.send().await.map_err(unreachable)?;
        if res.status().as_u16() != 201 {
            let s = res.status().as_u16();
            return Err(refused("upload a blob", s, &res.text().await.unwrap_or_default()));
        }
        Ok(())
    }

    /// Store a manifest under a tag or digest. Its digest, as the registry computed it.
    pub async fn put_manifest(
        &self,
        http: &reqwest::Client,
        repository: &str,
        reference: &str,
        media_type: &str,
        bytes: Bytes,
    ) -> Result<String> {
        let res = http
            .put(self.url(repository, &format!("manifests/{reference}")))
            .bearer_auth(self.token(repository, &["pull", "push"]))
            .header("content-type", media_type)
            .body(bytes)
            .send()
            .await
            .map_err(unreachable)?;
        if res.status().as_u16() != 201 {
            let s = res.status().as_u16();
            return Err(refused("store a manifest", s, &res.text().await.unwrap_or_default()));
        }
        Ok(res.headers().get("docker-content-digest").and_then(|d| d.to_str().ok()).unwrap_or("").to_string())
    }

    /// A manifest by tag or digest: its media type and bytes. None when the registry does not have it.
    pub async fn manifest(&self, http: &reqwest::Client, repository: &str, reference: &str) -> Result<Option<(String, Bytes)>> {
        let res = http
            .get(self.url(repository, &format!("manifests/{reference}")))
            .bearer_auth(self.token(repository, &["pull"]))
            .header("accept", MANIFEST_TYPES.join(", "))
            .send()
            .await
            .map_err(unreachable)?;
        match res.status().as_u16() {
            200 => {
                let mt = res.headers().get("content-type").and_then(|c| c.to_str().ok()).unwrap_or("").to_string();
                Ok(Some((mt, res.bytes().await.map_err(unreachable)?)))
            }
            404 => Ok(None),
            s => Err(refused("read a manifest", s, &res.text().await.unwrap_or_default())),
        }
    }

    /// A blob's bytes, streamed.
    pub async fn blob(&self, http: &reqwest::Client, repository: &str, digest: &str) -> Result<reqwest::Response> {
        let res = http
            .get(self.url(repository, &format!("blobs/{digest}")))
            .bearer_auth(self.token(repository, &["pull"]))
            .timeout(Duration::from_secs(3600))
            .send()
            .await
            .map_err(unreachable)?;
        if res.status().as_u16() != 200 {
            let s = res.status().as_u16();
            return Err(refused("read a blob", s, ""));
        }
        Ok(res)
    }

    /// Delete a manifest by digest, so the registry's garbage collection can free its layers. A manifest that is
    /// already gone is fine.
    pub async fn delete_manifest(&self, http: &reqwest::Client, repository: &str, digest: &str) -> Result<()> {
        let res = http
            .delete(self.url(repository, &format!("manifests/{digest}")))
            .bearer_auth(self.token(repository, &["delete"]))
            .send()
            .await
            .map_err(unreachable)?;
        match res.status().as_u16() {
            202 | 404 => Ok(()),
            s => Err(refused("delete a manifest", s, &res.text().await.unwrap_or_default())),
        }
    }
}

fn unreachable(e: reqwest::Error) -> Problem {
    Problem::new(503, "registry_unreachable", format!("Brod's image registry is not reachable: {e}"))
}

fn refused(what: &str, status: u16, body: &str) -> Problem {
    let body: String = body.chars().take(300).collect();
    Problem::new(502, "registry_failed", format!("Brod's image registry refused to {what} ({status}). {body}").trim().to_string())
}

/// The DER of the certificate in `pem` when it is for the public key `point` (an uncompressed P-256 point).
fn cert_for(pem: &str, point: &[u8]) -> Option<Vec<u8>> {
    let (_, p) = x509_parser::pem::parse_x509_pem(pem.as_bytes()).ok()?;
    let cert = p.parse_x509().ok()?;
    (cert.public_key().subject_public_key.data.as_ref() == point).then(|| p.contents.clone())
}

/// A self-signed CA certificate for the key, valid until 2100: its DER and PEM.
fn make_cert(pkcs8: &[u8]) -> std::result::Result<(Vec<u8>, String), String> {
    let kp = rcgen::KeyPair::try_from(pkcs8).map_err(|e| format!("the registry key: {e}"))?;
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).map_err(|e| e.to_string())?;
    params.distinguished_name = rcgen::DistinguishedName::new();
    params.distinguished_name.push(rcgen::DnType::CommonName, "Brod registry tokens");
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params.not_before = rcgen::date_time_ymd(2025, 1, 1);
    params.not_after = rcgen::date_time_ymd(2100, 1, 1);
    let cert = params.self_signed(&kp).map_err(|e| format!("the registry certificate: {e}"))?;
    Ok((cert.der().to_vec(), cert.pem()))
}

/// The claims of a token, without checking its signature (for tests and logs).
pub fn claims(token: &str) -> Option<Value> {
    let part = token.split('.').nth(1)?;
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(part).ok()?).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn registry() -> Registry {
        let dir = std::env::temp_dir().join(format!("brod-registry-test-{}", random_id("", 8)));
        let cfg = RegistryConfig {
            url: "http://registry:5000".into(),
            key_pkcs8: STANDARD.decode(new_key()).unwrap(),
            cert_file: dir.join("token.crt"),
        };
        let r = Registry::open(&cfg).unwrap();
        // Opening again keeps the certificate the registry already read.
        let pem = std::fs::read_to_string(&cfg.cert_file).unwrap();
        let again = Registry::open(&cfg).unwrap();
        assert_eq!(again.cert_der, r.cert_der);
        assert_eq!(std::fs::read_to_string(&cfg.cert_file).unwrap(), pem);
        // A certificate for another key is replaced.
        let other = RegistryConfig { key_pkcs8: STANDARD.decode(new_key()).unwrap(), ..cfg.clone() };
        let third = Registry::open(&other).unwrap();
        assert_ne!(third.cert_der, r.cert_der);
        let _ = std::fs::remove_dir_all(dir);
        r
    }

    #[test]
    fn tokens_are_scoped_to_one_repository_and_short_lived() {
        let r = registry();
        let token = r.token(&repository("app_abc"), &["pull"]);
        let c = claims(&token).unwrap();
        assert_eq!(c["iss"], ISSUER);
        assert_eq!(c["aud"], SERVICE);
        assert_eq!(c["access"], json!([{ "type": "repository", "name": "apps/app_abc", "actions": ["pull"] }]));
        assert_eq!(c["exp"].as_i64().unwrap() - c["iat"].as_i64().unwrap(), TOKEN_SECS);
        let push = claims(&r.token("apps/app_x", &["pull", "push"])).unwrap();
        assert_eq!(push["access"][0]["actions"], json!(["pull", "push"]));
        // The header carries the certificate the registry trusts, and the ES256 signature checks out against its key.
        let parts: Vec<&str> = token.split('.').collect();
        let header: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[0]).unwrap()).unwrap();
        assert_eq!(header["alg"], "ES256");
        assert_eq!(STANDARD.decode(header["x5c"][0].as_str().unwrap()).unwrap(), r.cert_der);
        let sig = URL_SAFE_NO_PAD.decode(parts[2]).unwrap();
        let key = ring::signature::UnparsedPublicKey::new(&ring::signature::ECDSA_P256_SHA256_FIXED, r.key.public_key().as_ref());
        assert!(key.verify(format!("{}.{}", parts[0], parts[1]).as_bytes(), &sig).is_ok());
        assert!(check_key(&STANDARD.decode(new_key()).unwrap()) && !check_key(b"nope"));
    }
}
