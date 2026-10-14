// SPDX-License-Identifier: AGPL-3.0-only
// HTTPS without a proxy in front. With BROD_TLS set, Brod listens on 443 and 80 itself:
//
// - 443: TLS. The handshake's server name (SNI) picks the certificate. A name without one gets it on its first
//   visit (on-demand TLS), but only after app::may_have_certificate says the address is real: the API host, a
//   workspace or app under APPS_DOMAIN, or a proven custom domain. Nobody can make Brod request certificates for
//   made-up names.
// - 80: answers the CA's HTTP-01 challenges and sends everything else to https.
//
// Certificates come from an ACME CA (BROD_TLS=acme: Let's Encrypt unless ACME_DIRECTORY says otherwise) or, for
// testing, from a local CA that Brod makes itself (BROD_TLS=local, like Caddy's `tls internal`). They are kept in
// <data dir>/certs/ and renewed in the background once a third of their lifetime is left. A name that stops being
// served (a removed domain or app) loses its certificate at the next renewal check.
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError, RwLock};
use std::time::{Duration, Instant};

use instant_acme::{
    Account, AccountCredentials, AuthorizationStatus, ChallengeType, Identifier, NewAccount, NewOrder, OrderStatus, RetryPolicy,
};
use rustls::ServerConfig;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use serde_json::json;
use tokio::net::TcpListener;
use tokio_rustls::LazyConfigAcceptor;

use crate::state::State;

pub const LETS_ENCRYPT: &str = "https://acme-v02.api.letsencrypt.org/directory";

/// Where certificates come from.
#[derive(Clone, Debug)]
pub enum Issuer {
    /// An ACME CA such as Let's Encrypt, over HTTP-01 on port 80.
    Acme {
        directory: String,
        email: Option<String>,
        /// A PEM root to trust for the ACME server itself (a test CA such as Pebble). None: the public roots.
        root: Option<PathBuf>,
    },
    /// A CA Brod makes and keeps in certs/local-ca.crt. Browsers do not trust it: for testing only.
    Local,
}

#[derive(Clone, Debug)]
pub struct TlsConfig {
    pub https_listen: SocketAddr,
    pub http_listen: SocketAddr,
    pub issuer: Issuer,
}

/// The crypto Brod's TLS uses.
fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

struct Entry {
    config: Arc<ServerConfig>,
    not_before: i64,
    not_after: i64,
}

impl Entry {
    /// Renew once a third of the certificate's lifetime is left.
    fn wants_renewal(&self, now: i64) -> bool {
        now > self.not_after - (self.not_after - self.not_before) / 3
    }
}

/// The certificates Brod holds, and what it needs to get more.
pub struct Certs {
    dir: PathBuf,
    issuer: Issuer,
    entries: RwLock<HashMap<String, Arc<Entry>>>,
    /// One issuance per name at a time.
    locks: Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
    /// Names whose issuance failed recently, so a CA's rate limit is not hammered.
    failures: Mutex<HashMap<String, Instant>>,
    /// HTTP-01 challenge tokens and their key authorizations, while an order is open.
    challenges: RwLock<HashMap<String, String>>,
    account: tokio::sync::OnceCell<Account>,
}

const RETRY_AFTER_FAILURE: Duration = Duration::from_secs(10 * 60);

fn now_secs() -> i64 {
    crate::util::now() / 1000
}

/// A server name worth looking at: lower case, no trailing dot, letters, digits, hyphens and dots only.
fn clean_name(name: &str) -> Option<String> {
    let n = name.trim_end_matches('.').to_ascii_lowercase();
    let ok = !n.is_empty()
        && n.len() <= 253
        && n.contains('.')
        && n.split('.').all(|l| !l.is_empty() && l.len() <= 63 && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'));
    ok.then_some(n)
}

/// A certificate chain and key in PEM as a server configuration, with the first certificate's validity.
fn entry_from_pem(chain_pem: &str, key_pem: &str) -> Result<Entry, String> {
    let chain: Vec<CertificateDer<'static>> =
        CertificateDer::pem_slice_iter(chain_pem.as_bytes()).collect::<Result<_, _>>().map_err(|e| format!("bad certificate: {e}"))?;
    let first = chain.first().ok_or("no certificate in the chain")?;
    let (_, cert) = x509_parser::parse_x509_certificate(first).map_err(|e| format!("bad certificate: {e}"))?;
    let (not_before, not_after) = (cert.validity().not_before.timestamp(), cert.validity().not_after.timestamp());
    let key = PrivateKeyDer::from_pem_slice(key_pem.as_bytes()).map_err(|e| format!("bad key: {e}"))?;
    let mut config = ServerConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .map_err(|e| format!("certificate and key do not match: {e}"))?;
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(Entry { config: Arc::new(config), not_before, not_after })
}

fn write_private(path: &Path, data: &str) -> std::io::Result<()> {
    use std::io::Write;
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create(true).truncate(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut o, 0o600);
    o.open(path)?.write_all(data.as_bytes())
}

impl Certs {
    pub fn new(data_dir: &Path, issuer: Issuer) -> std::io::Result<Arc<Certs>> {
        let dir = data_dir.join("certs");
        std::fs::create_dir_all(&dir)?;
        Ok(Arc::new(Certs {
            dir,
            issuer,
            entries: RwLock::default(),
            locks: Mutex::default(),
            failures: Mutex::default(),
            challenges: RwLock::default(),
            account: tokio::sync::OnceCell::new(),
        }))
    }

    fn paths(&self, name: &str) -> (PathBuf, PathBuf) {
        (self.dir.join(format!("{name}.crt")), self.dir.join(format!("{name}.key")))
    }

    fn cached(&self, name: &str) -> Option<Arc<Entry>> {
        self.entries.read().unwrap_or_else(PoisonError::into_inner).get(name).cloned()
    }

    fn load(&self, name: &str) -> Option<Entry> {
        let (crt, key) = self.paths(name);
        let (chain, key) = (std::fs::read_to_string(crt).ok()?, std::fs::read_to_string(key).ok()?);
        entry_from_pem(&chain, &key).map_err(|e| tracing::warn!("tls: ignoring the stored certificate for {name}: {e}")).ok()
    }

    /// The configuration to finish a handshake for `name`: held, stored, or newly issued when the name is one Brod
    /// serves. None when there is no certificate and none may be issued.
    pub async fn config_for(&self, st: &State, name: &str) -> Option<Arc<ServerConfig>> {
        let name = clean_name(name)?;
        let now = now_secs();
        if let Some(e) = self.cached(&name).filter(|e| e.not_after > now) {
            return Some(e.config.clone());
        }
        let lock = self.locks.lock().unwrap_or_else(PoisonError::into_inner).entry(name.clone()).or_default().clone();
        let _held = lock.lock().await;
        if let Some(e) = self.cached(&name).filter(|e| e.not_after > now) {
            return Some(e.config.clone());
        }
        if let Some(e) = self.load(&name).filter(|e| e.not_after > now) {
            let config = e.config.clone();
            self.entries.write().unwrap_or_else(PoisonError::into_inner).insert(name, Arc::new(e));
            return Some(config);
        }
        self.obtain(st, &name).await.map(|e| e.config.clone())
    }

    /// Issue a certificate for `name` if Brod serves it and it has not failed lately, store it and hold it.
    async fn obtain(&self, st: &State, name: &str) -> Option<Arc<Entry>> {
        if self.failures.lock().unwrap_or_else(PoisonError::into_inner).get(name).is_some_and(|t| t.elapsed() < RETRY_AFTER_FAILURE) {
            return None;
        }
        match crate::app::may_have_certificate(st, name).await {
            Ok(true) => {}
            Ok(false) => return None,
            Err(e) => {
                tracing::warn!("tls: could not check {name}: {}", e.message);
                return None;
            }
        }
        let issued = match &self.issuer {
            Issuer::Local => self.issue_local(name),
            Issuer::Acme { .. } => self.issue_acme(name).await,
        };
        let stored = issued.and_then(|(chain, key)| {
            let entry = entry_from_pem(&chain, &key)?;
            let (crt, k) = self.paths(name);
            write_private(&k, &key).and_then(|_| std::fs::write(&crt, &chain)).map_err(|e| format!("cannot store it: {e}"))?;
            Ok(entry)
        });
        match stored {
            Ok(entry) => {
                tracing::info!("tls: certificate for {name} until {}", crate::util::iso(entry.not_after * 1000));
                let entry = Arc::new(entry);
                self.entries.write().unwrap_or_else(PoisonError::into_inner).insert(name.to_string(), entry.clone());
                self.failures.lock().unwrap_or_else(PoisonError::into_inner).remove(name);
                Some(entry)
            }
            Err(e) => {
                tracing::warn!("tls: no certificate for {name}: {e}");
                self.failures.lock().unwrap_or_else(PoisonError::into_inner).insert(name.to_string(), Instant::now());
                None
            }
        }
    }

    // ---------- the local CA (testing) ----------

    fn local_ca_params() -> rcgen::CertificateParams {
        let mut p = rcgen::CertificateParams::default();
        p.distinguished_name.push(rcgen::DnType::CommonName, "Brod local CA");
        p.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        p.key_usages = vec![rcgen::KeyUsagePurpose::KeyCertSign, rcgen::KeyUsagePurpose::CrlSign, rcgen::KeyUsagePurpose::DigitalSignature];
        p
    }

    /// The local CA's key, made (with its certificate, certs/local-ca.crt, for clients to trust) on first use.
    fn local_ca_key(&self) -> Result<rcgen::KeyPair, String> {
        let (crt, key) = (self.dir.join("local-ca.crt"), self.dir.join("local-ca.key"));
        if let Ok(pem) = std::fs::read_to_string(&key) {
            return rcgen::KeyPair::from_pem(&pem).map_err(|e| e.to_string());
        }
        let k = rcgen::KeyPair::generate().map_err(|e| e.to_string())?;
        let cert = Self::local_ca_params().self_signed(&k).map_err(|e| e.to_string())?;
        write_private(&key, &k.serialize_pem()).and_then(|_| std::fs::write(&crt, cert.pem())).map_err(|e| e.to_string())?;
        Ok(k)
    }

    fn issue_local(&self, name: &str) -> Result<(String, String), String> {
        let ca = rcgen::Issuer::new(Self::local_ca_params(), self.local_ca_key()?);
        let mut p = rcgen::CertificateParams::new(vec![name.to_string()]).map_err(|e| e.to_string())?;
        let today = time_now();
        p.not_before = today - time::Duration::days(1);
        p.not_after = today + time::Duration::days(90);
        let key = rcgen::KeyPair::generate().map_err(|e| e.to_string())?;
        let cert = p.signed_by(&key, &ca).map_err(|e| e.to_string())?;
        Ok((cert.pem(), key.serialize_pem()))
    }

    // ---------- ACME ----------

    /// The ACME account, from certs/acme-account.json, or registered (and stored) on first use.
    async fn account(&self) -> Result<&Account, String> {
        let Issuer::Acme { directory, email, root } = &self.issuer else { return Err("not an ACME issuer".into()) };
        self.account
            .get_or_try_init(|| async {
                let builder = || match root {
                    Some(r) => Account::builder_with_root(r),
                    None => Account::builder(),
                };
                let file = self.dir.join("acme-account.json");
                if let Ok(raw) = std::fs::read_to_string(&file)
                    && let Ok(v) = serde_json::from_str::<serde_json::Value>(&raw)
                    && v["directory"].as_str() == Some(directory.as_str())
                    && let Ok(creds) = serde_json::from_value::<AccountCredentials>(v["credentials"].clone())
                {
                    return builder().map_err(|e| e.to_string())?.from_credentials(creds).await.map_err(|e| e.to_string());
                }
                let contact = email.as_ref().map(|e| format!("mailto:{e}"));
                let contacts: Vec<&str> = contact.iter().map(String::as_str).collect();
                let (account, creds) = builder()
                    .map_err(|e| e.to_string())?
                    .create(
                        &NewAccount { contact: &contacts, terms_of_service_agreed: true, only_return_existing: false },
                        directory.clone(),
                        None,
                    )
                    .await
                    .map_err(|e| format!("cannot register with {directory}: {e}"))?;
                let stored = json!({ "directory": directory, "credentials": creds });
                write_private(&file, &stored.to_string()).map_err(|e| format!("cannot store the ACME account: {e}"))?;
                tracing::info!("tls: registered an ACME account with {directory}");
                Ok(account)
            })
            .await
    }

    async fn issue_acme(&self, name: &str) -> Result<(String, String), String> {
        let account = self.account().await?;
        let mut order = account.new_order(&NewOrder::new(&[Identifier::Dns(name.to_string())])).await.map_err(|e| e.to_string())?;
        let mut tokens = Vec::new();
        let result = async {
            let mut auths = order.authorizations();
            while let Some(a) = auths.next().await {
                let mut a = a.map_err(|e| e.to_string())?;
                match a.status {
                    AuthorizationStatus::Pending => {}
                    AuthorizationStatus::Valid => continue,
                    s => return Err(format!("authorization is {s:?}")),
                }
                let mut ch = a.challenge(ChallengeType::Http01).ok_or("the CA offered no HTTP-01 challenge")?;
                let token = ch.token.clone();
                self.challenges
                    .write()
                    .unwrap_or_else(PoisonError::into_inner)
                    .insert(token.clone(), ch.key_authorization().as_str().to_string());
                tokens.push(token);
                ch.set_ready().await.map_err(|e| e.to_string())?;
            }
            let retry = RetryPolicy::new().timeout(Duration::from_secs(90));
            match order.poll_ready(&retry).await.map_err(|e| e.to_string())? {
                OrderStatus::Ready => {}
                s => {
                    return Err(format!("the order is {s:?}: the CA could not reach http://{name}/.well-known/acme-challenge/ on port 80"));
                }
            }
            let key = order.finalize().await.map_err(|e| e.to_string())?;
            let chain = order.poll_certificate(&retry).await.map_err(|e| e.to_string())?;
            Ok((chain, key))
        }
        .await;
        let mut ch = self.challenges.write().unwrap_or_else(PoisonError::into_inner);
        for t in tokens {
            ch.remove(&t);
        }
        result
    }

    /// The key authorization for an HTTP-01 token, while its order is open.
    pub fn challenge(&self, token: &str) -> Option<String> {
        self.challenges.read().unwrap_or_else(PoisonError::into_inner).get(token).cloned()
    }

    /// Renew certificates past two thirds of their life, and drop those for names Brod no longer serves.
    pub async fn renew(&self, st: &State) {
        let mut names: Vec<String> = std::fs::read_dir(&self.dir)
            .map(|d| {
                d.filter_map(|e| e.ok()?.file_name().to_str()?.strip_suffix(".crt").map(String::from)).filter(|n| n != "local-ca").collect()
            })
            .unwrap_or_default();
        names.sort();
        for name in names {
            let Some(entry) = self.cached(&name).or_else(|| self.load(&name).map(Arc::new)) else { continue };
            if !crate::app::may_have_certificate(st, &name).await.unwrap_or(true) {
                tracing::info!("tls: {name} is no longer served; removing its certificate");
                self.entries.write().unwrap_or_else(PoisonError::into_inner).remove(&name);
                let (crt, key) = self.paths(&name);
                let _ = std::fs::remove_file(crt);
                let _ = std::fs::remove_file(key);
                continue;
            }
            if entry.wants_renewal(now_secs()) {
                let lock = self.locks.lock().unwrap_or_else(PoisonError::into_inner).entry(name.clone()).or_default().clone();
                let _held = lock.lock().await;
                self.failures.lock().unwrap_or_else(PoisonError::into_inner).remove(&name);
                // On failure the old certificate stays in use until it expires, and the next check tries again.
                self.obtain(st, &name).await;
            }
        }
    }
}

fn time_now() -> time::OffsetDateTime {
    time::OffsetDateTime::from_unix_timestamp(now_secs()).unwrap_or(time::OffsetDateTime::UNIX_EPOCH)
}

/// Start the HTTPS and HTTP listeners and the renewal loop. Errors only when a port cannot be opened.
pub async fn start(st: State, tls: TlsConfig) -> Result<(), String> {
    let certs = Certs::new(&st.cfg.data_dir, tls.issuer.clone()).map_err(|e| format!("cannot create the certificate folder: {e}"))?;
    let https = TcpListener::bind(tls.https_listen).await.map_err(|e| format!("cannot listen on {}: {e}", tls.https_listen))?;
    let http = TcpListener::bind(tls.http_listen).await.map_err(|e| format!("cannot listen on {}: {e}", tls.http_listen))?;
    let what = match &tls.issuer {
        Issuer::Acme { directory, .. } => format!("certificates from {directory}"),
        Issuer::Local => format!("certificates from the local CA in {}", certs.dir.join("local-ca.crt").display()),
    };
    tracing::info!("Brod HTTPS on {} and HTTP on {} ({what})", tls.https_listen, tls.http_listen);

    {
        let (st, certs) = (st.clone(), certs.clone());
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(12 * 3600));
            loop {
                tick.tick().await;
                certs.renew(&st).await;
            }
        });
    }
    {
        let certs = certs.clone();
        tokio::spawn(async move {
            loop {
                let Ok((stream, peer)) = http.accept().await else { continue };
                let certs = certs.clone();
                tokio::spawn(async move {
                    let service = hyper::service::service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
                        let certs = certs.clone();
                        async move { Ok::<_, std::convert::Infallible>(plain_http(&certs, req)) }
                    });
                    let _ = hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new())
                        .serve_connection(hyper_util::rt::TokioIo::new(stream), service)
                        .await;
                    let _ = peer;
                });
            }
        });
    }
    tokio::spawn(async move {
        loop {
            let Ok((stream, peer)) = https.accept().await else { continue };
            let _ = stream.set_nodelay(true);
            let (st, certs) = (st.clone(), certs.clone());
            tokio::spawn(async move {
                let handshake = async {
                    let start = LazyConfigAcceptor::new(rustls::server::Acceptor::default(), stream).await.ok()?;
                    let name = start.client_hello().server_name()?.to_string();
                    let config = certs.config_for(&st, &name).await?;
                    start.into_stream(config).await.ok()
                };
                let Ok(Some(tls)) = tokio::time::timeout(Duration::from_secs(120), handshake).await else { return };
                crate::app::serve_connection(st, tls, peer.ip(), crate::http::Via::Https).await;
            });
        }
    });
    Ok(())
}

/// Port 80: the CA's HTTP-01 challenges, and a redirect to https for everything else.
fn plain_http<B>(certs: &Certs, req: hyper::Request<B>) -> axum::response::Response {
    use crate::http::response;
    let path = req.uri().path();
    if let Some(token) = path.strip_prefix("/.well-known/acme-challenge/") {
        return match certs.challenge(token) {
            Some(k) => response(200, k, &[("content-type", "application/octet-stream".into())]),
            None => response(404, "", &[]),
        };
    }
    let host = req.headers().get("host").and_then(|h| h.to_str().ok()).map(|h| h.split(':').next().unwrap_or("").to_string());
    match host.and_then(|h| clean_name(&h)) {
        Some(h) => {
            let pq = req.uri().path_and_query().map(|p| p.as_str()).unwrap_or("/");
            response(308, "", &[("location", format!("https://{h}{pq}"))])
        }
        None => response(400, "", &[]),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cleans_server_names() {
        assert_eq!(clean_name("Shop.Example.com.").as_deref(), Some("shop.example.com"));
        assert_eq!(clean_name("localhost"), None);
        assert_eq!(clean_name("a/b.com"), None);
        assert_eq!(clean_name("../x.com"), None);
    }

    #[test]
    fn issues_from_the_local_ca_and_reads_it_back() {
        let dir = std::env::temp_dir().join(format!("brod-tls-{}", crate::util::random_id("", 6)));
        let certs = Certs::new(&dir, Issuer::Local).unwrap();
        let (chain, key) = certs.issue_local("shop.example.test").unwrap();
        let e = entry_from_pem(&chain, &key).unwrap();
        assert!(e.not_after - e.not_before > 80 * 86400);
        assert!(!e.wants_renewal(now_secs()));
        assert!(e.wants_renewal(e.not_after - 10 * 86400));
        // The CA is made once and kept.
        let ca = std::fs::read_to_string(dir.join("certs/local-ca.crt")).unwrap();
        certs.issue_local("other.example.test").unwrap();
        assert_eq!(std::fs::read_to_string(dir.join("certs/local-ca.crt")).unwrap(), ca);
        let _ = std::fs::remove_dir_all(dir);
    }
}
