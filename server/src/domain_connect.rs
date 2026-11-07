// SPDX-License-Identifier: AGPL-3.0-only
// Domain Connect: a signed link that has a DNS provider add a custom domain's two records once the person confirms.
// The server that signs must have published a template in Domain-Connect/Templates and the matching public key in DNS,
// so this is off unless DOMAIN_CONNECT_PRIVATE_KEY and its companions are set. Off, it makes no lookups at all.
//
// It only runs for zones already found on Cloudflare (domains.rs). Whoever runs a zone controls its _domainconnect TXT
// record and so the settings it leads to, so every address taken from them must be on Cloudflare: Brod neither fetches
// nor opens anything else. Any other answer, or none, means the person gets the ordinary Cloudflare steps instead.
use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use reqwest::Url;
use ring::rand::SystemRandom;
use ring::signature::{RSA_PKCS1_SHA256, RsaKeyPair};
use serde_json::Value;

use crate::config::{Config, ConfigError};
use crate::state::State;
use crate::util::encode_uri_component;

const DEFAULT_SERVICE_ID: &str = "custom_domain";
const REQUEST_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Clone)]
pub struct DomainConnect {
    key: Arc<RsaKeyPair>,
    key_host: String,
    provider_id: String,
    service_id: String,
}

/// Config derives Debug: the key must not come out of it.
impl std::fmt::Debug for DomainConnect {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DomainConnect")
            .field("key", &"(hidden)")
            .field("key_host", &self.key_host)
            .field("provider_id", &self.provider_id)
            .field("service_id", &self.service_id)
            .finish()
    }
}

fn dns_like(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}

impl DomainConnect {
    /// None when none of it is set. Half of it set is a mistake worth stopping for, not a reason to quietly stay off.
    pub fn from_vars(get: impl Fn(&str) -> Option<String>) -> Result<Option<DomainConnect>, ConfigError> {
        let (key, key_host, provider_id, service_id) = (
            get("DOMAIN_CONNECT_PRIVATE_KEY"),
            get("DOMAIN_CONNECT_KEY_HOST"),
            get("DOMAIN_CONNECT_PROVIDER_ID"),
            get("DOMAIN_CONNECT_SERVICE_ID"),
        );
        if key.is_none() && key_host.is_none() && provider_id.is_none() && service_id.is_none() {
            return Ok(None);
        }
        let (Some(key), Some(key_host), Some(provider_id)) = (key, key_host, provider_id) else {
            return Err(ConfigError(
                "Domain Connect needs DOMAIN_CONNECT_PRIVATE_KEY, DOMAIN_CONNECT_KEY_HOST and DOMAIN_CONNECT_PROVIDER_ID together. Leave all of them unset to keep it off.".into(),
            ));
        };
        let service_id = service_id.unwrap_or_else(|| DEFAULT_SERVICE_ID.into());
        for (name, value) in [
            ("DOMAIN_CONNECT_KEY_HOST", &key_host),
            ("DOMAIN_CONNECT_PROVIDER_ID", &provider_id),
            ("DOMAIN_CONNECT_SERVICE_ID", &service_id),
        ] {
            if !dns_like(value) {
                return Err(ConfigError(format!("{name} may only hold letters, digits, dots, dashes and underscores, not {value:?}.")));
            }
        }
        // This message must never carry the value.
        let compact: String = key.chars().filter(|c| !c.is_whitespace()).collect();
        let key = STANDARD.decode(compact.as_bytes()).ok().and_then(|der| RsaKeyPair::from_pkcs8(&der).ok()).ok_or_else(|| {
            ConfigError(
                "DOMAIN_CONNECT_PRIVATE_KEY must be an RSA key of at least 2048 bits, as PKCS#8 in base64: \
                 openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -outform DER | base64 | tr -d '\\n'"
                    .into(),
            )
        })?;
        Ok(Some(DomainConnect { key: Arc::new(key), key_host, provider_id, service_id }))
    }

    fn sign(&self, query: &str) -> Option<String> {
        let mut sig = vec![0; self.key.public().modulus_len()];
        self.key.sign(&RSA_PKCS1_SHA256, &SystemRandom::new(), query.as_bytes(), &mut sig).ok()?;
        Some(STANDARD.encode(sig))
    }

    /// The link that applies the template to `host`.`zone`. The signature covers the query string exactly as sent, up
    /// to but not including key and sig. Cloudflare wants sig last.
    pub fn apply_url(&self, sync_ux: &str, zone: &str, host: &str, token: &str) -> Option<String> {
        let query =
            format!("domain={}&host={}&token={}", encode_uri_component(zone), encode_uri_component(host), encode_uri_component(token));
        let sig = self.sign(&query)?;
        Some(format!(
            "{sync_ux}/v2/domainTemplates/providers/{}/services/{}/apply?{query}&key={}&sig={}",
            self.provider_id,
            self.service_id,
            encode_uri_component(&self.key_host),
            encode_uri_component(&sig),
        ))
    }

    /// Where this zone's provider applies templates, when it has the sync flow and knows this server's template.
    pub async fn sync_ux(&self, st: &State, zone: &str) -> Option<String> {
        let prefix =
            crate::domains::txt_records(st, &format!("_domainconnect.{zone}")).await?.iter().find_map(|v| discovery_prefix(&st.cfg, v))?;
        let settings = get_json(st, &format!("{prefix}/v2/{zone}/settings")).await?;
        let sync_ux = provider_url(&st.cfg, settings.get("urlSyncUX")?.as_str()?)?;
        let api = provider_url(&st.cfg, settings.get("urlAPI")?.as_str()?)?;
        let template = format!("{api}/v2/domainTemplates/providers/{}/services/{}", self.provider_id, self.service_id);
        let known = st.http.get(&template).timeout(REQUEST_TIMEOUT).send().await.ok()?.status().is_success();
        known.then_some(sync_ux)
    }
}

async fn get_json(st: &State, url: &str) -> Option<Value> {
    let r = st.http.get(url).timeout(REQUEST_TIMEOUT).send().await.ok()?;
    if !r.status().is_success() {
        return None;
    }
    r.json().await.ok()
}

/// A URL prefix from a provider's answer, when Brod may use it: https on Cloudflare. DEV_MODE tests also serve a fake
/// provider from 127.0.0.1 over plain http.
fn provider_url(cfg: &Config, raw: &str) -> Option<String> {
    let url = Url::parse(raw.trim()).ok()?;
    let host = url.host_str()?;
    if !url.username().is_empty() || url.password().is_some() || url.query().is_some() || url.fragment().is_some() {
        return None;
    }
    let cloudflare = url.scheme() == "https" && url.port().is_none() && (host == "cloudflare.com" || host.ends_with(".cloudflare.com"));
    let test_provider = cfg.dev_allow_loopback_git && url.scheme() == "http" && host == "127.0.0.1";
    (cloudflare || test_provider).then(|| url.as_str().trim_end_matches('/').to_string())
}

/// The _domainconnect TXT value is a host and path with no scheme, and https is implied.
fn discovery_prefix(cfg: &Config, txt: &str) -> Option<String> {
    let txt = txt.trim();
    let scheme = if cfg.dev_allow_loopback_git && txt.starts_with("127.0.0.1:") { "http" } else { "https" };
    provider_url(cfg, &format!("{scheme}://{txt}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::signature::{RSA_PKCS1_2048_8192_SHA256, UnparsedPublicKey};
    use std::collections::HashMap;
    use std::process::Command;

    /// A throwaway key made for each test run, so none is ever stored in the repository. ring cannot generate RSA keys.
    fn generated_test_key() -> String {
        let out = Command::new("openssl")
            .args(["genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-outform", "DER"])
            .output()
            .expect("these tests need openssl on the PATH to generate a throwaway key");
        assert!(out.status.success(), "openssl genpkey failed");
        STANDARD.encode(out.stdout)
    }

    fn parse(vars: &[(&str, &str)]) -> Result<Option<DomainConnect>, ConfigError> {
        let map: HashMap<String, String> = vars.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        DomainConnect::from_vars(|k| map.get(k).cloned())
    }

    fn configured() -> DomainConnect {
        let key = generated_test_key();
        parse(&[
            ("DOMAIN_CONNECT_PRIVATE_KEY", &key),
            ("DOMAIN_CONNECT_KEY_HOST", "_dcpubkeyv1"),
            ("DOMAIN_CONNECT_PROVIDER_ID", "brod.example"),
        ])
        .unwrap()
        .unwrap()
    }

    #[test]
    fn it_is_off_with_no_config_and_refuses_half_of_one() {
        assert!(parse(&[]).unwrap().is_none());
        assert!(Config::for_tests().domain_connect.is_none());
        for one in ["DOMAIN_CONNECT_PRIVATE_KEY", "DOMAIN_CONNECT_KEY_HOST", "DOMAIN_CONNECT_PROVIDER_ID", "DOMAIN_CONNECT_SERVICE_ID"] {
            assert!(parse(&[(one, "x")]).is_err(), "{one}");
        }
    }

    #[test]
    fn a_bad_key_is_refused_without_repeating_it() {
        let bad = "not-a-real-key-value";
        let e = parse(&[
            ("DOMAIN_CONNECT_PRIVATE_KEY", bad),
            ("DOMAIN_CONNECT_KEY_HOST", "_k"),
            ("DOMAIN_CONNECT_PROVIDER_ID", "brod.example"),
        ])
        .unwrap_err();
        assert!(e.0.contains("PKCS#8") && !e.0.contains(bad), "{}", e.0);
        let e = parse(&[
            ("DOMAIN_CONNECT_PRIVATE_KEY", "x"),
            ("DOMAIN_CONNECT_KEY_HOST", "a/b"),
            ("DOMAIN_CONNECT_PROVIDER_ID", "brod.example"),
        ])
        .unwrap_err();
        assert!(e.0.contains("DOMAIN_CONNECT_KEY_HOST"), "{}", e.0);
    }

    #[test]
    fn signs_the_query_it_sends_and_puts_the_signature_last() {
        let dc = configured();
        let url = dc.apply_url("https://dash.cloudflare.com/domainconnect", "example.org", "shop", "tok123").unwrap();
        let (path, query) = url.split_once('?').unwrap();
        assert_eq!(
            path,
            "https://dash.cloudflare.com/domainconnect/v2/domainTemplates/providers/brod.example/services/custom_domain/apply"
        );
        let (signed, rest) = query.split_once("&key=").unwrap();
        assert_eq!(signed, "domain=example.org&host=shop&token=tok123");
        let (key, sig) = rest.split_once("&sig=").unwrap();
        assert_eq!(key, "_dcpubkeyv1");
        assert!(!sig.contains('&') && !sig.contains('+') && !sig.contains('/') && !sig.contains('='), "url-encoded: {sig}");

        let sig = STANDARD.decode(crate::util::decode_uri_component(sig).unwrap()).unwrap();
        let public = UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, dc.key.public().as_ref().to_vec());
        public.verify(signed.as_bytes(), &sig).expect("verifies over the query string as sent");
        assert!(public.verify(b"domain=example.org&host=other&token=tok123", &sig).is_err(), "and over nothing else");
    }

    #[test]
    fn the_key_stays_out_of_debug_output() {
        let key = generated_test_key();
        let dc = parse(&[
            ("DOMAIN_CONNECT_PRIVATE_KEY", &key),
            ("DOMAIN_CONNECT_KEY_HOST", "_k"),
            ("DOMAIN_CONNECT_PROVIDER_ID", "brod.example"),
        ])
        .unwrap()
        .unwrap();
        let shown = format!("{dc:?}");
        assert!(shown.contains("(hidden)") && !shown.contains(&key[..40]), "{shown}");
    }

    #[test]
    fn only_uses_addresses_on_cloudflare() {
        let cfg = Config { dev_allow_loopback_git: false, ..Config::for_tests() };
        assert_eq!(
            provider_url(&cfg, "https://dash.cloudflare.com/domainconnect/").as_deref(),
            Some("https://dash.cloudflare.com/domainconnect")
        );
        assert_eq!(
            discovery_prefix(&cfg, "api.cloudflare.com/client/v4/dns/domainconnect").as_deref(),
            Some("https://api.cloudflare.com/client/v4/dns/domainconnect")
        );
        for bad in [
            "http://dash.cloudflare.com/x",
            "https://notcloudflare.com/x",
            "https://cloudflare.com.evil.example/x",
            "https://dash.cloudflare.com:8443/x",
            "https://me@dash.cloudflare.com/x",
            "https://dash.cloudflare.com/x?a=1",
            "http://127.0.0.1:9000/x",
            "https://169.254.169.254/x",
            "not a url",
        ] {
            assert_eq!(provider_url(&cfg, bad), None, "{bad}");
        }
        assert_eq!(discovery_prefix(&cfg, "127.0.0.1:9000/dc"), None);
        assert_eq!(discovery_prefix(&cfg, "evil.example/dc"), None);

        let dev = Config { dev_allow_loopback_git: true, ..Config::for_tests() };
        assert_eq!(discovery_prefix(&dev, "127.0.0.1:9000/dc").as_deref(), Some("http://127.0.0.1:9000/dc"));
        assert_eq!(provider_url(&dev, "http://10.0.0.1/x"), None);
    }
}
