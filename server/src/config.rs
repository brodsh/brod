// SPDX-License-Identifier: AGPL-3.0-only
// Configuration from environment variables (and a .env file).
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;

#[derive(Clone, Debug)]
pub enum StorageConfig {
    /// App files in a folder on this machine.
    Fs { dir: PathBuf },
    /// App files in an S3-compatible bucket (Cloudflare R2, MinIO, AWS S3, ...).
    S3 { endpoint: String, bucket: String, access_key_id: String, secret_access_key: String, region: String, virtual_hosted: bool },
}

#[derive(Clone, Debug)]
pub struct Config {
    pub apps_domain: String,
    pub api_origin: String,
    /// The host of API_ORIGIN, lowercased, for example "brod.sh".
    pub api_host: String,
    pub admin_secret: String,
    pub identity_secret: String,
    pub secrets_key: String,
    pub dev_mode: bool,
    pub resend_api_key: Option<String>,
    /// The sender for sign-in and invitation emails. Required with RESEND_API_KEY.
    pub email_from: Option<String>,
    /// BROD_GA_ID: a Google Analytics 4 measurement ID for the public landing page (home.rs). None: no Google tag.
    pub ga_id: Option<String>,
    pub google_client_id: Option<String>,
    pub google_client_secret: Option<String>,
    pub listen: SocketAddr,
    pub data_dir: PathBuf,
    /// BROD_DATABASE_URL: Postgres instead of the SQLite file in data_dir. None: SQLite.
    pub database_url: Option<String>,
    pub storage: StorageConfig,
    /// Take the scheme from X-Forwarded-Proto (set it when Brod runs behind Caddy or another proxy you control).
    pub trust_proxy: bool,
    /// Server apps: where the workerd sidecar listens, and the secret it and Brod share. None: static apps only.
    pub runtime: Option<RuntimeConfig>,
    /// Marketplace previews: the headless-browser sidecar that screenshots and records a listing's release in a
    /// sandbox (preview.rs), and the secret both sides share. None: listings have only the previews people upload.
    pub preview: Option<RuntimeConfig>,
    /// Billing through Stripe. None: plans can only be changed by hand in the database.
    pub stripe: Option<StripeConfig>,
    /// DNS-over-HTTPS (JSON) endpoint that checks custom domains' TXT records. Default Cloudflare's.
    pub dns_resolver_url: String,
    /// The name custom domains point their CNAME at. None: the API host.
    pub custom_domain_target: Option<String>,
    /// BROD_TLS: Brod serves HTTPS itself, with certificates on demand (tls.rs). None: a proxy in front does.
    pub tls: Option<crate::tls::TlsConfig>,
    /// BROD_NETWORK: what happens when an app reaches an outside host its brod.json does not declare (network.rs).
    pub network: NetworkPolicy,
    /// DEV_MODE only: a smaller free plan storage (DEV_FREE_STORAGE_MB), so tests can run out of it.
    pub dev_free_storage_mb: Option<i64>,
}

/// BROD_NETWORK. `Log` (the default) lets every request through and records the undeclared ones, so makers can fix
/// their declarations before `Enforce` refuses them. `Off` neither checks nor records.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NetworkPolicy {
    Off,
    Log,
    Enforce,
}

impl NetworkPolicy {
    pub fn name(self) -> &'static str {
        match self {
            NetworkPolicy::Off => "off",
            NetworkPolicy::Log => "log",
            NetworkPolicy::Enforce => "enforce",
        }
    }
}

#[derive(Clone, Debug)]
pub struct StripeConfig {
    pub secret_key: String,
    pub webhook_secret: String,
    /// The recurring Stripe prices for the paid plans.
    pub price_solo: Option<String>,
    pub price_team: Option<String>,
    /// https://api.stripe.com, or a stand-in for tests.
    pub api_base: String,
}

#[derive(Clone, Debug)]
pub struct RuntimeConfig {
    pub url: String,
    pub secret: String,
}

/// A configuration problem the operator must fix. Its message names variables, never their values.
#[derive(Debug)]
pub struct ConfigError(pub String);

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl Config {
    /// Read the process environment, after loading `.env` from the working directory if there is one.
    pub fn from_env() -> Result<Config, ConfigError> {
        let _ = dotenvy::dotenv();
        Config::from_vars(&std::env::vars().collect())
    }

    pub fn from_vars(v: &HashMap<String, String>) -> Result<Config, ConfigError> {
        let get = |k: &str| v.get(k).map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
        let mut need: Vec<&str> =
            ["APPS_DOMAIN", "API_ORIGIN", "ADMIN_SECRET", "IDENTITY_SECRET"].into_iter().filter(|k| get(k).is_none()).collect();
        let s3_keys = ["S3_ENDPOINT", "S3_BUCKET", "S3_ACCESS_KEY_ID", "S3_SECRET_ACCESS_KEY"];
        let s3 = s3_keys.iter().any(|k| get(k).is_some());
        if s3 {
            need.extend(s3_keys.iter().filter(|k| get(k).is_none()));
        }
        if !need.is_empty() {
            return Err(ConfigError(format!(
                "Brod is not configured yet. Set these environment variables: {}. See deploy/.env.example.",
                need.join(", ")
            )));
        }
        let api_origin = get("API_ORIGIN").unwrap_or_default().trim_end_matches('/').to_string();
        let api_host = api_origin.split_once("://").map(|(_, h)| h).unwrap_or(&api_origin).split('/').next().unwrap_or("").to_lowercase();
        let data_dir = PathBuf::from(get("BROD_DATA_DIR").unwrap_or_else(|| "data".into()));
        let storage = if s3 {
            StorageConfig::S3 {
                endpoint: get("S3_ENDPOINT").unwrap_or_default(),
                bucket: get("S3_BUCKET").unwrap_or_default(),
                access_key_id: get("S3_ACCESS_KEY_ID").unwrap_or_default(),
                secret_access_key: get("S3_SECRET_ACCESS_KEY").unwrap_or_default(),
                region: get("S3_REGION").unwrap_or_else(|| "auto".into()),
                virtual_hosted: get("S3_VIRTUAL_HOSTED").as_deref() == Some("1"),
            }
        } else {
            StorageConfig::Fs { dir: get("FILES_DIR").map(PathBuf::from).unwrap_or_else(|| data_dir.join("files")) }
        };
        let listen = get("BROD_LISTEN").unwrap_or_else(|| "0.0.0.0:8080".into());
        let listen: SocketAddr =
            listen.parse().map_err(|_| ConfigError(format!("BROD_LISTEN must be an address such as 0.0.0.0:8080, not {listen:?}.")))?;
        let database_url = get("BROD_DATABASE_URL");
        if let Some(u) = &database_url
            && !(u.starts_with("postgres://") || u.starts_with("postgresql://"))
        {
            return Err(ConfigError("BROD_DATABASE_URL must be a postgres:// URL. Leave it unset to keep the SQLite database.".into()));
        }
        let runtime = match (get("BROD_RUNTIME_URL"), get("BROD_RUNTIME_SECRET")) {
            (Some(url), Some(secret)) if secret.len() >= 16 => Some(RuntimeConfig { url: url.trim_end_matches('/').to_string(), secret }),
            (Some(_), _) => {
                return Err(ConfigError("BROD_RUNTIME_URL needs BROD_RUNTIME_SECRET, a random value of at least 16 characters.".into()));
            }
            _ => None,
        };
        let preview = match (get("BROD_PREVIEW_URL"), get("BROD_PREVIEW_SECRET")) {
            (Some(url), Some(secret)) if secret.len() >= 16 => Some(RuntimeConfig { url: url.trim_end_matches('/').to_string(), secret }),
            (Some(_), _) => {
                return Err(ConfigError("BROD_PREVIEW_URL needs BROD_PREVIEW_SECRET, a random value of at least 16 characters.".into()));
            }
            _ => None,
        };
        let stripe = match (get("STRIPE_SECRET_KEY"), get("STRIPE_WEBHOOK_SECRET")) {
            (Some(secret_key), Some(webhook_secret)) => {
                let (price_solo, price_team) = (get("STRIPE_PRICE_SOLO"), get("STRIPE_PRICE_TEAM"));
                if price_solo.is_none() && price_team.is_none() {
                    return Err(ConfigError(
                        "Billing needs STRIPE_PRICE_SOLO or STRIPE_PRICE_TEAM, the price ids of the paid plans.".into(),
                    ));
                }
                let api_base = get("STRIPE_API_BASE").unwrap_or_else(|| "https://api.stripe.com".into()).trim_end_matches('/').to_string();
                Some(StripeConfig { secret_key, webhook_secret, price_solo, price_team, api_base })
            }
            (Some(_), None) => {
                return Err(ConfigError(
                    "STRIPE_SECRET_KEY needs STRIPE_WEBHOOK_SECRET, the signing secret of the webhook endpoint at /stripe/webhook.".into(),
                ));
            }
            _ => None,
        };
        let addr = |name: &str, default: &str| -> Result<SocketAddr, ConfigError> {
            let v = get(name).unwrap_or_else(|| default.into());
            v.parse().map_err(|_| ConfigError(format!("{name} must be an address such as {default}, not {v:?}.")))
        };
        let tls = match get("BROD_TLS").as_deref() {
            None | Some("0") | Some("off") => None,
            Some(mode @ ("acme" | "local")) => {
                if !api_origin.starts_with("https://") {
                    return Err(ConfigError("BROD_TLS serves HTTPS, so API_ORIGIN must be an https:// address.".into()));
                }
                let issuer = if mode == "local" {
                    crate::tls::Issuer::Local
                } else {
                    crate::tls::Issuer::Acme {
                        directory: get("ACME_DIRECTORY").unwrap_or_else(|| crate::tls::LETS_ENCRYPT.into()),
                        email: get("ACME_EMAIL"),
                        root: get("ACME_CA_ROOT").map(PathBuf::from),
                    }
                };
                Some(crate::tls::TlsConfig {
                    https_listen: addr("BROD_HTTPS_LISTEN", "0.0.0.0:443")?,
                    http_listen: addr("BROD_HTTP_LISTEN", "0.0.0.0:80")?,
                    issuer,
                })
            }
            Some(other) => {
                return Err(ConfigError(format!(
                    "BROD_TLS must be \"acme\" (certificates from Let's Encrypt or ACME_DIRECTORY), \"local\" (a local test CA) or unset, not {other:?}."
                )));
            }
        };
        if get("RESEND_API_KEY").is_some() && get("EMAIL_FROM").is_none() {
            return Err(ConfigError(
                "RESEND_API_KEY is set but EMAIL_FROM is not. Set EMAIL_FROM to a sender Resend has verified, for example \"Brod <brod@example.com>\"."
                    .into(),
            ));
        }
        let ga_id = get("BROD_GA_ID");
        if let Some(id) = &ga_id
            && !(id.starts_with("G-") && id.len() <= 24 && id[2..].chars().all(|c| c.is_ascii_alphanumeric()) && id.len() > 2)
        {
            return Err(ConfigError(format!("BROD_GA_ID must be a Google Analytics 4 measurement ID such as G-ABC123XYZ, not {id:?}.")));
        }
        let network = match get("BROD_NETWORK").as_deref() {
            None | Some("log") => NetworkPolicy::Log,
            Some("enforce") => NetworkPolicy::Enforce,
            Some("off") => NetworkPolicy::Off,
            Some(other) => {
                return Err(ConfigError(format!(
                    "BROD_NETWORK must be \"log\" (record undeclared outside requests, the default), \"enforce\" (refuse them) or \"off\", not {other:?}."
                )));
            }
        };
        Ok(Config {
            network,
            apps_domain: get("APPS_DOMAIN").unwrap_or_default().to_lowercase(),
            api_origin,
            api_host,
            admin_secret: get("ADMIN_SECRET").unwrap_or_default(),
            identity_secret: get("IDENTITY_SECRET").unwrap_or_default(),
            secrets_key: get("SECRETS_KEY").unwrap_or_default(),
            dev_mode: get("DEV_MODE").as_deref() == Some("1"),
            resend_api_key: get("RESEND_API_KEY"),
            email_from: get("EMAIL_FROM"),
            ga_id,
            google_client_id: get("GOOGLE_CLIENT_ID"),
            google_client_secret: get("GOOGLE_CLIENT_SECRET"),
            listen,
            data_dir,
            database_url,
            storage,
            trust_proxy: get("BROD_TRUST_PROXY").as_deref() == Some("1"),
            runtime,
            preview,
            stripe,
            dns_resolver_url: get("DNS_RESOLVER_URL").unwrap_or_else(|| "https://cloudflare-dns.com/dns-query".into()),
            tls,
            custom_domain_target: get("CUSTOM_DOMAIN_TARGET")
                .map(|t| t.trim().trim_end_matches('.').to_lowercase())
                .filter(|t| !t.is_empty()),
            dev_free_storage_mb: if get("DEV_MODE").as_deref() == Some("1") {
                get("DEV_FREE_STORAGE_MB").and_then(|v| v.parse().ok())
            } else {
                None
            },
        })
    }

    /// A configuration for tests.
    pub fn for_tests() -> Config {
        let v: HashMap<String, String> = [
            ("APPS_DOMAIN", "localhost:8787"),
            ("API_ORIGIN", "http://localhost:8787"),
            ("ADMIN_SECRET", "test-admin-secret"),
            ("IDENTITY_SECRET", "test-identity-secret"),
            ("SECRETS_KEY", "test-secrets-key-0123456789"),
            ("DEV_MODE", "1"),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
        Config::from_vars(&v).expect("test configuration is complete")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_missing_variables_without_values() {
        let err = Config::from_vars(&[("API_ORIGIN".to_string(), "https://brod.sh/".to_string())].into_iter().collect()).unwrap_err();
        assert!(err.0.contains("APPS_DOMAIN, ADMIN_SECRET, IDENTITY_SECRET"), "{}", err.0);
        let c = Config::for_tests();
        assert_eq!(c.api_host, "localhost:8787");
        assert!(matches!(c.storage, StorageConfig::Fs { .. }));
    }

    fn with(extra: &[(&str, &str)]) -> Result<Config, ConfigError> {
        let mut v: HashMap<String, String> = [
            ("APPS_DOMAIN", "localhost:8787"),
            ("API_ORIGIN", "http://localhost:8787"),
            ("ADMIN_SECRET", "test-admin-secret"),
            ("IDENTITY_SECRET", "test-identity-secret"),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
        v.extend(extra.iter().map(|(k, v)| (k.to_string(), v.to_string())));
        Config::from_vars(&v)
    }

    #[test]
    fn email_needs_an_explicit_sender() {
        let err = with(&[("RESEND_API_KEY", "re_test")]).unwrap_err();
        assert!(err.0.contains("EMAIL_FROM"), "{}", err.0);
        assert!(with(&[("RESEND_API_KEY", "re_test"), ("EMAIL_FROM", "Brod <brod@example.test>")]).is_ok());
    }

    #[test]
    fn google_analytics_is_off_unless_a_valid_id_is_set() {
        assert_eq!(with(&[]).unwrap().ga_id, None);
        assert_eq!(with(&[("BROD_GA_ID", "G-ABC123")]).unwrap().ga_id.as_deref(), Some("G-ABC123"));
        for bad in ["UA-1234-1", "G-", "G-abc'); alert(1)//", "G-AAAAAAAAAAAAAAAAAAAAAAAAAAAA"] {
            assert!(with(&[("BROD_GA_ID", bad)]).is_err(), "{bad}");
        }
    }
}
