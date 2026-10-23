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

/// BROD_MODE. `SelfHosted` (the default) is one organisation's own Brod: no plans or billing, no public landing page,
/// and only workspace admins create workspaces. `Hosted` is a public multi-tenant service such as brod.sh.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    SelfHosted,
    Hosted,
}

#[derive(Clone, Debug)]
pub struct Config {
    pub mode: Mode,
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
    /// BROD_ADMIN_EMAIL: on a database with no people yet, this person becomes the admin of a first workspace (setup.rs).
    pub admin_email: Option<String>,
    /// BROD_AUTO_MIGRATE: apply new database migrations at start (the default). Off: refuse to start until `brod migrate`.
    pub auto_migrate: bool,
    /// BROD_MARKETPLACE: the cross-workspace app listings (market.rs). Default on when hosted, off when self-hosted.
    pub marketplace: bool,
    /// BROD_ABUSE_CHECKS: the deploy-time phishing scan, the public report link in apps and the hold on new
    /// workspaces (abuse.rs, scan.rs). Default on when hosted, off when self-hosted.
    pub abuse_checks: bool,
    /// SMTP_URL: send email through an SMTP server (email.rs), for example smtps://user:pass@smtp.example.com.
    pub smtp_url: Option<String>,
    /// Secrets that were not in the environment and came from (or were written to) `<data>`/secrets.env instead.
    pub generated_secrets: Vec<String>,
    /// Problems worth a line in the log at start, such as a short secret on a self-hosted server.
    pub warnings: Vec<String>,
    /// BROD_GA_ID: a Google Analytics 4 measurement ID for the public landing page (home.rs). None: no Google tag.
    pub ga_id: Option<String>,
    /// BROD_HEYCATCH_KEY: a HeyCatch publishable project key (hck_pk_...) for the public landing page (home.rs). None: no HeyCatch tag.
    pub heycatch_key: Option<String>,
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
    /// `https://api.stripe.com`, or a stand-in for tests.
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
    /// Self-hosted, secrets that are not set are generated once and kept in `<data>`/secrets.env, so a first start needs
    /// no configuration at all. Hosted, every secret must come from the environment.
    pub fn from_env() -> Result<Config, ConfigError> {
        let _ = dotenvy::dotenv();
        let mut vars: HashMap<String, String> = std::env::vars().collect();
        let set = |vars: &HashMap<String, String>, k: &str| vars.get(k).is_some_and(|v| !v.trim().is_empty());
        let hosted = vars.get("BROD_MODE").is_some_and(|m| m.trim() == "hosted");
        let mut generated = Vec::new();
        let data_dir = PathBuf::from(
            vars.get("BROD_DATA_DIR").filter(|d| !d.trim().is_empty()).map(|d| d.trim().to_string()).unwrap_or_else(|| "data".into()),
        );
        if !hosted && GENERATED.iter().any(|k| !set(&vars, k)) {
            let stored = load_or_create_secrets(&data_dir)?;
            for k in GENERATED {
                if !set(&vars, k)
                    && let Some(v) = stored.get(k)
                {
                    vars.insert(k.to_string(), v.clone());
                    generated.push(k.to_string());
                }
            }
        }
        let mut cfg = Config::from_vars(&vars)?;
        cfg.generated_secrets = generated;
        // The runtime sidecar reads the secret Brod uses from a file, so Compose needs no copy of it: BROD_RUNTIME_SECRET_FILE
        // (Compose puts it in a volume that holds nothing else), or <data>/runtime-secret.
        if let (false, Some(secret)) = (hosted, vars.get("BROD_RUNTIME_SECRET").map(|s| s.trim()).filter(|s| !s.is_empty())) {
            let path = vars
                .get("BROD_RUNTIME_SECRET_FILE")
                .map(|p| p.trim())
                .filter(|p| !p.is_empty())
                .map(PathBuf::from)
                .unwrap_or_else(|| data_dir.join("runtime-secret"));
            if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
                std::fs::create_dir_all(dir).map_err(|e| ConfigError(format!("Could not create {}: {e}", dir.display())))?;
            }
            write_private(&path, secret).map_err(|e| ConfigError(format!("Could not write {}: {e}", path.display())))?;
        }
        Ok(cfg)
    }

    pub fn from_vars(v: &HashMap<String, String>) -> Result<Config, ConfigError> {
        let get = |k: &str| v.get(k).map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
        let mode = match get("BROD_MODE").as_deref() {
            None | Some("self-hosted") => Mode::SelfHosted,
            Some("hosted") => Mode::Hosted,
            Some(other) => {
                return Err(ConfigError(format!("BROD_MODE must be \"self-hosted\" (the default) or \"hosted\", not {other:?}.")));
            }
        };
        let hosted = mode == Mode::Hosted;
        let listen = get("BROD_LISTEN").unwrap_or_else(|| "0.0.0.0:8080".into());
        let listen: SocketAddr =
            listen.parse().map_err(|_| ConfigError(format!("BROD_LISTEN must be an address such as 0.0.0.0:8080, not {listen:?}.")))?;
        // BROD_PUBLIC_URL is where people and agents reach Brod. API_ORIGIN is its older name. Self-hosted, it defaults to
        // this machine, and apps live under the same host (<app>.<workspace>.localhost:8080).
        let public_url = get("BROD_PUBLIC_URL")
            .or_else(|| get("API_ORIGIN"))
            .or_else(|| (!hosted).then(|| format!("http://localhost:{}", listen.port())));
        let mut need: Vec<&str> = Vec::new();
        if public_url.is_none() {
            need.push("BROD_PUBLIC_URL");
        }
        if hosted && get("APPS_DOMAIN").is_none() {
            need.push("APPS_DOMAIN");
        }
        need.extend(["ADMIN_SECRET", "IDENTITY_SECRET"].into_iter().filter(|k| get(k).is_none()));
        // Hosted, app secrets must be readable after every restart, so their key cannot be left to chance.
        if hosted && get("SECRETS_KEY").is_none() {
            need.push("SECRETS_KEY");
        }
        let s3_keys = ["S3_ENDPOINT", "S3_BUCKET", "S3_ACCESS_KEY_ID", "S3_SECRET_ACCESS_KEY"];
        let s3 = s3_keys.iter().any(|k| get(k).is_some());
        if s3 {
            need.extend(s3_keys.iter().filter(|k| get(k).is_none()));
        }
        if !need.is_empty() {
            return Err(ConfigError(format!(
                "Brod is not configured yet. Set these environment variables: {}. See .env.example and docs/configuration.md.",
                need.join(", ")
            )));
        }
        let api_origin = public_url.unwrap_or_default().trim_end_matches('/').to_string();
        if !(api_origin.starts_with("http://") || api_origin.starts_with("https://")) {
            return Err(ConfigError(format!("BROD_PUBLIC_URL must start with http:// or https://, not {api_origin:?}.")));
        }
        let api_host = api_origin.split_once("://").map(|(_, h)| h).unwrap_or(&api_origin).split('/').next().unwrap_or("").to_lowercase();
        let apps_domain = get("APPS_DOMAIN").map(|d| d.to_lowercase()).unwrap_or_else(|| api_host.clone());
        let on_off = |name: &str, default: bool| -> Result<bool, ConfigError> {
            match get(name).as_deref() {
                None => Ok(default),
                Some("1" | "true" | "on" | "yes") => Ok(true),
                Some("0" | "false" | "off" | "no") => Ok(false),
                Some(other) => Err(ConfigError(format!("{name} must be true or false, not {other:?}."))),
            }
        };
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
                    return Err(ConfigError("BROD_TLS serves HTTPS, so BROD_PUBLIC_URL must be an https:// address.".into()));
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
        let heycatch_key = get("BROD_HEYCATCH_KEY");
        if let Some(key) = &heycatch_key
            && !(key.len() > "hck_pk_".len()
                && key.len() <= 64
                && key.starts_with("hck_pk_")
                && key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-'))
        {
            return Err(ConfigError(format!(
                "BROD_HEYCATCH_KEY must be a HeyCatch publishable project key starting with hck_pk_, not {key:?}."
            )));
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
        let mut warnings = Vec::new();
        for k in ["ADMIN_SECRET", "IDENTITY_SECRET", "SECRETS_KEY", "BROD_RUNTIME_SECRET"] {
            let Some(value) = get(k) else { continue };
            if !is_weak_secret(&value) {
                continue;
            }
            let msg = format!("{k} is short or a well-known example value. Use at least 32 random characters: openssl rand -hex 32");
            if hosted && get("DEV_MODE").as_deref() != Some("1") {
                return Err(ConfigError(msg));
            }
            warnings.push(msg);
        }
        let admin_email = get("BROD_ADMIN_EMAIL").map(|e| crate::util::norm_email(&e));
        if let Some(e) = &admin_email
            && !crate::util::is_email(e)
        {
            return Err(ConfigError(format!("BROD_ADMIN_EMAIL must be an email address, not {e:?}.")));
        }
        let smtp_url = get("SMTP_URL");
        if let Some(u) = &smtp_url {
            if !(u.starts_with("smtp://") || u.starts_with("smtps://")) {
                return Err(ConfigError("SMTP_URL must start with smtp:// (STARTTLS) or smtps:// (TLS).".into()));
            }
            if get("EMAIL_FROM").is_none() {
                return Err(ConfigError(
                    "SMTP_URL is set but EMAIL_FROM is not. Set EMAIL_FROM, for example \"Brod <brod@example.com>\".".into(),
                ));
            }
        }
        Ok(Config {
            mode,
            generated_secrets: Vec::new(),
            warnings,
            auto_migrate: on_off("BROD_AUTO_MIGRATE", true)?,
            marketplace: on_off("BROD_MARKETPLACE", hosted)?,
            abuse_checks: on_off("BROD_ABUSE_CHECKS", hosted)?,
            admin_email,
            smtp_url,
            network,
            apps_domain,
            api_origin,
            api_host,
            admin_secret: get("ADMIN_SECRET").unwrap_or_default(),
            identity_secret: get("IDENTITY_SECRET").unwrap_or_default(),
            secrets_key: get("SECRETS_KEY").unwrap_or_default(),
            dev_mode: get("DEV_MODE").as_deref() == Some("1"),
            resend_api_key: get("RESEND_API_KEY"),
            email_from: get("EMAIL_FROM"),
            ga_id,
            heycatch_key,
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

/// The secrets a self-hosted Brod makes for itself when the environment does not set them.
pub const GENERATED: [&str; 4] = ["ADMIN_SECRET", "IDENTITY_SECRET", "SECRETS_KEY", "BROD_RUNTIME_SECRET"];

/// Values that must never protect a real server: the examples in Brod's own docs and tests, and the usual guesses.
fn is_weak_secret(v: &str) -> bool {
    const KNOWN: [&str; 6] = ["dev-admin-secret", "dev-identity-secret", "dev-secrets-key-0123456789", "change-me", "changeme", "secret"];
    v.len() < 32 || KNOWN.contains(&v) || v.starts_with("change-me")
}

/// Read `<data>`/secrets.env, or write one with a fresh random value for each of GENERATED.
fn load_or_create_secrets(data_dir: &std::path::Path) -> Result<HashMap<String, String>, ConfigError> {
    let path = data_dir.join("secrets.env");
    let fail = |e: std::io::Error| ConfigError(format!("Could not keep generated secrets in {}: {e}", path.display()));
    let mut out: HashMap<String, String> = match std::fs::read_to_string(&path) {
        Ok(text) => text.lines().filter_map(|l| l.split_once('=')).map(|(k, v)| (k.trim().to_string(), v.trim().to_string())).collect(),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => HashMap::new(),
        Err(e) => return Err(fail(e)),
    };
    if GENERATED.iter().any(|k| !out.contains_key(*k)) {
        for k in GENERATED {
            out.entry(k.to_string()).or_insert_with(|| crate::util::random_id("", 32));
        }
        std::fs::create_dir_all(data_dir).map_err(fail)?;
        let mut text = String::from("# Generated by Brod on first start. Keep this file private; back it up with the database.\n");
        for k in GENERATED {
            text.push_str(&format!("{k}={}\n", out[k]));
        }
        write_private(&path, &text).map_err(fail)?;
    }
    Ok(out)
}

/// Write a file only its owner can read.
fn write_private(path: &std::path::Path, text: &str) -> std::io::Result<()> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut opts, 0o600);
    std::io::Write::write_all(&mut opts.open(path)?, text.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_missing_variables_without_values() {
        let vars = |pairs: &[(&str, &str)]| pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect::<HashMap<_, _>>();
        let err = Config::from_vars(&vars(&[("BROD_MODE", "hosted"), ("API_ORIGIN", "https://brod.example.test/")])).unwrap_err();
        assert!(err.0.contains("APPS_DOMAIN, ADMIN_SECRET, IDENTITY_SECRET, SECRETS_KEY"), "{}", err.0);
        // Self-hosted needs only the two secrets (from_env generates them), and defaults to this machine.
        let err = Config::from_vars(&vars(&[])).unwrap_err();
        assert!(err.0.contains("Set these environment variables: ADMIN_SECRET, IDENTITY_SECRET."), "{}", err.0);
        let local =
            Config::from_vars(&vars(&[("ADMIN_SECRET", "a"), ("IDENTITY_SECRET", "b"), ("BROD_LISTEN", "127.0.0.1:9000")])).unwrap();
        assert_eq!((local.api_origin.as_str(), local.apps_domain.as_str()), ("http://localhost:9000", "localhost:9000"));
        assert_eq!(local.mode, Mode::SelfHosted);
        assert!(!local.marketplace && !local.abuse_checks && local.auto_migrate);
        assert_eq!(local.warnings.len(), 2, "short secrets are reported");
        // BROD_PUBLIC_URL wins over the older API_ORIGIN.
        let named = Config::from_vars(&vars(&[
            ("ADMIN_SECRET", "a"),
            ("IDENTITY_SECRET", "b"),
            ("BROD_PUBLIC_URL", "https://brod.acme.test"),
            ("API_ORIGIN", "https://old.test"),
        ]))
        .unwrap();
        assert_eq!(named.api_origin, "https://brod.acme.test");
        // Hosted refuses a well-known or short secret outside DEV_MODE.
        let weak = Config::from_vars(&vars(&[
            ("BROD_MODE", "hosted"),
            ("API_ORIGIN", "https://b.test"),
            ("APPS_DOMAIN", "b.test"),
            ("ADMIN_SECRET", "dev-admin-secret"),
            ("IDENTITY_SECRET", &"x".repeat(40)),
            ("SECRETS_KEY", &"y".repeat(40)),
        ]));
        assert!(weak.unwrap_err().0.starts_with("ADMIN_SECRET is short"));
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
    fn generated_secrets_are_kept_and_reused() {
        let dir = std::env::temp_dir().join(format!("brod-secrets-{}", crate::util::random_id("", 6)));
        let first = load_or_create_secrets(&dir).unwrap();
        let again = load_or_create_secrets(&dir).unwrap();
        assert_eq!(first, again);
        assert!(GENERATED.iter().all(|k| first[*k].len() == 64));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(dir.join("secrets.env")).unwrap().permissions().mode() & 0o777, 0o600);
        }
        let _ = std::fs::remove_dir_all(dir);
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

    #[test]
    fn heycatch_is_off_unless_a_valid_key_is_set() {
        assert_eq!(with(&[]).unwrap().heycatch_key, None);
        let key = "hck_pk_3i8uCwh2DpfbL5zOYQ-puh6KVeXhaVug";
        assert_eq!(with(&[("BROD_HEYCATCH_KEY", key)]).unwrap().heycatch_key.as_deref(), Some(key));
        for bad in ["hck_pk_", "hck_sk_abc", "abc", "hck_pk_a'); alert(1)//", &format!("hck_pk_{}", "a".repeat(64))] {
            assert!(with(&[("BROD_HEYCATCH_KEY", bad)]).is_err(), "{bad}");
        }
    }
}
