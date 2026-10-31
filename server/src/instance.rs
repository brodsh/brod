// SPDX-License-Identifier: AGPL-3.0-only
// Instance settings: what an operator can change while Brod runs (docs/plans/admin-mode.md). Each setting has a key,
// a kind, a built-in default and an environment variable. The value used is the environment variable when it is set
// (the setting is then locked: the console shows it read-only), else the operator's value in instance_settings,
// else the default. Secrets (ADMIN_SECRET, IDENTITY_SECRET, SECRETS_KEY, Stripe, SMTP, S3) are never settings.
//
// A limit is a JSON number, or null for unlimited. In an environment variable, "unlimited" means null.
use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use serde_json::{Value, json};

use crate::config::{Config, Mode};
use crate::db::{Connection, Sql, params, tx};
use crate::problem::{Problem, Result};
use crate::util::now;

/// How long a replica trusts its cached settings before reading them again. Another replica on the same Postgres may
/// have changed them; on one server a change refreshes the cache at once.
pub const CACHE_TTL: Duration = Duration::from_secs(15);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// A whole number of at least 0, or null for unlimited.
    Limit,
    /// A whole number in min..=max.
    Int(i64, i64),
    Bool,
    Enum(&'static [&'static str]),
    /// A list of lowercase email domains, such as ["acme.com"]. Empty means any domain.
    Domains,
}

pub struct Setting {
    pub key: &'static str,
    pub env: &'static str,
    pub kind: Kind,
    pub help: &'static str,
    default: fn(&Config) -> Value,
}

/// Who may create a workspace (workspaces.creation).
pub const CREATION: &[&str] = &["operators", "workspace_admins", "anyone_verified"];

fn unlimited(_: &Config) -> Value {
    Value::Null
}

pub static SETTINGS: &[Setting] = &[
    Setting {
        key: "limits.max_running_apps",
        env: "BROD_LIMIT_RUNNING_APPS",
        kind: Kind::Limit,
        help: "Running (live) apps per workspace, unless the workspace's plan or override says otherwise. Paused apps do not count.",
        default: unlimited,
    },
    Setting {
        key: "limits.max_members",
        env: "BROD_LIMIT_MEMBERS",
        kind: Kind::Limit,
        help: "Members per workspace. Guests do not count.",
        default: unlimited,
    },
    Setting {
        key: "limits.max_storage_mb",
        env: "BROD_LIMIT_STORAGE_MB",
        kind: Kind::Limit,
        help: "Storage per workspace in MB: bundles, files and app data.",
        default: unlimited,
    },
    Setting {
        key: "limits.analytics_days",
        env: "BROD_LIMIT_ANALYTICS_DAYS",
        kind: Kind::Int(1, 3650),
        help: "Days of analytics a workspace keeps.",
        default: |_| json!(crate::model::SELF_HOSTED_ANALYTICS_DAYS),
    },
    Setting {
        key: "server.max_workspaces",
        env: "BROD_MAX_WORKSPACES",
        kind: Kind::Limit,
        help: "Workspaces on this server.",
        default: unlimited,
    },
    Setting {
        key: "server.max_users",
        env: "BROD_MAX_USERS",
        kind: Kind::Limit,
        help: "People with an account on this server.",
        default: unlimited,
    },
    Setting {
        key: "workspaces.creation",
        env: "BROD_WORKSPACE_CREATION",
        kind: Kind::Enum(CREATION),
        help: "Who may create a workspace: operators only, people who are already a workspace admin, or anyone with a verified email.",
        default: |c| json!(if c.mode == Mode::Hosted { "anyone_verified" } else { "workspace_admins" }),
    },
    Setting {
        key: "signin.allowed_email_domains",
        env: "BROD_ALLOWED_EMAIL_DOMAINS",
        kind: Kind::Domains,
        help: "Only people with an email address at one of these domains may sign in. Empty allows any.",
        default: |_| json!([]),
    },
    Setting {
        key: "features.marketplace",
        env: "BROD_MARKETPLACE",
        kind: Kind::Bool,
        help: "The marketplace, where workspaces publish and install apps.",
        default: |c| json!(c.mode == Mode::Hosted),
    },
    Setting {
        key: "features.abuse_checks",
        env: "BROD_ABUSE_CHECKS",
        kind: Kind::Bool,
        help: "The deploy-time phishing scan, the report link in apps and the hold on new workspaces.",
        default: |c| json!(c.mode == Mode::Hosted),
    },
    Setting {
        key: "rate.deploys_per_hour",
        env: "BROD_RATE_DEPLOYS_PER_HOUR",
        kind: Kind::Int(1, 100_000),
        help: "Deploys per workspace per hour.",
        default: |_| json!(crate::model::limits::DEPLOYS_PER_HOUR),
    },
    Setting {
        key: "rate.calls_per_minute",
        env: "BROD_RATE_CALLS_PER_MINUTE",
        kind: Kind::Int(1, 1_000_000),
        help: "REST and MCP calls per connection per minute.",
        default: |_| json!(crate::abuse::CALLS_PER_MINUTE),
    },
    Setting {
        key: "rate.workspaces_per_user_day",
        env: "BROD_RATE_WORKSPACES_PER_USER_DAY",
        kind: Kind::Int(1, 10_000),
        help: "Workspaces one person may create per day.",
        default: |_| json!(crate::abuse::WORKSPACES_PER_USER_DAY),
    },
];

pub fn setting(key: &str) -> Option<&'static Setting> {
    SETTINGS.iter().find(|s| s.key == key)
}

/// Check `v` against `kind` and return it in its stored form, or say what is wrong.
pub fn normalize(kind: Kind, v: &Value) -> std::result::Result<Value, String> {
    match kind {
        Kind::Limit => match v {
            Value::Null => Ok(Value::Null),
            Value::String(s) if s == "unlimited" => Ok(Value::Null),
            _ => match v.as_i64() {
                Some(n) if n >= 0 => Ok(json!(n)),
                _ => Err("must be a whole number of at least 0, or null for unlimited".into()),
            },
        },
        Kind::Int(min, max) => match v.as_i64() {
            Some(n) if (min..=max).contains(&n) => Ok(json!(n)),
            _ => Err(format!("must be a whole number from {min} to {max}")),
        },
        Kind::Bool => v.as_bool().map(Value::Bool).ok_or_else(|| "must be true or false".into()),
        Kind::Enum(options) => match v.as_str() {
            Some(s) if options.contains(&s) => Ok(json!(s)),
            _ => Err(format!("must be one of {}", options.join(", "))),
        },
        Kind::Domains => {
            let Some(items) = v.as_array() else {
                return Err("must be a list of email domains, such as [\"acme.com\"]".into());
            };
            let mut out: Vec<String> = Vec::new();
            for item in items {
                let d = item.as_str().map(|d| d.trim().trim_start_matches('@').to_ascii_lowercase()).unwrap_or_default();
                let valid = d.contains('.')
                    && d.len() <= 253
                    && d.split('.').all(|l| !l.is_empty() && l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'));
                if !valid {
                    return Err(format!("{item} is not an email domain such as acme.com"));
                }
                if !out.contains(&d) {
                    out.push(d);
                }
            }
            Ok(json!(out))
        }
    }
}

/// An environment variable's text as a value of `kind`.
fn parse_env(kind: Kind, raw: &str) -> std::result::Result<Value, String> {
    let raw = raw.trim();
    let v = match kind {
        Kind::Limit if raw.eq_ignore_ascii_case("unlimited") => Value::Null,
        Kind::Limit | Kind::Int(..) => json!(raw.parse::<i64>().map_err(|_| "must be a whole number".to_string())?),
        Kind::Bool => match raw {
            "1" | "true" | "on" | "yes" => json!(true),
            "0" | "false" | "off" | "no" => json!(false),
            _ => return Err("must be true or false".into()),
        },
        Kind::Enum(_) => json!(raw),
        Kind::Domains => json!(raw.split(',').map(str::trim).filter(|d| !d.is_empty()).collect::<Vec<_>>()),
    };
    normalize(kind, &v)
}

/// The settings whose environment variable is set, for Config. An invalid value stops the server from starting.
pub fn from_env(get: &dyn Fn(&str) -> Option<String>) -> std::result::Result<BTreeMap<&'static str, Value>, String> {
    let mut out = BTreeMap::new();
    for s in SETTINGS {
        if let Some(raw) = get(s.env) {
            let v = parse_env(s.kind, &raw).map_err(|e| format!("{} {e}, not {raw:?}.", s.env))?;
            out.insert(s.key, v);
        }
    }
    Ok(out)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source {
    Env,
    Database,
    Default,
}

impl Source {
    pub fn as_str(self) -> &'static str {
        match self {
            Source::Env => "env",
            Source::Database => "database",
            Source::Default => "default",
        }
    }
}

/// Every setting's value and where it came from.
#[derive(Clone, Debug)]
pub struct Settings {
    values: BTreeMap<&'static str, (Value, Source)>,
}

impl Settings {
    /// Environment and defaults only, before the database is read.
    pub fn from_config(cfg: &Config) -> Settings {
        Settings::resolve(cfg, &BTreeMap::new())
    }

    fn resolve(cfg: &Config, stored: &BTreeMap<String, Value>) -> Settings {
        let values = SETTINGS
            .iter()
            .map(|s| {
                let v = if let Some(v) = cfg.settings_env.get(s.key) {
                    (v.clone(), Source::Env)
                } else if let Some(v) = stored.get(s.key).and_then(|v| normalize(s.kind, v).ok()) {
                    (v, Source::Database)
                } else {
                    ((s.default)(cfg), Source::Default)
                };
                (s.key, v)
            })
            .collect();
        Settings { values }
    }

    /// Read the operator's values from instance_settings. A stored value that no longer fits its setting (or a key
    /// no longer known) is ignored, so a bad row can never stop the server.
    pub fn load(conn: &Connection, cfg: &Config) -> Result<Settings> {
        let rows = conn.all("SELECT key, value FROM instance_settings", (), |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?;
        let stored = rows.into_iter().filter_map(|(k, v)| serde_json::from_str(&v).ok().map(|v| (k, v))).collect();
        Ok(Settings::resolve(cfg, &stored))
    }

    pub fn get(&self, key: &str) -> &Value {
        self.values.get(key).map(|(v, _)| v).unwrap_or(&Value::Null)
    }

    pub fn source(&self, key: &str) -> Option<Source> {
        self.values.get(key).map(|(_, s)| *s)
    }

    /// A Limit setting: None when unlimited.
    pub fn limit(&self, key: &str) -> Option<i64> {
        self.get(key).as_i64()
    }

    pub fn int(&self, key: &str) -> i64 {
        self.get(key).as_i64().unwrap_or_default()
    }

    pub fn flag(&self, key: &str) -> bool {
        self.get(key).as_bool().unwrap_or_default()
    }

    pub fn text(&self, key: &str) -> &str {
        self.get(key).as_str().unwrap_or_default()
    }

    pub fn list(&self, key: &str) -> Vec<String> {
        self.get(key).as_array().map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect()).unwrap_or_default()
    }

    /// Every setting for the console and the admin API: value, default, source and whether it is locked by env.
    pub fn describe(&self, cfg: &Config) -> Vec<Value> {
        SETTINGS
            .iter()
            .map(|s| {
                let source = self.source(s.key).unwrap_or(Source::Default);
                let kind = match s.kind {
                    Kind::Limit => json!({ "type": "limit" }),
                    Kind::Int(min, max) => json!({ "type": "int", "min": min, "max": max }),
                    Kind::Bool => json!({ "type": "bool" }),
                    Kind::Enum(o) => json!({ "type": "enum", "options": o }),
                    Kind::Domains => json!({ "type": "domains" }),
                };
                json!({
                    "key": s.key, "value": self.get(s.key), "default": (s.default)(cfg), "source": source.as_str(),
                    "locked_by": (source == Source::Env).then_some(s.env), "env": s.env, "kind": kind, "help": s.help,
                })
            })
            .collect()
    }
}

/// Set `key` to `value`, or back to its default with None. Refuses unknown keys, values of the wrong kind and keys
/// locked by their environment variable. Returns the value stored.
pub fn write(conn: &Connection, cfg: &Config, key: &str, value: Option<&Value>, by: &str) -> Result<Option<Value>> {
    let Some(s) = setting(key) else {
        return Err(Problem::new(404, "unknown_setting", format!("There is no setting {key:?}.")));
    };
    if cfg.settings_env.contains_key(s.key) {
        return Err(Problem::new(
            409,
            "setting_locked",
            format!("{key} is set by the environment variable {}. Change it there and restart Brod.", s.env),
        ));
    }
    let Some(value) = value else {
        conn.run("DELETE FROM instance_settings WHERE key = ?", [key])?;
        return Ok(None);
    };
    let v = normalize(s.kind, value).map_err(|e| Problem::new(400, "bad_setting", format!("{key} {e}.")))?;
    let text = v.to_string();
    tx(conn, |c| {
        if c.run("UPDATE instance_settings SET value = ?, updated_by = ?, updated_at = ? WHERE key = ?", params![text, by, now(), key])?
            == 0
        {
            c.run("INSERT INTO instance_settings (key, value, updated_by, updated_at) VALUES (?, ?, ?, ?)", params![key, text, by, now()])?;
        }
        Ok(())
    })?;
    Ok(Some(v))
}

/// The settings in State: cached, read again after CACHE_TTL, and refreshed at once by `set`.
pub struct Cache {
    inner: RwLock<(Arc<Settings>, Option<Instant>)>,
}

impl Cache {
    /// Starts from environment and defaults; the first `current` reads the database.
    pub fn new(cfg: &Config) -> Cache {
        Cache { inner: RwLock::new((Arc::new(Settings::from_config(cfg)), None)) }
    }

    fn fresh(&self) -> Option<Arc<Settings>> {
        let g = self.inner.read().unwrap_or_else(|e| e.into_inner());
        g.1.filter(|at| at.elapsed() < CACHE_TTL).map(|_| g.0.clone())
    }

    fn put(&self, s: Settings) -> Arc<Settings> {
        let s = Arc::new(s);
        *self.inner.write().unwrap_or_else(|e| e.into_inner()) = (s.clone(), Some(Instant::now()));
        s
    }

    /// The last settings read, even if stale. For code that cannot wait for the database.
    pub fn last(&self) -> Arc<Settings> {
        self.inner.read().unwrap_or_else(|e| e.into_inner()).0.clone()
    }
}

/// The settings now in force. When the database cannot be read, the last known settings stay in force.
pub async fn current(st: &crate::state::State) -> Arc<Settings> {
    if let Some(s) = st.settings.fresh() {
        return s;
    }
    let cfg = st.cfg.clone();
    match st.db.call(move |c| Settings::load(c, &cfg)).await {
        Ok(s) => st.settings.put(s),
        Err(e) => {
            tracing::warn!("could not read the instance settings: {}", e.message);
            st.settings.last()
        }
    }
}

/// Change a setting (see `write`) and refresh the cache.
pub async fn set(st: &crate::state::State, key: &str, value: Option<Value>, by: &str) -> Result<Arc<Settings>> {
    let (cfg, key, by) = (st.cfg.clone(), key.to_string(), by.to_string());
    let s = st
        .db
        .call(move |c| {
            write(c, &cfg, &key, value.as_ref(), &by)?;
            Settings::load(c, &cfg)
        })
        .await?;
    Ok(st.settings.put(s))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg_with(env: &[(&str, &str)]) -> Config {
        let mut c = Config::for_tests();
        let map: std::collections::HashMap<String, String> = env.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        c.settings_env = from_env(&|k| map.get(k).cloned()).unwrap();
        c
    }

    #[test]
    fn every_setting_has_a_valid_default_and_a_unique_key() {
        let cfg = Config::for_tests();
        let mut keys = std::collections::HashSet::new();
        for s in SETTINGS {
            assert!(keys.insert(s.key), "{} twice", s.key);
            assert_eq!(normalize(s.kind, &(s.default)(&cfg)).as_ref(), Ok(&(s.default)(&cfg)), "{}", s.key);
        }
    }

    #[test]
    fn values_are_checked_against_their_kind() {
        assert_eq!(normalize(Kind::Limit, &json!(5)), Ok(json!(5)));
        assert_eq!(normalize(Kind::Limit, &json!("unlimited")), Ok(Value::Null));
        assert!(normalize(Kind::Limit, &json!(-1)).is_err());
        assert!(normalize(Kind::Limit, &json!(1.5)).is_err());
        assert!(normalize(Kind::Int(1, 10), &json!(11)).is_err());
        assert!(normalize(Kind::Enum(CREATION), &json!("everyone")).is_err());
        assert_eq!(normalize(Kind::Domains, &json!(["@Acme.com", "acme.com", "b.io"])), Ok(json!(["acme.com", "b.io"])));
        assert!(normalize(Kind::Domains, &json!(["not a domain"])).is_err());
    }

    #[test]
    fn env_values_parse_and_bad_ones_stop_the_server() {
        let c = cfg_with(&[
            ("BROD_LIMIT_RUNNING_APPS", "3"),
            ("BROD_MAX_USERS", "unlimited"),
            ("BROD_ALLOWED_EMAIL_DOMAINS", "acme.com, b.io"),
        ]);
        assert_eq!(c.settings_env.get("limits.max_running_apps"), Some(&json!(3)));
        assert_eq!(c.settings_env.get("server.max_users"), Some(&Value::Null));
        assert_eq!(c.settings_env.get("signin.allowed_email_domains"), Some(&json!(["acme.com", "b.io"])));
        let bad = std::collections::HashMap::from([("BROD_WORKSPACE_CREATION".to_string(), "everyone".to_string())]);
        assert!(from_env(&|k| bad.get(k).cloned()).unwrap_err().contains("BROD_WORKSPACE_CREATION"));
    }

    #[tokio::test]
    async fn env_beats_database_beats_default_and_env_keys_are_locked() {
        let cfg = cfg_with(&[("BROD_LIMIT_MEMBERS", "7")]);
        let db = crate::db::test_db();
        let c2 = cfg.clone();
        let s = db
            .call(move |c| {
                write(c, &c2, "limits.max_running_apps", Some(&json!(4)), "op@acme.test")?;
                write(c, &c2, "limits.max_running_apps", Some(&json!(5)), "op@acme.test")?;
                let locked = write(c, &c2, "limits.max_members", Some(&json!(9)), "op@acme.test").unwrap_err();
                assert_eq!(locked.code, "setting_locked");
                assert_eq!(write(c, &c2, "nope", Some(&json!(1)), "x").unwrap_err().status, 404);
                assert_eq!(write(c, &c2, "rate.deploys_per_hour", Some(&json!(0)), "x").unwrap_err().status, 400);
                Settings::load(c, &c2)
            })
            .await
            .unwrap();
        assert_eq!((s.limit("limits.max_running_apps"), s.source("limits.max_running_apps")), (Some(5), Some(Source::Database)));
        assert_eq!((s.limit("limits.max_members"), s.source("limits.max_members")), (Some(7), Some(Source::Env)));
        assert_eq!((s.limit("limits.max_storage_mb"), s.source("limits.max_storage_mb")), (None, Some(Source::Default)));
        let d = s.describe(&cfg);
        let members = d.iter().find(|v| v["key"] == "limits.max_members").unwrap();
        assert_eq!(members["locked_by"], "BROD_LIMIT_MEMBERS");

        let c2 = cfg.clone();
        let s = db
            .call(move |c| {
                write(c, &c2, "limits.max_running_apps", None, "x")?;
                // A row that no longer fits its setting is ignored, not fatal.
                c.run("INSERT INTO instance_settings (key, value, updated_at) VALUES ('rate.deploys_per_hour', '\"lots\"', 0)", ())?;
                Settings::load(c, &c2)
            })
            .await
            .unwrap();
        assert_eq!(s.source("limits.max_running_apps"), Some(Source::Default));
        assert_eq!(s.int("rate.deploys_per_hour"), crate::model::limits::DEPLOYS_PER_HOUR);
    }
}
