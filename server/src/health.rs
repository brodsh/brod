// SPDX-License-Identifier: AGPL-3.0-only
//! Readiness: GET /readyz answers 200 only when what Brod needs to serve and deploy answers too: its own database, the
//! server-app runtime (when BROD_RUNTIME_URL is set) and the image registry (when BROD_REGISTRY_URL is set).
//!
//! GET /healthz stays a cheap liveness check that touches nothing: the container's health check uses it, and in
//! Compose the runtime only starts once Brod is healthy, so a /healthz that waited for the runtime would never pass.
//! Deploys and upgrades (deploy/upgrade.sh) and load balancers ask /readyz.
//!
//! The answer names each check and says ok, failed or off; why a check failed goes to the log only, since it can
//! name internal addresses.

use std::time::Duration;

use serde_json::{Map, Value, json};

use crate::db::Sql;
use crate::state::State;

/// How long each check may take. They run at the same time.
const CHECK_SECS: u64 = 3;

/// The outcome of one check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Check {
    Ok,
    Failed,
    /// Not configured on this server, so not needed.
    Off,
}

impl Check {
    fn as_str(self) -> &'static str {
        match self {
            Check::Ok => "ok",
            Check::Failed => "failed",
            Check::Off => "off",
        }
    }
}

/// Run every check; whether all passed, and the body for /readyz.
pub async fn ready(st: &State) -> (bool, Value) {
    let (database, runtime, registry) = tokio::join!(database(st), runtime(st), registry(st));
    summary(&[("database", database), ("runtime", runtime), ("registry", registry)])
}

fn summary(checks: &[(&str, Check)]) -> (bool, Value) {
    let ok = checks.iter().all(|(_, c)| *c != Check::Failed);
    let mut m = Map::new();
    for (name, c) in checks {
        m.insert(name.to_string(), json!(c.as_str()));
    }
    (ok, json!({ "service": "brod", "ok": ok, "checks": m }))
}

async fn timed<F: std::future::Future<Output = Result<(), String>>>(what: &str, f: F) -> Check {
    match tokio::time::timeout(Duration::from_secs(CHECK_SECS), f).await {
        Ok(Ok(())) => Check::Ok,
        Ok(Err(e)) => {
            tracing::warn!("readiness: {what} failed: {e}");
            Check::Failed
        }
        Err(_) => {
            tracing::warn!("readiness: {what} did not answer within {CHECK_SECS} s");
            Check::Failed
        }
    }
}

async fn database(st: &State) -> Check {
    timed("the database", async {
        let answered = st.db.call(|c| c.exists("SELECT 1", ())).await.map_err(|e| e.message)?;
        if answered { Ok(()) } else { Err("SELECT 1 returned nothing".into()) }
    })
    .await
}

async fn runtime(st: &State) -> Check {
    let Some(rt) = &st.cfg.runtime else { return Check::Off };
    timed("the server-app runtime", async {
        let res = st
            .http
            .get(format!("{}/_runtime/health", rt.url))
            .header("x-brod-runtime-secret", &rt.secret)
            .send()
            .await
            .map_err(|e| e.to_string())?;
        if res.status().is_success() { Ok(()) } else { Err(format!("it answered {}", res.status())) }
    })
    .await
}

async fn registry(st: &State) -> Check {
    let Some(cfg) = &st.cfg.registry else { return Check::Off };
    // Configured but not usable (a bad key, an unwritable certificate file): nothing can be deployed.
    if st.registry.is_none() {
        tracing::warn!("readiness: the image registry is configured but could not be opened (see the start-up log)");
        return Check::Failed;
    }
    timed("the image registry", async {
        // The registry's version check: 200, or 401 asking for a token, both mean it is up.
        let res = st.http.get(format!("{}/v2/", cfg.url)).send().await.map_err(|e| e.to_string())?;
        match res.status().as_u16() {
            200 | 401 => Ok(()),
            s => Err(format!("it answered {s}")),
        }
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ready_only_when_nothing_failed() {
        let (ok, v) = summary(&[("database", Check::Ok), ("runtime", Check::Off), ("registry", Check::Ok)]);
        assert!(ok);
        assert_eq!(v["checks"], json!({ "database": "ok", "runtime": "off", "registry": "ok" }));
        let (ok, v) = summary(&[("database", Check::Ok), ("runtime", Check::Failed), ("registry", Check::Off)]);
        assert!(!ok);
        assert_eq!(v["ok"], json!(false));
        assert_eq!(v["checks"]["runtime"], json!("failed"));
    }

    #[tokio::test]
    async fn checks_the_database_and_reports_unreachable_services() {
        let mut cfg = crate::config::Config::for_tests();
        // Nothing listens on port 9 of localhost: the runtime and the registry are configured but down.
        cfg.runtime = Some(crate::config::RuntimeConfig { url: "http://127.0.0.1:9".into(), secret: "s".into() });
        let st = crate::state::AppState::new(cfg, crate::db::test_db());
        let (ok, v) = ready(&st).await;
        assert!(!ok);
        assert_eq!(v["checks"]["database"], json!("ok"));
        assert_eq!(v["checks"]["runtime"], json!("failed"));
        assert_eq!(v["checks"]["registry"], json!("off"));

        let mut cfg = crate::config::Config::for_tests();
        cfg.runtime = None;
        cfg.registry = None;
        let st = crate::state::AppState::new(cfg, crate::db::test_db());
        let (ok, v) = ready(&st).await;
        assert!(ok, "{v}");
    }
}
