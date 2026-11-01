// SPDX-License-Identifier: AGPL-3.0-only
//! What a workspace may use (docs/plans/admin-mode.md 1.3, 1.4): running apps, members, storage and days of analytics.
//!
//! Each limit is resolved from the database at the moment it is checked, so an operator's change applies at once on
//! every replica: the workspace's override (workspace_limits) if the operator set one, else the paid plan on a hosted
//! server, else the instance settings (limits.*) on a self-hosted one. Lowering a limit never removes anything; it
//! only refuses what would go over it.

use crate::config::{Config, Mode};
use crate::db::{Connection, Sql};
use crate::instance::Settings;
use crate::model::{MB, Plan, UNLIMITED, Workspace, plan_table};
use crate::problem::Result;

/// The operator's override for one workspace. None inherits; Some(UNLIMITED) means no limit.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct Override {
    pub max_running_apps: Option<i64>,
    pub max_members: Option<i64>,
    /// In bytes, already converted from the stored megabytes.
    pub max_storage: Option<i64>,
    pub analytics_days: Option<i64>,
    pub note: String,
}

/// A stored override column: NULL inherits, -1 is unlimited.
fn column(v: Option<i64>, scale: i64) -> Option<i64> {
    v.map(|n| if n < 0 { UNLIMITED } else { n.saturating_mul(scale) })
}

pub fn override_of(conn: &Connection, workspace_id: &str) -> Result<Option<Override>> {
    conn.first(
        "SELECT max_running_apps, max_members, max_storage_mb, analytics_days, note FROM workspace_limits WHERE workspace_id = ?",
        [workspace_id],
        |r| {
            Ok(Override {
                max_running_apps: column(r.get(0)?, 1),
                max_members: column(r.get(1)?, 1),
                max_storage: column(r.get(2)?, MB),
                analytics_days: column(r.get(3)?, 1),
                note: r.get(4)?,
            })
        },
    )
}

/// What applies before any override: the plan when hosted, the instance settings when self-hosted.
pub fn base(settings: &Settings, mode: Mode, plan_name: &str) -> Plan {
    if mode == Mode::Hosted {
        return plan_table(plan_name);
    }
    let limit = |key: &str, scale: i64| settings.limit(key).map_or(UNLIMITED, |n| n.saturating_mul(scale));
    Plan {
        apps: limit("limits.max_running_apps", 1),
        members: limit("limits.max_members", 1),
        storage: limit("limits.max_storage_mb", MB),
        analytics_days: settings.int("limits.analytics_days"),
    }
}

/// Apply an override on top of the base.
pub fn apply(mut p: Plan, o: Option<&Override>) -> Plan {
    if let Some(o) = o {
        p.apps = o.max_running_apps.unwrap_or(p.apps);
        p.members = o.max_members.unwrap_or(p.members);
        p.storage = o.max_storage.unwrap_or(p.storage);
        p.analytics_days = o.analytics_days.unwrap_or(p.analytics_days);
    }
    p
}

/// The limits in force for a workspace, given by id and plan name (for callers that only have those).
pub fn for_id(conn: &Connection, cfg: &Config, workspace_id: &str, plan_name: &str) -> Result<Plan> {
    let settings = Settings::load(conn, cfg)?;
    Ok(apply(base(&settings, cfg.mode, plan_name), override_of(conn, workspace_id)?.as_ref()))
}

/// The limits in force for a workspace.
pub fn effective(conn: &Connection, cfg: &Config, w: &Workspace) -> Result<Plan> {
    for_id(conn, cfg, &w.id, &w.plan)
}

/// Refuse a new account when the server already has `server.max_users` people. Someone who already has an
/// account always gets in, so lowering the cap never locks anyone out.
pub fn check_new_user(conn: &Connection, cfg: &Config, email: &str) -> Result<()> {
    let e = crate::util::norm_email(email);
    if conn.exists("SELECT 1 FROM users WHERE email = ?", [&e])? {
        return Ok(());
    }
    let Some(max) = Settings::load(conn, cfg)?.limit("server.max_users") else { return Ok(()) };
    if conn.count("SELECT COUNT(*) FROM users", ())? >= max {
        return Err(crate::problem::Problem::new(
            403,
            "server_full",
            "This server has reached its limit of people. Ask the operator to raise it.",
        ));
    }
    Ok(())
}

/// Refuse a new account whose email is outside `signin.allowed_email_domains` (when that list is not empty). Someone
/// who already has an account always gets in, and so does someone a workspace admin invited (accept_invite only
/// checks `check_new_user`): the allowlist closes open sign-up, not invitations.
pub fn check_email_domain(conn: &Connection, cfg: &Config, email: &str) -> Result<()> {
    let e = crate::util::norm_email(email);
    let allowed = Settings::load(conn, cfg)?.list("signin.allowed_email_domains");
    if allowed.is_empty() || conn.exists("SELECT 1 FROM users WHERE email = ?", [&e])? {
        return Ok(());
    }
    let domain = e.rsplit_once('@').map(|(_, d)| d).unwrap_or("");
    if allowed.iter().any(|d| d == domain) {
        return Ok(());
    }
    Err(crate::problem::Problem::new(
        403,
        "email_domain_not_allowed",
        format!("This server only lets in people with an email address at {}. Ask an admin to invite you.", allowed.join(", ")),
    ))
}

/// Both checks for someone signing in by themselves (a sign-in link or Google): the domain allowlist and the cap.
pub fn check_new_signin(conn: &Connection, cfg: &Config, email: &str) -> Result<()> {
    check_email_domain(conn, cfg, email)?;
    check_new_user(conn, cfg, email)
}

/// Refuse a new workspace when the server already has `server.max_workspaces`.
pub fn check_new_workspace(conn: &Connection, cfg: &Config) -> Result<()> {
    let Some(max) = Settings::load(conn, cfg)?.limit("server.max_workspaces") else { return Ok(()) };
    if conn.count("SELECT COUNT(*) FROM workspaces", ())? >= max {
        return Err(crate::problem::Problem::new(
            403,
            "server_full",
            "This server has reached its limit of workspaces. Ask the operator to raise it.",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::params;

    fn cfg(mode: Mode, env: &[(&str, &str)]) -> Config {
        let mut c = Config::for_tests();
        c.mode = mode;
        let map: std::collections::HashMap<String, String> = env.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        c.settings_env = crate::instance::from_env(&|k| map.get(k).cloned()).unwrap();
        c
    }

    fn workspace(conn: &Connection, id: &str, plan: &str) {
        conn.run("INSERT INTO workspaces (id, slug, name, plan, created_at) VALUES (?, ?, ?, ?, 0)", params![id, id, id, plan]).unwrap();
    }

    #[tokio::test]
    async fn hosted_uses_the_plan_and_self_hosted_the_settings() {
        let db = crate::db::test_db();
        db.call(|conn| {
            workspace(conn, "w1", "solo");
            let hosted = for_id(conn, &cfg(Mode::Hosted, &[]), "w1", "solo")?;
            assert_eq!((hosted.apps, hosted.members), (15, 1));
            let open = for_id(conn, &cfg(Mode::SelfHosted, &[]), "w1", "solo")?;
            assert_eq!((open.apps, open.members, open.storage), (UNLIMITED, UNLIMITED, UNLIMITED));
            let capped = cfg(Mode::SelfHosted, &[("BROD_LIMIT_RUNNING_APPS", "3"), ("BROD_LIMIT_STORAGE_MB", "2")]);
            let p = for_id(conn, &capped, "w1", "solo")?;
            assert_eq!((p.apps, p.storage), (3, 2 * MB));
            Ok(())
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn an_override_beats_the_plan_and_null_inherits() {
        let db = crate::db::test_db();
        db.call(|conn| {
            workspace(conn, "w2", "free");
            conn.run(
                "INSERT INTO workspace_limits (workspace_id, max_running_apps, max_members, max_storage_mb, analytics_days, note, updated_at) VALUES (?, ?, ?, ?, ?, ?, 0)",
                params!["w2", 40_i64, None::<i64>, -1_i64, None::<i64>, "pilot customer"],
            )?;
            let p = for_id(conn, &cfg(Mode::Hosted, &[]), "w2", "free")?;
            assert_eq!(p.apps, 40);
            assert_eq!(p.members, 10, "a NULL column keeps the plan's value");
            assert_eq!(p.storage, UNLIMITED, "-1 means no limit");
            assert_eq!(p.analytics_days, 30);
            Ok(())
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn server_caps_refuse_newcomers_but_never_existing_people() {
        let db = crate::db::test_db();
        db.call(|conn| {
            let c = cfg(Mode::SelfHosted, &[("BROD_MAX_USERS", "1"), ("BROD_MAX_WORKSPACES", "1")]);
            check_new_user(conn, &c, "a@x.test")?;
            crate::people::verified_user(conn, "a@x.test", "")?;
            assert_eq!(check_new_user(conn, &c, "b@x.test").unwrap_err().status, 403);
            check_new_user(conn, &c, "A@x.test")?;
            check_new_workspace(conn, &c)?;
            workspace(conn, "w3", "free");
            assert_eq!(check_new_workspace(conn, &c).unwrap_err().status, 403);
            let open = cfg(Mode::SelfHosted, &[]);
            check_new_user(conn, &open, "b@x.test")?;
            check_new_workspace(conn, &open)?;
            Ok(())
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn the_domain_allowlist_closes_sign_up_but_not_existing_accounts() {
        let db = crate::db::test_db();
        db.call(|conn| {
            let c = cfg(Mode::SelfHosted, &[("BROD_ALLOWED_EMAIL_DOMAINS", "acme.com, Acme.io")]);
            crate::people::verified_user(conn, "old@elsewhere.test", "")?;
            check_new_signin(conn, &c, "new@acme.com")?;
            check_new_signin(conn, &c, "New@ACME.io")?;
            check_new_signin(conn, &c, "old@elsewhere.test")?;
            let e = check_new_signin(conn, &c, "x@evil.test").unwrap_err();
            assert_eq!((e.status, e.code.as_str()), (403, "email_domain_not_allowed"));
            // A look-alike subdomain is not the domain.
            assert!(check_new_signin(conn, &c, "x@notacme.com").is_err());
            check_new_signin(conn, &cfg(Mode::SelfHosted, &[]), "x@evil.test")?;
            Ok(())
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn the_creation_policy_decides_who_may_make_a_workspace() {
        let db = crate::db::test_db();
        db.call(|conn| {
            let admin = crate::people::verified_user(conn, "admin@x.test", "")?;
            let other = crate::people::verified_user(conn, "other@x.test", "")?;
            workspace(conn, "w1", "free");
            conn.run("INSERT INTO members (workspace_id, user_id, role, created_at) VALUES ('w1', ?, 'admin', 1)", [&admin.id])?;
            let may = |c: &Config, u: &crate::model::User| crate::people::may_create_workspace(conn, c, u).unwrap();
            let anyone = cfg(Mode::SelfHosted, &[("BROD_WORKSPACE_CREATION", "anyone_verified")]);
            assert!(may(&anyone, &admin) && may(&anyone, &other));
            let admins = cfg(Mode::SelfHosted, &[]);
            assert!(may(&admins, &admin) && !may(&admins, &other));
            let ops = cfg(Mode::SelfHosted, &[("BROD_WORKSPACE_CREATION", "operators")]);
            assert!(!may(&ops, &admin) && !may(&ops, &other));
            conn.run("UPDATE users SET operator_at = 1 WHERE id = ?", [&other.id])?;
            assert!(may(&ops, &other));
            assert!(may(&cfg(Mode::Hosted, &[]), &admin));
            Ok(())
        })
        .await
        .unwrap();
    }
}
