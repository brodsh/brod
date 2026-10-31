// SPDX-License-Identifier: AGPL-3.0-only
// Operators run the whole Brod server (docs/plans/admin-mode.md §1.1). That is a different job from a workspace admin,
// who runs one workspace. users.operator_at marks an operator. The admin API (/v1/admin) accepts an operator signed
// in on the dashboard or the ADMIN_SECRET bearer that scripts use; both arrive here as one Operator.
use crate::config::{Config, Mode};
use crate::db::{Connection, Sql, params};
use crate::http::Req;
use crate::problem::{Problem, Result};
use crate::state::State;
use crate::util::{now, safe_equal};

/// Who is acting through the admin API.
#[derive(Clone, Debug)]
pub struct Operator {
    /// The name the audit log shows: the operator's email, or abuse::OPERATOR for the admin secret.
    pub actor: String,
    /// The signed-in operator, or None for the admin secret.
    pub user_id: Option<String>,
}

/// Make operators who should be, and say how many there are. Idempotent, so it runs at boot and again when someone
/// who may have just become one asks (`authenticate`):
/// - the person whose email is BROD_ADMIN_EMAIL, once they have an account;
/// - self-hosted with no BROD_ADMIN_EMAIL and no operator yet: the first admin of the first workspace, so the person
///   who set the server up runs it, as on first start today.
pub fn bootstrap(conn: &Connection, cfg: &Config) -> Result<i64> {
    if let Some(email) = &cfg.admin_email {
        conn.run("UPDATE users SET operator_at = ? WHERE email = ? AND operator_at IS NULL", params![now(), email])?;
    } else if cfg.mode == Mode::SelfHosted && count(conn)? == 0 {
        let first: Option<String> = conn.first(
            "SELECT m.user_id FROM members m JOIN workspaces w ON w.id = m.workspace_id
             WHERE m.role = 'admin' ORDER BY w.created_at, w.id, m.created_at, m.user_id LIMIT 1",
            (),
            |r| r.get(0),
        )?;
        if let Some(id) = first {
            conn.run("UPDATE users SET operator_at = ? WHERE id = ? AND operator_at IS NULL", params![now(), id])?;
        }
    }
    count(conn)
}

pub fn count(conn: &Connection) -> Result<i64> {
    Ok(conn.first("SELECT COUNT(*) FROM users WHERE operator_at IS NOT NULL", (), |r| r.get(0))?.unwrap_or(0))
}

pub fn is_operator(conn: &Connection, user_id: &str) -> Result<bool> {
    conn.exists("SELECT 1 FROM users WHERE id = ? AND operator_at IS NOT NULL", [user_id])
}

/// The operator making this request, or 401/403. An Authorization header must be the admin secret; it never falls
/// back to the cookie. A cookie-signed-in operator may only change things from the dashboard's own origin.
pub async fn authenticate(st: &State, req: &Req) -> Result<Operator> {
    let cr = crate::control::Credentials::of(req);
    if cr.authorization.is_some() {
        let given = cr.bearer().unwrap_or_default();
        if st.cfg.admin_secret.is_empty() || !safe_equal(&given, &st.cfg.admin_secret) {
            return Err(Problem::new(401, "unauthorized", "The admin API needs the admin secret or an operator's sign-in."));
        }
        return Ok(Operator { actor: crate::abuse::OPERATOR.to_string(), user_id: None });
    }
    let cfg = st.cfg.clone();
    st.db
        .call(move |c| {
            let Some((user, _)) = crate::control::person(c, &cfg, cr.cookie.as_deref())? else {
                return Err(Problem::new(401, "unauthorized", "Sign in as an operator, or send the admin secret as a bearer token."));
            };
            if !is_operator(c, &user.id)? && (bootstrap(c, &cfg)? == 0 || !is_operator(c, &user.id)?) {
                return Err(Problem::new(403, "not_operator", "Only the server's operators can use the admin console."));
            }
            crate::control::check_origin(&cfg, &cr.method, cr.origin.as_deref())?;
            Ok(Operator { actor: user.email, user_id: Some(user.id) })
        })
        .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::people;

    fn cfg(mode: Mode, admin: Option<&str>) -> Config {
        let mut c = Config::for_tests();
        c.mode = mode;
        c.admin_email = admin.map(String::from);
        c
    }

    #[tokio::test]
    async fn the_admin_email_becomes_an_operator_once_they_have_an_account() {
        let db = crate::db::test_db();
        let c = cfg(Mode::Hosted, Some("op@acme.test"));
        db.call(move |conn| {
            assert_eq!(bootstrap(conn, &c)?, 0);
            let op = people::verified_user(conn, "op@acme.test", "")?;
            let other = people::verified_user(conn, "ada@acme.test", "")?;
            assert_eq!(bootstrap(conn, &c)?, 1);
            assert!(is_operator(conn, &op.id)? && !is_operator(conn, &other.id)?);
            // Run again: nothing changes.
            assert_eq!(bootstrap(conn, &c)?, 1);
            Ok(())
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn self_hosted_without_an_admin_email_promotes_the_first_workspace_admin_only() {
        let db = crate::db::test_db();
        let c = cfg(Mode::SelfHosted, None);
        db.call(move |conn| {
            assert_eq!(bootstrap(conn, &c)?, 0);
            let first = people::verified_user(conn, "first@acme.test", "")?;
            people::create_workspace(conn, &c, &first, "First", true)?;
            assert_eq!(bootstrap(conn, &c)?, 1);
            assert!(is_operator(conn, &first.id)?);
            // A later workspace's admin does not become one.
            let second = people::verified_user(conn, "second@acme.test", "")?;
            conn.run(
                "INSERT INTO workspaces (id, slug, name, plan, color, icon, created_at) VALUES ('ws_b','b','B','free','','',?)",
                [now() + 1],
            )?;
            conn.run(
                "INSERT INTO members (workspace_id, user_id, role, created_at) VALUES ('ws_b', ?, 'admin', ?)",
                params![second.id, now()],
            )?;
            assert_eq!(bootstrap(conn, &c)?, 1);
            assert!(!is_operator(conn, &second.id)?);
            Ok(())
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn hosted_without_an_admin_email_has_no_operator() {
        let db = crate::db::test_db();
        let c = cfg(Mode::Hosted, None);
        db.call(move |conn| {
            let u = people::verified_user(conn, "first@acme.test", "")?;
            people::create_workspace(conn, &c, &u, "First", true)?;
            assert_eq!(bootstrap(conn, &c)?, 0);
            Ok(())
        })
        .await
        .unwrap();
    }
}
