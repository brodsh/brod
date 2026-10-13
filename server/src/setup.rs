// SPDX-License-Identifier: AGPL-3.0-only
// First start. On a self-hosted server with no workspace yet, BROD_ADMIN_EMAIL becomes the admin of a workspace
// called "Default". Until that person has signed in once, every start prints a sign-in link for them and the lines
// that connect an agent, so the first screen an operator sees is `docker compose logs brod`.
// `brod setup-link` prints a fresh link at any time.
use crate::config::{Config, Mode};
use crate::db::{Connection, Sql, params};
use crate::people;
use crate::problem::Result;
use crate::util::{now, random_id, sha256_hex};

/// How long the link printed at start keeps working.
pub const SETUP_LINK_TTL_MS: i64 = 24 * 3_600_000;

/// What `prepare` found or made.
pub enum Setup {
    /// The admin has signed in before: nothing to print.
    Done,
    /// A sign-in link for the admin, and their first workspace.
    Link { email: String, workspace: String, link: String },
    /// No workspace and no BROD_ADMIN_EMAIL: the first person to sign in may make one.
    Open,
}

/// Make the admin and their workspace when the database has none, then decide what to print.
/// `force`: a fresh link even if the admin has signed in before (`brod setup-link`).
pub fn prepare(conn: &Connection, cfg: &Config, force: bool) -> Result<Setup> {
    if cfg.mode == Mode::Hosted {
        return Ok(Setup::Done);
    }
    let Some(email) = cfg.admin_email.clone() else {
        return Ok(if conn.exists("SELECT 1 FROM workspaces", ())? { Setup::Done } else { Setup::Open });
    };
    let user = people::verified_user(conn, &email, "")?;
    if !conn.exists("SELECT 1 FROM workspaces", ())? {
        people::create_workspace(conn, cfg, &user, "Default", true)?;
    }
    let Some(workspace) = conn.first(
        "SELECT w.slug FROM members m JOIN workspaces w ON w.id = m.workspace_id WHERE m.user_id = ? AND m.role = 'admin' ORDER BY m.created_at LIMIT 1",
        [&user.id],
        |r| r.get::<_, String>(0),
    )?
    else {
        // The admin email names someone who is not an admin of any workspace on a server that already has some.
        return Ok(Setup::Done);
    };
    if !force && conn.exists("SELECT 1 FROM sessions WHERE user_id = ?", [&user.id])? {
        return Ok(Setup::Done);
    }
    let token = random_id("", 24);
    conn.run(
        "INSERT INTO login_links (hash, email, return_to, created_at, expires_at) VALUES (?,?,?,?,?)",
        params![sha256_hex(&token), email, format!("/w/{workspace}/connections"), now(), now() + SETUP_LINK_TTL_MS],
    )?;
    Ok(Setup::Link { email, link: format!("{}/auth/verify?token={token}", cfg.api_origin), workspace })
}

/// The lines to print for `setup`, ready to copy.
pub fn banner(cfg: &Config, setup: &Setup) -> Option<String> {
    let url = &cfg.api_origin;
    let connect = format!("claude mcp add --transport http brod {url}/mcp --header \"Authorization: Bearer <token>\"",);
    let body = match setup {
        Setup::Done => return None,
        Setup::Link { email, workspace, link } => format!(
            "Brod is ready at {url}\n\n\
             1. Sign in as {email}. This link works once, for 24 hours:\n\n   {link}\n\n\
             2. It opens the agent connections page ({url}/w/{workspace}/connections).\n   Make a token there. It is shown once.\n\n\
             3. Connect Claude Code:\n\n   {connect}\n\n\
             Lost the link? Print a new one with: docker compose exec brod brod setup-link",
        ),
        Setup::Open => format!(
            "Brod is ready at {url}, with no workspace yet.\n\n\
             Set BROD_ADMIN_EMAIL and restart to make the first admin and print a sign-in link here.\n\
             Until then, the first person to sign in at {url} may create the first workspace."
        ),
    };
    let rule = "-".repeat(72);
    Some(format!("{rule}\n{body}\n{rule}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(admin: Option<&str>) -> Config {
        let mut c = Config::for_tests();
        c.mode = Mode::SelfHosted;
        c.admin_email = admin.map(String::from);
        c
    }

    #[tokio::test]
    async fn makes_the_admin_and_a_workspace_once() {
        let db = crate::db::test_db();
        let c = cfg(Some("ada@acme.test"));
        let first = db.call({
            let c = c.clone();
            move |conn| prepare(conn, &c, false)
        });
        let Setup::Link { email, workspace, link } = first.await.expect("setup") else { panic!("expected a link") };
        assert_eq!((email.as_str(), workspace.as_str()), ("ada@acme.test", "default"));
        assert!(link.starts_with("http://localhost:8787/auth/verify?token="));
        let text = banner(&c, &Setup::Link { email, workspace, link }).expect("banner");
        assert!(text.contains("claude mcp add --transport http brod http://localhost:8787/mcp"));

        // A second start makes nothing new, and prints a link again while the admin has not signed in.
        let again = db.call({
            let c = c.clone();
            move |conn| {
                let s = prepare(conn, &c, false)?;
                Ok((matches!(s, Setup::Link { .. }), conn.count("SELECT COUNT(*) FROM workspaces", ())?))
            }
        });
        assert_eq!(again.await.expect("again"), (true, 1));

        // Once they have a session, nothing is printed unless asked.
        let after = db.call(move |conn| {
            let user = people::verified_user(conn, "ada@acme.test", "")?;
            people::create_session(conn, &user.id, None, None)?;
            Ok((matches!(prepare(conn, &c, false)?, Setup::Done), matches!(prepare(conn, &c, true)?, Setup::Link { .. })))
        });
        assert_eq!(after.await.expect("after"), (true, true));
    }

    #[tokio::test]
    async fn without_an_admin_email_the_server_says_how_to_start() {
        let db = crate::db::test_db();
        let c = cfg(None);
        let s = db.call(move |conn| prepare(conn, &c, false)).await.expect("setup");
        assert!(matches!(s, Setup::Open));
        assert!(banner(&cfg(None), &s).expect("banner").contains("Set BROD_ADMIN_EMAIL"));
    }

    #[tokio::test]
    async fn only_admins_make_more_workspaces() {
        let db = crate::db::test_db();
        let c = cfg(Some("ada@acme.test"));
        let out = db
            .call(move |conn| {
                prepare(conn, &c, false)?;
                let ada = people::verified_user(conn, "ada@acme.test", "")?;
                let bo = people::verified_user(conn, "bo@acme.test", "")?;
                Ok((people::may_create_workspace(conn, &c, &ada)?, people::may_create_workspace(conn, &c, &bo)?))
            })
            .await
            .expect("check");
        assert_eq!(out, (true, false));
    }
}
