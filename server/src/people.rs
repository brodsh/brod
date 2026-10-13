// SPDX-License-Identifier: AGPL-3.0-only
// The workspace layer: people, workspaces, groups, invites, per-app role grants, sessions,
// and the one access decision the gateway makes for every visitor request.
// Functions here are synchronous over one database connection; callers run them on the blocking pool.
use crate::db::{Connection, Row, params};
use serde_json::{Map, Value, json};

use crate::config::Config;
use crate::db::{Sql, event, tx};
use crate::model::{AppRow, Caller, User, Workspace, field, limits, plan, present, rank};
use crate::problem::{Problem, Result};
use crate::util::{app_url, is_email, js_slice, js_trim, norm_email, now, random_id, sha256_hex, workspace_slugify};

pub fn require_role(c: &Caller, least: &str, what: &str) -> Result<()> {
    if rank(&c.role) < rank(least) {
        let or_admin = if least == "admin" { "" } else { " or admin" };
        return Err(Problem::new(403, "forbidden", format!("Only a workspace {least}{or_admin} can {what}. You are a {}.", c.role)));
    }
    Ok(())
}
fn home_url(cfg: &Config, w: &Workspace) -> String {
    format!("{}/w/{}", cfg.api_origin, w.slug)
}

// ---------- people ----------

fn user_from_row(r: &Row) -> crate::problem::Result<User> {
    Ok(User { id: r.get("id")?, email: r.get("email")?, name: r.get("name")?, email_verified_at: r.get("email_verified_at")? })
}

pub fn user_by_email(conn: &Connection, email: &str) -> Result<Option<User>> {
    conn.first("SELECT id, email, name, email_verified_at FROM users WHERE email = ?", [email], user_from_row)
}

/// Find or create the person who just proved they own this email address.
pub fn verified_user(conn: &Connection, email: &str, name: &str) -> Result<User> {
    let e = norm_email(email);
    let t = now();
    conn.run(
        "INSERT INTO users (id, email, name, email_verified_at, created_at) VALUES (?,?,?,?,?)
         ON CONFLICT(email) DO UPDATE SET email_verified_at = COALESCE(users.email_verified_at, excluded.email_verified_at),
           name = CASE WHEN users.name = '' THEN excluded.name ELSE users.name END",
        params![random_id("usr_", 12), e, js_slice(name, 80), t, t],
    )?;
    user_by_email(conn, &e)?.ok_or_else(|| Problem::internal("user vanished after insert"))
}

// ---------- sessions ----------

/// Make a session. A platform session has no app; an app session belongs to one app and to the platform session it came from.
pub fn create_session(conn: &Connection, user_id: &str, app_id: Option<&str>, parent: Option<&str>) -> Result<String> {
    let token = random_id("", 24);
    conn.run(
        "INSERT INTO sessions (hash, user_id, app_id, parent, created_at, expires_at) VALUES (?,?,?,?,?,?)",
        params![sha256_hex(&token), user_id, app_id, parent, now(), now() + limits::SESSION_TTL_MS],
    )?;
    Ok(token)
}

#[derive(Clone, Debug)]
pub struct SessionUser {
    pub user: User,
    pub hash: String,
    pub parent: Option<String>,
}

pub fn session_user(conn: &Connection, token: &str, app_id: Option<&str>) -> Result<Option<SessionUser>> {
    if token.len() != 48 || !token.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
        return Ok(None);
    }
    let hash = sha256_hex(token);
    let t = now();
    let row = conn.first(
        "SELECT u.id, u.email, u.name, u.email_verified_at, s.parent FROM sessions s JOIN users u ON u.id = s.user_id
         LEFT JOIN sessions p ON p.hash = s.parent
         WHERE s.hash = ? AND s.revoked_at IS NULL AND s.expires_at > ? AND s.app_id IS ? AND (s.parent IS NULL OR (p.revoked_at IS NULL AND p.expires_at > ?))",
        params![hash, t, app_id, t],
        |r| Ok((user_from_row(r)?, r.get::<_, Option<String>>("parent")?)),
    )?;
    Ok(row.map(|(user, parent)| SessionUser { user, hash, parent }))
}

/// Sign out everywhere: the platform session and every app session made from it.
pub fn revoke_session(conn: &Connection, platform_hash: &str) -> Result<()> {
    conn.run(
        "UPDATE sessions SET revoked_at = ? WHERE (hash = ? OR parent = ?) AND revoked_at IS NULL",
        params![now(), platform_hash, platform_hash],
    )?;
    Ok(())
}

// ---------- workspaces ----------

pub fn my_workspaces(conn: &Connection, cfg: &Config, user: &User) -> Result<Vec<Value>> {
    conn.all(
        "SELECT w.slug, w.name, w.plan, m.role FROM members m JOIN workspaces w ON w.id = m.workspace_id WHERE m.user_id = ? ORDER BY m.created_at",
        [&user.id],
        |r| {
            let slug: String = r.get(0)?;
            Ok(json!({ "slug": slug, "name": r.get::<_, String>(1)?, "plan": r.get::<_, String>(2)?, "role": r.get::<_, String>(3)?, "home": format!("{}/w/{slug}", cfg.api_origin) }))
        },
    )
}

pub fn membership(conn: &Connection, user: &User, workspace: Option<&str>) -> Result<Option<(Workspace, String)>> {
    conn.first(
        "SELECT w.*, m.role AS mrole FROM members m JOIN workspaces w ON w.id = m.workspace_id
         WHERE m.user_id = ? AND (? IS NULL OR w.slug = ?) ORDER BY m.role = 'guest', m.created_at LIMIT 1",
        params![user.id, workspace, workspace],
        |r| Ok((Workspace::from_row(r)?, r.get::<_, String>("mrole")?)),
    )
}

pub fn create_workspace(conn: &Connection, cfg: &Config, user: &User, name: &str, accept_terms: bool) -> Result<Value> {
    let clean = js_slice(js_trim(name), 60);
    if clean.is_empty() {
        return Err(Problem::new(400, "need_name", "Give the workspace a name, for example your team or company."));
    }
    if user.email_verified_at.is_none() {
        return Err(Problem::new(403, "unverified", "Confirm your email address first."));
    }
    let t = now();
    if !accept_terms {
        let accepted: Option<i64> = conn.first("SELECT terms_accepted_at FROM users WHERE id = ?", [&user.id], |r| r.get(0))?.flatten();
        if accepted.is_none() {
            return Err(Problem::new(
                400,
                "terms",
                "Accept the terms of use and acceptable-use policy to create a workspace (\"accept_terms\": true).",
            ));
        }
    }
    crate::abuse::rate_limit(
        conn,
        "workspaces",
        &user.id,
        crate::abuse::WORKSPACES_PER_USER_DAY,
        crate::abuse::DAY,
        &format!(
            "You can create {} workspaces a day and have reached that; use one you already have.",
            crate::abuse::WORKSPACES_PER_USER_DAY
        ),
    )?;
    let base = workspace_slugify(&clean);
    let mut slug = base.clone();
    let mut i = 0;
    while conn.exists("SELECT 1 FROM workspaces WHERE slug = ?", [&slug])? {
        slug = format!("{base}-{}", random_id("", if i < 5 { 2 } else { 4 }));
        i += 1;
    }
    let w = Workspace {
        id: random_id("ws_", 12),
        slug,
        name: clean.clone(),
        plan: "free".into(),
        color: "#1f6f4a".into(),
        icon: String::new(),
        created_at: t,
    };
    tx(conn, |c| {
        c.run(
            "INSERT INTO workspaces (id, slug, name, plan, color, icon, created_at) VALUES (?,?,?,?,?,?,?)",
            params![w.id, w.slug, w.name, w.plan, w.color, w.icon, t],
        )?;
        c.run("INSERT INTO members (workspace_id, user_id, role, created_at) VALUES (?,?,'admin',?)", params![w.id, user.id, t])?;
        c.run("UPDATE users SET terms_accepted_at = COALESCE(terms_accepted_at, ?) WHERE id = ?", params![t, user.id])?;
        event(c, &w.id, &user.email, None, "workspace_created", &clean)
    })?;
    Ok(json!({ "workspace": w.slug, "name": w.name, "home": home_url(cfg, &w), "role": "admin" }))
}

pub fn update_workspace(conn: &Connection, c: &Caller, o: &Map<String, Value>) -> Result<Value> {
    require_role(c, "admin", "change the workspace name or branding")?;
    let name = match o.get("name") {
        None => c.workspace.name.clone(),
        Some(v) => js_slice(js_trim(&crate::model::js_string(v)), 60),
    };
    let color = match o.get("color") {
        None => c.workspace.color.clone(),
        Some(v) => crate::model::js_string(v),
    };
    let icon = match o.get("icon") {
        None => c.workspace.icon.clone(),
        Some(v) => crate::model::js_string(v).chars().take(2).collect(),
    };
    if name.is_empty() {
        return Err(Problem::new(400, "need_name", "The workspace needs a name."));
    }
    if !crate::util::is_hex_color(&color) {
        return Err(Problem::new(400, "bad_color", "Colour is a hex value such as \"#1f6f4a\"."));
    }
    tx(conn, |x| {
        x.run("UPDATE workspaces SET name = ?, color = ?, icon = ? WHERE id = ?", params![name, color, icon, c.workspace.id])?;
        event(x, &c.workspace.id, &c.actor, None, "branding", &format!("name \"{name}\", colour {color}"))
    })?;
    let mut w = c.workspace.clone();
    w.name = name;
    w.color = color;
    w.icon = icon;
    Ok(serde_json::to_value(w)?)
}

pub fn member_count(conn: &Connection, w: &Workspace) -> Result<i64> {
    conn.count(
        "SELECT (SELECT COUNT(*) FROM members WHERE workspace_id = ?1 AND role != 'guest') +
                (SELECT COUNT(*) FROM invites WHERE workspace_id = ?1 AND role != 'guest' AND used_at IS NULL AND revoked_at IS NULL AND expires_at > ?2) AS n",
        params![w.id, now()],
    )
}

/// What an agent needs to build an app that fits this workspace (get_workspace).
pub fn describe_workspace(conn: &Connection, cfg: &Config, c: &Caller) -> Result<Value> {
    let groups = conn.all(
        "SELECT g.name, COUNT(gm.user_id) AS members FROM groups g LEFT JOIN group_members gm ON gm.group_id = g.id WHERE g.workspace_id = ? GROUP BY g.id ORDER BY g.name",
        [&c.workspace.id],
        |r| Ok(json!({ "name": r.get::<_, String>(0)?, "members": r.get::<_, i64>(1)? })),
    )?;
    let apps = conn.count("SELECT COUNT(*) AS n FROM apps WHERE workspace_id = ? AND status = 'live'", [&c.workspace.id])?;
    let p = plan(&c.workspace);
    Ok(json!({
        "workspace": c.workspace.slug, "name": c.workspace.name, "home": home_url(cfg, &c.workspace), "your_role": c.role,
        "plan": c.workspace.plan, "running_apps": apps, "app_limit": p.apps, "members": member_count(conn, &c.workspace)?, "member_limit": p.members,
        "storage_bytes": crate::usage::workspace_storage(conn, &c.workspace.id)?.total(), "storage_limit": p.storage,
        "groups": groups,
        "default_app_roles": ["owner", "editor", "viewer"],
        "access_modes": {
            "private": "Only the app's owner (and workspace admins).",
            "people": "Only the people and groups granted a role on the app.",
            "workspace": "Everyone in the workspace. Guests only if granted.",
            "password": "Anyone with the address and the password, without signing in. Set it with set_access { \"access\": \"password\", \"password\": \"...\" }; share the address and the password separately. People granted a role can sign in instead.",
            "signed_in": "Anyone who signs in.",
            "public": "Anyone, without signing in.",
        },
        "identity": {
            "how": "An app never keeps its own user table. The platform signs people in before a request reaches the app. In the browser, GET /_brod/me on the app's own address returns the signed-in person, or 401 if nobody is signed in (public apps).",
            "shape": { "user": { "id": "usr_…", "email": "ana@example.com", "name": "Ana" }, "role": "editor", "groups": ["finance"], "app": "reading-list", "workspace": c.workspace.slug, "token": "<signed identity token>" },
            "client_library": "<script src=\"/_brod/client.js\"></script> then: const me = await Brod.me(); if (me?.role === \"editor\") { … }; Brod.signIn(); Brod.signOut();",
            "roles": "Check me.role against the roles the app declares (default owner, editor, viewer; most powerful first). Hide or disable what a role may not do.",
            "server_apps": "Server code (_worker.js) receives the signed-in person on every request as headers x-brod-user-id, x-brod-user-email, x-brod-user-name (URI-encoded), x-brod-role and x-brod-groups (comma-separated), plus x-brod-identity (the signed token). They are absent for anonymous visitors of public apps. The platform removes any x-brod-* header a visitor sends.",
            "signed_token": "me.token and x-brod-identity are base64url(JSON) + \".\" + an HMAC-SHA256 signature with a per-app key, valid 5 minutes, for passing identity on to another service.",
        },
        "settings": {
            "how": "To let whoever uses or installs the app change its name, logo, colours or wording without touching the code, declare those settings in a brod.json at the top of the bundle; Brod imposes none. Each has a key, a label, a type (text, textarea, color, image, url, email, number, boolean, select) and a default; an image's default is a picture in the bundle. People change them on the app's Customize page or when installing it from the marketplace. Never hard-code what you declared: read it.",
            "example": { "settings": [{ "key": "name", "label": "Shop name", "type": "text", "default": "My shop" }, { "key": "logo", "label": "Logo", "type": "image", "default": "logo.png" }, { "key": "accent", "label": "Accent colour", "type": "color", "default": "#1f6f4a" }] },
            "reading": "In the browser: const s = await Brod.settings(); (GET /_brod/settings) gives { name, logo, accent }, every key present with its default when unset; an image is an address to use as <img src>. Server code reads the same object as env.SETTINGS.",
        },
        "network": {
            "how": "An app may only send data to its own address and the outside hosts it declares in the \"network\" list of brod.json, for example { \"network\": [\"api.stripe.com\", \"cdn.jsdelivr.net\", \"*.googleapis.com\"] } (host names only, no https:// or path; *. covers subdomains). This covers server code's fetch() and everything the page loads or sends: scripts and fonts from CDNs, API calls, form posts, images. Declare every host the app uses; people approve the list before installing a shared app.",
            "policy": cfg.network.name(),
            "policy_means": match cfg.network {
                crate::config::NetworkPolicy::Enforce => "Undeclared requests are refused and recorded.",
                crate::config::NetworkPolicy::Log => "Undeclared requests still work for now, but are recorded and shown on the app's Network page (get_status: network.undeclared). Declare them before this server starts refusing them.",
                crate::config::NetworkPolicy::Off => "This server does not check outside requests.",
            },
        },
    }))
}

// ---------- people directory ----------

pub fn list_people(conn: &Connection, c: &Caller) -> Result<Value> {
    let people = conn.all(
        "SELECT u.id, u.email, u.name, m.role, m.created_at,
           (SELECT GROUP_CONCAT(g.name, ', ') FROM group_members gm JOIN groups g ON g.id = gm.group_id WHERE gm.user_id = u.id AND g.workspace_id = m.workspace_id) AS groups
         FROM members m JOIN users u ON u.id = m.user_id WHERE m.workspace_id = ? ORDER BY m.created_at",
        [&c.workspace.id],
        |r| {
            let groups: Option<String> = r.get(5)?;
            let groups: Vec<String> = groups.filter(|g| !g.is_empty()).map(|g| g.split(", ").map(String::from).collect()).unwrap_or_default();
            Ok(json!({ "id": r.get::<_, String>(0)?, "email": r.get::<_, String>(1)?, "name": r.get::<_, String>(2)?, "role": r.get::<_, String>(3)?, "groups": groups }))
        },
    )?;
    Ok(json!({ "people": people }))
}

pub(crate) struct Person {
    pub id: String,
    pub email: String,
    pub role: String,
}

pub(crate) fn person_in_workspace(conn: &Connection, c: &Caller, who: &str) -> Result<Person> {
    let key = if who.contains('@') { norm_email(who) } else { who.to_string() };
    conn.first(
        "SELECT u.id, u.email, m.role FROM members m JOIN users u ON u.id = m.user_id WHERE m.workspace_id = ? AND (u.id = ? OR u.email = ?)",
        params![c.workspace.id, key, key],
        |r| Ok(Person { id: r.get(0)?, email: r.get(1)?, role: r.get(2)? }),
    )?
    .ok_or_else(|| Problem::new(404, "no_person", format!("{who} is not in this workspace. Invite them first.")))
}

fn admins(conn: &Connection, w: &Workspace) -> Result<i64> {
    conn.count("SELECT COUNT(*) AS n FROM members WHERE workspace_id = ? AND role = 'admin'", [&w.id])
}

fn member_limit(c: &Caller) -> Problem {
    let p = plan(&c.workspace);
    Problem::new(
        402,
        "member_limit",
        format!(
            "Your {} plan includes {} members and all are in use or invited. Remove someone, invite them as a guest to named apps, or upgrade the plan.",
            c.workspace.plan, p.members
        ),
    )
    .with("member_limit", json!(p.members))
}

const ROLES: [&str; 4] = ["admin", "builder", "member", "guest"];

pub fn set_person_role(conn: &Connection, c: &Caller, who: &str, role: &str) -> Result<Value> {
    require_role(c, "admin", "change workspace roles")?;
    if !ROLES.contains(&role) {
        return Err(Problem::new(400, "bad_role", "Workspace roles are admin, builder, member and guest."));
    }
    let p = person_in_workspace(conn, c, who)?;
    if p.role == "admin" && role != "admin" && admins(conn, &c.workspace)? <= 1 {
        return Err(Problem::new(409, "last_admin", "A workspace needs at least one admin."));
    }
    if p.role == "guest" && role != "guest" && member_count(conn, &c.workspace)? >= plan(&c.workspace).members {
        return Err(member_limit(c));
    }
    tx(conn, |x| {
        x.run("UPDATE members SET role = ? WHERE workspace_id = ? AND user_id = ?", params![role, c.workspace.id, p.id])?;
        event(x, &c.workspace.id, &c.actor, None, "role_changed", &format!("{}: {} to {role}", p.email, p.role))
    })?;
    Ok(json!({ "id": p.id, "email": p.email, "role": role }))
}

/// Remove a person: their access to every app in the workspace ends on their next request.
pub fn remove_person(conn: &Connection, c: &Caller, who: &str) -> Result<Value> {
    require_role(c, "admin", "remove people")?;
    let p = person_in_workspace(conn, c, who)?;
    if p.role == "admin" && admins(conn, &c.workspace)? <= 1 {
        return Err(Problem::new(409, "last_admin", "A workspace needs at least one admin."));
    }
    tx(conn, |x| {
        x.run("DELETE FROM members WHERE workspace_id = ? AND user_id = ?", params![c.workspace.id, p.id])?;
        x.run(
            "DELETE FROM group_members WHERE user_id = ? AND group_id IN (SELECT id FROM groups WHERE workspace_id = ?)",
            params![p.id, c.workspace.id],
        )?;
        x.run(
            "DELETE FROM space_members WHERE user_id = ? AND space_id IN (SELECT id FROM spaces WHERE workspace_id = ?)",
            params![p.id, c.workspace.id],
        )?;
        x.run(
            "DELETE FROM grants WHERE subject = ? AND app_id IN (SELECT id FROM apps WHERE workspace_id = ?)",
            params![format!("user:{}", p.id), c.workspace.id],
        )?;
        x.run(
            "UPDATE tokens SET revoked_at = ? WHERE workspace_id = ? AND user_id = ? AND revoked_at IS NULL",
            params![now(), c.workspace.id, p.id],
        )?;
        event(x, &c.workspace.id, &c.actor, None, "person_removed", &p.email)
    })?;
    Ok(json!({ "removed": p.email }))
}

/// Giving someone a private app opens it to named people, or the grant would do nothing.
fn share_with_people(conn: &Connection, app_id: &str) -> Result<()> {
    conn.run("UPDATE apps SET access = 'people' WHERE id = ? AND access = 'private'", [app_id])?;
    Ok(())
}

// ---------- invites ----------

pub struct CheckedInvite {
    pub email: String,
    pub role: String,
    pub app: Option<AppRow>,
    pub app_role: Option<String>,
}

/// Check an invite without sending it, so an agent's request can be validated before it waits for a person to confirm.
pub fn check_invite(
    conn: &Connection,
    c: &Caller,
    o: &Map<String, Value>,
    get_app: &dyn Fn(&str) -> Result<AppRow>,
) -> Result<CheckedInvite> {
    let email = norm_email(&field(o, "email"));
    if !is_email(&email) {
        return Err(Problem::new(400, "bad_email", "That does not look like an email address."));
    }
    let app = match o.get("app") {
        Some(v) if crate::model::truthy(Some(v)) => Some(get_app(&crate::model::js_string(v))?),
        _ => None,
    };
    let role = match present(o, "role") {
        Some(v) => crate::model::js_string(v),
        None => if app.is_some() { "guest" } else { "member" }.to_string(),
    };
    if !ROLES.contains(&role.as_str()) {
        return Err(Problem::new(400, "bad_role", "Invite as admin, builder, member, or guest."));
    }
    if role == "guest" && app.is_none() {
        return Err(Problem::new(400, "need_app", "A guest is invited to a named app. Give \"app\"."));
    }
    if role == "guest" {
        require_role(c, "builder", "invite guests to an app")?;
    } else {
        require_role(c, "admin", "invite people into the workspace")?;
    }
    let mut app_role = None;
    if let Some(a) = &app {
        let roles = a.role_list();
        let r = match present(o, "app_role") {
            Some(v) => crate::model::js_string(v),
            None => roles.last().cloned().unwrap_or_default(),
        };
        if !roles.contains(&r) {
            return Err(Problem::new(400, "bad_role", format!("{} understands the roles {}.", a.slug, roles.join(", "))));
        }
        app_role = Some(r);
    }
    if role != "guest" && member_count(conn, &c.workspace)? >= plan(&c.workspace).members {
        return Err(member_limit(c));
    }
    Ok(CheckedInvite { email, role, app, app_role })
}

/// An email to send once the database work is done.
pub struct Email {
    pub to: String,
    pub subject: String,
    pub text: String,
}

/// The database half of invite(): grant straight away, or record the invitation and return the email to send.
pub fn invite(
    conn: &Connection,
    cfg: &Config,
    c: &Caller,
    o: &Map<String, Value>,
    get_app: &dyn Fn(&str) -> Result<AppRow>,
) -> Result<(Value, Option<Email>)> {
    let CheckedInvite { email, role, app, app_role } = check_invite(conn, c, o, get_app)?;
    // Someone already in the workspace who is being given an app gets the grant straight away.
    let existing: Option<(String, String)> = conn.first(
        "SELECT u.id, m.role FROM users u JOIN members m ON m.user_id = u.id AND m.workspace_id = ? WHERE u.email = ?",
        params![c.workspace.id, email],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    if let Some((_, existing_role)) = &existing
        && app.is_none()
    {
        return Err(Problem::new(409, "already_member", format!("{email} is already in this workspace as a {existing_role}.")));
    }
    if let (Some((uid, _)), Some(a)) = (&existing, &app) {
        let ar = app_role.clone().unwrap_or_default();
        tx(conn, |x| {
            x.run(
                "INSERT INTO grants (app_id, subject, role, created_at) VALUES (?,?,?,?) ON CONFLICT(app_id, subject) DO UPDATE SET role = excluded.role",
                params![a.id, format!("user:{uid}"), ar, now()],
            )?;
            share_with_people(x, &a.id)?;
            event(x, &c.workspace.id, &c.actor, Some(&a.id), "grant", &format!("{email} as {ar}"))
        })?;
        return Ok((
            json!({ "email": email, "granted": { "app": a.slug, "role": ar }, "url": app_url(cfg, &c.workspace.slug, &a.slug) }),
            None,
        ));
    }
    let token = random_id("", 24);
    let id = random_id("inv_", 8);
    let detail = format!(
        "{email} as {role}{}",
        app.as_ref().map(|a| format!(" to {} ({})", a.slug, app_role.clone().unwrap_or_default())).unwrap_or_default()
    );
    tx(conn, |x| {
        x.run(
            "INSERT INTO invites (id, workspace_id, email, role, app_id, app_role, hash, invited_by, created_at, expires_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
            params![id, c.workspace.id, email, role, app.as_ref().map(|a| a.id.clone()), app_role, sha256_hex(&token), c.actor, now(), now() + limits::INVITE_TTL_MS],
        )?;
        event(x, &c.workspace.id, &c.actor, app.as_ref().map(|a| a.id.as_str()), "invite", &detail)
    })?;
    let link = format!("{}/auth/invite?token={token}", cfg.api_origin);
    let what = match &app {
        Some(a) => format!("the app \"{}\"", a.display_name()),
        None => format!("the {} workspace", c.workspace.name),
    };
    let mail = Email {
        to: email.clone(),
        subject: format!("You're invited to {what}"),
        text: format!(
            "{} invited you to {what} on Brod.\n\nOpen this link to accept. It works once and expires in 7 days:\n{link}\n\nIf you were not expecting this, ignore this email.",
            c.user.email
        ),
    };
    let mut out = Map::new();
    out.insert("invite".into(), json!(id));
    out.insert("email".into(), json!(email));
    out.insert("role".into(), json!(role));
    if let Some(a) = &app {
        out.insert("app".into(), json!(a.slug));
        out.insert("app_role".into(), json!(app_role));
    }
    out.insert("expires_in_days".into(), json!(7));
    if cfg.dev_mode {
        out.insert("dev_link".into(), json!(link));
    }
    Ok((Value::Object(out), Some(mail)))
}

pub fn list_invites(conn: &Connection, c: &Caller) -> Result<Value> {
    require_role(c, "builder", "see invites")?;
    let rows = conn.rows_json(
        "SELECT i.id, i.email, i.role, a.slug AS app, i.app_role, i.invited_by, i.created_at, i.expires_at FROM invites i LEFT JOIN apps a ON a.id = i.app_id
         WHERE i.workspace_id = ? AND i.used_at IS NULL AND i.revoked_at IS NULL AND i.expires_at > ? ORDER BY i.created_at DESC",
        params![c.workspace.id, now()],
    )?;
    Ok(json!({ "pending": rows }))
}

pub fn revoke_invite(conn: &Connection, c: &Caller, id: &str) -> Result<Value> {
    require_role(c, "builder", "revoke invites")?;
    let n = conn.run(
        "UPDATE invites SET revoked_at = ? WHERE id = ? AND workspace_id = ? AND used_at IS NULL AND revoked_at IS NULL",
        params![now(), id, c.workspace.id],
    )?;
    if n == 0 {
        return Err(Problem::new(404, "not_found", "No pending invite with that id."));
    }
    event(conn, &c.workspace.id, &c.actor, None, "invite_revoked", id)?;
    Ok(json!({ "revoked": id }))
}

pub struct Accepted {
    pub user: User,
    /// The app the invite was for, as <app>.<workspace>.
    pub app_ref: Option<String>,
    pub workspace_slug: String,
}

/// Accept an invite. The emailed link proves the address, so it also signs the person in.
pub fn accept_invite(conn: &Connection, token: &str) -> Result<Accepted> {
    let hash = sha256_hex(token);
    let gone = || Problem::new(410, "invite_gone", "This invitation has expired, was already used, or was withdrawn. Ask for a new one.");
    struct Inv {
        id: String,
        workspace_id: String,
        email: String,
        role: String,
        app_id: Option<String>,
        app_role: Option<String>,
        expires_at: i64,
        used_at: Option<i64>,
        revoked_at: Option<i64>,
        wslug: String,
    }
    let inv = conn
        .first("SELECT i.*, w.slug AS wslug FROM invites i JOIN workspaces w ON w.id = i.workspace_id WHERE i.hash = ?", [&hash], |r| {
            Ok(Inv {
                id: r.get("id")?,
                workspace_id: r.get("workspace_id")?,
                email: r.get("email")?,
                role: r.get("role")?,
                app_id: r.get("app_id")?,
                app_role: r.get("app_role")?,
                expires_at: r.get("expires_at")?,
                used_at: r.get("used_at")?,
                revoked_at: r.get("revoked_at")?,
                wslug: r.get("wslug")?,
            })
        })?
        .ok_or_else(gone)?;
    if inv.used_at.is_some() || inv.revoked_at.is_some() || inv.expires_at < now() {
        return Err(gone());
    }
    if conn.run("UPDATE invites SET used_at = ? WHERE id = ? AND used_at IS NULL", params![now(), inv.id])? == 0 {
        return Err(Problem::new(410, "invite_gone", "This invitation was already used."));
    }
    let user = verified_user(conn, &inv.email, "")?;
    tx(conn, |x| {
        // Keep a higher role if they already have one.
        x.run(
            "INSERT INTO members (workspace_id, user_id, role, created_at) VALUES (?,?,?,?) ON CONFLICT(workspace_id, user_id) DO UPDATE SET role =
             CASE WHEN (CASE members.role WHEN 'admin' THEN 3 WHEN 'builder' THEN 2 WHEN 'member' THEN 1 ELSE 0 END) >=
                       (CASE excluded.role WHEN 'admin' THEN 3 WHEN 'builder' THEN 2 WHEN 'member' THEN 1 ELSE 0 END) THEN members.role ELSE excluded.role END",
            params![inv.workspace_id, user.id, inv.role, now()],
        )?;
        event(x, &inv.workspace_id, &user.email, inv.app_id.as_deref(), "invite_accepted", &format!("{} as {}", user.email, inv.role))?;
        if let Some(app_id) = &inv.app_id {
            x.run(
                "INSERT INTO grants (app_id, subject, role, created_at) VALUES (?,?,?,?) ON CONFLICT(app_id, subject) DO UPDATE SET role = excluded.role",
                params![app_id, format!("user:{}", user.id), inv.app_role, now()],
            )?;
            share_with_people(x, app_id)?;
        }
        Ok(())
    })?;
    let app_ref = match &inv.app_id {
        Some(id) => {
            conn.first("SELECT slug FROM apps WHERE id = ?", [id], |r| r.get::<_, String>(0))?.map(|s| format!("{s}.{}", inv.wslug))
        }
        None => None,
    };
    Ok(Accepted { user, app_ref, workspace_slug: inv.wslug })
}

// ---------- groups ----------

pub fn list_groups(conn: &Connection, c: &Caller) -> Result<Vec<Value>> {
    conn.all(
        "SELECT g.id, g.name, (SELECT GROUP_CONCAT(u.email, ', ') FROM group_members gm JOIN users u ON u.id = gm.user_id WHERE gm.group_id = g.id) AS people
         FROM groups g WHERE g.workspace_id = ? ORDER BY g.name",
        [&c.workspace.id],
        |r| {
            let people: Option<String> = r.get(2)?;
            let people: Vec<String> = people.filter(|p| !p.is_empty()).map(|p| p.split(", ").map(String::from).collect()).unwrap_or_default();
            Ok(json!({ "id": r.get::<_, String>(0)?, "name": r.get::<_, String>(1)?, "people": people }))
        },
    )
}

fn group_by_name(conn: &Connection, c: &Caller, name: &str) -> Result<(String, String)> {
    conn.first(
        "SELECT id, name FROM groups WHERE workspace_id = ? AND (id = ? OR name = ?)",
        params![c.workspace.id, name, js_trim(name).to_lowercase()],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?
    .ok_or_else(|| Problem::new(404, "no_group", format!("There is no group \"{name}\". Use list_groups or GET /v1/groups to see them.")))
}

fn valid_group_name(s: &str) -> bool {
    let b = s.as_bytes();
    !b.is_empty()
        && (b[0].is_ascii_lowercase() || b[0].is_ascii_digit())
        && b.iter().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, b' ' | b'_' | b'-'))
}

pub fn create_group(conn: &Connection, c: &Caller, name: &str) -> Result<Value> {
    require_role(c, "admin", "define groups")?;
    let clean = js_slice(&js_trim(name).to_lowercase(), 40);
    if !valid_group_name(&clean) {
        return Err(Problem::new(400, "bad_name", "A group name uses letters, numbers, spaces, - and _, for example \"finance\"."));
    }
    if conn.exists("SELECT 1 FROM groups WHERE workspace_id = ? AND name = ?", params![c.workspace.id, clean])? {
        return Err(Problem::new(409, "exists", format!("There is already a group called \"{clean}\".")));
    }
    let id = random_id("grp_", 8);
    tx(conn, |x| {
        x.run("INSERT INTO groups (id, workspace_id, name, created_at) VALUES (?,?,?,?)", params![id, c.workspace.id, clean, now()])?;
        event(x, &c.workspace.id, &c.actor, None, "group_created", &clean)
    })?;
    Ok(json!({ "id": id, "name": clean, "people": [] }))
}

pub fn delete_group(conn: &Connection, c: &Caller, name: &str) -> Result<Value> {
    require_role(c, "admin", "delete groups")?;
    let (id, gname) = group_by_name(conn, c, name)?;
    tx(conn, |x| {
        x.run("DELETE FROM group_members WHERE group_id = ?", [&id])?;
        x.run("DELETE FROM grants WHERE subject = ?", [format!("group:{id}")])?;
        x.run("DELETE FROM groups WHERE id = ?", [&id])?;
        event(x, &c.workspace.id, &c.actor, None, "group_deleted", &gname)
    })?;
    Ok(json!({ "deleted": gname }))
}

pub fn set_group_member(conn: &Connection, c: &Caller, group: &str, who: &str, add: bool) -> Result<Value> {
    require_role(c, "admin", "change group membership")?;
    let (gid, gname) = group_by_name(conn, c, group)?;
    let p = person_in_workspace(conn, c, who)?;
    tx(conn, |x| {
        if add {
            x.run("INSERT OR IGNORE INTO group_members (group_id, user_id) VALUES (?,?)", params![gid, p.id])?;
        } else {
            x.run("DELETE FROM group_members WHERE group_id = ? AND user_id = ?", params![gid, p.id])?;
        }
        let detail = format!("{} {} {gname}", p.email, if add { "to" } else { "from" });
        event(x, &c.workspace.id, &c.actor, None, if add { "group_add" } else { "group_remove" }, &detail)
    })?;
    // JSON.stringify drops an undefined result, so a group that vanished answers with an empty body.
    Ok(list_groups(conn, c)?.into_iter().find(|g| g["id"] == json!(gid)).unwrap_or(Value::Null))
}

// ---------- app role grants ----------

pub struct Subject {
    pub subject: String,
    pub label: String,
}

/// One grant, as given by a person or agent: exactly one of email, group, domain, or everyone ("workspace" or "signed_in").
pub fn resolve_subject(conn: &Connection, c: &Caller, g: &Map<String, Value>) -> Result<Subject> {
    let s = |k: &str| present(g, k).filter(|v| crate::model::truthy(Some(v))).map(crate::model::js_string);
    if let Some(email) = s("email") {
        let p = person_in_workspace(conn, c, &email)?;
        return Ok(Subject { subject: format!("user:{}", p.id), label: p.email });
    }
    if let Some(group) = s("group") {
        let (id, name) = group_by_name(conn, c, &group)?;
        return Ok(Subject { subject: format!("group:{id}"), label: format!("group {name}") });
    }
    if let Some(domain) = s("domain") {
        let d = js_trim(&domain).to_lowercase();
        let d = d.strip_prefix('@').unwrap_or(&d).to_string();
        if !valid_domain(&d) {
            return Err(Problem::new(400, "bad_domain", "A domain looks like \"example.com\"."));
        }
        return Ok(Subject { subject: format!("domain:{d}"), label: format!("anyone @{d}") });
    }
    match g.get("everyone").and_then(|v| v.as_str()) {
        Some("workspace") => Ok(Subject { subject: "workspace".into(), label: "everyone in the workspace".into() }),
        Some("signed_in") => Ok(Subject { subject: "signed_in".into(), label: "anyone signed in".into() }),
        _ => Err(Problem::new(
            400,
            "bad_grant",
            "Each grant names one of \"email\", \"group\", \"domain\", or \"everyone\" (\"workspace\" or \"signed_in\"), plus a \"role\".",
        )),
    }
}

/// `/^[a-z0-9.-]+\.[a-z]{2,}$/`
fn valid_domain(d: &str) -> bool {
    let Some(dot) = d.rfind('.') else {
        return false;
    };
    let (head, tld) = (&d[..dot], &d[dot + 1..]);
    !head.is_empty()
        && head.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-')
        && tld.len() >= 2
        && tld.bytes().all(|b| b.is_ascii_lowercase())
}

pub fn list_grants(conn: &Connection, app: &AppRow) -> Result<Vec<Value>> {
    conn.all(
        "SELECT g.subject, g.role, u.email, gr.name AS gname FROM grants g
         LEFT JOIN users u ON g.subject = 'user:' || u.id LEFT JOIN groups gr ON g.subject = 'group:' || gr.id
         WHERE g.app_id = ? ORDER BY g.created_at",
        [&app.id],
        |r| {
            let subject: String = r.get(0)?;
            let role: String = r.get(1)?;
            let email: Option<String> = r.get(2)?;
            let gname: Option<String> = r.get(3)?;
            let mut m = Map::new();
            m.insert("role".into(), json!(role));
            match (email.filter(|e| !e.is_empty()), gname.filter(|g| !g.is_empty())) {
                (Some(e), _) => m.insert("email".into(), json!(e)),
                (None, Some(g)) => m.insert("group".into(), json!(g)),
                (None, None) => match subject.strip_prefix("domain:") {
                    Some(d) => m.insert("domain".into(), json!(d)),
                    None => m.insert("everyone".into(), json!(subject)),
                },
            };
            Ok(Value::Object(m))
        },
    )
}

// ---------- the access decision ----------

#[derive(Clone, Debug, PartialEq)]
pub struct Decision {
    pub allowed: bool,
    pub sign_in_needed: bool,
    pub role: Option<String>,
    pub groups: Vec<String>,
    pub member: Option<String>,
}

/// Decide whether a person (or an anonymous visitor) may open an app, and with which app role.
/// The app's owner and workspace admins get the top role. Otherwise the best matching grant wins,
/// and modes that let a person in without a grant give the app's lowest role.
pub fn decide(conn: &Connection, app: &AppRow, user: Option<&User>) -> Result<Decision> {
    let roles = app.role_list();
    let lowest = roles.last().cloned().unwrap_or_default();
    let Some(user) = user else {
        let public = app.access == "public";
        return Ok(Decision { allowed: public, sign_in_needed: !public, role: None, groups: vec![], member: None });
    };
    let member: Option<String> =
        conn.first("SELECT role FROM members WHERE workspace_id = ? AND user_id = ?", params![app.workspace_id, user.id], |r| r.get(0))?;
    let groups: Vec<(String, String)> = conn.all(
        "SELECT g.id, g.name FROM group_members gm JOIN groups g ON g.id = gm.group_id WHERE gm.user_id = ? AND g.workspace_id = ?",
        params![user.id, app.workspace_id],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    let mut grants: Vec<(String, String)> =
        conn.all("SELECT subject, role FROM grants WHERE app_id = ?", [&app.id], |r| Ok((r.get(0)?, r.get(1)?)))?;
    // Everyone in the app's space counts as named on it: their space role when the app has that role, else its lowest.
    if let Some(space) = &app.space_id {
        let role: Option<String> =
            conn.first("SELECT role FROM space_members WHERE space_id = ? AND user_id = ?", params![space, user.id], |r| r.get(0))?;
        if let Some(role) = role {
            grants.push((format!("user:{}", user.id), if roles.contains(&role) { role } else { lowest.clone() }));
        }
    }
    Ok(decide_with(app, &roles, &lowest, user, member, &groups, &grants))
}

/// The pure part of decide(): the same rules over rows already read.
pub fn decide_with(
    app: &AppRow,
    roles: &[String],
    lowest: &str,
    user: &User,
    member: Option<String>,
    groups: &[(String, String)],
    grants: &[(String, String)],
) -> Decision {
    let insider = member.as_deref().is_some_and(|m| m != "guest");
    let domain = user.email.split('@').nth(1).unwrap_or("undefined");
    let mut subjects: Vec<String> = vec![format!("user:{}", user.id), format!("domain:{domain}")];
    subjects.extend(groups.iter().map(|(id, _)| format!("group:{id}")));
    subjects.push("signed_in".into());
    if insider {
        subjects.push("workspace".into());
    }
    let index = |r: &str| roles.iter().position(|x| x == r);
    let matched: Vec<&(String, String)> = grants.iter().filter(|(s, r)| subjects.contains(s) && index(r).is_some()).collect();
    let best_of = |list: &[&(String, String)]| list.iter().filter_map(|(_, r)| index(r)).min().map(|i| roles[i].clone());
    let best = best_of(&matched);
    let names: Vec<String> = groups.iter().map(|(_, n)| n.clone()).collect();
    let yes =
        |role: String| Decision { allowed: true, sign_in_needed: false, role: Some(role), groups: names.clone(), member: member.clone() };
    if app.owner_id == user.id || member.as_deref() == Some("admin") {
        return yes(roles.first().cloned().unwrap_or_default());
    }
    // A grant to everyone in the workspace or everyone signed in only counts when the mode lets those people in.
    let direct: Vec<&(String, String)> = matched.iter().copied().filter(|(s, _)| s != "workspace" && s != "signed_in").collect();
    match app.access.as_str() {
        "people" | "password" => {
            if let Some(r) = best_of(&direct) {
                return yes(r);
            }
        }
        "workspace" => {
            if insider || !direct.is_empty() {
                return yes(if insider { best.unwrap_or_else(|| lowest.to_string()) } else { best_of(&direct).unwrap_or_default() });
            }
        }
        "signed_in" | "public" => return yes(best.unwrap_or_else(|| lowest.to_string())),
        _ => {}
    }
    Decision { allowed: false, sign_in_needed: false, role: None, groups: names, member }
}

/// One sentence that says who can open an app (the share sheet).
pub fn who_can_open(app: &AppRow, grants: &[Value], workspace_name: &str) -> String {
    let named: Vec<String> = grants
        .iter()
        .filter_map(|g| {
            if let Some(e) = g.get("email").and_then(|v| v.as_str()) {
                Some(e.to_string())
            } else if let Some(gr) = g.get("group").and_then(|v| v.as_str()) {
                Some(format!("the {gr} group"))
            } else {
                g.get("domain").and_then(|v| v.as_str()).map(|d| format!("anyone @{d}"))
            }
        })
        .collect();
    let list = if named.len() > 3 { format!("{} and {} more", named[..3].join(", "), named.len() - 3) } else { named.join(", ") };
    match app.access.as_str() {
        "private" => "Only you (the owner) and workspace admins can open it.".into(),
        "people" => {
            if named.is_empty() {
                "Nobody but you and workspace admins yet: add people or groups to share it.".into()
            } else {
                format!("Only {list} can open it, after signing in.")
            }
        }
        "workspace" => format!(
            "Everyone in {workspace_name} can open it after signing in{}.",
            if named.is_empty() { String::new() } else { format!(", plus {list}") }
        ),
        "password" => format!(
            "Anyone with the address and its password can open it, without signing in{}.",
            if named.is_empty() { String::new() } else { format!("; {list} can also sign in") }
        ),
        "signed_in" => "Anyone who signs in with an email address can open it.".into(),
        _ => "Anyone with the address can open it, without signing in.".into(),
    }
}

/// The app at a slug, with no workspace check (the gateway and the sign-in pages).
pub fn app_by_slug(conn: &Connection, slug: &str) -> Result<Option<AppRow>> {
    conn.first("SELECT * FROM apps WHERE slug = ?", [slug], AppRow::from_row)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::test_db;

    const W: &str = "ws_access";
    const PEOPLE: [&str; 7] = ["owner", "admin", "builder", "member", "guest", "outsider", "domainer"];

    fn user(w: &str) -> User {
        User {
            id: format!("usr_{w}"),
            email: if w == "domainer" { "d@partner.test".into() } else { format!("{w}@acme.test") },
            name: w.into(),
            email_verified_at: Some(1),
        }
    }

    fn seed(c: &Connection) -> Result<()> {
        let t = now();
        c.run("INSERT INTO workspaces (id, slug, name, created_at) VALUES (?,?,?,?)", params![W, "acme-access", "Acme", t])?;
        for p in PEOPLE {
            let u = user(p);
            c.run(
                "INSERT INTO users (id, email, name, email_verified_at, created_at) VALUES (?,?,?,?,?)",
                params![u.id, u.email, p, t, t],
            )?;
        }
        for (p, role) in [("owner", "builder"), ("builder", "builder"), ("admin", "admin"), ("member", "member"), ("guest", "guest")] {
            c.run("INSERT INTO members (workspace_id, user_id, role, created_at) VALUES (?,?,?,?)", params![W, user(p).id, role, t])?;
        }
        c.run("INSERT INTO groups (id, workspace_id, name, created_at) VALUES (?,?,?,?)", params!["grp_fin", W, "finance", t])?;
        c.run("INSERT INTO group_members (group_id, user_id) VALUES (?,?)", params!["grp_fin", user("member").id])?;
        Ok(())
    }

    fn app(c: &Connection, n: usize, access: &str, grants: &[(&str, &str)]) -> Result<AppRow> {
        let id = format!("app_{n}");
        c.run(
            "INSERT INTO apps (id, workspace_id, owner_id, slug, name, access, roles, live_version, created_at) VALUES (?,?,?,?,?,?,?,?,?)",
            params![id, W, user("owner").id, format!("access-{n}"), "App", access, "[\"owner\",\"editor\",\"viewer\"]", 1, now()],
        )?;
        for (s, r) in grants {
            c.run("INSERT INTO grants (app_id, subject, role, created_at) VALUES (?,?,?,?)", params![id, s, r, now()])?;
        }
        Ok(app_by_slug(c, &format!("access-{n}"))?.expect("app exists"))
    }

    /// The role each person gets, or "-" when refused, in the order owner, admin, builder, member, guest, outsider, domainer, anonymous.
    fn roles(c: &Connection, a: &AppRow) -> Vec<String> {
        let mut out: Vec<String> = PEOPLE
            .iter()
            .map(|p| {
                let d = decide(c, a, Some(&user(p))).unwrap();
                if d.allowed {
                    d.role.unwrap_or("anon".into())
                } else if d.sign_in_needed {
                    "sign-in".into()
                } else {
                    "-".into()
                }
            })
            .collect();
        let d = decide(c, a, None).unwrap();
        out.push(if d.allowed { "anon".into() } else { "sign-in".into() });
        out
    }

    #[tokio::test]
    async fn the_access_decision_for_every_mode_and_person() {
        let db = test_db();
        db.call(|c| {
            seed(c)?;
            let t = |a: &AppRow| roles(c, a).join(" ");
            // private: only the owner and workspace admins
            assert_eq!(t(&app(c, 1, "private", &[("user:usr_member", "editor")])?), "owner owner - - - - - sign-in");
            // people: only grants count, by person, group or email domain; the best role wins
            let a = app(
                c,
                2,
                "people",
                &[("user:usr_member", "viewer"), ("group:grp_fin", "editor"), ("domain:partner.test", "viewer"), ("workspace", "editor")],
            )?;
            assert_eq!(t(&a), "owner owner - editor - - viewer sign-in");
            // workspace: insiders get the lowest role, guests only with a grant
            assert_eq!(t(&app(c, 3, "workspace", &[])?), "owner owner viewer viewer - - - sign-in");
            assert_eq!(
                t(&app(c, 4, "workspace", &[("user:usr_guest", "editor"), ("workspace", "editor")])?),
                "owner owner editor editor editor - - sign-in"
            );
            // signed_in: anyone who signs in
            assert_eq!(
                t(&app(c, 5, "signed_in", &[("group:grp_fin", "editor")])?),
                "owner owner viewer editor viewer viewer viewer sign-in"
            );
            // public: anyone, without signing in
            assert_eq!(t(&app(c, 6, "public", &[])?), "owner owner viewer viewer viewer viewer viewer anon");
            // password: grants count as for named people; everyone else needs the password (the gateway checks it)
            assert_eq!(
                t(&app(c, 8, "password", &[("group:grp_fin", "editor"), ("workspace", "editor")])?),
                "owner owner - editor - - - sign-in"
            );
            // grants for roles the app no longer declares are ignored
            assert_eq!(t(&app(c, 7, "people", &[("user:usr_member", "superuser")])?), "owner owner - - - - - sign-in");
            Ok(())
        })
        .await
        .unwrap();
    }

    #[test]
    fn says_who_can_open_an_app() {
        let mut a = AppRow {
            id: "a".into(),
            workspace_id: W.into(),
            owner_id: "o".into(),
            slug: "s".into(),
            name: "n".into(),
            title: String::new(),
            welcome: String::new(),
            status: "live".into(),
            access: "private".into(),
            roles: "[]".into(),
            live_version: None,
            created_at: 0,
            secrets_rev: 0,
            space_id: None,
            file_bytes: 0,
            data_bytes: 0,
            password_hash: None,
            taken_down_at: None,
            takedown_reason: String::new(),
            staging_version: None,
        };
        assert!(who_can_open(&a, &[], "Acme").starts_with("Only you"));
        a.access = "people".into();
        assert_eq!(
            who_can_open(&a, &[json!({ "group": "finance" }), json!({ "email": "x@y.z" })], "Acme"),
            "Only the finance group, x@y.z can open it, after signing in."
        );
        a.access = "workspace".into();
        assert_eq!(who_can_open(&a, &[], "Acme"), "Everyone in Acme can open it after signing in.");
        a.access = "public".into();
        assert!(who_can_open(&a, &[], "Acme").contains("without signing in"));
        a.access = "password".into();
        assert_eq!(who_can_open(&a, &[], "Acme"), "Anyone with the address and its password can open it, without signing in.");
        assert_eq!(
            who_can_open(&a, &[json!({ "group": "finance" })], "Acme"),
            "Anyone with the address and its password can open it, without signing in; the finance group can also sign in."
        );
    }
}
