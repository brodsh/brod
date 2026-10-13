// Spaces: a named set of apps and the people who use them, inside a workspace. Adding someone to a space gives them
// every app in it (people::decide counts them as named on the app), so a team gets its tools in one step.
// Admins manage spaces and their people; builders put apps in a space.
use crate::db::{Connection, params};
use serde_json::{Value, json};

use crate::db::{Sql, event, tx};
use crate::model::Caller;
use crate::people::{person_in_workspace, require_role};
use crate::problem::{Problem, Result};
use crate::util::{js_slice, js_trim, now, random_id};

fn valid_role(r: &str) -> bool {
    !r.is_empty() && r.len() <= 30 && r.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
}

fn clean_name(name: &str) -> Result<String> {
    let clean = js_slice(js_trim(name), 40);
    if clean.is_empty() {
        return Err(Problem::new(400, "need_name", "Give the space a name, for example \"Front desk\"."));
    }
    Ok(clean)
}

/// A space by its name or id, in the caller's workspace.
pub fn space_by_name(conn: &Connection, c: &Caller, name: &str) -> Result<(String, String)> {
    conn.first(
        "SELECT id, name FROM spaces WHERE workspace_id = ? AND (id = ? OR name = ? COLLATE NOCASE)",
        params![c.workspace.id, name, js_trim(name)],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?
    .ok_or_else(|| Problem::new(404, "no_space", format!("There is no space called \"{name}\". Create it first.")))
}

pub fn list_spaces(conn: &Connection, c: &Caller) -> Result<Value> {
    let spaces: Vec<(String, String, String)> =
        conn.all("SELECT id, name, note FROM spaces WHERE workspace_id = ? ORDER BY name COLLATE NOCASE", [&c.workspace.id], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?))
        })?;
    let mut out = Vec::new();
    for (id, name, note) in spaces {
        let apps = conn.all("SELECT slug, name FROM apps WHERE space_id = ? ORDER BY name", [&id], |r| {
            Ok(json!({ "app": r.get::<_, String>(0)?, "name": r.get::<_, String>(1)? }))
        })?;
        let people = conn.all(
            "SELECT u.email, u.name, s.role FROM space_members s JOIN users u ON u.id = s.user_id WHERE s.space_id = ? ORDER BY u.email",
            [&id],
            |r| Ok(json!({ "email": r.get::<_, String>(0)?, "name": r.get::<_, String>(1)?, "role": r.get::<_, String>(2)? })),
        )?;
        out.push(json!({ "id": id, "name": name, "note": note, "apps": apps, "people": people }));
    }
    Ok(json!({ "spaces": out }))
}

pub fn create_space(conn: &Connection, c: &Caller, name: &str, note: &str) -> Result<Value> {
    require_role(c, "admin", "create spaces")?;
    let clean = clean_name(name)?;
    if conn.exists("SELECT 1 FROM spaces WHERE workspace_id = ? AND name = ? COLLATE NOCASE", params![c.workspace.id, clean])? {
        return Err(Problem::new(409, "exists", format!("There is already a space called \"{clean}\".")));
    }
    let id = random_id("spc_", 8);
    let note = js_slice(js_trim(note), 120);
    tx(conn, |x| {
        x.run(
            "INSERT INTO spaces (id, workspace_id, name, note, created_at) VALUES (?,?,?,?,?)",
            params![id, c.workspace.id, clean, note, now()],
        )?;
        event(x, &c.workspace.id, &c.actor, None, "space_created", &clean)
    })?;
    Ok(json!({ "id": id, "name": clean, "note": note, "apps": [], "people": [] }))
}

pub fn delete_space(conn: &Connection, c: &Caller, name: &str) -> Result<Value> {
    require_role(c, "admin", "delete spaces")?;
    let (id, sname) = space_by_name(conn, c, name)?;
    tx(conn, |x| {
        x.run("UPDATE apps SET space_id = NULL WHERE space_id = ?", [&id])?;
        x.run("DELETE FROM space_members WHERE space_id = ?", [&id])?;
        x.run("DELETE FROM spaces WHERE id = ?", [&id])?;
        event(x, &c.workspace.id, &c.actor, None, "space_deleted", &sname)
    })?;
    Ok(json!({ "deleted": sname }))
}

/// Add someone to a space (or change their role in it), or take them out with `role` None.
pub fn set_space_member(conn: &Connection, c: &Caller, space: &str, who: &str, role: Option<&str>) -> Result<Value> {
    require_role(c, "admin", "change who is in a space")?;
    let (id, sname) = space_by_name(conn, c, space)?;
    let p = person_in_workspace(conn, c, who)?;
    tx(conn, |x| match role {
        Some(role) => {
            let role = js_trim(role).to_lowercase();
            let role = if role.is_empty() { "viewer".to_string() } else { role };
            if !valid_role(&role) {
                return Err(Problem::new(400, "bad_role", "A space role is one word, for example \"editor\" or \"viewer\"."));
            }
            x.run(
                "INSERT INTO space_members (space_id, user_id, role, created_at) VALUES (?,?,?,?)
                 ON CONFLICT (space_id, user_id) DO UPDATE SET role = excluded.role",
                params![id, p.id, role, now()],
            )?;
            event(x, &c.workspace.id, &c.actor, None, "space_add", &format!("{} to {sname} as {role}", p.email))
        }
        None => {
            x.run("DELETE FROM space_members WHERE space_id = ? AND user_id = ?", params![id, p.id])?;
            event(x, &c.workspace.id, &c.actor, None, "space_remove", &format!("{} from {sname}", p.email))
        }
    })?;
    Ok(json!({ "space": sname, "email": p.email, "role": role }))
}

/// Put an app in a space, or take it out with an empty name.
pub fn set_app_space(conn: &Connection, c: &Caller, slug: &str, space: &str) -> Result<Value> {
    require_role(c, "builder", "move apps between spaces")?;
    let app = crate::control::get_app(conn, c, slug)?;
    let target = if js_trim(space).is_empty() { None } else { Some(space_by_name(conn, c, space)?) };
    tx(conn, |x| {
        x.run("UPDATE apps SET space_id = ? WHERE id = ?", params![target.as_ref().map(|t| &t.0), app.id])?;
        let detail = match &target {
            Some((_, n)) => format!("{} moved to {n}", app.slug),
            None => format!("{} taken out of its space", app.slug),
        };
        event(x, &c.workspace.id, &c.actor, Some(&app.id), "space_app", &detail)
    })?;
    Ok(json!({ "app": app.slug, "space": target.map(|t| t.1) }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::test_db;
    use crate::model::{AppRow, User, Workspace};

    fn caller(id: &str, role: &str) -> Caller {
        let user = User { id: format!("usr_{id}"), email: format!("{id}@sp.test"), name: id.into(), email_verified_at: Some(1) };
        let workspace = Workspace {
            id: "ws_sp".into(),
            slug: "sp".into(),
            name: "Sp".into(),
            plan: "free".into(),
            color: String::new(),
            icon: String::new(),
            created_at: 0,
        };
        Caller { workspace, actor: user.email.clone(), user, role: role.into(), agent: false, read_only: false }
    }

    #[tokio::test]
    async fn a_space_gives_its_people_its_apps() {
        let db = test_db();
        let r = db
            .call(|c| {
                let t = now();
                c.run("INSERT INTO workspaces (id, slug, name, created_at) VALUES ('ws_sp','sp','Sp',?)", [t])?;
                for (u, role) in [("boss", "admin"), ("ana", "member"), ("bo", "member")] {
                    c.run(
                        "INSERT INTO users (id, email, name, email_verified_at, created_at) VALUES (?,?,?,?,?)",
                        params![format!("usr_{u}"), format!("{u}@sp.test"), u, t, t],
                    )?;
                    c.run("INSERT INTO members (workspace_id, user_id, role, created_at) VALUES ('ws_sp',?,?,?)", params![format!("usr_{u}"), role, t])?;
                }
                c.run(
                    "INSERT INTO apps (id, workspace_id, owner_id, slug, name, access, created_at) VALUES ('app_sp','ws_sp','usr_boss','desk','Desk','people',?)",
                    [t],
                )?;
                let (boss, ana) = (caller("boss", "admin"), caller("ana", "member"));
                assert_eq!(create_space(c, &ana, "Front desk", "").unwrap_err().status, 403);
                create_space(c, &boss, "Front desk", "Tools for the desk")?;
                assert_eq!(create_space(c, &boss, "front DESK", "").unwrap_err().code, "exists");
                set_app_space(c, &boss, "desk", "front desk")?;
                set_space_member(c, &boss, "Front desk", "ana@sp.test", Some("editor"))?;
                set_space_member(c, &boss, "Front desk", "bo@sp.test", Some("helper"))?;
                let app = c.first("SELECT * FROM apps WHERE id = 'app_sp'", (), AppRow::from_row)?.unwrap();
                let who = |u: &str| User { id: format!("usr_{u}"), email: format!("{u}@sp.test"), name: u.into(), email_verified_at: Some(1) };
                let ana_d = crate::people::decide(c, &app, Some(&who("ana")))?;
                let bo_d = crate::people::decide(c, &app, Some(&who("bo")))?;
                // An unknown space role falls back to the app's lowest role.
                assert_eq!((ana_d.allowed, ana_d.role.as_deref(), bo_d.role.as_deref()), (true, Some("editor"), Some("viewer")));
                set_space_member(c, &boss, "Front desk", "bo@sp.test", None)?;
                assert!(!crate::people::decide(c, &app, Some(&who("bo")))?.allowed);
                // A private app stays private, space or not.
                c.run("UPDATE apps SET access = 'private' WHERE id = 'app_sp'", ())?;
                let app = c.first("SELECT * FROM apps WHERE id = 'app_sp'", (), AppRow::from_row)?.unwrap();
                assert!(!crate::people::decide(c, &app, Some(&who("ana")))?.allowed);
                let listed = list_spaces(c, &boss)?;
                delete_space(c, &boss, "Front desk")?;
                let gone: Option<String> = c.first("SELECT space_id FROM apps WHERE id = 'app_sp'", (), |r| r.get(0))?.flatten();
                Ok((listed, gone))
            })
            .await
            .unwrap();
        assert_eq!(r.0["spaces"][0]["apps"][0]["app"], "desk");
        assert_eq!(r.0["spaces"][0]["people"].as_array().unwrap().len(), 1);
        assert_eq!(r.1, None);
    }
}
