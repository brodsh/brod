// The workspace admin page at /w/<workspace>/admin, for builders and admins: apps (deploy from a zip, versions,
// access, secrets, pause, delete), the marketplace (install, updates, listings), people and invites, groups, a link to
// the agent connections page, and the activity log.
// The page is one static document; everything it does goes through the /v1 API with the session cookie, so the
// API's own role checks decide what each person may change.
use axum::response::Response;
use serde_json::json;

use crate::control;
use crate::http::{Req, notice, redirect, response};
use crate::people;
use crate::problem::Result;
use crate::state::State;
use crate::util::{encode_uri_component, esc, is_hex_color};

const PAGE: &str = include_str!("admin.html");

pub async fn page(st: &State, req: &Req, slug: String) -> Result<Response> {
    let cfg = st.cfg.clone();
    let cookie = req.header("cookie").map(String::from);
    let s2 = slug.clone();
    let found = st
        .db
        .call(move |c| {
            let Some((user, _)) = control::person(c, &cfg, cookie.as_deref())? else { return Ok(None) };
            Ok(Some((people::membership(c, &user, Some(&s2))?, user)))
        })
        .await?;
    let Some((membership, user)) = found else {
        return Ok(redirect(&format!("/auth/signin?return={}", encode_uri_component(&format!("/w/{slug}/admin"))), &[]));
    };
    let Some((w, role)) = membership else {
        return Ok(notice(404, "Not your workspace", "You are not in this workspace. Ask an admin to invite you.", ""));
    };
    if role != "admin" && role != "builder" {
        return Ok(notice(
            403,
            "Builders and admins only",
            "This page is for the people who build and run the workspace's apps. Ask an admin to make you a builder.",
            &format!("<p><a href=\"/w/{}\">Back to {}</a></p>", esc(&w.slug), esc(&w.name)),
        ));
    }
    // Inside <script type="application/json">, so "<" is escaped to keep "</script>" out of the data.
    let boot = json!({
        "workspace": w.slug, "name": w.name, "icon": w.icon, "role": role, "email": user.email,
    })
    .to_string()
    .replace('<', "\\u003c");
    let accent = if is_hex_color(&w.color) { w.color.as_str() } else { "#1f6f4a" };
    let html = PAGE.replace("{{TITLE}}", &esc(&format!("Brod – {}", w.name))).replace("{{ACCENT}}", accent).replace("{{BOOT}}", &boot);
    Ok(response(
        200,
        html,
        &[
            ("content-type", "text/html; charset=utf-8".into()),
            ("cache-control", "no-store".into()),
            ("x-robots-tag", "noindex".into()),
            ("x-frame-options", "DENY".into()),
            ("referrer-policy", "same-origin".into()),
        ],
    ))
}
