// SPDX-License-Identifier: AGPL-3.0-only
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
const OPERATOR_PAGE: &str = include_str!("operator.html");

/// The page's source. In a debug build with BROD_DEV_ASSETS set to the folder holding admin.html (server/src), it is
/// read from disk on every request, so a change to the page needs only a browser reload. Release builds ignore it.
fn source() -> std::borrow::Cow<'static, str> {
    asset("admin.html", PAGE)
}

fn asset(name: &str, built_in: &'static str) -> std::borrow::Cow<'static, str> {
    #[cfg(debug_assertions)]
    if let Some(page) =
        std::env::var("BROD_DEV_ASSETS").ok().and_then(|dir| std::fs::read_to_string(std::path::Path::new(&dir).join(name)).ok())
    {
        return page.into();
    }
    let _ = name;
    built_in.into()
}

const PAGE_HEADERS: [(&str, &str); 5] = [
    ("content-type", "text/html; charset=utf-8"),
    ("cache-control", "no-store"),
    ("x-robots-tag", "noindex"),
    ("x-frame-options", "DENY"),
    ("referrer-policy", "same-origin"),
];

/// The operator console at /admin on the API host (docs/plans/admin-mode.md 1.6). It shares the workspace admin
/// page's head and styles, and talks only to /v1/admin, which checks on every call that the person is an operator.
pub async fn operator_page(st: &State, req: &Req) -> Result<Response> {
    let cfg = st.cfg.clone();
    let cookie = req.header("cookie").map(String::from);
    let found = st
        .db
        .call(move |c| {
            let Some((user, _)) = control::person(c, &cfg, cookie.as_deref())? else { return Ok(None) };
            let _ = crate::operator::bootstrap(c, &cfg)?;
            Ok(Some((crate::operator::is_operator(c, &user.id)?, user)))
        })
        .await?;
    let Some((is_operator, user)) = found else {
        return Ok(redirect(&format!("/auth/signin?return={}", encode_uri_component("/admin")), &[]));
    };
    if !is_operator {
        return Ok(notice(403, "Operators only", "This page is for the people who run this Brod server.", "<p><a href=\"/\">Home</a></p>"));
    }
    let boot = json!({ "email": user.email, "hosted": st.cfg.mode == crate::config::Mode::Hosted }).to_string().replace('<', "\\u003c");
    let page = source();
    let head = page.split("<script type=\"application/json\" id=\"boot\">").next().unwrap_or_default();
    let html = format!("{head}{}", asset("operator.html", OPERATOR_PAGE))
        .replace("{{TITLE}}", "Brod – admin")
        .replace("{{ACCENT}}", "#1f6f4a")
        .replace("{{BOOT}}", &boot);
    Ok(response(200, html, &PAGE_HEADERS.map(|(k, v)| (k, v.to_string()))))
}

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
        "hosted": st.cfg.mode == crate::config::Mode::Hosted, "marketplace": st.settings.last().flag("features.marketplace"),
    })
    .to_string()
    .replace('<', "\\u003c");
    let accent = if is_hex_color(&w.color) { w.color.as_str() } else { "#1f6f4a" };
    let html = source().replace("{{TITLE}}", &esc(&format!("Brod – {}", w.name))).replace("{{ACCENT}}", accent).replace("{{BOOT}}", &boot);
    Ok(response(200, html, &PAGE_HEADERS.map(|(k, v)| (k, v.to_string()))))
}
