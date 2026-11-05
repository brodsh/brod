// SPDX-License-Identifier: AGPL-3.0-only
// The REST control-plane API under /v1/: agents with a token, the dashboard with a session.
use axum::http::Method;
use axum::response::Response;
use serde_json::{Map, Value, json};

use crate::control::{self, Credentials, DeployTarget, body_str, is_true};
use crate::http::{Req, json, json_response};
use crate::model::{Caller, js_to_number};
use crate::people;
use crate::problem::{Problem, Result};
use crate::state::State;
use crate::tar::{self, BUNDLE_BYTES};
use crate::util::decode_uri_component;

fn created(v: Value) -> Response {
    json_response(&v, 201, &[])
}

/// Unpack an uploaded archive and deploy it with the upload address's caller. A refused deploy leaves the address usable.
async fn deploy_upload(st: &State, id: String, archive: Vec<u8>) -> Result<Response> {
    // A git bundle is an import (git_import.rs): the address's app and note apply, and it lands on staging.
    if archive.starts_with(b"# v2 git bundle\n") || archive.starts_with(b"# v3 git bundle\n") {
        let id2 = id.clone();
        let (caller, target) = st.db.call(move |c| control::claim_upload(c, &id2)).await?;
        let run = async {
            let Some(app) = target.app_slug().map(String::from) else {
                return Err(Problem::new(
                    400,
                    "need_app",
                    "A git bundle is imported into an existing app: create the address with \"app\".",
                ));
            };
            let mut o = target.options.clone().unwrap_or_default();
            o.insert("target".into(), json!(target.environment.clone().unwrap_or_else(|| "staging".into())));
            if let Some(b) = &target.base_version {
                o.insert("base_version".into(), b.clone());
            }
            if let Some(n) = &target.note {
                o.insert("note".into(), json!(n));
            }
            let req = crate::git_import::ImportRequest::from_json(&app, &o, crate::git_import::Source::Bundle(archive))?;
            crate::git_import::run(st, &caller, req).await
        };
        return match run.await {
            Ok(v) => Ok(created(v)),
            Err(e) => {
                st.db.call(move |c| control::release_upload(c, &id)).await?;
                Err(e)
            }
        };
    }
    // A tar with a Dockerfile at its top is a container app's source (deployments.rs); it may be up to 200 MB.
    let (archive, container) = tokio::task::spawn_blocking(move || {
        let container = crate::containers::survey(&archive).ok().flatten().is_some_and(|s| s.dockerfile);
        (archive, container)
    })
    .await
    .map_err(Problem::internal)?;
    if !container && archive.len() > BUNDLE_BYTES {
        return Err(Problem::new(
            413,
            "too_large",
            "The bundle is larger than 25 MB (200 MB for a container app's source with a Dockerfile).",
        ));
    }
    let id2 = id.clone();
    let (caller, target) = st.db.call(move |c| control::claim_upload(c, &id2)).await?;
    let result = if container {
        crate::deployments::deploy(st, &caller, target, archive).await
    } else {
        match tokio::task::spawn_blocking(move || tar::unpack(&archive)).await.map_err(Problem::internal)? {
            Ok(files) => control::deploy(st, &caller, target, files).await,
            Err(e) => Err(e),
        }
    };
    match result {
        Ok(v) => Ok(created(v)),
        Err(e) => {
            st.db.call(move |c| control::release_upload(c, &id)).await?;
            Err(e)
        }
    }
}

/// One piece of API work over a database connection, run on the blocking pool.
type Job = Box<dyn FnOnce(&crate::db::Connection, &crate::config::Config, &Caller) -> Result<Value> + Send>;

pub async fn serve(st: &State, mut req: Req) -> Result<Response> {
    let p = req.path.trim_end_matches('/').to_string();
    let m = req.method.clone();
    let seg: Vec<String> = p
        .split('/')
        .skip(2)
        .map(|s| decode_uri_component(s).ok_or_else(|| Problem::internal(format!("URIError: malformed {s}"))))
        .collect::<Result<_>>()?;
    let s = |i: usize| seg.get(i).map(String::as_str).filter(|x| !x.is_empty());
    let cfg = st.cfg.clone();

    // A one-time upload address is its own credential, so it is checked before sign-in.
    if s(0) == Some("uploads") && s(1).is_some() && s(2).is_none() && m == Method::PUT {
        let declared: u64 = req.header("content-length").and_then(|v| v.trim().parse().ok()).unwrap_or(0);
        let cap = if st.cfg.containers == crate::config::Containers::Off { BUNDLE_BYTES } else { crate::containers::ARCHIVE_BYTES };
        if declared > cap as u64 {
            return Err(Problem::new(413, "too_large", format!("The bundle is larger than {} MB.", cap / 1024 / 1024)));
        }
        let archive = req.bytes(cap, "The bundle").await?;
        return deploy_upload(st, seg[1].clone(), archive).await;
    }

    // A download address, like an upload address, is its own credential.
    if s(0) == Some("downloads") && s(1).is_some() && s(2).is_none() && m == Method::GET {
        let (name, body, kind) = control::download(st, &seg[1]).await?;
        return Ok(crate::http::response(
            200,
            body,
            &[
                ("content-type", kind.into()),
                ("content-disposition", format!("attachment; filename=\"{name}\"")),
                ("cache-control", "no-store".into()),
            ],
        ));
    }

    // A push on a mirrored remote (git_mirror.rs): the signature is the credential.
    if s(0) == Some("apps") && s(1).is_some() && s(2) == Some("git-webhook") && s(3).is_none() && m == Method::POST {
        return crate::git_mirror::webhook(st, &mut req, &seg[1]).await;
    }

    // Read-only git over HTTP (git_export.rs): git clients sign in with HTTP Basic, so it is answered before sign-in.
    if s(0) == Some("apps") && s(1).and_then(crate::git_export::git_slug).is_some() {
        let slug = crate::git_export::git_slug(&seg[1]).unwrap_or_default().to_string();
        let rest: Vec<&str> = seg[2..].iter().map(String::as_str).collect();
        return crate::git_export::smart_http(st, &mut req, &slug, &rest).await;
    }

    // The operator's API for nodes (nodes.rs), then the report queue, takedowns, suspensions (abuse.rs).
    if s(0) == Some("admin") && s(1) == Some("nodes") {
        return crate::nodes::admin(st, &mut req, &seg).await;
    }
    if s(0) == Some("admin") && s(1) == Some("backups") {
        return crate::backups::admin(st, &mut req, &seg).await;
    }
    if s(0) == Some("admin") && crate::console::handles(&seg) {
        return crate::console::serve(st, &mut req, &seg).await;
    }
    if s(0) == Some("admin") {
        return crate::abuse::serve(st, &mut req, &seg).await;
    }

    // Routes for a signed-in person before they pick a workspace.
    if (s(0) == Some("me") && m == Method::GET) || (s(0) == Some("workspaces") && m == Method::POST) {
        let cr = Credentials::of(&req);
        let cookie = cr.cookie.clone();
        let cfg2 = cfg.clone();
        let who = st.db.call(move |c| control::person(c, &cfg2, cookie.as_deref())).await?;
        let Some((user, _)) = who else {
            return Err(Problem::new(401, "unauthorized", "Sign in first."));
        };
        control::check_origin(&cfg, &cr.method, cr.origin.as_deref())?;
        if s(0) == Some("me") {
            let u = user.clone();
            let ws = st.db.call(move |c| people::my_workspaces(c, &cfg, &u)).await?;
            let id = user.id.clone();
            let operator = st.db.call(move |c| crate::operator::is_operator(c, &id)).await?;
            return Ok(json(json!({ "user": user, "workspaces": ws, "operator": operator })));
        }
        let b = req.json_object().await?;
        let (name, accept) = (body_str(&b, "name"), is_true(&b, "accept_terms"));
        return Ok(created(st.db.call(move |c| people::create_workspace(c, &cfg, &user, &name, accept)).await?));
    }

    let c = control::authenticate_async(st, Credentials::of(&req)).await?;
    st.calls.check(&c, crate::instance::current(st).await.int("rate.calls_per_minute"))?;
    if m != Method::GET && m != Method::HEAD {
        control::require_write(&c, "make changes")?;
    }
    let one = |seg: Option<&str>| seg.map(String::from).unwrap_or_default();
    let db = |f: Job| {
        let (c, cfg) = (c.clone(), cfg.clone());
        async move { st.db.call(move |conn| f(conn, &cfg, &c)).await }
    };
    match s(0) {
        Some("workspace") => {
            if m == Method::GET {
                return Ok(json(db(Box::new(people::describe_workspace)).await?));
            }
            if m == Method::PATCH {
                let b = req.json_object().await?;
                return Ok(json(db(Box::new(move |conn, _, c| people::update_workspace(conn, c, &b))).await?));
            }
        }
        Some("people") => {
            if m == Method::GET && s(1).is_none() {
                return Ok(json(db(Box::new(|conn, _, c| people::list_people(conn, c))).await?));
            }
            if m == Method::PATCH && s(1).is_some() {
                let (who, role) = (one(s(1)), body_str(&req.json_object().await?, "role"));
                return Ok(json(db(Box::new(move |conn, cfg, c| people::set_person_role(conn, cfg, c, &who, &role))).await?));
            }
            if m == Method::DELETE && s(1).is_some() {
                let who = one(s(1));
                return Ok(json(db(Box::new(move |conn, _, c| people::remove_person(conn, c, &who))).await?));
            }
        }
        Some("invites") => {
            if m == Method::GET && s(1).is_none() {
                return Ok(json(db(Box::new(|conn, _, c| people::list_invites(conn, c))).await?));
            }
            if m == Method::POST && s(1).is_none() {
                let b = req.json_object().await?;
                return Ok(created(control::invite_from(st, &c, b).await?));
            }
            if m == Method::DELETE && s(1).is_some() {
                let id = one(s(1));
                return Ok(json(db(Box::new(move |conn, _, c| people::revoke_invite(conn, c, &id))).await?));
            }
        }
        Some("groups") => {
            if m == Method::GET && s(1).is_none() {
                return Ok(json(db(Box::new(|conn, _, c| people::list_groups(conn, c).map(|g| json!({ "groups": g })))).await?));
            }
            if m == Method::POST && s(1).is_none() {
                let name = body_str(&req.json_object().await?, "name");
                return Ok(created(db(Box::new(move |conn, _, c| people::create_group(conn, c, &name))).await?));
            }
            if m == Method::DELETE && s(1).is_some() && s(2).is_none() {
                let name = one(s(1));
                return Ok(json(db(Box::new(move |conn, _, c| people::delete_group(conn, c, &name))).await?));
            }
            if s(1).is_some() && s(2) == Some("members") {
                if m == Method::POST && s(3).is_none() {
                    let (g, email) = (one(s(1)), body_str(&req.json_object().await?, "email"));
                    return Ok(json(db(Box::new(move |conn, _, c| people::set_group_member(conn, c, &g, &email, true))).await?));
                }
                if m == Method::DELETE && s(3).is_some() {
                    let (g, who) = (one(s(1)), one(s(3)));
                    return Ok(json(db(Box::new(move |conn, _, c| people::set_group_member(conn, c, &g, &who, false))).await?));
                }
            }
        }
        Some("tokens") => {
            if m == Method::GET && s(1).is_none() {
                return Ok(json(db(Box::new(|conn, _, c| control::list_tokens(conn, c).map(|t| json!({ "connections": t })))).await?));
            }
            if m == Method::POST && s(1).is_none() {
                let b = req.json_object().await?;
                let name = body_str(&b, "name");
                let (scope, expires_at) = (control::token_scope(b.get("scope"))?, control::token_expiry(b.get("expires_in_days"))?);
                // "app": a token for that app's MCP endpoint only (app_mcp.rs), its staging one with "staging": true.
                if let Some(app) = b.get("app").filter(|v| !v.is_null()).map(crate::model::js_string) {
                    let staging = crate::model::truthy(b.get("staging"));
                    return Ok(created(
                        db(Box::new(move |conn, cfg, c| crate::app_mcp::create_pat(conn, cfg, c, &app, staging, &name, expires_at)))
                            .await?,
                    ));
                }
                return Ok(created(db(Box::new(move |conn, _, c| control::create_token(conn, c, &name, &scope, expires_at))).await?));
            }
            if m == Method::DELETE && s(1).is_some() {
                let id = one(s(1));
                return Ok(json(
                    db(Box::new(move |conn, _, c| control::revoke_token(conn, c, &id).map(|_| json!({ "revoked": id })))).await?,
                ));
            }
        }
        Some("events") => {
            if m == Method::GET {
                let (app, action) = (req.param("app"), req.param("action"));
                let limit = Some(req.param("limit").map(|l| js_to_number(Some(&Value::String(l))).unwrap_or(f64::NAN)).unwrap_or(0.0));
                return Ok(json(
                    db(Box::new(move |conn, _, c| control::list_events(conn, c, app.as_deref(), action.as_deref(), limit))).await?,
                ));
            }
        }
        Some("domains") => {
            if m == Method::GET && s(1).is_none() {
                return Ok(json(db(Box::new(crate::domains::list_domains)).await?));
            }
            if m == Method::POST && s(1).is_none() {
                let b = req.json_object().await?;
                let domain = match b.get("domain") {
                    None | Some(Value::Null) => String::new(),
                    Some(v) => crate::model::js_string(v),
                };
                let app = match b.get("app") {
                    Some(Value::String(a)) => Some(a.clone()),
                    _ => None,
                };
                return Ok(created(crate::domains::add_domain(st, &c, &domain, app).await?));
            }
            if m == Method::POST && s(1).is_some() && s(2) == Some("verify") {
                return Ok(json(crate::domains::verify_domain(st, &c, &seg[1]).await?));
            }
            if m == Method::DELETE && s(1).is_some() && s(2).is_none() {
                return Ok(json(crate::domains::remove_domain(st, &c, &seg[1]).await?));
            }
        }
        // Plans and payment exist only on a hosted server (BROD_MODE=hosted).
        Some("billing") if st.cfg.mode == crate::config::Mode::Hosted => {
            if m == Method::GET && s(1).is_none() {
                return Ok(json(crate::billing::summary(st, &c).await?));
            }
            if m == Method::POST && s(1) == Some("checkout") {
                let want = body_str(&req.json_object().await?, "plan");
                return Ok(json(crate::billing::change_plan(st, &c, &want).await?));
            }
            if m == Method::POST && s(1) == Some("portal") {
                return Ok(json(crate::billing::portal(st, &c).await?));
            }
        }
        Some("spaces") => {
            if m == Method::GET && s(1).is_none() {
                return Ok(json(db(Box::new(|conn, _, c| crate::spaces::list_spaces(conn, c))).await?));
            }
            if m == Method::POST && s(1).is_none() {
                let b = req.json_object().await?;
                let (name, note) = (body_str(&b, "name"), body_str(&b, "note"));
                return Ok(created(db(Box::new(move |conn, _, c| crate::spaces::create_space(conn, c, &name, &note))).await?));
            }
            if m == Method::DELETE && s(1).is_some() && s(2).is_none() {
                let name = one(s(1));
                return Ok(json(db(Box::new(move |conn, _, c| crate::spaces::delete_space(conn, c, &name))).await?));
            }
            if s(1).is_some() && s(2) == Some("members") {
                if m == Method::POST && s(3).is_none() {
                    let b = req.json_object().await?;
                    let (sp, email, role) = (one(s(1)), body_str(&b, "email"), body_str(&b, "role"));
                    return Ok(json(
                        db(Box::new(move |conn, _, c| crate::spaces::set_space_member(conn, c, &sp, &email, Some(&role)))).await?,
                    ));
                }
                if m == Method::DELETE && s(3).is_some() {
                    let (sp, who) = (one(s(1)), one(s(3)));
                    return Ok(json(db(Box::new(move |conn, _, c| crate::spaces::set_space_member(conn, c, &sp, &who, None))).await?));
                }
            }
        }
        Some("marketplace") if st.settings.last().flag("features.marketplace") => {
            if m == Method::GET && s(1).is_none() {
                let search = req.param("search").filter(|x| !x.is_empty());
                let mut v = db(Box::new(move |conn, _, c| crate::market::browse(conn, c, search.as_deref()))).await?;
                // Whether Brod refuses undeclared outside requests ("enforce") or only records them ("log").
                v["network_policy"] = json!(st.cfg.network.name());
                return Ok(json(v));
            }
            if m == Method::GET && s(1).is_some() && s(2).is_none() {
                let key = one(s(1));
                let mut v = db(Box::new(move |conn, _, c| crate::market::get_listing(conn, c, &key))).await?;
                v["network_policy"] = json!(st.cfg.network.name());
                return Ok(json(v));
            }
            if m == Method::GET && s(1).is_some() && s(2) == Some("media") && s(3).is_some() && s(4).is_none() {
                return crate::market::serve_media(st, &c, &one(s(1)), &one(s(3))).await;
            }
            if m == Method::POST && s(1).is_some() && s(2) == Some("install") {
                let (key, b) = (one(s(1)), req.json_object().await?);
                return Ok(created(crate::market::install(st, &c, &key, b).await?));
            }
        }
        Some("listings") if st.settings.last().flag("features.marketplace") => {
            if m == Method::GET && s(1).is_none() {
                let mut v = db(Box::new(|conn, _, c| crate::market::my_listings(conn, c))).await?;
                v["auto_previews"] = json!(st.cfg.preview.is_some());
                v["network_policy"] = json!(st.cfg.network.name());
                return Ok(json(v));
            }
            if m == Method::POST && s(1).is_none() {
                let b = req.json_object().await?;
                return Ok(created(crate::market::create_listing(st, &c, b).await?));
            }
            if m == Method::PATCH && s(1).is_some() && s(2).is_none() {
                let (key, b) = (one(s(1)), req.json_object().await?);
                return Ok(json(db(Box::new(move |conn, _, c| crate::market::update_listing(conn, c, &key, &b))).await?));
            }
            if m == Method::DELETE && s(1).is_some() && s(2).is_none() {
                return Ok(json(crate::market::delete_listing(st, &c, &one(s(1))).await?));
            }
            if m == Method::POST && s(1).is_some() && s(2) == Some("previews") && s(3).is_none() {
                return Ok(json(crate::market::regenerate_previews(st, &c, &one(s(1))).await?));
            }
            if m == Method::POST && s(1).is_some() && s(2) == Some("media") && s(3).is_none() {
                let body = req.bytes(crate::tar::FILE_BYTES, "A preview").await?;
                let caption = req.param("caption");
                return Ok(created(crate::market::add_media(st, &c, &one(s(1)), body, caption).await?));
            }
            if m == Method::DELETE && s(1).is_some() && s(2) == Some("media") && s(3).is_some() {
                return Ok(json(crate::market::delete_media(st, &c, &one(s(1)), &one(s(3))).await?));
            }
            if m == Method::POST && s(1).is_some() && s(2) == Some("releases") {
                let (key, b) = (one(s(1)), req.json_object().await?);
                return Ok(created(crate::market::publish_release(st, &c, &key, b).await?));
            }
        }
        Some("usage") => {
            if m == Method::GET {
                crate::usage::flush(st).await?;
                let days = req.param("days").and_then(|d| d.parse().ok());
                return Ok(json(db(Box::new(move |conn, cfg, c| crate::usage::workspace_usage(conn, cfg, c, days))).await?));
            }
        }
        Some("analytics") => {
            if m == Method::GET {
                crate::usage::flush(st).await?;
                crate::analytics::flush(st).await?;
                let q = crate::analytics::Query::from_params(|k| req.param(k))?;
                return Ok(json(db(Box::new(move |conn, cfg, c| crate::analytics::report(conn, cfg, c, &q))).await?));
            }
        }
        Some("deploys") => {
            if m == Method::POST {
                let b = req.json_object().await?;
                let target = DeployTarget::from_json(&b);
                if let Some(patch) = crate::patch::parse(&b)? {
                    return Ok(created(crate::patch::deploy_patch(st, &c, target, patch).await?));
                }
                return match b.get("files") {
                    None => Ok(created(db(Box::new(move |conn, cfg, c| control::create_upload(conn, cfg, c, &target))).await?)),
                    Some(files) => {
                        let files = crate::mcp::inline_files(
                            files,
                            false,
                            "Files passed inline can total 1 MB. Leave out \"files\" to get an upload address for larger apps.",
                        )?;
                        Ok(created(control::deploy(st, &c, target, files).await?))
                    }
                };
            }
        }
        Some("apps") => {
            let (slug, action) = (s(1).map(String::from), s(2));
            match (&slug, action) {
                (None, _) if m == Method::GET => {
                    return Ok(json(db(Box::new(control::list_apps)).await?));
                }
                (Some(slug), None) => {
                    let slug = slug.clone();
                    if m == Method::GET {
                        return Ok(json(
                            db(Box::new(move |conn, cfg, c| control::get_status(conn, cfg, c, &slug).map(Value::Object))).await?,
                        ));
                    }
                    if m == Method::PATCH {
                        let b = req.json_object().await?;
                        return Ok(json(db(Box::new(move |conn, cfg, c| control::update_app(conn, cfg, c, &slug, &b))).await?));
                    }
                    if m == Method::DELETE {
                        return Ok(json(control::delete_app(st, &c, &slug).await?));
                    }
                }
                (Some(slug), Some(action)) => {
                    let slug = slug.clone();
                    if action == "files" && m == Method::GET {
                        let version = req.param("version").map(|v| json!(v));
                        let since = req.param("since").map(|v| json!(v));
                        return Ok(json(control::get_files(st, &c, &slug, version, since).await?));
                    }
                    if action == "export.bundle" && m == Method::GET {
                        let (name, body) = crate::git_export::export_bundle(st, &c, &slug).await?;
                        return Ok(crate::http::response(
                            200,
                            body,
                            &[
                                ("content-type", "application/x-git-bundle".into()),
                                ("content-disposition", format!("attachment; filename=\"{name}\"")),
                                ("cache-control", "no-store".into()),
                            ],
                        ));
                    }
                    if action == "git-mirror" {
                        if m == Method::GET {
                            return Ok(json(db(Box::new(move |conn, cfg, c| crate::git_mirror::get(conn, cfg, c, &slug))).await?));
                        }
                        if m == Method::PUT {
                            let b = req.json_object().await?;
                            return Ok(json(crate::git_mirror::set(st, &c, &slug, &b).await?));
                        }
                        if m == Method::DELETE {
                            return Ok(json(db(Box::new(move |conn, _, c| crate::git_mirror::remove(conn, c, &slug))).await?));
                        }
                    }
                    if action == "import" && m == Method::POST {
                        return Ok(created(import_request(st, &c, &slug, &mut req).await?));
                    }
                    if action == "diff" && m == Method::GET {
                        let (from, to) = (req.param("from").map(|v| json!(v)), req.param("to").map(|v| json!(v)));
                        return Ok(json(crate::patch::diff_versions(st, &c, &slug, from.as_ref(), to.as_ref()).await?));
                    }
                    if action == "usage" && m == Method::GET {
                        crate::usage::flush(st).await?;
                        let days = req.param("days").and_then(|d| d.parse().ok());
                        return Ok(json(db(Box::new(move |conn, _, c| crate::usage::app_usage(conn, c, &slug, days))).await?));
                    }
                    if action == "versions" && m == Method::DELETE {
                        let Some(n) = s(3).and_then(|v| v.parse::<i64>().ok()) else {
                            return Err(Problem::new(
                                400,
                                "need_version",
                                "Name the version to delete, for example DELETE /v1/apps/notes/versions/3.",
                            ));
                        };
                        return Ok(json(control::delete_version(st, &c, &slug, n).await?));
                    }
                    if action == "marketplace"
                        && st.settings.last().flag("features.marketplace")
                        && m == Method::POST
                        && s(3) == Some("update")
                    {
                        let b = req.json_object().await?;
                        return Ok(json(crate::market::update_install(st, &c, &slug, b).await?));
                    }
                    if action == "marketplace" && st.settings.last().flag("features.marketplace") && m == Method::DELETE && s(3).is_none() {
                        return Ok(json(db(Box::new(move |conn, _, c| crate::market::unlink(conn, c, &slug))).await?));
                    }
                    if action == "settings" && s(3).is_none() && m == Method::GET {
                        return Ok(json(db(Box::new(move |conn, _, c| crate::settings::get(conn, c, &slug))).await?));
                    }
                    if action == "settings" && s(3).is_none() && m == Method::PATCH {
                        let b = req.json_object().await?;
                        return Ok(json(crate::settings::update(st, &c, &slug, b).await?));
                    }
                    if action == "settings" && s(3).is_some() && s(4).is_none() {
                        let key = one(s(3));
                        if m == Method::GET {
                            return crate::settings::serve_image(st, &c, &slug, &key).await;
                        }
                        if m == Method::PUT {
                            let body = req.bytes(crate::settings::IMAGE_BYTES, "An image").await?;
                            return Ok(json(crate::settings::put_image(st, &c, &slug, &key, body).await?));
                        }
                        if m == Method::DELETE {
                            let b = Map::from_iter([(key, Value::Null)]);
                            return Ok(json(crate::settings::update(st, &c, &slug, b).await?));
                        }
                    }
                    if action == "staging" && m == Method::DELETE && s(3).is_none() {
                        return Ok(json(db(Box::new(move |conn, cfg, c| control::discard_staging(conn, cfg, c, &slug))).await?));
                    }
                    if action == "logs" && m == Method::GET {
                        let search = req.param("search").filter(|x| !x.is_empty());
                        return Ok(json(db(Box::new(move |conn, _, c| control::get_logs(conn, c, &slug, search.as_deref()))).await?));
                    }
                    if action == "secrets" && s(3).is_none() && m == Method::GET {
                        return Ok(json(
                            db(Box::new(move |conn, cfg, c| {
                                let st = control::get_status(conn, cfg, c, &slug)?;
                                Ok(json!({ "app": st["app"], "secrets": st["secrets"] }))
                            }))
                            .await?,
                        ));
                    }
                    if action == "secrets" && s(3).is_some() && m == Method::PUT {
                        let (name, value) = (one(s(3)), body_str(&req.json_object().await?, "value"));
                        return Ok(json(
                            db(Box::new(move |conn, cfg, c| control::set_secret(conn, cfg, c, &slug, &name, Some(&value)))).await?,
                        ));
                    }
                    if action == "secrets" && s(3).is_some() && m == Method::DELETE {
                        let name = one(s(3));
                        return Ok(json(db(Box::new(move |conn, cfg, c| control::set_secret(conn, cfg, c, &slug, &name, None))).await?));
                    }
                    if action == "open-paths" && s(3).is_none() && m == Method::GET {
                        return Ok(json(
                            db(Box::new(move |conn, cfg, c| {
                                let app = control::get_app(conn, c, &slug)?;
                                Ok(json!({ "app": app.slug, "open_paths": control::open_paths_of(conn, cfg, &app)? }))
                            }))
                            .await?,
                        ));
                    }
                    if action == "open-paths" && s(3).is_none() && (m == Method::PUT || m == Method::POST) {
                        let list = req.json_object().await?.get("open_paths").cloned().unwrap_or(Value::Null);
                        return Ok(json(db(Box::new(move |conn, cfg, c| control::set_open_paths(conn, cfg, c, &slug, &list))).await?));
                    }
                    if action == "deployments" && m == Method::GET {
                        let id = s(3).map(String::from);
                        return Ok(json(
                            db(Box::new(move |conn, _, c| match id {
                                Some(id) => crate::deployments::get_deployment(conn, c, &slug, Some(&id)),
                                None => {
                                    people::require_role(c, "builder", "see app deployments")?;
                                    let app = control::get_app(conn, c, &slug)?;
                                    Ok(json!({ "deployments": crate::deployments::recent(conn, &app.id)? }))
                                }
                            }))
                            .await?,
                        ));
                    }
                    if action == "access" && m == Method::GET {
                        return Ok(json(
                            db(Box::new(move |conn, _, c| {
                                let app = control::get_app(conn, c, &slug)?;
                                Ok(json!({ "access": app.access, "shared_with": people::list_grants(conn, &app)? }))
                            }))
                            .await?,
                        ));
                    }
                    if m == Method::POST {
                        match action {
                            "rollback" => {
                                let version = js_to_number(req.json_object().await?.get("version"));
                                return Ok(json(crate::deployments::rollback(st, &c, &slug, version).await?));
                            }
                            "access" => {
                                let b: Map<String, Value> = req.json_object().await?;
                                return Ok(json(
                                    db(Box::new(move |conn, cfg, c| control::set_access(conn, cfg, c, &slug, &b, None))).await?,
                                ));
                            }
                            "space" => {
                                let space = body_str(&req.json_object().await?, "space");
                                return Ok(json(
                                    db(Box::new(move |conn, _, c| crate::spaces::set_app_space(conn, c, &slug, &space))).await?,
                                ));
                            }
                            "publish" => {
                                return Ok(json(db(Box::new(move |conn, cfg, c| control::publish_staging(conn, cfg, c, &slug))).await?));
                            }
                            "pause" | "resume" => {
                                let paused = action == "pause";
                                return Ok(json(db(Box::new(move |conn, cfg, c| control::set_paused(conn, cfg, c, &slug, paused))).await?));
                            }
                            _ => {}
                        }
                    }
                }
                _ => {}
            }
        }
        _ => {}
    }
    Err(Problem::new(404, "not_found", format!("No such API route: {m} {p}")))
}

/// POST /v1/apps/:slug/import: a JSON body {url, ref, ...} or a raw git bundle with the options in the query string.
async fn import_request(st: &State, c: &Caller, slug: &str, req: &mut Req) -> Result<Value> {
    use crate::git_import::{ImportRequest, Source};
    let is_json = req.header("content-type").is_some_and(|t| t.to_ascii_lowercase().contains("json"));
    let cap = (crate::instance::current(st).await.int("git.max_import_mb").max(1) as usize) * 1024 * 1024;
    if is_json {
        let b = req.json_object().await?;
        let Some(url) = b.get("url").and_then(Value::as_str).filter(|u| !u.trim().is_empty()) else {
            return Err(Problem::new(400, "need_source", "Send {\"url\": \"https://...\"} or a git bundle as the request body."));
        };
        let r = ImportRequest::from_json(slug, &b, Source::Url(url.to_string()))?;
        return crate::git_import::run(st, c, r).await;
    }
    let bundle = req.bytes(cap, "The bundle").await?;
    let mut o = Map::new();
    for k in ["ref", "base_version", "history", "target", "note"] {
        if let Some(v) = req.param(k) {
            o.insert(k.into(), json!(v));
        }
    }
    let r = ImportRequest::from_json(slug, &o, Source::Bundle(bundle))?;
    crate::git_import::run(st, c, r).await
}
