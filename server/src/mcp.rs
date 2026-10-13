// MCP endpoint (Streamable HTTP, stateless, JSON responses). Each tool is a thin wrapper over the control plane.
use axum::response::Response;
use base64::Engine;
use serde_json::{Map, Value, json};

use crate::control::{self, Credentials, DeployTarget};
use crate::http::{Req, empty, json_response};
use crate::model::{Caller, js_string, js_to_number, limits};
use crate::people;
use crate::problem::{Problem, Result};
use crate::state::State;
use crate::tar::BundleFile;

const VERSIONS: [&str; 3] = ["2025-06-18", "2025-03-26", "2024-11-05"];

fn s(description: &str) -> Value {
    json!({ "type": "string", "description": description })
}

pub fn tools() -> Value {
    let app_arg = || s("The app's short name (slug), as shown by list_apps.");
    let grant_item = json!({
        "type": "object",
        "description": "Exactly one of email, group, domain or everyone, plus a role.",
        "properties": {
            "email": s("A person already in the workspace."), "group": s("A workspace group name, for example \"finance\"."),
            "domain": s("An email domain, for example \"example.com\"."), "everyone": { "type": "string", "enum": ["workspace", "signed_in"] },
            "role": s("One of the app's roles (default owner, editor, viewer)."),
        },
    });
    json!([
        {
            "name": "deploy_app",
            "title": "Deploy an app",
            "description": concat!(
                "Put a web app online and get its address back, or publish a new version of an existing app. ",
                "For a small app (up to 1 MB total), pass its files directly in \"files\". ",
                "For anything larger, call this WITHOUT \"files\": you get a one-time upload address and a one-line command that uploads the built output folder (such as dist/ or build/). ",
                "Give \"name\" to create a new app, or \"app\" to add a version to an existing one. New apps start private to their owner; use set_access to share them (with people or groups, the workspace, or anyone who has a password). ",
                "Static files are served as they are. For server code, include \"_worker.js\" (or a \"_worker/\" folder with index.js): an ES module with ",
                "`export default { async fetch(request, env, ctx) { ... } }`. Files that exist in the bundle are served directly; every other request goes to fetch. ",
                "Inside fetch, env holds the app's secrets (set_secret) plus its own storage: env.DB (SQLite: await env.DB.query(sql, params) returns rows, await env.DB.run(sql, params), ",
                "await env.DB.batch([{sql, params}]) in one transaction), env.KV (get, put, delete, list; string values) and env.FILES (put(key, body, contentType), get(key) returns a Response or null, delete, list(prefix)). ",
                "The signed-in person arrives as request headers x-brod-user-id, x-brod-user-email, x-brod-role and x-brod-groups (the platform strips any a visitor sends). ",
                "Never build a login or user table. A version whose server code does not start is refused, and the live version stays. Use get_logs to see console output and errors. ",
                "STAGING: when you update an app that already has a live version, ask the person first whether to try it on staging before it goes live (recommended) or to publish straight away. ",
                "Updates to a live app go to staging unless \"environment\" is \"production\": the result's staging_url serves the new version to the app's builders only, while visitors keep the live one. ",
                "Give the person the staging_url to test, and call publish_staging only once they say it is ready. Staging and live share the app's data (env.DB, env.KV, env.FILES) and secrets. ",
                "SEVERAL PEOPLE: others may update the same app. When updating, pass \"base_version\": the version your files started from (the \"version\" your last deploy_app returned, or \"current_version\" from get_status when you began). ",
                "If someone deployed since, nothing is deployed and the error stale_base says who changed what: call get_files for the current version, add your changes to it, and deploy again; do not deploy over their work unless the person says to. ",
                "If the result has a \"warning\", someone else is also working on the app: tell the person."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "name": s("Name for a NEW app, for example \"Reading list\". The address is derived from it."),
                    "app": s("Slug of an EXISTING app to publish a new version of."),
                    "note": s("One line on what this version is or what changed."),
                    "environment": {
                        "type": "string", "enum": ["staging", "production"],
                        "description": "Where this version goes. \"staging\": only to the app's staging address for testing; the live version is unchanged. \"production\": live at once. Default: staging when updating an app that is already live, production for a new app.",
                    },
                    "base_version": {
                        "type": "integer", "minimum": 1,
                        "description": "For an update: the version your files started from. The deploy is refused (stale_base) if the app's current version (staging, else live) is no longer this one, so you never undo someone else's changes.",
                    },
                    "files": {
                        "type": "array", "description": "The app's files, for small apps. Must include index.html at the top level.",
                        "items": { "type": "object", "properties": { "path": s("Path inside the app, for example \"index.html\" or \"assets/app.js\"."), "content": s("File content."), "encoding": { "type": "string", "enum": ["utf8", "base64"], "description": "How content is encoded. Default utf8." } }, "required": ["path", "content"] },
                    },
                },
            },
            "annotations": { "readOnlyHint": false, "destructiveHint": false, "openWorldHint": true },
        },
        { "name": "list_apps", "title": "List apps", "description": "List the workspace's apps with address, status, who can open each, live version, plus how many plan slots are in use.", "inputSchema": { "type": "object", "properties": {} }, "annotations": { "readOnlyHint": true } },
        {
            "name": "get_files", "title": "Get an app's files",
            "description": concat!(
                "Get the files of an app's current version (the one on staging, else the live one), or of the \"version\" you name, to change them. ",
                "Call this before changing an app someone else may have changed, so you start from what is deployed rather than an older copy, then deploy_app with \"base_version\" set to the \"version\" returned. ",
                "Small apps come back inline in \"files\" (base64 when \"encoding\" says so); larger ones as a download_url with a one-line curl | tar command. ",
                "The files are the built output as deployed. If the result has a \"warning\", someone else is working on the app too: tell the person."
            ),
            "inputSchema": { "type": "object", "properties": { "app": app_arg(), "version": { "type": "integer", "minimum": 1, "description": "A version number. Default: the current version." } }, "required": ["app"] },
            "annotations": { "readOnlyHint": true },
        },
        { "name": "get_status", "title": "App status", "description": "Show one app: address, status, access, roles, who it is shared with, its versions with which one is live, and what is on staging (version and address).", "inputSchema": { "type": "object", "properties": { "app": app_arg() }, "required": ["app"] }, "annotations": { "readOnlyHint": true } },
        {
            "name": "get_logs", "title": "App activity and logs",
            "description": concat!("Show one app's recent activity (deploys, rollbacks, access changes, sign-in refusals, pauses, and which connection or person made each) ",
                "and, for server apps, its last 50 requests with their console output and exceptions (kept 7 days). Use \"search\" to find requests whose logs, errors or path contain some text."),
            "inputSchema": { "type": "object", "properties": { "app": app_arg(), "search": s("Only requests whose logs, exceptions or path contain this text.") }, "required": ["app"] },
            "annotations": { "readOnlyHint": true },
        },
        {
            "name": "set_secret", "title": "Set a secret",
            "description": concat!("Store a secret for an app's server code, such as an API key. The app reads it as env.NAME from its next request. Values are encrypted and write-only: ",
                "nobody, you included, can read one back. get_status lists the names. Give \"remove\": true instead of a value to delete one."),
            "inputSchema": {
                "type": "object",
                "properties": { "app": app_arg(), "name": s("UPPER_SNAKE_CASE name, for example \"STRIPE_KEY\"."), "value": s("The secret value, up to 5 KB."), "remove": { "type": "boolean", "description": "Delete this secret." } },
                "required": ["app", "name"],
            },
            "annotations": { "readOnlyHint": false, "destructiveHint": false, "idempotentHint": true },
        },
        {
            "name": "publish_staging", "title": "Publish staging",
            "description": concat!("Make the version on an app's staging address live, after the person has tried it there and said it is ready. Takes effect on the next request. ",
                "Give \"discard\": true instead to take it off staging without publishing (the version is kept; rollback can still serve it). get_status shows what is on staging."),
            "inputSchema": { "type": "object", "properties": { "app": app_arg(), "discard": { "type": "boolean", "description": "Take the version off staging instead of publishing it." } }, "required": ["app"] },
            "annotations": { "readOnlyHint": false, "destructiveHint": false, "idempotentHint": false },
        },
        { "name": "rollback", "title": "Roll back", "description": "Make an earlier version live again. Takes effect on the next request and rebuilds nothing. Use get_status to see version numbers.", "inputSchema": { "type": "object", "properties": { "app": app_arg(), "version": { "type": "integer", "description": "Version number to serve." } }, "required": ["app", "version"] }, "annotations": { "readOnlyHint": false, "destructiveHint": false, "idempotentHint": true } },
        {
            "name": "set_access", "title": "Change who can open an app",
            "description": concat!("Set an app's access mode and who holds which app role. Modes: \"private\" (owner and admins only), \"people\" (only granted people and groups), \"workspace\" (everyone in the workspace), ",
                "\"password\" (anyone with the address and the password, no sign-in or account needed: give \"password\" too), \"signed_in\" (anyone who signs in), \"public\" (anyone, no sign-in). ",
                "To share an app quietly with people outside the workspace, use \"password\": visitors see a password page, and the address plus the password is all they need. Brod keeps only a hash, so tell the owner the password you set; ",
                "setting a new one signs out everyone who used the old one, and moving the app to another mode removes it. Grants give a person (by email, must already be in the workspace), a group, an email domain, or everyone (\"workspace\"/\"signed_in\") one of the app's roles. ",
                "Narrowing access applies at once. Widening it (a more open mode, new grants or a new password) does NOT apply yet: the result has a confirm_url the owner must open and confirm. Give them that link."),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "app": app_arg(),
                    "access": { "type": "string", "enum": ["private", "people", "workspace", "password", "signed_in", "public"] },
                    "password": s("With \"access\": \"password\": the password to share the app with, 6 to 128 characters. Giving it alone switches the app to \"password\"."),
                    "add": { "type": "array", "description": "Grants to add or change.", "items": grant_item },
                    "remove": { "type": "array", "description": "Grants to remove (role is ignored).", "items": grant_item },
                },
                "required": ["app"],
            },
            "annotations": { "readOnlyHint": false, "destructiveHint": true, "idempotentHint": true },
        },
        { "name": "set_paused", "title": "Pause or resume", "description": "Pause an app (visitors see a \"paused\" page and its plan slot is freed) or resume it.", "inputSchema": { "type": "object", "properties": { "app": app_arg(), "paused": { "type": "boolean" } }, "required": ["app", "paused"] }, "annotations": { "readOnlyHint": false, "destructiveHint": false, "idempotentHint": true } },
        {
            "name": "invite", "title": "Invite someone",
            "description": concat!("Invite a person by email: into the workspace (role admin, builder or member), or as a guest to one app (give \"app\" and optionally \"app_role\"). Someone already in the workspace who is given an app just gets the role on it. ",
                "This needs the owner's confirmation: the result has a confirm_url to give them. The invitation email goes out once they confirm."),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "email": s("Their email address."),
                    "role": { "type": "string", "enum": ["admin", "builder", "member", "guest"], "description": "Workspace role. Default member, or guest when \"app\" is given." },
                    "app": s("Slug of an app to give them."),
                    "app_role": s("Their role on that app, one of the roles the app declares. Default its lowest role."),
                },
                "required": ["email"],
            },
            "annotations": { "readOnlyHint": false, "destructiveHint": false, "openWorldHint": true },
        },
        {
            "name": "set_domain", "title": "Custom domain",
            "description": concat!("Serve an app at a domain the workspace owns, such as \"shop.example.com\" (give \"app\"), or every app in the workspace under a domain, such as \"*.apps.example.com\" ",
                "(<app>.apps.example.com opens that app; admins only). The result lists two DNS records the owner must add: a TXT record that proves they own the domain, and a CNAME that sends visitors to Brod. ",
                "Call set_domain again with the same domain once the records are in to check them; the domain is served only after it is verified. Sign-in, roles and access work the same as on the app's own address. ",
                "Give \"remove\": true to stop serving a domain. get_status lists an app's domains."),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "domain": s("The domain, for example \"shop.example.com\", or \"*.apps.example.com\" for the whole workspace."),
                    "app": s("Slug of the app to serve there. Leave out for a \"*.\" domain."),
                    "remove": { "type": "boolean", "description": "Stop serving this domain." },
                },
                "required": ["domain"],
            },
            "annotations": { "readOnlyHint": false, "destructiveHint": false, "idempotentHint": true, "openWorldHint": true },
        },
        {
            "name": "get_workspace", "title": "Workspace and identity",
            "description": concat!("Read the workspace an app will live in: its groups, the default app roles, the access modes, plan slots, and how an app reads the signed-in person (the identity contract). ",
                "Call this before building an app that needs sign-in or roles: apps never keep their own user table."),
            "inputSchema": { "type": "object", "properties": {} }, "annotations": { "readOnlyHint": true },
        },
    ])
}

/// Files passed inline in a tool call (or in POST /v1/deploys when `strict` is false).
pub fn inline_files(raw: &Value, strict: bool, too_large: &str) -> Result<Vec<BundleFile>> {
    let Value::Array(list) = raw else {
        return Err(Problem::new(400, "bad_files", "\"files\" must be a list of { path, content }."));
    };
    let mut total = 0usize;
    let mut out = Vec::with_capacity(list.len());
    for f in list {
        let path = f.get("path");
        let content = f.get("content");
        if strict && !(matches!(path, Some(Value::String(_))) && matches!(content, Some(Value::String(_)))) {
            return Err(Problem::new(400, "bad_files", "Each file needs a \"path\" and a \"content\" string."));
        }
        let path = match path {
            None | Some(Value::Null) => String::new(),
            Some(v) => js_string(v),
        };
        let content = match content {
            None | Some(Value::Null) => String::new(),
            Some(v) => js_string(v),
        };
        let bytes = if f.get("encoding").and_then(|e| e.as_str()) == Some("base64") {
            atob(&content).ok_or_else(|| Problem::new(400, "bad_files", format!("{path} is not valid base64.")))?
        } else {
            content.into_bytes()
        };
        total += bytes.len();
        out.push(BundleFile { path, bytes });
    }
    if total > limits::INLINE_BYTES {
        return Err(Problem::new(413, "too_large", too_large));
    }
    Ok(out)
}

/// atob(): base64 with or without padding, ignoring ASCII whitespace.
fn atob(s: &str) -> Option<Vec<u8>> {
    let clean: String = s.chars().filter(|c| !matches!(c, ' ' | '\t' | '\n' | '\x0c' | '\r')).collect();
    let trimmed = clean.trim_end_matches('=');
    if clean.len() - trimmed.len() > 2 || (!clean.len().is_multiple_of(4) && clean.len() != trimmed.len()) || trimmed.len() % 4 == 1 {
        return None;
    }
    base64::engine::general_purpose::STANDARD_NO_PAD.decode(trimmed).ok()
}

/// The tools a read-only connection may call: they look and change nothing.
pub const READ_TOOLS: [&str; 5] = ["list_apps", "get_files", "get_status", "get_logs", "get_workspace"];

/// The tools this caller may use: all of them, or only the reading ones for a read-only connection.
fn tools_for(c: &Caller) -> Value {
    let mut all = tools();
    if c.read_only
        && let Value::Array(list) = &mut all
    {
        list.retain(|t| t["name"].as_str().is_some_and(|n| READ_TOOLS.contains(&n)));
    }
    all
}

async fn call(st: &State, c: &Caller, name: &str, a: &Map<String, Value>) -> Result<Value> {
    if !READ_TOOLS.contains(&name) && tools().as_array().is_some_and(|l| l.iter().any(|t| t["name"] == name)) {
        control::require_write(c, &format!("use {name}"))?;
    }
    let str_arg = |k: &str| match a.get(k) {
        None | Some(Value::Null) => String::new(),
        Some(v) => js_string(v),
    };
    let cfg = st.cfg.clone();
    let c2 = c.clone();
    match name {
        "deploy_app" => {
            let target = DeployTarget::from_json(a);
            match a.get("files") {
                None => st.db.call(move |conn| control::create_upload(conn, &cfg, &c2, &target)).await,
                Some(files) => {
                    let files = inline_files(
                        files,
                        true,
                        "Files passed inline can total 1 MB. Call deploy_app without \"files\" to get an upload address for larger apps.",
                    )?;
                    control::deploy(st, c, target, files).await
                }
            }
        }
        "list_apps" => st.db.call(move |conn| control::list_apps(conn, &cfg, &c2)).await,
        "get_files" => control::get_files(st, c, &str_arg("app"), a.get("version").cloned()).await,
        "get_status" => {
            let slug = str_arg("app");
            st.db.call(move |conn| control::get_status(conn, &cfg, &c2, &slug).map(Value::Object)).await
        }
        "get_logs" => {
            let slug = str_arg("app");
            let search = if crate::model::truthy(a.get("search")) { Some(str_arg("search")) } else { None };
            st.db.call(move |conn| control::get_logs(conn, &c2, &slug, search.as_deref())).await
        }
        "set_secret" => {
            let remove = matches!(a.get("remove"), Some(Value::Bool(true)));
            let value = match a.get("value") {
                Some(Value::String(v)) => Some(v.clone()),
                _ if remove => None,
                _ => {
                    return Err(Problem::new(400, "bad_value", "Give \"value\", or \"remove\": true to delete the secret."));
                }
            };
            let (slug, name) = (str_arg("app"), str_arg("name"));
            let value = if remove { None } else { value };
            st.db.call(move |conn| control::set_secret(conn, &cfg, &c2, &slug, &name, value.as_deref())).await
        }
        "publish_staging" => {
            let slug = str_arg("app");
            if matches!(a.get("discard"), Some(Value::Bool(true))) {
                st.db.call(move |conn| control::discard_staging(conn, &cfg, &c2, &slug)).await
            } else {
                st.db.call(move |conn| control::publish_staging(conn, &cfg, &c2, &slug)).await
            }
        }
        "rollback" => {
            let slug = str_arg("app");
            let version = js_to_number(a.get("version"));
            st.db.call(move |conn| control::rollback(conn, &cfg, &c2, &slug, version)).await
        }
        "set_access" => {
            let slug = str_arg("app");
            let mut o = Map::new();
            for k in ["access", "add", "remove", "password"] {
                if let Some(v) = a.get(k) {
                    o.insert(k.into(), v.clone());
                }
            }
            st.db.call(move |conn| control::set_access(conn, &cfg, &c2, &slug, &o, None)).await
        }
        "set_paused" => {
            let slug = str_arg("app");
            let paused = matches!(a.get("paused"), Some(Value::Bool(true)));
            st.db.call(move |conn| control::set_paused(conn, &cfg, &c2, &slug, paused)).await
        }
        "invite" => {
            let mut o = Map::new();
            for k in ["email", "role", "app", "app_role"] {
                if let Some(v) = a.get(k) {
                    o.insert(k.into(), v.clone());
                }
            }
            control::invite_from(st, c, o).await
        }
        "set_domain" => crate::domains::set_domain(st, c, a).await,
        "get_workspace" => st.db.call(move |conn| people::describe_workspace(conn, &cfg, &c2)).await,
        _ => Err(Problem::new(404, "unknown_tool", format!("There is no tool called \"{name}\"."))),
    }
}

fn text(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        _ => serde_json::to_string_pretty(v).unwrap_or_default(),
    }
}

async fn handle(st: &State, c: &Caller, m: &Value) -> Option<Value> {
    let id = m.get("id").filter(|v| !v.is_null())?.clone();
    let reply = |result: Value| json!({ "jsonrpc": "2.0", "id": id, "result": result });
    let method = m.get("method").and_then(|v| v.as_str()).unwrap_or("");
    let params = m.get("params");
    match method {
        "initialize" => {
            let asked = params.and_then(|p| p.get("protocolVersion")).and_then(|v| v.as_str());
            let version = asked.filter(|v| VERSIONS.contains(v)).unwrap_or(VERSIONS[0]);
            Some(reply(json!({
                "protocolVersion": version,
                "capabilities": { "tools": { "listChanged": false } },
                "serverInfo": { "name": "brod", "title": "Brod", "version": "0.2.0" },
                "instructions": concat!("Brod puts small web apps online inside a team workspace with one sign-in. Call get_workspace before building an app that needs to know who is using it: ",
                    "the platform signs people in and the app reads them from /_brod/me, so never build a login or user table. Use deploy_app to publish and return the address. ",
                    "Apps start private. To share one with people outside the workspace without accounts, set_access with \"access\": \"password\" and a password, then give them the address and the password. ",
                    "Sharing more widely and inviting people need the owner to confirm: pass on the confirm_url you get back. ",
                    "Once an app is live, ask before changing it whether to deploy to staging first: updates go to its staging address, the person tests there, and publish_staging makes it live. ",
                    "Other people may change the same app: before changing one, call get_files for its current version, and pass base_version (the version your files started from) to deploy_app, so a deploy never undoes someone else's. ",
                    "When a result has a \"warning\" that someone else is working on the app, tell the person."),
            })))
        }
        "ping" => Some(reply(json!({}))),
        "tools/list" => Some(reply(json!({ "tools": tools_for(c) }))),
        "tools/call" => {
            let name =
                params.and_then(|p| p.get("name")).map(|v| if v.is_null() { String::new() } else { js_string(v) }).unwrap_or_default();
            let args = match params.and_then(|p| p.get("arguments")) {
                Some(Value::Object(a)) => a.clone(),
                _ => Map::new(),
            };
            Some(match call(st, c, &name, &args).await {
                Ok(result) => {
                    reply(json!({ "content": [{ "type": "text", "text": text(&result) }], "structuredContent": result, "isError": false }))
                }
                Err(e) if e.is_internal() => {
                    eprintln!("error: {e}");
                    reply(
                        json!({ "content": [{ "type": "text", "text": "Something went wrong on our side. Try again." }], "isError": true }),
                    )
                }
                Err(e) => {
                    // Tool errors go back as results the agent can read and act on, not as protocol errors.
                    let mut body = Map::new();
                    body.insert("error".into(), json!(e.code));
                    body.insert("message".into(), json!(e.message));
                    body.extend(e.extra.iter().map(|(k, v)| (k.clone(), v.clone())));
                    reply(json!({ "content": [{ "type": "text", "text": text(&Value::Object(body)) }], "isError": true }))
                }
            })
        }
        _ => Some(json!({ "jsonrpc": "2.0", "id": id, "error": { "code": -32601, "message": format!("Method not found: {method}") } })),
    }
}

pub async fn serve(st: &State, mut req: Req) -> Result<Response> {
    if req.method != axum::http::Method::POST {
        return Ok(json_response(
            &json!({ "error": { "code": "method_not_allowed", "message": "This MCP endpoint takes POST requests only." } }),
            405,
            &[("allow", "POST".into())],
        ));
    }
    let caller = match control::authenticate_async(st, Credentials::of(&req)).await {
        Ok(c) => c,
        Err(e) if e.is_internal() => return Err(e),
        Err(e) => {
            return Ok(json_response(
                &json!({ "jsonrpc": "2.0", "id": null, "error": { "code": -32001, "message": e.message } }),
                401,
                &[(
                    "www-authenticate",
                    format!("Bearer realm=\"brod\", resource_metadata=\"{}\"", crate::connect::resource_metadata_url(&st.cfg)),
                )],
            ));
        }
    };
    let raw = req.bytes(crate::tar::BUNDLE_BYTES, "The request body").await?;
    let body: Value = match serde_json::from_slice(&raw) {
        Ok(v) => v,
        Err(_) => {
            return Ok(json_response(
                &json!({ "jsonrpc": "2.0", "id": null, "error": { "code": -32700, "message": "Parse error" } }),
                400,
                &[],
            ));
        }
    };
    if let Value::Array(list) = &body {
        let mut replies = Vec::new();
        for m in list {
            if let Some(r) = handle(st, &caller, m).await {
                replies.push(r);
            }
        }
        return Ok(if replies.is_empty() { empty(202) } else { json_response(&Value::Array(replies), 200, &[]) });
    }
    Ok(match handle(st, &caller, &body).await {
        Some(r) => json_response(&r, 200, &[]),
        None => empty(202),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lists_the_tools_in_order() {
        let names: Vec<String> = tools().as_array().unwrap().iter().map(|t| t["name"].as_str().unwrap().to_string()).collect();
        assert_eq!(
            names,
            [
                "deploy_app",
                "list_apps",
                "get_files",
                "get_status",
                "get_logs",
                "set_secret",
                "publish_staging",
                "rollback",
                "set_access",
                "set_paused",
                "invite",
                "set_domain",
                "get_workspace"
            ]
        );
    }

    #[test]
    fn read_only_connections_see_only_the_reading_tools() {
        let user = crate::model::User { id: "usr_a".into(), email: "a@a.test".into(), name: String::new(), email_verified_at: None };
        let workspace = crate::model::Workspace {
            id: "ws_a".into(),
            slug: "a".into(),
            name: "A".into(),
            plan: "free".into(),
            color: String::new(),
            icon: String::new(),
            created_at: 0,
        };
        let mut c = Caller { workspace, user, role: "builder".into(), actor: "agent".into(), agent: true, read_only: false };
        let all = tools_for(&c).as_array().unwrap().len();
        c.read_only = true;
        let names: Vec<String> = tools_for(&c).as_array().unwrap().iter().map(|t| t["name"].as_str().unwrap().to_string()).collect();
        assert_eq!(names, READ_TOOLS);
        assert_eq!(all, tools().as_array().unwrap().len());
        // Every reading tool says so in its annotations.
        for t in tools().as_array().unwrap() {
            assert_eq!(READ_TOOLS.contains(&t["name"].as_str().unwrap()), t["annotations"]["readOnlyHint"] == true, "{}", t["name"]);
        }
    }

    #[test]
    fn decodes_inline_files() {
        let files = inline_files(
            &json!([{ "path": "a.txt", "content": "aGk=", "encoding": "base64" }, { "path": "b.txt", "content": "x" }]),
            true,
            "big",
        )
        .unwrap();
        assert_eq!(files[0].bytes, b"hi");
        assert_eq!(
            inline_files(&json!([{ "path": "a", "content": "!!", "encoding": "base64" }]), true, "big").unwrap_err().code,
            "bad_files"
        );
        assert_eq!(inline_files(&json!([{ "path": 1, "content": "x" }]), true, "big").unwrap_err().code, "bad_files");
        assert_eq!(inline_files(&json!("x"), true, "big").unwrap_err().code, "bad_files");
        let big = "a".repeat(limits::INLINE_BYTES + 1);
        assert_eq!(inline_files(&json!([{ "path": "a", "content": big }]), true, "big").unwrap_err().code, "too_large");
    }
}
