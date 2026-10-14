// SPDX-License-Identifier: AGPL-3.0-only
// Previews made for the marketplace: Brod runs a listing's release itself and screenshots and records it, so every
// listing shows what the app looks like without its publisher doing anything.
//
// The release runs in a sandbox, never the publisher's live app: a fresh, empty copy with no secrets and none of the
// publisher's data, keyed by the listing's id (its server code gets its own empty database and files, wiped before
// and after). So a preview shows exactly what an installer gets on day one, and nothing private can end up in a
// picture every workspace sees.
//
// A headless browser in a sidecar (deploy/preview/, BROD_PREVIEW_URL) does the capturing. For one capture Brod opens
// the sandbox at http://<token>.brod-preview.internal on its internal listener only; the token is random, names one
// release, lasts two minutes and is dropped when the capture ends. The sidecar maps that name to Brod's address, so
// nothing about it is public. It answers a desktop screenshot, a phone screenshot and a short screencast, which
// replace the listing's previous automatic previews; previews people uploaded stay as they are.
use std::collections::{HashMap, HashSet};
use std::sync::Mutex;
use std::time::Duration;

use axum::response::Response;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use bytes::Bytes;
use serde_json::{Value, json};

use crate::db::{Sql, params, tx};
use crate::http::{Req, json_response, notice, response};
use crate::model::{AppRow, User};
use crate::people::Decision;
use crate::problem::{Problem, Result};
use crate::runtime::ServerInfo;
use crate::state::State;
use crate::util::{now, random_id};

/// The name the sandbox is opened at, under the token: never a real domain, and only on Brod's internal listener.
pub const HOST_SUFFIX: &str = ".brod-preview.internal";
const TOKEN_TTL_MS: i64 = 2 * 60 * 1000;

#[derive(Clone)]
struct Sandbox {
    listing_id: String,
    slug: String,
    name: String,
    n: i64,
    roles: String,
    server: Option<String>,
    expires_at: i64,
}

/// Sandboxes open for a capture, by token, and the listings being captured right now (one capture per listing).
#[derive(Default)]
pub struct Previews {
    open: Mutex<HashMap<String, Sandbox>>,
    busy: Mutex<HashSet<String>>,
}

/// The token of a sandbox host ("<token>.brod-preview.internal", with or without a port), if it is one.
pub fn token_of(host: &str) -> Option<&str> {
    let name = host.rsplit_once(':').map_or(host, |(h, p)| if p.bytes().all(|b| b.is_ascii_digit()) { h } else { host });
    name.strip_suffix(HOST_SUFFIX).filter(|t| t.len() == 32 && t.bytes().all(|b| b.is_ascii_hexdigit()))
}

/// Serve a sandbox: the release's files and server code, to the capturing browser, as a person with the app's top role.
pub async fn serve(st: &State, req: Req, token: &str) -> Result<Response> {
    let found = {
        let open = st.previews.open.lock().unwrap();
        open.get(token).filter(|s| s.expires_at > now()).cloned()
    };
    let Some(sb) = found else {
        return Ok(notice(404, "Not found", "Nothing here.", ""));
    };
    let app = AppRow {
        id: sb.listing_id.clone(),
        workspace_id: String::new(),
        owner_id: String::new(),
        slug: sb.slug.clone(),
        name: sb.name.clone(),
        title: String::new(),
        welcome: String::new(),
        status: "live".into(),
        access: "private".into(),
        roles: sb.roles.clone(),
        live_version: Some(sb.n),
        created_at: 0,
        secrets_rev: 0,
        space_id: None,
        file_bytes: 0,
        data_bytes: 0,
        password_hash: None,
        taken_down_at: None,
        staging_version: None,
        takedown_reason: String::new(),
    };
    let user = User { id: "usr_preview".into(), email: "preview@brod.invalid".into(), name: "Preview".into(), email_verified_at: Some(0) };
    let decision =
        Decision { allowed: true, sign_in_needed: false, role: app.role_list().first().cloned(), groups: Vec::new(), member: None };
    let identity = crate::gateway::identity_for(&st.cfg, &app, "preview", &user, &decision);
    match req.path.as_str() {
        "/_brod/client.js" => {
            return Ok(response(200, crate::gateway::CLIENT_JS, &[("content-type", "text/javascript; charset=utf-8".into())]));
        }
        "/_brod/me" => {
            let (mut me, token) = identity;
            me["token"] = json!(token);
            return Ok(json_response(&me, 200, &[("cache-control", "no-store".into())]));
        }
        // The release's settings as an installer gets them on day one: every default, nothing customised.
        "/_brod/settings" => {
            let (id, n) = (sb.listing_id.clone(), sb.n);
            let values = st.db.call(move |c| crate::settings::values(c, &id, n)).await?;
            return Ok(json_response(&serde_json::Value::Object(values), 200, &[("cache-control", "no-store".into())]));
        }
        p if p.starts_with("/_brod/") => return Ok(notice(404, "Not found", "Nothing here.", "")),
        _ => {}
    }
    let server: Option<ServerInfo> = match &sb.server {
        Some(s) => Some(serde_json::from_str(s)?),
        None => None,
    };
    let origin = format!("http://{}", req.host);
    crate::gateway::serve_version(st, req, &app, sb.n, server, &origin, Some(identity)).await
}

/// Empty a sandbox: its database and key-value store in the runtime, its files, and the request logs it left.
async fn wipe(st: &State, listing_id: &str, server: bool) -> Result<()> {
    if server {
        crate::runtime::wipe_app_data(st, listing_id).await?;
    }
    st.store.delete_prefix(&format!("{listing_id}/files/")).await?;
    let id = listing_id.to_string();
    st.db.call(move |c| c.run("DELETE FROM app_logs WHERE app_id = ?", [&id]).map(|_| ())).await
}

/// Capture a listing's release (its latest, or `n`) and make the results its automatic previews. Ok(None) when this
/// server has no preview sidecar, or when the listing is already being captured.
pub async fn generate(st: &State, listing_id: &str, n: Option<i64>) -> Result<Option<usize>> {
    let Some(pv) = st.cfg.preview.clone() else { return Ok(None) };
    if !st.previews.busy.lock().unwrap().insert(listing_id.to_string()) {
        return Ok(None);
    }
    let r = capture(st, &pv, listing_id, n).await;
    st.previews.busy.lock().unwrap().remove(listing_id);
    r.map(Some)
}

async fn capture(st: &State, pv: &crate::config::RuntimeConfig, listing_id: &str, n: Option<i64>) -> Result<usize> {
    let id = listing_id.to_string();
    let sb = st
        .db
        .call(move |c| {
            c.first(
                "SELECT l.slug, l.name, r.n, r.roles, r.server FROM listings l JOIN releases r ON r.listing_id = l.id
                 WHERE l.id = ? AND r.n = COALESCE(?, l.latest_release)",
                params![id, n],
                |r| {
                    Ok(Sandbox {
                        listing_id: id.clone(),
                        slug: r.get(0)?,
                        name: r.get(1)?,
                        n: r.get(2)?,
                        roles: r.get(3)?,
                        server: r.get(4)?,
                        expires_at: now() + TOKEN_TTL_MS,
                    })
                },
            )?
            .ok_or_else(|| Problem::new(404, "no_release", "This listing has no release to preview yet."))
        })
        .await?;
    let has_server = sb.server.is_some();
    if has_server && st.cfg.runtime.is_none() {
        return Err(Problem::new(409, "server_apps_unavailable", "This server runs no server apps, so it cannot preview this one."));
    }
    let token = random_id("", 16);
    wipe(st, listing_id, has_server).await?;
    st.previews.open.lock().unwrap().insert(token.clone(), sb.clone());
    let res = st
        .http
        .post(format!("{}/capture", pv.url))
        .header("x-brod-preview-secret", &pv.secret)
        .timeout(Duration::from_secs(120))
        .json(&json!({ "host": format!("{token}{HOST_SUFFIX}") }))
        .send()
        .await;
    st.previews.open.lock().unwrap().remove(&token);
    let cleaned = wipe(st, listing_id, has_server).await;
    let res = res.map_err(|e| Problem::new(502, "preview_failed", format!("The preview service could not be reached: {e}")))?;
    if !res.status().is_success() {
        let status = res.status();
        let text = res.text().await.unwrap_or_default();
        return Err(Problem::new(
            502,
            "preview_failed",
            format!("The preview service answered {status}: {}", crate::util::js_slice(&text, 300)),
        ));
    }
    cleaned?;
    let out: Value =
        res.json().await.map_err(|e| Problem::new(502, "preview_failed", format!("The preview service answered nonsense: {e}")))?;
    let title = out["title"].as_str().map(|t| crate::util::js_slice(crate::util::js_trim(t), 100)).unwrap_or_default();
    // Each capture is checked like an upload: only an image or a video is kept, whatever the sidecar says it is.
    let mut shots = Vec::new();
    for (i, s) in out["shots"].as_array().cloned().unwrap_or_default().iter().enumerate() {
        let Some(bytes) = s["data"].as_str().and_then(|d| STANDARD.decode(d).ok()) else { continue };
        let Some((kind, ct)) = crate::market::sniff_media(&bytes) else { continue };
        if bytes.len() > crate::tar::FILE_BYTES {
            continue;
        }
        let caption = match s["name"].as_str() {
            Some("phone") => "On a phone".to_string(),
            Some("screencast") => "A quick look".to_string(),
            _ if !title.is_empty() => title.clone(),
            _ => "Home page".to_string(),
        };
        shots.push((random_id("med_", 10), kind, ct, bytes, caption, i as i64));
    }
    if shots.is_empty() {
        return Err(Problem::new(502, "preview_failed", "The preview service made no screenshot."));
    }
    for (mid, _, ct, bytes, _, _) in &shots {
        st.store.put(&format!("{listing_id}/_media/{mid}"), Bytes::from(bytes.clone()), Some(ct)).await?;
    }
    let (id, count, n) = (listing_id.to_string(), shots.len(), sb.n);
    let rows: Vec<(String, &'static str, &'static str, i64, String, i64)> =
        shots.into_iter().map(|(mid, kind, ct, bytes, caption, i)| (mid, kind, ct, bytes.len() as i64, caption, i)).collect();
    let new_ids: Vec<String> = rows.iter().map(|r| r.0.clone()).collect();
    let stored = st
        .db
        .call(move |c| {
            tx(c, |x| {
                // The listing may have been deleted while the browser was busy: then nothing is kept.
                if !x.exists("SELECT 1 FROM listings WHERE id = ?", [&id])? {
                    return Err(Problem::new(404, "no_listing", "The listing was deleted while its previews were being made."));
                }
                let old = x.all("SELECT id FROM listing_media WHERE listing_id = ? AND source = 'auto'", [&id], |r| r.get::<_, String>(0))?;
                x.run("DELETE FROM listing_media WHERE listing_id = ? AND source = 'auto'", [&id])?;
                // Automatic previews come first, in the order they were taken; uploaded ones keep their order after them.
                for (mid, kind, ct, size, caption, i) in &rows {
                    x.run(
                        "INSERT INTO listing_media (id, listing_id, kind, content_type, bytes, caption, position, created_at, source) VALUES (?,?,?,?,?,?,?,?,'auto')",
                        params![mid, id, kind, ct, size, caption, i - 100, now()],
                    )?;
                }
                x.run("UPDATE listings SET previews_release = ? WHERE id = ?", params![n, id])?;
                Ok(old)
            })
        })
        .await;
    let old = match stored {
        Ok(old) => old,
        Err(e) => {
            for mid in new_ids {
                let _ = st.store.delete(&format!("{listing_id}/_media/{mid}")).await;
            }
            return Err(e);
        }
    };
    for mid in old {
        st.store.delete(&format!("{listing_id}/_media/{mid}")).await?;
    }
    Ok(count)
}

/// Make previews in the background after a release is published, so publishing answers at once.
pub fn spawn(st: &State, listing_id: &str) {
    if st.cfg.preview.is_none() {
        return;
    }
    let (st, id) = (st.clone(), listing_id.to_string());
    tokio::spawn(async move {
        if let Err(e) = generate(&st, &id, None).await {
            eprintln!("preview of {id} failed: {}", e.message);
        }
    });
}

#[cfg(test)]
mod tests {
    use super::token_of;

    #[test]
    fn only_sandbox_hosts_with_a_full_token_are_sandboxes() {
        let t = "0123456789abcdef0123456789abcdef";
        assert_eq!(token_of(&format!("{t}.brod-preview.internal")), Some(t));
        assert_eq!(token_of(&format!("{t}.brod-preview.internal:8080")), Some(t));
        assert_eq!(token_of("short.brod-preview.internal"), None);
        assert_eq!(token_of(&format!("{t}.brod-preview.internal.evil.test")), None);
        assert_eq!(token_of(&format!("x.{t}.brod-preview.internal")), None);
        assert_eq!(token_of("brod.sh"), None);
    }
}
