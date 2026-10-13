// SPDX-License-Identifier: AGPL-3.0-only
// App settings: the values a workspace sets on its copy of an app, such as its name, logo, colours or wording, without
// touching its code. Brod imposes none of them. Whoever makes the app declares what can be customised in a brod.json
// file at the top of its bundle, with a label and a default for each:
//
//   { "settings": [
//       { "key": "name", "label": "Shop name", "type": "text", "default": "My shop" },
//       { "key": "logo", "label": "Logo", "type": "image", "default": "logo.png" },
//       { "key": "accent", "label": "Accent colour", "type": "color", "default": "#1f6f4a" } ] }
//
// The declaration is read on every deploy and kept with the version (versions.settings), so it travels with releases
// into the marketplace, where installers fill it in. The app reads the values at /_brod/settings (Brod.settings() in
// client.js), and server code as env.SETTINGS. A value nobody set is the declared default, so an app that is never
// customised looks exactly as its maker shipped it.
use crate::db::{Connection, params};
use bytes::Bytes;
use serde_json::{Map, Value, json};

use crate::db::{Sql, event, tx};
use crate::model::{AppRow, Caller};
use crate::people::require_role;
use crate::problem::{Problem, Result};
use crate::state::State;
use crate::tar::BundleFile;
use crate::util::{iso, js_trim, now, random_id};

/// The file an app declares its settings in.
pub const MANIFEST: &str = "brod.json";
pub const MAX_SETTINGS: usize = 30;
/// An uploaded image (a logo, an icon, a header picture) is at most this big.
pub const IMAGE_BYTES: usize = 1024 * 1024;
const TYPES: [&str; 9] = ["text", "textarea", "color", "image", "url", "email", "number", "boolean", "select"];
const IMAGE_EXTS: [&str; 6] = ["png", "jpg", "jpeg", "gif", "webp", "svg"];

fn bad(msg: String) -> Problem {
    Problem::new(400, "bad_settings", msg)
}

fn valid_key(k: &str) -> bool {
    let b = k.as_bytes();
    !b.is_empty()
        && b.len() <= 40
        && b[0].is_ascii_lowercase()
        && b.iter().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'_')
}

/// "#abc" and "#AABBCC" become "#aabbcc", so a colour picker can always show the value.
fn color(s: &str) -> Option<String> {
    let h = s.strip_prefix('#')?;
    if !h.bytes().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    match h.len() {
        3 => Some(format!("#{}", h.chars().flat_map(|c| [c, c]).collect::<String>().to_lowercase())),
        6 => Some(format!("#{}", h.to_lowercase())),
        _ => None,
    }
}

fn str_of(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

/// A value checked against its setting, in the form the app reads it. Images are uploaded as files, never set here.
pub fn check_value(s: &Value, v: &Value) -> Result<Value> {
    let key = s["key"].as_str().unwrap_or("");
    let label = s["label"].as_str().unwrap_or(key);
    let kind = s["type"].as_str().unwrap_or("text");
    let wrong = |what: &str| Problem::new(400, "bad_setting", format!("{label} ({key}) {what}.")).with("setting", json!(key));
    let text = || str_of(v).map(|t| js_trim(&t).to_string()).ok_or_else(|| wrong("is text"));
    match kind {
        "text" | "textarea" => {
            let t = text()?;
            let max = if kind == "text" { 200 } else { 4000 };
            if t.chars().count() > max {
                return Err(wrong(&format!("can be at most {max} characters")));
            }
            Ok(json!(t))
        }
        "color" => color(&text()?).map(Value::String).ok_or_else(|| wrong("is a colour like #1f6f4a")),
        "url" => {
            let t = text()?;
            let ok = (t.starts_with("https://") || t.starts_with("http://")) && t.len() <= 2000 && !t.contains(char::is_whitespace);
            if ok { Ok(json!(t)) } else { Err(wrong("is an address starting with https://")) }
        }
        "email" => {
            let t = text()?;
            let ok = t.len() <= 254
                && !t.contains(char::is_whitespace)
                && t.split_once('@').is_some_and(|(a, d)| !a.is_empty() && d.contains('.'));
            if ok { Ok(json!(t)) } else { Err(wrong("is an email address")) }
        }
        "number" => {
            let n = match v {
                Value::Number(n) => n.as_f64(),
                Value::String(t) => js_trim(t).parse::<f64>().ok(),
                _ => None,
            }
            .filter(|n| n.is_finite())
            .ok_or_else(|| wrong("is a number"))?;
            if let Some(min) = s["min"].as_f64().filter(|m| n < *m) {
                return Err(wrong(&format!("is at least {min}")));
            }
            if let Some(max) = s["max"].as_f64().filter(|m| n > *m) {
                return Err(wrong(&format!("is at most {max}")));
            }
            Ok(json!(n))
        }
        "boolean" => match v {
            Value::Bool(b) => Ok(json!(b)),
            Value::String(t) if t == "true" || t == "false" => Ok(json!(t == "true")),
            _ => Err(wrong("is true or false")),
        },
        "select" => {
            let t = text()?;
            let options: Vec<&str> = s["options"].as_array().map(|o| o.iter().filter_map(Value::as_str).collect()).unwrap_or_default();
            if options.contains(&t.as_str()) { Ok(json!(t)) } else { Err(wrong(&format!("is one of: {}", options.join(", ")))) }
        }
        "image" => Err(wrong("is an image: upload the file instead")),
        _ => Err(wrong("has a type Brod does not know")),
    }
}

/// Read brod.json from a bundle, if it has one, and return its settings as the JSON kept with the version. A bundle
/// with a brod.json Brod cannot use is refused, so the mistake shows at deploy rather than on someone's install.
pub fn from_bundle(files: &[BundleFile]) -> Result<Option<String>> {
    let Some(f) = files.iter().find(|f| f.path == MANIFEST) else { return Ok(None) };
    let doc: Value = serde_json::from_slice(&f.bytes).map_err(|e| bad(format!("{MANIFEST} is not valid JSON: {e}.")))?;
    let Some(doc) = doc.as_object() else { return Err(bad(format!("{MANIFEST} is a JSON object, like {{ \"settings\": [] }}."))) };
    let Some(list) = doc.get("settings") else { return Ok(None) };
    let Some(list) = list.as_array() else { return Err(bad(format!("\"settings\" in {MANIFEST} is a list."))) };
    if list.len() > MAX_SETTINGS {
        return Err(bad(format!("An app can declare at most {MAX_SETTINGS} settings; {MANIFEST} has {}.", list.len())));
    }
    let mut out: Vec<Value> = Vec::new();
    for (i, s) in list.iter().enumerate() {
        let at = |what: &str| bad(format!("{MANIFEST}, setting {}: {what}", i + 1));
        let Some(s) = s.as_object() else { return Err(at("each setting is an object with a key, a label and a type.")) };
        let key = s.get("key").and_then(Value::as_str).unwrap_or("");
        if !valid_key(key) {
            return Err(at(
                "\"key\" is lowercase letters, digits and _, starting with a letter, at most 40 characters, like \"accent_color\".",
            ));
        }
        if out.iter().any(|o| o["key"] == key) {
            return Err(at(&format!("the key \"{key}\" is declared twice.")));
        }
        let kind = s.get("type").and_then(Value::as_str).unwrap_or("text");
        if !TYPES.contains(&kind) {
            return Err(at(&format!("\"type\" is one of {}.", TYPES.join(", "))));
        }
        let field = |name: &str, max: usize| -> Result<String> {
            let t = s.get(name).and_then(Value::as_str).map(|t| js_trim(t).to_string()).unwrap_or_default();
            if t.chars().count() > max { Err(at(&format!("\"{name}\" can be at most {max} characters."))) } else { Ok(t) }
        };
        let label = field("label", 60)?;
        let mut m = Map::new();
        m.insert("key".into(), json!(key));
        m.insert("label".into(), json!(if label.is_empty() { key.to_string() } else { label }));
        m.insert("type".into(), json!(kind));
        let help = field("help", 200)?;
        if !help.is_empty() {
            m.insert("help".into(), json!(help));
        }
        if kind == "select" {
            let options: Vec<String> =
                s.get("options").and_then(Value::as_array).map(|o| o.iter().filter_map(str_of).collect()).unwrap_or_default();
            if options.is_empty() || options.len() > 50 || options.iter().any(|o| o.is_empty() || o.chars().count() > 100) {
                return Err(at("a \"select\" setting lists 1 to 50 \"options\", each a short text."));
            }
            m.insert("options".into(), json!(options));
        }
        if kind == "number" {
            for b in ["min", "max"] {
                match s.get(b) {
                    None | Some(Value::Null) => {}
                    Some(Value::Number(n)) => {
                        m.insert(b.into(), json!(n));
                    }
                    Some(_) => return Err(at(&format!("\"{b}\" is a number."))),
                }
            }
        }
        match s.get("default") {
            None | Some(Value::Null) => {}
            Some(d) if kind == "image" => {
                // An image's default is a picture in the bundle itself, like the logo the app ships with.
                let p = d.as_str().unwrap_or("").trim_start_matches('/');
                let ext = p.rsplit_once('.').map(|(_, e)| e.to_ascii_lowercase()).unwrap_or_default();
                if !IMAGE_EXTS.contains(&ext.as_str()) || !files.iter().any(|f| f.path == p) {
                    return Err(at(&format!(
                        "the default of an image is the path of a picture in the bundle, like \"logo.png\"; \"{p}\" is not one."
                    )));
                }
                m.insert("default".into(), json!(p));
            }
            Some(d) => {
                let v = check_value(&Value::Object(m.clone()), d).map_err(|e| at(&format!("the default: {}", e.message)))?;
                m.insert("default".into(), v);
            }
        }
        out.push(Value::Object(m));
    }
    if out.is_empty() { Ok(None) } else { Ok(Some(Value::Array(out).to_string())) }
}

fn parse(json: Option<String>) -> Vec<Value> {
    json.and_then(|j| serde_json::from_str::<Value>(&j).ok()).and_then(|v| v.as_array().cloned()).unwrap_or_default()
}

/// The settings a version of an app declares. A marketplace preview sandbox runs a release by its listing's id.
pub fn declared(conn: &Connection, app_id: &str, version: i64) -> Result<Vec<Value>> {
    let sql = if app_id.starts_with("lst_") {
        "SELECT settings FROM releases WHERE listing_id = ? AND n = ?"
    } else {
        "SELECT settings FROM versions WHERE app_id = ? AND n = ?"
    };
    Ok(parse(conn.first(sql, params![app_id, version], |r| r.get::<_, Option<String>>(0))?.flatten()))
}

/// The settings that can be set on an app now: those its live version declares, and its staging version's on top,
/// so a new setting can be filled in while the version that brings it is still being tried.
fn settable(conn: &Connection, app: &AppRow) -> Result<Vec<Value>> {
    let mut out = match app.live_version {
        Some(n) => declared(conn, &app.id, n)?,
        None => Vec::new(),
    };
    if let Some(n) = app.staging_version {
        for s in declared(conn, &app.id, n)? {
            match out.iter_mut().find(|o| o["key"] == s["key"]) {
                Some(o) => *o = s,
                None => out.push(s),
            }
        }
    }
    Ok(out)
}

struct Stored {
    value: Value,
    image: bool,
    updated_at: i64,
    by: String,
}

fn stored(conn: &Connection, app_id: &str) -> Result<Vec<(String, Stored)>> {
    conn.all("SELECT key, value, content_type, updated_at, updated_by FROM app_settings WHERE app_id = ?", [app_id], |r| {
        let value: String = r.get(1)?;
        Ok((
            r.get::<_, String>(0)?,
            Stored {
                value: serde_json::from_str(&value).unwrap_or(Value::Null),
                image: r.get::<_, Option<String>>(2)?.is_some(),
                updated_at: r.get(3)?,
                by: r.get(4)?,
            },
        ))
    })
}

/// What one setting is for the app right now: its value, or its default. An image is an address on the app's own host.
fn current(s: &Value, set: Option<&Stored>) -> Value {
    let key = s["key"].as_str().unwrap_or("");
    match (s["type"].as_str(), set) {
        (Some("image"), Some(v)) if v.image => json!(format!("/_brod/settings/{key}?v={}", v.value.as_str().unwrap_or(""))),
        (Some("image"), _) => s.get("default").and_then(Value::as_str).map(|p| json!(format!("/{p}"))).unwrap_or(Value::Null),
        (_, Some(v)) if !v.image => v.value.clone(),
        _ => s.get("default").cloned().unwrap_or(Value::Null),
    }
}

/// The settings as the app reads them, for one version: { key: value }, every declared key present.
pub fn values(conn: &Connection, app_id: &str, version: i64) -> Result<Map<String, Value>> {
    let set = if app_id.starts_with("lst_") { Vec::new() } else { stored(conn, app_id)? };
    Ok(declared(conn, app_id, version)?
        .iter()
        .map(|s| {
            let key = s["key"].as_str().unwrap_or("").to_string();
            let v = current(s, set.iter().find(|(k, _)| *k == key).map(|(_, v)| v));
            (key, v)
        })
        .collect())
}

/// The settings of an app, for the people who customise it: each declaration with its current value and who set it.
pub fn for_app(conn: &Connection, app: &AppRow) -> Result<Value> {
    let set = stored(conn, &app.id)?;
    let list: Vec<Value> = settable(conn, app)?
        .into_iter()
        .map(|mut s| {
            let key = s["key"].as_str().unwrap_or("").to_string();
            let mine = set.iter().find(|(k, _)| *k == key).map(|(_, v)| v);
            s["value"] = current(&s, mine);
            s["customised"] = json!(mine.is_some());
            if let Some(m) = mine {
                s["updated"] = json!(iso(m.updated_at));
                s["by"] = json!(m.by);
            }
            s
        })
        .collect();
    Ok(Value::Array(list))
}

/// GET /v1/apps/`<app>`/settings
pub fn get(conn: &Connection, c: &Caller, slug: &str) -> Result<Value> {
    require_role(c, "builder", "see app settings")?;
    let app = crate::control::get_app(conn, c, slug)?;
    Ok(json!({ "app": app.slug, "settings": for_app(conn, &app)? }))
}

/// Check a whole set of changes against the declarations before anything is written: { key: value, key: null }.
/// null puts a setting back to its default.
pub fn check_changes(declared: &[Value], o: &Map<String, Value>) -> Result<Vec<(String, Option<Value>)>> {
    let mut out = Vec::new();
    for (k, v) in o {
        let Some(s) = declared.iter().find(|s| s["key"] == k.as_str()) else {
            let known: Vec<&str> = declared.iter().filter_map(|s| s["key"].as_str()).collect();
            let hint =
                if known.is_empty() { "This app declares no settings.".to_string() } else { format!("It has: {}.", known.join(", ")) };
            return Err(
                Problem::new(400, "unknown_setting", format!("There is no setting called \"{k}\". {hint}")).with("setting", json!(k))
            );
        };
        if v.is_null() {
            out.push((k.clone(), None));
        } else {
            out.push((k.clone(), Some(check_value(s, v)?)));
        }
    }
    Ok(out)
}

/// Write checked changes, inside the caller's transaction. Returns image files that a reset left behind, to delete.
/// Changing settings bumps the app's runtime revision, so server code sees the new env.SETTINGS on its next request.
pub fn write(x: &Connection, app_id: &str, actor: &str, changes: &[(String, Option<Value>)]) -> Result<Vec<String>> {
    let mut gone = Vec::new();
    for (k, v) in changes {
        let old: Option<(Option<String>, i64)> =
            x.first("SELECT content_type, bytes FROM app_settings WHERE app_id = ? AND key = ?", params![app_id, k], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })?;
        if let Some((Some(_), bytes)) = old {
            crate::usage::add_file_bytes(x, app_id, -bytes)?;
            gone.push(format!("{app_id}/_settings/{k}"));
        }
        match v {
            None => {
                x.run("DELETE FROM app_settings WHERE app_id = ? AND key = ?", params![app_id, k])?;
            }
            Some(v) => {
                x.run(
                    "INSERT INTO app_settings (app_id, key, value, content_type, bytes, updated_at, updated_by) VALUES (?,?,?,NULL,0,?,?)
                     ON CONFLICT(app_id, key) DO UPDATE SET value = excluded.value, content_type = NULL, bytes = 0, updated_at = excluded.updated_at, updated_by = excluded.updated_by",
                    params![app_id, k, v.to_string(), now(), actor],
                )?;
            }
        }
    }
    if !changes.is_empty() {
        x.run("UPDATE apps SET secrets_rev = secrets_rev + 1 WHERE id = ?", [app_id])?;
    }
    Ok(gone)
}

/// PATCH /v1/apps/`<app>`/settings { key: value, ... }: change some settings; null puts one back to its default.
pub async fn update(st: &State, c: &Caller, slug: &str, o: Map<String, Value>) -> Result<Value> {
    let (c2, slug2) = (c.clone(), slug.to_string());
    let (out, gone) = st
        .db
        .call(move |conn| {
            require_role(&c2, "builder", "change app settings")?;
            let app = crate::control::get_app(conn, &c2, &slug2)?;
            crate::abuse::check_up(conn, &app)?;
            let changes = check_changes(&settable(conn, &app)?, &o)?;
            let gone = tx(conn, |x| {
                let gone = write(x, &app.id, &c2.actor, &changes)?;
                let keys: Vec<&str> = changes.iter().map(|(k, _)| k.as_str()).collect();
                if !keys.is_empty() {
                    event(x, &c2.workspace.id, &c2.actor, Some(&app.id), "settings_changed", &keys.join(", "))?;
                }
                Ok(gone)
            })?;
            Ok((json!({ "app": app.slug, "settings": for_app(conn, &app)? }), gone))
        })
        .await?;
    for k in gone {
        st.store.delete(&k).await?;
    }
    Ok(out)
}

/// PUT /v1/apps/`<app>`/settings/`<key>` with the picture as the body: set an image setting, such as a logo.
pub async fn put_image(st: &State, c: &Caller, slug: &str, key: &str, body: Vec<u8>) -> Result<Value> {
    let ct = match crate::market::sniff_media(&body) {
        Some(("image", ct)) => ct,
        _ => return Err(Problem::new(415, "bad_image", "An image setting takes a PNG, JPEG, WebP or GIF picture.")),
    };
    if body.len() > IMAGE_BYTES {
        return Err(Problem::new(413, "too_large", "An image setting can be at most 1 MB."));
    }
    let (c2, slug2, key2, cfg, size) = (c.clone(), slug.to_string(), key.to_string(), st.cfg.clone(), body.len() as i64);
    let app = st
        .db
        .call(move |conn| {
            require_role(&c2, "builder", "change app settings")?;
            let app = crate::control::get_app(conn, &c2, &slug2)?;
            crate::abuse::check_up(conn, &app)?;
            let decl = settable(conn, &app)?;
            match decl.iter().find(|s| s["key"] == key2.as_str()) {
                Some(s) if s["type"] == "image" => {}
                Some(s) => {
                    return Err(Problem::new(
                        400,
                        "bad_setting",
                        format!("{} ({key2}) is not an image. Set it with PATCH instead.", s["label"].as_str().unwrap_or(&key2)),
                    ));
                }
                None => {
                    check_changes(&decl, &Map::from_iter([(key2.clone(), Value::Null)]))?;
                }
            }
            crate::usage::check_storage(conn, &cfg, &c2.workspace, size)?;
            Ok(app)
        })
        .await?;
    let file = format!("{}/_settings/{key}", app.id);
    st.store.put(&file, Bytes::from(body), Some(ct)).await?;
    let (c3, key3, app2) = (c.clone(), key.to_string(), app.clone());
    st.db
        .call(move |conn| {
            tx(conn, |x| {
                let old = x.count("SELECT COALESCE(SUM(bytes), 0) FROM app_settings WHERE app_id = ? AND key = ?", params![app2.id, key3])?;
                x.run(
                    "INSERT INTO app_settings (app_id, key, value, content_type, bytes, updated_at, updated_by) VALUES (?,?,?,?,?,?,?)
                     ON CONFLICT(app_id, key) DO UPDATE SET value = excluded.value, content_type = excluded.content_type, bytes = excluded.bytes, updated_at = excluded.updated_at, updated_by = excluded.updated_by",
                    params![app2.id, key3, json!(random_id("", 8)).to_string(), ct, size, now(), c3.actor],
                )?;
                crate::usage::add_file_bytes(x, &app2.id, size - old)?;
                x.run("UPDATE apps SET secrets_rev = secrets_rev + 1 WHERE id = ?", [&app2.id])?;
                event(x, &c3.workspace.id, &c3.actor, Some(&app2.id), "settings_changed", &format!("{key3} (image)"))
            })?;
            Ok(json!({ "app": app2.slug, "settings": for_app(conn, &app2)? }))
        })
        .await
}

/// An uploaded image setting's file, for the app's host (/_brod/settings/`<key>`) and the admin page.
pub async fn image(st: &State, app_id: &str, key: &str) -> Result<Option<(crate::storage::Object, String)>> {
    let (id, k) = (app_id.to_string(), key.to_string());
    let ct: Option<String> = st
        .db
        .call(move |c| c.first("SELECT content_type FROM app_settings WHERE app_id = ? AND key = ?", params![id, k], |r| r.get(0)))
        .await?
        .flatten();
    let Some(ct) = ct else { return Ok(None) };
    Ok(st.store.get(&format!("{app_id}/_settings/{key}")).await?.map(|o| (o, ct)))
}

/// Serve an image setting so a browser can only show it as the picture it is.
pub fn image_response(obj: crate::storage::Object, ct: String, public: bool) -> axum::response::Response {
    crate::http::response(
        200,
        obj.body,
        &[
            ("content-type", ct),
            ("content-length", obj.meta.size.to_string()),
            ("cache-control", if public { "public, max-age=300" } else { "private, max-age=300" }.into()),
            ("x-content-type-options", "nosniff".into()),
            ("content-security-policy", "default-src 'none'; sandbox".into()),
        ],
    )
}

/// GET /v1/apps/`<app>`/settings/`<key>`: an uploaded image, for the admin page.
pub async fn serve_image(st: &State, c: &Caller, slug: &str, key: &str) -> Result<axum::response::Response> {
    let (c2, slug2) = (c.clone(), slug.to_string());
    let app = st
        .db
        .call(move |conn| {
            require_role(&c2, "builder", "see app settings")?;
            crate::control::get_app(conn, &c2, &slug2)
        })
        .await?;
    match image(st, &app.id, key).await? {
        Some((obj, ct)) => Ok(image_response(obj, ct, false)),
        None => Err(Problem::new(404, "no_image", format!("{} has no image uploaded for {key}.", app.slug))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bundle(manifest: &str) -> Vec<BundleFile> {
        vec![
            BundleFile { path: "index.html".into(), bytes: b"<h1>x</h1>".to_vec() },
            BundleFile { path: "img/logo.png".into(), bytes: b"\x89PNG\r\n\x1a\n".to_vec() },
            BundleFile { path: MANIFEST.into(), bytes: manifest.as_bytes().to_vec() },
        ]
    }

    #[test]
    fn reads_the_declaration_from_brod_json() {
        let got = from_bundle(&bundle(
            r##"{ "settings": [
                { "key": "name", "label": "Shop name", "default": "  Corner shop " },
                { "key": "logo", "label": "Logo", "type": "image", "default": "/img/logo.png" },
                { "key": "accent", "type": "color", "default": "#ABC" },
                { "key": "tables", "type": "number", "min": 1, "max": 40, "default": "12" },
                { "key": "theme", "type": "select", "options": ["light", "dark"], "default": "dark", "help": "How it looks" } ] }"##,
        ))
        .unwrap()
        .unwrap();
        let v: Value = serde_json::from_str(&got).unwrap();
        assert_eq!(v[0], json!({ "key": "name", "label": "Shop name", "type": "text", "default": "Corner shop" }));
        assert_eq!(v[1]["default"], "img/logo.png");
        assert_eq!(v[2], json!({ "key": "accent", "label": "accent", "type": "color", "default": "#aabbcc" }));
        assert_eq!(v[3]["default"], json!(12.0));
        assert_eq!(v[4]["help"], "How it looks");
        // No brod.json, or one without settings, declares nothing.
        assert_eq!(from_bundle(&bundle("{}")).unwrap(), None);
        assert_eq!(from_bundle(&[]).unwrap(), None);
    }

    #[test]
    fn refuses_a_declaration_it_cannot_use() {
        for bad in [
            "not json",
            "[]",
            r#"{ "settings": {} }"#,
            r#"{ "settings": [{ "key": "Name" }] }"#,
            r#"{ "settings": [{ "key": "a" }, { "key": "a" }] }"#,
            r#"{ "settings": [{ "key": "a", "type": "file" }] }"#,
            r#"{ "settings": [{ "key": "a", "type": "color", "default": "green" }] }"#,
            r#"{ "settings": [{ "key": "a", "type": "image", "default": "missing.png" }] }"#,
            r#"{ "settings": [{ "key": "a", "type": "image", "default": "index.html" }] }"#,
            r#"{ "settings": [{ "key": "a", "type": "select" }] }"#,
            r#"{ "settings": [{ "key": "a", "type": "number", "max": 3, "default": 4 }] }"#,
        ] {
            assert_eq!(from_bundle(&bundle(bad)).unwrap_err().code, "bad_settings", "{bad}");
        }
    }

    #[test]
    fn checks_values_by_type() {
        let s = |t: Value| t;
        let ok = |d: Value, v: Value| check_value(&s(d), &v).unwrap();
        let no = |d: Value, v: Value| check_value(&s(d), &v).unwrap_err().code;
        assert_eq!(ok(json!({ "key": "c", "type": "color" }), json!("#FFF")), "#ffffff");
        assert_eq!(no(json!({ "key": "c", "type": "color" }), json!("red")), "bad_setting");
        assert_eq!(ok(json!({ "key": "u", "type": "url" }), json!("https://a.test/x")), "https://a.test/x");
        assert_eq!(no(json!({ "key": "u", "type": "url" }), json!("javascript:alert(1)")), "bad_setting");
        assert_eq!(ok(json!({ "key": "b", "type": "boolean" }), json!("true")), true);
        assert_eq!(no(json!({ "key": "s", "type": "select", "options": ["a"] }), json!("b")), "bad_setting");
        assert_eq!(no(json!({ "key": "t", "type": "text" }), json!("x".repeat(201))), "bad_setting");
        assert_eq!(no(json!({ "key": "i", "type": "image" }), json!("https://a.test/logo.png")), "bad_setting");
        assert_eq!(no(json!({ "key": "n", "type": "number", "min": 1 }), json!(0)), "bad_setting");
        assert_eq!(no(json!({ "key": "e", "type": "email" }), json!("nobody")), "bad_setting");
    }

    #[test]
    fn unknown_keys_are_named() {
        let decl = vec![json!({ "key": "name", "type": "text" })];
        let e = check_changes(&decl, &Map::from_iter([("colour".to_string(), json!("#fff"))])).unwrap_err();
        assert_eq!(e.code, "unknown_setting");
        assert!(e.message.contains("name"));
        let ok = check_changes(&decl, &Map::from_iter([("name".to_string(), Value::Null)])).unwrap();
        assert_eq!(ok, vec![("name".to_string(), None)]);
    }
}
