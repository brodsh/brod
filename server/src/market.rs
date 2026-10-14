// SPDX-License-Identifier: AGPL-3.0-only
// The marketplace: a builder lists one of the workspace's apps, and any workspace on the server installs its own copy
// and hosts it there, with its own address, sign-in, access, secrets and data.
//
// Publishing makes a release: a frozen copy of one version's files under "<listing id>/<n>/<path>", so the publisher
// can keep deploying, roll back or delete versions without changing what installers get. An installed app stays
// linked to its listing (the installs table). When the publisher puts out a newer release, the installed app shows
// it as an update; nothing is deployed until a builder in the installing workspace asks for it, and the update is
// an ordinary new version, so a rollback undoes it. Secrets and data are never copied.
//
// Every listing is free for now (price_cents 0). The price is stored and returned so paid listings can come later;
// until then a paid listing cannot be made, and an install of one is refused.
use crate::db::{Connection, params};
use bytes::Bytes;
use serde_json::{Map, Value, json};

use crate::control::{self, DeployTarget};
use crate::db::{Sql, event, tx};
use crate::model::{Caller, present};
use crate::people::require_role;
use crate::problem::{Problem, Result};
use crate::state::State;
use crate::tar::{BundleFile, FILE_BYTES};
use crate::util::{iso, js_slice, js_trim, now, random_id, slugify};

#[derive(Clone, Debug)]
pub struct Listing {
    pub id: String,
    pub workspace_id: String,
    pub app_id: Option<String>,
    pub slug: String,
    pub name: String,
    pub summary: String,
    pub description: String,
    pub price_cents: i64,
    pub currency: String,
    pub status: String,
    pub latest_release: i64,
    pub updated_at: i64,
    /// The publishing workspace's name.
    pub publisher: String,
}

const LISTING: &str = "SELECT l.id, l.workspace_id, l.app_id, l.slug, l.name, l.summary, l.description, l.price_cents, l.currency,
    l.status, l.latest_release, l.updated_at, w.name AS publisher FROM listings l JOIN workspaces w ON w.id = l.workspace_id";

impl Listing {
    fn from_row(r: &crate::db::Row) -> Result<Listing> {
        Ok(Listing {
            id: r.get("id")?,
            workspace_id: r.get("workspace_id")?,
            app_id: r.get("app_id")?,
            slug: r.get("slug")?,
            name: r.get("name")?,
            summary: r.get("summary")?,
            description: r.get("description")?,
            price_cents: r.get("price_cents")?,
            currency: r.get("currency")?,
            status: r.get("status")?,
            latest_release: r.get("latest_release")?,
            updated_at: r.get("updated_at")?,
            publisher: r.get("publisher")?,
        })
    }
    fn yours(&self, c: &Caller) -> bool {
        self.workspace_id == c.workspace.id
    }
}

/// A listing by its slug or id that the caller may see: any listed one, and every one their own workspace published.
fn find(conn: &Connection, c: &Caller, key: &str) -> Result<Listing> {
    let key = js_trim(key).to_lowercase();
    conn.first(
        &format!("{LISTING} WHERE (l.slug = ? OR l.id = ?) AND (l.status = 'listed' OR l.workspace_id = ?)"),
        params![key, key, c.workspace.id],
        Listing::from_row,
    )?
    .ok_or_else(|| Problem::new(404, "no_listing", format!("There is no app called \"{key}\" in the marketplace.")))
}

/// One of the caller's own workspace's listings, to change it.
fn own(conn: &Connection, c: &Caller, key: &str) -> Result<Listing> {
    let l = find(conn, c, key)?;
    if !l.yours(c) {
        return Err(Problem::new(
            403,
            "not_yours",
            format!("{} is published by {}. Only its publisher can change it.", l.name, l.publisher),
        ));
    }
    Ok(l)
}

/// Putting code in front of every workspace on the server is for a person to do, not an agent.
fn people_only(c: &Caller, what: &str) -> Result<()> {
    if c.agent {
        return Err(Problem::new(
            403,
            "people_only",
            format!(
                "An agent cannot {what}: it shares the app with every workspace on this server. A builder does it from the admin page's Marketplace."
            ),
        ));
    }
    Ok(())
}

/// An app that sends data outside goes into a workspace only once a person there has seen where, and said yes
/// (accept_network: true). An agent cannot say yes for them.
fn approve_network(c: &Caller, o: &Map<String, Value>, name: &str, hosts: &[String], what: &str) -> Result<()> {
    if hosts.is_empty() || (control::is_true(o, "accept_network") && !c.agent) {
        return Ok(());
    }
    let list = hosts.join(", ");
    if c.agent {
        return Err(Problem::new(
            403,
            "network_needs_a_person",
            format!("{name} {what} sends data to {list}. A person in this workspace must approve that, from the admin page's Marketplace."),
        )
        .with("network", json!(hosts)));
    }
    Err(Problem::new(
        409,
        "accept_network",
        format!("{name} {what} sends data to {list}. Check that this is what you expect, then send accept_network: true."),
    )
    .with("network", json!(hosts)))
}

fn free_only(o: &Map<String, Value>) -> Result<()> {
    let price = present(o, "price").map(|v| crate::model::js_to_number(Some(v)).unwrap_or(f64::NAN));
    match price {
        None => Ok(()),
        Some(0.0) => Ok(()),
        Some(_) => Err(Problem::new(400, "paid_not_yet", "Paid listings are not available yet. List the app for free (price 0) for now.")),
    }
}

fn text(o: &Map<String, Value>, key: &str, max: usize) -> Option<String> {
    present(o, key).map(|v| js_slice(js_trim(&crate::model::js_string(v)), max))
}

fn new_slug(conn: &Connection, name: &str) -> Result<String> {
    let base = slugify(name);
    for i in 0..6 {
        let s = if i == 0 { base.clone() } else { format!("{base}-{}", random_id("", 2)) };
        if !conn.exists("SELECT 1 FROM listings WHERE slug = ?", [&s])? {
            return Ok(s);
        }
    }
    Ok(format!("{base}-{}", random_id("", 4)))
}

fn kind(server: &Option<String>) -> &'static str {
    if server.is_some() { "server" } else { "static" }
}

/// What a listing looks like to the caller. Installs are counted, never named: who installed is the installer's business.
fn shape(conn: &Connection, c: &Caller, l: &Listing) -> Result<Value> {
    let latest: Option<(Option<String>, String, i64)> = conn.first(
        "SELECT server, secrets, created_at FROM releases WHERE listing_id = ? AND n = ?",
        params![l.id, l.latest_release],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
    )?;
    let installs = conn.count("SELECT COUNT(*) FROM installs WHERE listing_id = ?", [&l.id])?;
    let installed = conn.all(
        "SELECT a.slug FROM installs i JOIN apps a ON a.id = i.app_id WHERE i.listing_id = ? AND a.workspace_id = ? ORDER BY a.slug",
        params![l.id, c.workspace.id],
        |r| r.get::<_, String>(0),
    )?;
    let mut m = Map::new();
    m.insert("listing".into(), json!(l.slug));
    m.insert("name".into(), json!(l.name));
    m.insert("summary".into(), json!(l.summary));
    m.insert("description".into(), json!(l.description));
    m.insert("publisher".into(), json!(l.publisher));
    m.insert("price".into(), json!({ "amount": l.price_cents, "currency": l.currency }));
    m.insert("free".into(), json!(l.price_cents == 0));
    m.insert("status".into(), json!(l.status));
    m.insert("latest_release".into(), json!(l.latest_release));
    m.insert("updated".into(), json!(iso(l.updated_at)));
    if let Some((server, secrets, _)) = &latest {
        m.insert("kind".into(), json!(kind(server)));
        m.insert("needs_secrets".into(), serde_json::from_str(secrets).unwrap_or(json!([])));
        // What an installer can make their own (a name, a logo, colours...), as the app's maker declared it.
        m.insert("settings".into(), Value::Array(crate::settings::declared(conn, &l.id, l.latest_release)?));
        // Where it sends data: the only outside hosts it may reach, which installers approve (network.rs).
        m.insert("network".into(), json!(crate::network::declared(conn, &l.id, l.latest_release)?));
    }
    m.insert("installs".into(), json!(installs));
    m.insert("installed".into(), json!(installed));
    m.insert("media".into(), Value::Array(media_list(conn, l)?));
    let previews: Option<i64> = conn.first("SELECT previews_release FROM listings WHERE id = ?", [&l.id], |r| r.get(0))?.flatten();
    m.insert("previews_release".into(), json!(previews));
    m.insert("yours".into(), json!(l.yours(c)));
    if l.yours(c) {
        let app: Option<String> = match &l.app_id {
            Some(id) => conn.first("SELECT slug FROM apps WHERE id = ?", [id], |r| r.get(0))?,
            None => None,
        };
        m.insert("app".into(), json!(app));
    }
    Ok(Value::Object(m))
}

fn releases(conn: &Connection, c: &Caller, l: &Listing) -> Result<Vec<Value>> {
    let yours = l.yours(c);
    conn.all(
        "SELECT n, note, server, file_count, bytes, created_at, from_version FROM releases WHERE listing_id = ? ORDER BY n DESC LIMIT 50",
        [&l.id],
        |r| {
            let server: Option<String> = r.get(2)?;
            let mut v = json!({
                "release": r.get::<_, i64>(0)?, "note": r.get::<_, String>(1)?, "kind": kind(&server),
                "files": r.get::<_, i64>(3)?, "bytes": r.get::<_, i64>(4)?, "at": iso(r.get(5)?),
            });
            if yours {
                v["from_version"] = json!(r.get::<_, i64>(6)?);
            }
            Ok(v)
        },
    )
}

// ---------- browsing ----------

/// Every listed app with at least one release, newest first, optionally filtered by a word in its name or summary.
pub fn browse(conn: &Connection, c: &Caller, search: Option<&str>) -> Result<Value> {
    let q = search.map(|s| format!("%{}%", js_trim(s).to_lowercase().replace(['%', '_'], ""))).unwrap_or_else(|| "%".into());
    let found = conn.all(
        &format!("{LISTING} WHERE l.status = 'listed' AND l.latest_release > 0 AND (LOWER(l.name) LIKE ? OR LOWER(l.summary) LIKE ?) ORDER BY l.updated_at DESC LIMIT 200"),
        params![q, q],
        Listing::from_row,
    )?;
    let listings = found.iter().map(|l| shape(conn, c, l)).collect::<Result<Vec<_>>>()?;
    Ok(json!({ "listings": listings }))
}

pub fn get_listing(conn: &Connection, c: &Caller, key: &str) -> Result<Value> {
    let l = find(conn, c, key)?;
    let mut v = shape(conn, c, &l)?;
    v["releases"] = Value::Array(releases(conn, c, &l)?);
    Ok(v)
}

/// The listings the caller's workspace published, listed or not.
pub fn my_listings(conn: &Connection, c: &Caller) -> Result<Value> {
    let found =
        conn.all(&format!("{LISTING} WHERE l.workspace_id = ? ORDER BY l.created_at DESC"), [&c.workspace.id], Listing::from_row)?;
    let mut out = Vec::new();
    for l in &found {
        let mut v = shape(conn, c, l)?;
        v["releases"] = Value::Array(releases(conn, c, l)?);
        out.push(v);
    }
    Ok(json!({ "listings": out }))
}

// ---------- files ----------

/// Every file under a version or release prefix, read into memory as a bundle (paths relative to the prefix).
pub(crate) async fn read_tree(st: &State, prefix: &str) -> Result<Vec<BundleFile>> {
    let mut keys = Vec::new();
    let mut cursor = None;
    loop {
        let (objects, next) = st.store.list(prefix, cursor, 1000).await?;
        keys.extend(objects.into_iter().map(|o| o.key));
        match next {
            Some(c) => cursor = Some(c),
            None => break,
        }
    }
    let mut out = Vec::with_capacity(keys.len());
    for chunk in keys.chunks(20) {
        let got = futures_util::future::try_join_all(chunk.iter().map(|k| async move {
            let obj = st.store.get(k).await?.ok_or_else(|| Problem::internal(format!("{k} vanished while reading")))?;
            let bytes = crate::http::read_capped(obj.body, FILE_BYTES, k).await?;
            Ok::<_, Problem>(BundleFile { path: k[prefix.len()..].to_string(), bytes })
        }))
        .await?;
        out.extend(got);
    }
    Ok(out)
}

async fn write_tree(st: &State, prefix: &str, files: Vec<BundleFile>) -> Result<()> {
    let mut pending = files.into_iter();
    loop {
        let chunk: Vec<BundleFile> = pending.by_ref().take(20).collect();
        if chunk.is_empty() {
            return Ok(());
        }
        futures_util::future::try_join_all(chunk.into_iter().map(|f| {
            let key = format!("{prefix}{}", f.path);
            let ct = crate::util::content_type(&f.path);
            async move { st.store.put(&key, Bytes::from(f.bytes), Some(ct)).await }
        }))
        .await?;
    }
}

// ---------- publishing ----------

/// What a publish copies: one version of an app, and what an installer needs to know about it.
struct Source {
    app_id: String,
    version: i64,
    roles: String,
    secrets: String,
    server: Option<String>,
    settings: Option<String>,
    network: Option<String>,
    file_count: i64,
    bytes: i64,
}

fn source(conn: &Connection, c: &Caller, app_id: &str, version: Option<i64>) -> Result<Source> {
    let app = conn
        .first("SELECT * FROM apps WHERE id = ? AND workspace_id = ?", params![app_id, c.workspace.id], crate::model::AppRow::from_row)?
        .ok_or_else(|| {
            Problem::new(409, "no_app", "The app this listing was published from has been deleted, so there is nothing new to publish.")
        })?;
    let Some(n) = version.or(app.live_version) else {
        return Err(Problem::new(409, "not_deployed", format!("{} has no live version yet. Deploy it first.", app.slug)));
    };
    // Nothing taken down, or flagged by the phishing check, goes out to other workspaces (abuse.rs).
    crate::abuse::check_up(conn, &app)?;
    if let Some(reasons) = crate::abuse::flag_of(conn, &app.id, Some(n))? {
        return Err(Problem::new(403, "flagged", crate::abuse::flag_message(&app.slug, n, &reasons)).with("reasons", json!(reasons)));
    }
    let (server, file_count, bytes, settings, network) = conn
        .first("SELECT server, file_count, bytes, settings, network FROM versions WHERE app_id = ? AND n = ?", params![app.id, n], |r| {
            Ok((
                r.get::<_, Option<String>>(0)?,
                r.get::<_, i64>(1)?,
                r.get::<_, i64>(2)?,
                r.get::<_, Option<String>>(3)?,
                r.get::<_, Option<String>>(4)?,
            ))
        })?
        .ok_or_else(|| Problem::new(404, "no_version", format!("{} has no version {n}.", app.slug)))?;
    let secrets = conn.all("SELECT name FROM secrets WHERE app_id = ? ORDER BY name", [&app.id], |r| r.get::<_, String>(0))?;
    Ok(Source {
        app_id: app.id,
        version: n,
        roles: app.roles,
        secrets: json!(secrets).to_string(),
        server,
        settings,
        network,
        file_count,
        bytes,
    })
}

/// Copy the source version's files into the release, then record the release (and the listing, when it is new) in one
/// transaction. If recording fails, the copied files are removed again.
async fn publish(st: &State, c: &Caller, listing_id: &str, n: i64, src: Source, note: String, insert: Option<Listing>) -> Result<()> {
    let files = read_tree(st, &format!("{}/{}/", src.app_id, src.version)).await?;
    let prefix = format!("{listing_id}/{n}/");
    write_tree(st, &prefix, files).await?;
    let (c2, id) = (c.clone(), listing_id.to_string());
    let r = st
        .db
        .call(move |conn| {
            tx(conn, |x| {
                let t = now();
                let name = match &insert {
                    Some(l) => {
                        x.run(
                            "INSERT INTO listings (id, workspace_id, app_id, slug, name, summary, description, price_cents, currency, status, latest_release, created_at, updated_at)
                             VALUES (?,?,?,?,?,?,?,0,'usd','listed',?,?,?)",
                            params![id, c2.workspace.id, src.app_id, l.slug, l.name, l.summary, l.description, n, t, t],
                        )?;
                        event(x, &c2.workspace.id, &c2.actor, Some(&src.app_id), "listing_created", &format!("{} in the marketplace", l.name))?;
                        l.name.clone()
                    }
                    None => {
                        let changed = x.run(
                            "UPDATE listings SET latest_release = ?, updated_at = ? WHERE id = ? AND latest_release = ?",
                            params![n, t, id, n - 1],
                        )?;
                        if changed == 0 {
                            return Err(Problem::new(409, "busy", "Another release was published at the same moment. Try again."));
                        }
                        x.first("SELECT name FROM listings WHERE id = ?", [&id], |r| r.get::<_, String>(0))?.unwrap_or_default()
                    }
                };
                x.run(
                    "INSERT INTO releases (listing_id, n, from_version, note, roles, secrets, server, file_count, bytes, actor, created_at, settings, network) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    params![id, n, src.version, note, src.roles, src.secrets, src.server, src.file_count, src.bytes, c2.actor, t, src.settings, src.network],
                )?;
                event(x, &c2.workspace.id, &c2.actor, Some(&src.app_id), "release_published", &format!("{name} release {n} (from v{}): {note}", src.version))
            })
        })
        .await;
    if r.is_err() {
        let _ = st.store.delete_prefix(&prefix).await;
    }
    r
}

/// List one of the workspace's apps in the marketplace, with its live version as the first release.
/// Body: app, and optionally name, summary, description, version, note, price (0 only, for now).
pub async fn create_listing(st: &State, c: &Caller, o: Map<String, Value>) -> Result<Value> {
    let (c2, cfg) = (c.clone(), st.cfg.clone());
    let (src, listing, note) = st
        .db
        .call(move |conn| {
            require_role(&c2, "builder", "list apps in the marketplace")?;
            people_only(&c2, "list an app in the marketplace")?;
            free_only(&o)?;
            let app = control::get_app(conn, &c2, &control::body_str(&o, "app"))?;
            if let Some(slug) = conn.first("SELECT slug FROM listings WHERE app_id = ?", [&app.id], |r| r.get::<_, String>(0))? {
                return Err(Problem::new(
                    409,
                    "already_listed",
                    format!("{} is already in the marketplace as {slug}. Publish a new release of it instead.", app.slug),
                )
                .with("listing", json!(slug)));
            }
            let name = text(&o, "name", 60).filter(|n| !n.is_empty()).unwrap_or_else(|| app.display_name().to_string());
            let version = present(&o, "version").and_then(|v| crate::model::js_to_number(Some(v))).map(|v| v as i64);
            let src = source(conn, &c2, &app.id, version)?;
            crate::usage::check_storage(conn, &cfg, &c2.workspace, src.bytes)?;
            let listing = Listing {
                id: random_id("lst_", 10),
                workspace_id: c2.workspace.id.clone(),
                app_id: Some(app.id.clone()),
                slug: new_slug(conn, &name)?,
                name,
                summary: text(&o, "summary", 140).unwrap_or_default(),
                description: text(&o, "description", 4000).unwrap_or_default(),
                price_cents: 0,
                currency: "usd".into(),
                status: "listed".into(),
                latest_release: 1,
                updated_at: now(),
                publisher: c2.workspace.name.clone(),
            };
            let note = text(&o, "note", 200).filter(|n| !n.is_empty()).unwrap_or_else(|| "First release".into());
            Ok((src, listing, note))
        })
        .await?;
    let id = listing.id.clone();
    publish(st, c, &id, 1, src, note, Some(listing)).await?;
    crate::preview::spawn(st, &id);
    let (c3, id2) = (c.clone(), id.clone());
    st.db.call(move |conn| get_listing(conn, &c3, &id2)).await
}

/// Publish a new release of a listing: the app's live version, or `version`. Installed copies are offered it as an
/// update; none of them changes until its own workspace deploys it.
pub async fn publish_release(st: &State, c: &Caller, key: &str, o: Map<String, Value>) -> Result<Value> {
    let (c2, key2, cfg) = (c.clone(), key.to_string(), st.cfg.clone());
    let (id, n, src, note) = st
        .db
        .call(move |conn| {
            require_role(&c2, "builder", "publish releases")?;
            people_only(&c2, "publish a release to the marketplace")?;
            let l = own(conn, &c2, &key2)?;
            let Some(app_id) = &l.app_id else {
                return Err(Problem::new(
                    409,
                    "no_app",
                    "The app this listing was published from has been deleted, so there is nothing new to publish.",
                ));
            };
            let version = present(&o, "version").and_then(|v| crate::model::js_to_number(Some(v))).map(|v| v as i64);
            let src = source(conn, &c2, app_id, version)?;
            let last: Option<i64> =
                conn.first("SELECT from_version FROM releases WHERE listing_id = ? AND n = ?", params![l.id, l.latest_release], |r| {
                    r.get(0)
                })?;
            if last == Some(src.version) && version.is_none() {
                return Err(Problem::new(
                    409,
                    "nothing_new",
                    format!(
                        "Release {} is already v{} of the app. Deploy a new version first, then publish it.",
                        l.latest_release, src.version
                    ),
                ));
            }
            crate::usage::check_storage(conn, &cfg, &c2.workspace, src.bytes)?;
            let n = l.latest_release + 1;
            let note = text(&o, "note", 200).filter(|n| !n.is_empty()).unwrap_or_else(|| format!("Release {n}"));
            Ok((l.id, n, src, note))
        })
        .await?;
    publish(st, c, &id, n, src, note, None).await?;
    crate::preview::spawn(st, &id);
    let c3 = c.clone();
    let mut v = st.db.call(move |conn| get_listing(conn, &c3, &id)).await?;
    v["published"] = json!(n);
    Ok(v)
}

/// Change a listing's name, summary, description, or whether it is listed. Unlisting hides it from the marketplace
/// and stops new installs; apps already installed keep running and still see its releases.
pub fn update_listing(conn: &Connection, c: &Caller, key: &str, o: &Map<String, Value>) -> Result<Value> {
    require_role(c, "builder", "change marketplace listings")?;
    let l = own(conn, c, key)?;
    free_only(o)?;
    let name = text(o, "name", 60).filter(|n| !n.is_empty()).unwrap_or(l.name.clone());
    let summary = text(o, "summary", 140).unwrap_or(l.summary.clone());
    let description = text(o, "description", 4000).unwrap_or(l.description.clone());
    let status = match present(o, "status").map(crate::model::js_string) {
        None => l.status.clone(),
        Some(s) if s == "listed" || s == "unlisted" => s,
        Some(_) => return Err(Problem::new(400, "bad_status", "A listing's status is \"listed\" or \"unlisted\".")),
    };
    if status == "listed" && l.status != "listed" {
        people_only(c, "list an app in the marketplace again")?;
    }
    tx(conn, |x| {
        x.run(
            "UPDATE listings SET name = ?, summary = ?, description = ?, status = ?, updated_at = ? WHERE id = ?",
            params![name, summary, description, status, now(), l.id],
        )?;
        let what = if status != l.status { status.clone() } else { "details changed".into() };
        event(x, &c.workspace.id, &c.actor, l.app_id.as_deref(), "listing_updated", &format!("{name}: {what}"))
    })?;
    get_listing(conn, c, &l.id)
}

/// Take a listing out of the marketplace for good, with its releases. Installed copies keep running as ordinary apps,
/// no longer linked to anything.
pub async fn delete_listing(st: &State, c: &Caller, key: &str) -> Result<Value> {
    let (c2, key2) = (c.clone(), key.to_string());
    let l = st
        .db
        .call(move |conn| {
            require_role(&c2, "builder", "delete marketplace listings")?;
            let l = own(conn, &c2, &key2)?;
            tx(conn, |x| {
                let unlinked = x.run("DELETE FROM installs WHERE listing_id = ?", [&l.id])?;
                x.run("DELETE FROM releases WHERE listing_id = ?", [&l.id])?;
                x.run("DELETE FROM listing_media WHERE listing_id = ?", [&l.id])?;
                x.run("DELETE FROM listings WHERE id = ?", [&l.id])?;
                event(
                    x,
                    &c2.workspace.id,
                    &c2.actor,
                    l.app_id.as_deref(),
                    "listing_deleted",
                    &format!("{} ({unlinked} installed copies unlinked)", l.name),
                )
            })?;
            Ok(l)
        })
        .await?;
    st.store.delete_prefix(&format!("{}/", l.id)).await?;
    Ok(json!({ "deleted": l.slug }))
}

// ---------- installing and updating ----------

fn release_row(conn: &Connection, l: &Listing, n: i64) -> Result<(String, String, String)> {
    conn.first("SELECT note, roles, secrets FROM releases WHERE listing_id = ? AND n = ?", params![l.id, n], |r| {
        Ok((r.get(0)?, r.get(1)?, r.get(2)?))
    })?
    .ok_or_else(|| Problem::new(404, "no_release", format!("{} has no release {n}.", l.name)))
}

/// Install a copy of a listing's latest release into the caller's workspace as a new, private app, linked to the
/// listing for updates. Body: optionally name (the new app's name, default the listing's), and settings, the values
/// of the settings the release declares ({ key: value }), checked before anything is deployed. Images are uploaded after.
pub async fn install(st: &State, c: &Caller, key: &str, o: Map<String, Value>) -> Result<Value> {
    let (c2, key2) = (c.clone(), key.to_string());
    let wanted = match present(&o, "settings") {
        None => Map::new(),
        Some(Value::Object(m)) => m.clone(),
        Some(_) => return Err(Problem::new(400, "bad_settings", "\"settings\" is an object of setting keys and values.")),
    };
    let o2 = o.clone();
    let (l, n, roles, secrets, changes) = st
        .db
        .call(move |conn| {
            require_role(&c2, "builder", "install apps from the marketplace")?;
            let l = find(conn, &c2, &key2)?;
            if l.status != "listed" && !l.yours(&c2) {
                return Err(Problem::new(404, "no_listing", format!("{} is no longer in the marketplace.", l.name)));
            }
            if l.price_cents > 0 {
                return Err(Problem::new(
                    402,
                    "paid_listing",
                    format!("{} is a paid app, and paying for apps is not available yet.", l.name),
                ));
            }
            if l.latest_release == 0 {
                return Err(Problem::new(409, "no_release", format!("{} has no release to install yet.", l.name)));
            }
            let (_, roles, secrets) = release_row(conn, &l, l.latest_release)?;
            let n = l.latest_release;
            let changes = crate::settings::check_changes(&crate::settings::declared(conn, &l.id, n)?, &wanted)?;
            approve_network(&c2, &o2, &l.name, &crate::network::declared(conn, &l.id, n)?, "release")?;
            Ok((l, n, roles, secrets, changes))
        })
        .await?;
    let files = read_tree(st, &format!("{}/{n}/", l.id)).await?;
    let name = text(&o, "name", 60).filter(|n| !n.is_empty()).unwrap_or(l.name.clone());
    let target = DeployTarget {
        environment: Some("production".into()),
        app: None,
        name: Some(name),
        note: Some(format!("Installed {} release {n} from the marketplace", l.name)),
        base_version: None,
    };
    let mut out = control::deploy(st, c, target, files).await?;
    let (c3, slug, l2, roles2) = (c.clone(), out["app"].as_str().unwrap_or("").to_string(), l.clone(), roles.clone());
    st.db
        .call(move |conn| {
            let app = control::get_app(conn, &c3, &slug)?;
            tx(conn, |x| {
                let t = now();
                x.run(
                    "INSERT INTO installs (app_id, listing_id, release_n, installed_by, installed_at, updated_at) VALUES (?,?,?,?,?,?)",
                    params![app.id, l2.id, n, c3.actor, t, t],
                )?;
                x.run("UPDATE apps SET roles = ? WHERE id = ?", params![roles2, app.id])?;
                crate::settings::write(x, &app.id, &c3.actor, &changes)?;
                event(x, &c3.workspace.id, &c3.actor, Some(&app.id), "install", &format!("{} release {n} from {}", l2.name, l2.publisher))
            })
        })
        .await?;
    out["roles"] = serde_json::from_str(&roles).unwrap_or(Value::Null);
    out["needs_secrets"] = serde_json::from_str(&secrets).unwrap_or(json!([]));
    let (l5, n5) = (l.id.clone(), n);
    out["network"] = json!(st.db.call(move |conn| crate::network::declared(conn, &l5, n5)).await?);
    let (c4, slug4) = (c.clone(), out["app"].as_str().unwrap_or("").to_string());
    out["settings"] = st.db.call(move |conn| crate::settings::get(conn, &c4, &slug4)).await?["settings"].take();
    out["marketplace"] = json!({ "listing": l.slug, "name": l.name, "publisher": l.publisher, "release": n, "latest_release": n, "update_available": false });
    Ok(out)
}

/// The listing an installed app is linked to, and whether a newer release is waiting. None for other apps.
pub fn link(conn: &Connection, app_id: &str) -> Result<Option<Value>> {
    let row: Option<(i64, Listing)> = conn.first(
        "SELECT i.release_n, l.id, l.workspace_id, l.app_id, l.slug, l.name, l.summary, l.description, l.price_cents, l.currency,
            l.status, l.latest_release, l.updated_at, w.name AS publisher
            FROM installs i JOIN listings l ON l.id = i.listing_id JOIN workspaces w ON w.id = l.workspace_id WHERE i.app_id = ?",
        [app_id],
        |r| Ok((r.get(0)?, Listing::from_row(r)?)),
    )?;
    let Some((installed, l)) = row else { return Ok(None) };
    let newer = conn.all(
        "SELECT n, note, created_at, server FROM releases WHERE listing_id = ? AND n > ? ORDER BY n DESC LIMIT 20",
        params![l.id, installed],
        |r| {
            let server: Option<String> = r.get(3)?;
            Ok(json!({ "release": r.get::<_, i64>(0)?, "note": r.get::<_, String>(1)?, "at": iso(r.get(2)?), "kind": kind(&server) }))
        },
    )?;
    let network = crate::network::declared(conn, &l.id, installed)?;
    let network_added = crate::network::added(&network, &crate::network::declared(conn, &l.id, l.latest_release)?);
    Ok(Some(json!({
        "listing": l.slug, "name": l.name, "publisher": l.publisher, "listed": l.status == "listed",
        "release": installed, "latest_release": l.latest_release, "update_available": l.latest_release > installed, "newer": newer,
        "network": network, "network_added": network_added,
    })))
}

/// Deploy a newer release of an installed app's listing as the app's next version: the latest, or `release`.
/// This is the only way an installed app changes from the marketplace, and a rollback undoes it like any deploy.
pub async fn update_install(st: &State, c: &Caller, slug: &str, o: Map<String, Value>) -> Result<Value> {
    let (c2, slug2) = (c.clone(), slug.to_string());
    let asked = present(&o, "release").and_then(|v| crate::model::js_to_number(Some(v))).map(|v| v as i64);
    let o2 = o.clone();
    let (app_slug, l, n, note, secrets) = st
        .db
        .call(move |conn| {
            require_role(&c2, "builder", "deploy updates from the marketplace")?;
            let app = control::get_app(conn, &c2, &slug2)?;
            let listing_id: String =
                conn.first("SELECT listing_id FROM installs WHERE app_id = ?", [&app.id], |r| r.get(0))?.ok_or_else(|| {
                    Problem::new(
                        409,
                        "not_installed",
                        format!("{} was not installed from the marketplace, so it has no updates there.", app.slug),
                    )
                })?;
            let l = conn
                .first(&format!("{LISTING} WHERE l.id = ?"), [&listing_id], Listing::from_row)?
                .ok_or_else(|| Problem::internal("an install points at a missing listing"))?;
            if l.price_cents > 0 {
                return Err(Problem::new(
                    402,
                    "paid_listing",
                    format!("{} is a paid app now, and paying for apps is not available yet.", l.name),
                ));
            }
            let installed = conn.count("SELECT release_n FROM installs WHERE app_id = ?", [&app.id])?;
            let n = asked.unwrap_or(l.latest_release);
            if asked.is_none() && n <= installed {
                return Err(Problem::new(
                    409,
                    "up_to_date",
                    format!("{} already has the latest release of {} (release {installed}).", app.slug, l.name),
                ));
            }
            let (note, _, secrets) = release_row(conn, &l, n)?;
            // A release that sends data somewhere new is deployed only once a person approves the new hosts.
            let new_hosts =
                crate::network::added(&crate::network::declared(conn, &l.id, installed)?, &crate::network::declared(conn, &l.id, n)?);
            approve_network(&c2, &o2, &l.name, &new_hosts, &format!("release {n} also"))?;
            Ok((app.slug, l, n, note, secrets))
        })
        .await?;
    let files = read_tree(st, &format!("{}/{n}/", l.id)).await?;
    let target = DeployTarget {
        app: Some(app_slug.clone()),
        name: None,
        note: Some(js_slice(&format!("{} release {n}: {note}", l.name), 200)),
        // A builder chose to deploy this release, so it goes live as it always has.
        environment: Some("production".into()),
        base_version: None,
    };
    let mut out = control::deploy(st, c, target, files).await?;
    let (c3, l2) = (c.clone(), l.clone());
    let link = st
        .db
        .call(move |conn| {
            let app = control::get_app(conn, &c3, &app_slug)?;
            tx(conn, |x| {
                x.run("UPDATE installs SET release_n = ?, updated_at = ? WHERE app_id = ?", params![n, now(), app.id])?;
                event(x, &c3.workspace.id, &c3.actor, Some(&app.id), "marketplace_update", &format!("{} release {n}", l2.name))
            })?;
            link(conn, &app.id)
        })
        .await?;
    out["marketplace"] = link.unwrap_or(Value::Null);
    out["needs_secrets"] = serde_json::from_str(&secrets).unwrap_or(json!([]));
    Ok(out)
}

/// Stop following a listing: the app stays as it is, and is no longer offered its updates.
pub fn unlink(conn: &Connection, c: &Caller, slug: &str) -> Result<Value> {
    require_role(c, "builder", "unlink apps from the marketplace")?;
    let app = control::get_app(conn, c, slug)?;
    tx(conn, |x| {
        if x.run("DELETE FROM installs WHERE app_id = ?", [&app.id])? == 0 {
            return Err(Problem::new(409, "not_installed", format!("{} is not linked to the marketplace.", app.slug)));
        }
        event(x, &c.workspace.id, &c.actor, Some(&app.id), "marketplace_unlinked", &app.slug)
    })?;
    Ok(json!({ "app": app.slug, "marketplace": null }))
}

// ---------- previews: screenshots and screencasts ----------

/// A listing shows at most this many screenshots and screencasts.
pub const MEDIA_PER_LISTING: i64 = 6;

/// The media type of an uploaded preview, from its first bytes, never from what the uploader claims: these files are
/// served from the API host, so anything that is not plainly an image or a video (HTML, SVG, scripts) is refused.
pub fn sniff_media(b: &[u8]) -> Option<(&'static str, &'static str)> {
    let at = |i: usize, sig: &[u8]| b.len() >= i + sig.len() && &b[i..i + sig.len()] == sig;
    if at(0, b"\x89PNG\r\n\x1a\n") {
        Some(("image", "image/png"))
    } else if at(0, b"\xff\xd8\xff") {
        Some(("image", "image/jpeg"))
    } else if at(0, b"GIF87a") || at(0, b"GIF89a") {
        Some(("image", "image/gif"))
    } else if at(0, b"RIFF") && at(8, b"WEBP") {
        Some(("image", "image/webp"))
    } else if at(0, b"\x1a\x45\xdf\xa3") {
        Some(("video", "video/webm"))
    } else if at(4, b"ftyp") {
        // MP4 and QuickTime (what most screen recorders save) share the ISO base media layout.
        if at(8, b"qt  ") { Some(("video", "video/quicktime")) } else { Some(("video", "video/mp4")) }
    } else {
        None
    }
}

fn media_url(l: &Listing, id: &str) -> String {
    format!("/v1/marketplace/{}/media/{id}", l.slug)
}

fn media_list(conn: &Connection, l: &Listing) -> Result<Vec<Value>> {
    conn.all(
        "SELECT id, kind, content_type, bytes, caption, source FROM listing_media WHERE listing_id = ? ORDER BY position, created_at",
        [&l.id],
        |r| {
            let id: String = r.get(0)?;
            Ok(json!({
                "id": id, "kind": r.get::<_, String>(1)?, "type": r.get::<_, String>(2)?, "bytes": r.get::<_, i64>(3)?,
                "caption": r.get::<_, String>(4)?, "source": r.get::<_, String>(5)?, "url": media_url(l, &id),
            }))
        },
    )
}

/// Add a screenshot or screencast to one of the workspace's listings.
pub async fn add_media(st: &State, c: &Caller, key: &str, body: Vec<u8>, caption: Option<String>) -> Result<Value> {
    let Some((kind, ct)) = sniff_media(&body) else {
        return Err(Problem::new(
            415,
            "bad_media",
            "A preview is a screenshot (PNG, JPEG, WebP or GIF) or a screencast (MP4, MOV or WebM).",
        ));
    };
    let (c2, key2, cfg, size) = (c.clone(), key.to_string(), st.cfg.clone(), body.len() as i64);
    let (l, id, pos) = st
        .db
        .call(move |conn| {
            require_role(&c2, "builder", "add previews to listings")?;
            let l = own(conn, &c2, &key2)?;
            let n = conn.count("SELECT COUNT(*) FROM listing_media WHERE listing_id = ?", [&l.id])?;
            if n >= MEDIA_PER_LISTING {
                return Err(Problem::new(
                    409,
                    "too_many_media",
                    format!("A listing can show {MEDIA_PER_LISTING} screenshots and screencasts. Remove one first."),
                ));
            }
            crate::usage::check_storage(conn, &cfg, &c2.workspace, size)?;
            let pos = conn.count("SELECT COALESCE(MAX(position) + 1, 0) FROM listing_media WHERE listing_id = ?", [&l.id])?;
            Ok((l, random_id("med_", 10), pos))
        })
        .await?;
    st.store.put(&format!("{}/_media/{id}", l.id), Bytes::from(body), Some(ct)).await?;
    let (c3, l2, id2) = (c.clone(), l.clone(), id.clone());
    let caption = js_slice(js_trim(caption.as_deref().unwrap_or("")), 140);
    let caption2 = caption.clone();
    st.db
        .call(move |conn| {
            tx(conn, |x| {
                x.run(
                    "INSERT INTO listing_media (id, listing_id, kind, content_type, bytes, caption, position, created_at) VALUES (?,?,?,?,?,?,?,?)",
                    params![id2, l2.id, kind, ct, size, caption2, pos, now()],
                )?;
                x.run("UPDATE listings SET updated_at = ? WHERE id = ?", params![now(), l2.id])?;
                event(x, &c3.workspace.id, &c3.actor, l2.app_id.as_deref(), "listing_updated", &format!("{}: {kind} preview added", l2.name))
            })
        })
        .await?;
    Ok(json!({ "id": id, "kind": kind, "type": ct, "bytes": size, "caption": caption, "url": media_url(&l, &id) }))
}

pub async fn delete_media(st: &State, c: &Caller, key: &str, id: &str) -> Result<Value> {
    let (c2, key2, id2) = (c.clone(), key.to_string(), id.to_string());
    let l = st
        .db
        .call(move |conn| {
            require_role(&c2, "builder", "remove previews from listings")?;
            let l = own(conn, &c2, &key2)?;
            tx(conn, |x| {
                if x.run("DELETE FROM listing_media WHERE id = ? AND listing_id = ?", params![id2, l.id])? == 0 {
                    return Err(Problem::new(404, "no_media", "This listing has no such preview."));
                }
                event(x, &c2.workspace.id, &c2.actor, l.app_id.as_deref(), "listing_updated", &format!("{}: preview removed", l.name))
            })?;
            Ok(l)
        })
        .await?;
    st.store.delete(&format!("{}/_media/{id}", l.id)).await?;
    Ok(json!({ "deleted": id }))
}

/// A preview's file, to anyone signed in who may see the listing. Served so a browser can only show it as the image
/// or video it is: the sniffed type, nosniff, and a sandboxing CSP.
pub async fn serve_media(st: &State, c: &Caller, key: &str, id: &str) -> Result<axum::response::Response> {
    let (c2, key2, id2) = (c.clone(), key.to_string(), id.to_string());
    let (listing_id, ct) = st
        .db
        .call(move |conn| {
            let l = find(conn, &c2, &key2)?;
            let ct: String = conn
                .first("SELECT content_type FROM listing_media WHERE id = ? AND listing_id = ?", params![id2, l.id], |r| r.get(0))?
                .ok_or_else(|| Problem::new(404, "no_media", "This listing has no such preview."))?;
            Ok((l.id, ct))
        })
        .await?;
    let obj = st
        .store
        .get(&format!("{listing_id}/_media/{id}"))
        .await?
        .ok_or_else(|| Problem::new(404, "no_media", "This listing has no such preview."))?;
    Ok(crate::http::response(
        200,
        obj.body,
        &[
            ("content-type", ct),
            ("content-length", obj.meta.size.to_string()),
            ("cache-control", "private, max-age=3600".into()),
            ("x-content-type-options", "nosniff".into()),
            ("content-security-policy", "default-src 'none'; sandbox".into()),
            ("content-disposition", "inline".into()),
        ],
    ))
}

/// Take a listing's automatic previews again, now: a screenshot on a desktop and on a phone, and a short screencast,
/// of its latest release running in an empty sandbox (preview.rs).
pub async fn regenerate_previews(st: &State, c: &Caller, key: &str) -> Result<Value> {
    let (c2, key2) = (c.clone(), key.to_string());
    let l = st
        .db
        .call(move |conn| {
            require_role(&c2, "builder", "make previews for listings")?;
            own(conn, &c2, &key2)
        })
        .await?;
    if st.cfg.preview.is_none() {
        return Err(Problem::new(
            409,
            "previews_unavailable",
            "This server has no preview service, so it cannot take screenshots itself. Upload them instead, or ask its operator to set BROD_PREVIEW_URL.",
        ));
    }
    if crate::preview::generate(st, &l.id, None).await?.is_none() {
        return Err(Problem::new(409, "busy", "Previews for this listing are being made right now. Try again in a minute."));
    }
    let (c3, id) = (c.clone(), l.id.clone());
    st.db.call(move |conn| get_listing(conn, &c3, &id)).await
}

#[cfg(test)]
mod tests {
    use super::sniff_media;

    #[test]
    fn previews_are_typed_by_their_bytes() {
        assert_eq!(sniff_media(b"\x89PNG\r\n\x1a\n...."), Some(("image", "image/png")));
        assert_eq!(sniff_media(b"\xff\xd8\xff\xe0"), Some(("image", "image/jpeg")));
        assert_eq!(sniff_media(b"GIF89a.."), Some(("image", "image/gif")));
        assert_eq!(sniff_media(b"RIFF\0\0\0\0WEBPVP8 "), Some(("image", "image/webp")));
        assert_eq!(sniff_media(b"\0\0\0\x18ftypmp42"), Some(("video", "video/mp4")));
        assert_eq!(sniff_media(b"\0\0\0\x14ftypqt  "), Some(("video", "video/quicktime")));
        assert_eq!(sniff_media(b"\x1a\x45\xdf\xa3\x01"), Some(("video", "video/webm")));
        // Whatever the uploader calls it, markup is never a preview.
        assert_eq!(sniff_media(b"<svg xmlns='http://www.w3.org/2000/svg'><script>alert(1)</script></svg>"), None);
        assert_eq!(sniff_media(b"<!doctype html><script>"), None);
        assert_eq!(sniff_media(b""), None);
    }
}
