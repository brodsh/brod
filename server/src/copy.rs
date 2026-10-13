// `brod migrate-to-postgres <sqlite-file> <postgres-url>`: a one-time copy of a SQLite database into a fresh Postgres one.
// Every row of every table, with its ids, and the event and log id sequences carried on, so nothing is renumbered.
use rusqlite::OpenFlags;
use std::path::Path;

use crate::db::{Connection, MIGRATIONS, Sql, Val, migrate, tx};

/// Every table, parents before the tables that point at them. A table missing here stops the copy rather than being left behind.
pub const TABLES: &[&str] = &[
    "users",
    "workspaces",
    "members",
    "groups",
    "group_members",
    "spaces",
    "space_members",
    "invites",
    "tokens",
    "apps",
    "grants",
    "domains",
    "versions",
    "secrets",
    "app_settings",
    "network_reports",
    "uploads",
    "downloads",
    "editing",
    "login_links",
    "sessions",
    "app_codes",
    "confirmations",
    "reports",
    "events",
    "app_logs",
    "oauth_clients",
    "oauth_codes",
    "stripe_events",
    "visits",
    "visit_visitors",
    "page_views",
    "app_events",
    "request_stats",
    "listings",
    "releases",
    "installs",
    "rate_limits",
    "listing_media",
];

/// Tables whose ids come from AUTOINCREMENT in SQLite and an identity column in Postgres.
const SEQUENCES: &[&str] = &["events", "app_logs"];

/// Rows per INSERT: well under Postgres's 65,535 parameters for the widest table.
const BATCH: usize = 200;

/// Copy `from` (a SQLite file, which is only read) into the Postgres database at `url`, which must have no Brod data yet.
/// Returns the tables and how many rows each got. All of it is one Postgres transaction: on any error nothing is kept.
pub fn sqlite_to_postgres(from: &Path, url: &str) -> Result<Vec<(String, i64)>, String> {
    if !from.is_file() {
        return Err(format!("{} is not a file", from.display()));
    }
    let src = rusqlite::Connection::open_with_flags(from, OpenFlags::SQLITE_OPEN_READ_ONLY)
        .map_err(|e| format!("cannot open {}: {e}", from.display()))?;
    src.busy_timeout(std::time::Duration::from_secs(30)).map_err(|e| e.to_string())?;
    // One read transaction: a consistent snapshot even if a server is still writing (stop it first, or its later writes are not copied).
    src.execute_batch("BEGIN").map_err(|e| e.to_string())?;

    let applied: Vec<String> = src
        .prepare("SELECT name FROM d1_migrations ORDER BY id")
        .and_then(|mut s| s.query_map([], |r| r.get(0))?.collect())
        .map_err(|e| format!("{} is not a Brod database: {e}", from.display()))?;
    let pending: Vec<&str> = MIGRATIONS.iter().map(|(n, _)| *n).filter(|n| !applied.iter().any(|a| a == n)).collect();
    if !pending.is_empty() {
        return Err(format!(
            "{} has migrations this version of Brod would apply ({}). Start this version of brod on it once, stop it, then copy.",
            from.display(),
            pending.join(", ")
        ));
    }
    let tables: Vec<String> = src
        .prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' AND name != 'd1_migrations'")
        .and_then(|mut s| s.query_map([], |r| r.get(0))?.collect())
        .map_err(|e| e.to_string())?;
    if let Some(t) = tables.iter().find(|t| !TABLES.contains(&t.as_str())) {
        return Err(format!("{} has a table this copy does not know: {t}", from.display()));
    }

    let dst = Connection::connect_pg(url)?;
    if !dst.is_postgres() {
        return Err("the destination is not Postgres".into());
    }
    migrate(&dst)?;
    for t in TABLES {
        if dst.exists(&format!("SELECT 1 FROM {t} LIMIT 1"), ()).map_err(|e| e.to_string())? {
            return Err(format!("The Postgres database already has rows in {t}. Copy into a fresh, empty database."));
        }
    }

    let mut copied = Vec::new();
    tx(&dst, |pg| {
        for t in TABLES {
            let mut stmt = src.prepare(&format!("SELECT * FROM {t} ORDER BY rowid"))?;
            let cols: Vec<String> = stmt.column_names().into_iter().map(String::from).collect();
            let row_sql = format!("({})", vec!["?"; cols.len()].join(","));
            let head = format!("INSERT INTO {t} ({}) VALUES ", cols.join(", "));
            let mut rows = stmt.query([])?;
            let mut batch: Vec<Val> = Vec::with_capacity(BATCH * cols.len());
            let mut n: i64 = 0;
            let flush = |batch: &mut Vec<Val>| -> crate::problem::Result<()> {
                if batch.is_empty() {
                    return Ok(());
                }
                let k = batch.len() / cols.len();
                pg.run(&format!("{head}{}", vec![row_sql.as_str(); k].join(",")), std::mem::take(batch))
                    .map_err(|e| crate::problem::Problem::internal(format!("copying {t}: {e}")))?;
                Ok(())
            };
            while let Some(row) = rows.next()? {
                for i in 0..cols.len() {
                    batch.push(Val::from(row.get_ref(i)?));
                }
                n += 1;
                if batch.len() >= BATCH * cols.len() {
                    flush(&mut batch)?;
                }
            }
            flush(&mut batch)?;
            let landed = pg.count(&format!("SELECT COUNT(*) FROM {t}"), ())?;
            if landed != n {
                return Err(crate::problem::Problem::internal(format!("{t}: read {n} rows but {landed} arrived")));
            }
            copied.push((t.to_string(), n));
        }
        // Carry the id sequences on from SQLite's high-water mark, which can be past the largest id left after pruning.
        for t in SEQUENCES {
            let seq: i64 = src
                .query_row("SELECT seq FROM sqlite_sequence WHERE name = ?", [t], |r| r.get(0))
                .or_else(|e| if e == rusqlite::Error::QueryReturnedNoRows { Ok(0) } else { Err(e) })?;
            pg.first(
                &format!("SELECT setval(pg_get_serial_sequence('{t}', 'id'), GREATEST(?, COALESCE(MAX(id), 0)) + 1, false) FROM {t}"),
                [seq],
                |_| Ok(()),
            )?;
        }
        Ok(())
    })
    .map_err(|e| e.to_string())?;
    Ok(copied)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::{Db, params};

    /// The two migration sets build the same tables with the same columns, in the same order and of matching types.
    /// Needs Postgres: set BROD_TEST_DATABASE_URL.
    #[test]
    fn copies_a_sqlite_database_into_postgres() {
        let Some(url) = std::env::var("BROD_TEST_DATABASE_URL").ok().filter(|u| !u.is_empty()) else {
            return;
        };
        let dir = std::env::temp_dir().join(format!("brod-copy-{}", crate::util::random_id("", 8)));
        let path = dir.join("brod.db");
        // A SQLite database with a row in every table, and pruned events so the sequence is ahead of the largest id.
        drop(Db::open(&path, 1).unwrap());
        rusqlite::Connection::open(&path).unwrap().execute_batch(include_str!("../tests/fixtures/copy.sql")).unwrap();

        // A fresh database for the copy.
        let name = format!("brod_copy_{}", crate::util::random_id("", 8));
        let admin = Connection::connect_pg(&url).unwrap();
        admin.execute_batch(&format!("CREATE DATABASE {name}")).unwrap();
        let target_url = format!("{}/{name}", url.rsplit_once('/').unwrap().0);

        let copied = sqlite_to_postgres(&path, &target_url).unwrap();
        assert_eq!(copied.len(), TABLES.len());
        assert!(copied.iter().all(|(_, n)| *n > 0), "{copied:?}");
        // A second copy into the same database is refused.
        assert!(sqlite_to_postgres(&path, &target_url).unwrap_err().contains("already has rows"));

        let pg = Connection::connect_pg(&target_url).unwrap();
        let sqlite = rusqlite::Connection::open(&path).unwrap();
        for t in TABLES {
            let cols = |c: &Connection| {
                c.all(
                    "SELECT column_name, data_type FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = ? ORDER BY ordinal_position",
                    [t],
                    |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)),
                )
                .unwrap()
            };
            let lite: Vec<(String, String)> = sqlite
                .prepare(&format!("SELECT name, type FROM pragma_table_info('{t}') ORDER BY cid"))
                .unwrap()
                .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
                .unwrap()
                .collect::<rusqlite::Result<_>>()
                .unwrap();
            let want: Vec<(String, String)> = lite
                .into_iter()
                .map(|(n, ty)| {
                    // SQLite's INTEGER and REAL are 8 bytes, like Postgres's BIGINT and DOUBLE PRECISION.
                    let ty = match ty.as_str() {
                        "INTEGER" => "bigint".into(),
                        "REAL" => "double precision".into(),
                        _ => ty.to_lowercase(),
                    };
                    (n, ty)
                })
                .collect();
            assert_eq!(cols(&pg), want, "columns of {t}");
            // Every value arrived as it was. Sorted here: the two databases order text differently.
            let sorted = |mut rows: Vec<Vec<Val>>| {
                rows.sort_by_key(|r| format!("{r:?}"));
                rows
            };
            let mut s = sqlite.prepare(&format!("SELECT * FROM {t}")).unwrap();
            let n = s.column_count();
            let mine: Vec<Vec<Val>> = s
                .query_map([], |r| (0..n).map(|i| r.get_ref(i).map(Val::from)).collect())
                .unwrap()
                .collect::<rusqlite::Result<_>>()
                .unwrap();
            let theirs = pg.all(&format!("SELECT * FROM {t}"), (), |r| Ok(r.vals().to_vec())).unwrap();
            assert_eq!(sorted(mine), sorted(theirs), "rows of {t}");
        }
        // New events carry on past SQLite's high-water mark.
        pg.run("INSERT INTO events (workspace_id, at, actor, action, detail) VALUES ('ws_1', 1, 'a', 'b', 'c')", ()).unwrap();
        let id = pg.count("SELECT MAX(id) FROM events", ()).unwrap();
        assert_eq!(id, 101);
        pg.run(
            "INSERT INTO app_logs (app_id, at, method, path, outcome, logs, exceptions) VALUES (?,?,?,?,?,?,?)",
            params!["app_1", 1, "GET", "/", "ok", "[]", "[]"],
        )
        .unwrap();
        assert_eq!(pg.count("SELECT MAX(id) FROM app_logs", ()).unwrap(), 3);
        drop(pg);
        admin.execute_batch(&format!("DROP DATABASE {name} WITH (FORCE)")).unwrap();
    }
}
