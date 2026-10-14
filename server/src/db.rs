// SPDX-License-Identifier: AGPL-3.0-only
// The metadata database: one SQLite file in WAL mode (the default), or Postgres when BROD_DATABASE_URL is set.
// Both get the same schema under the same migration names, and a small pool of connections.
// Database calls block, so every call runs on tokio's blocking pool and never on the async workers.
//
// Domain code writes SQLite's dialect, through `Sql`, `Row` and `params!`, and never sees
// the driver. On Postgres each statement is translated once (`pg_sql`) and kept prepared.
use postgres::types::{FromSql, IsNull, ToSql, Type};
use rusqlite::OpenFlags;
use rusqlite::types::{ToSqlOutput, ValueRef};
use serde_json::{Map, Value};
use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::Semaphore;

use crate::problem::{Problem, Result};

/// migrations/*.sql, built into the binary so the image needs nothing else. Applied migrations are recorded by name in d1_migrations.
pub const MIGRATIONS: &[(&str, &str)] = &[
    ("0001_init.sql", include_str!("../../migrations/0001_init.sql")),
    ("0002_server_apps.sql", include_str!("../../migrations/0002_server_apps.sql")),
    ("0003_app_slug_per_workspace.sql", include_str!("../../migrations/0003_app_slug_per_workspace.sql")),
    ("0004_oauth.sql", include_str!("../../migrations/0004_oauth.sql")),
    ("0005_billing_visits_spaces.sql", include_str!("../../migrations/0005_billing_visits_spaces.sql")),
    ("0006_app_data_bytes.sql", include_str!("../../migrations/0006_app_data_bytes.sql")),
    ("0007_custom_domains.sql", include_str!("../../migrations/0007_custom_domains.sql")),
    ("0008_marketplace.sql", include_str!("../../migrations/0008_marketplace.sql")),
    ("0009_app_password.sql", include_str!("../../migrations/0009_app_password.sql")),
    ("0010_abuse.sql", include_str!("../../migrations/0010_abuse.sql")),
    ("0011_listing_media.sql", include_str!("../../migrations/0011_listing_media.sql")),
    ("0012_analytics.sql", include_str!("../../migrations/0012_analytics.sql")),
    ("0013_staging.sql", include_str!("../../migrations/0013_staging.sql")),
    ("0014_listing_previews.sql", include_str!("../../migrations/0014_listing_previews.sql")),
    ("0015_app_settings.sql", include_str!("../../migrations/0015_app_settings.sql")),
    ("0016_network.sql", include_str!("../../migrations/0016_network.sql")),
    ("0017_token_expiry_scopes.sql", include_str!("../../migrations/0017_token_expiry_scopes.sql")),
    ("0018_version_history.sql", include_str!("../../migrations/0018_version_history.sql")),
    ("0019_files_and_editing.sql", include_str!("../../migrations/0019_files_and_editing.sql")),
];

/// The same migrations written for Postgres, under the same names, so d1_migrations reads the same on both.
pub const PG_MIGRATIONS: &[(&str, &str)] = &[
    ("0001_init.sql", include_str!("../../migrations-pg/0001_init.sql")),
    ("0002_server_apps.sql", include_str!("../../migrations-pg/0002_server_apps.sql")),
    ("0003_app_slug_per_workspace.sql", include_str!("../../migrations-pg/0003_app_slug_per_workspace.sql")),
    ("0004_oauth.sql", include_str!("../../migrations-pg/0004_oauth.sql")),
    ("0005_billing_visits_spaces.sql", include_str!("../../migrations-pg/0005_billing_visits_spaces.sql")),
    ("0006_app_data_bytes.sql", include_str!("../../migrations-pg/0006_app_data_bytes.sql")),
    ("0007_custom_domains.sql", include_str!("../../migrations-pg/0007_custom_domains.sql")),
    ("0008_marketplace.sql", include_str!("../../migrations-pg/0008_marketplace.sql")),
    ("0009_app_password.sql", include_str!("../../migrations-pg/0009_app_password.sql")),
    ("0010_abuse.sql", include_str!("../../migrations-pg/0010_abuse.sql")),
    ("0011_listing_media.sql", include_str!("../../migrations-pg/0011_listing_media.sql")),
    ("0012_analytics.sql", include_str!("../../migrations-pg/0012_analytics.sql")),
    ("0013_staging.sql", include_str!("../../migrations-pg/0013_staging.sql")),
    ("0014_listing_previews.sql", include_str!("../../migrations-pg/0014_listing_previews.sql")),
    ("0015_app_settings.sql", include_str!("../../migrations-pg/0015_app_settings.sql")),
    ("0016_network.sql", include_str!("../../migrations-pg/0016_network.sql")),
    ("0017_token_expiry_scopes.sql", include_str!("../../migrations-pg/0017_token_expiry_scopes.sql")),
    ("0018_version_history.sql", include_str!("../../migrations-pg/0018_version_history.sql")),
    ("0019_files_and_editing.sql", include_str!("../../migrations-pg/0019_files_and_editing.sql")),
];

/// Postgres advisory lock keys: one for every write transaction (see `tx`) and one while migrating.
const PG_WRITE_LOCK: i64 = 0x6272_6f64;
const PG_MIGRATE_LOCK: i64 = 0x6272_6f65;

#[derive(Clone)]
pub struct Db {
    inner: Arc<Inner>,
}

struct Inner {
    conns: Mutex<Vec<Connection>>,
    permits: Semaphore,
    /// Postgres only: how to open a replacement for a connection the server closed.
    pg: Option<postgres::Config>,
}

fn configure(conn: &rusqlite::Connection) -> rusqlite::Result<()> {
    conn.busy_timeout(Duration::from_secs(10))?;
    conn.execute_batch("PRAGMA journal_mode = WAL; PRAGMA synchronous = NORMAL; PRAGMA foreign_keys = ON; PRAGMA temp_store = MEMORY;")?;
    conn.set_prepared_statement_cache_capacity(128);
    Ok(())
}

impl Db {
    /// Open (or create) the SQLite file, apply pending migrations, and keep `size` connections ready.
    pub fn open(path: &Path, size: usize) -> std::result::Result<Db, String> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
        }
        let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_CREATE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_URI;
        let mut conns = Vec::with_capacity(size);
        for i in 0..size.max(1) {
            let conn = rusqlite::Connection::open_with_flags(path, flags).map_err(|e| format!("cannot open {}: {e}", path.display()))?;
            configure(&conn).map_err(|e| format!("cannot configure the database: {e}"))?;
            let conn = Connection(Backend::Sqlite(conn));
            if i == 0 {
                migrate(&conn)?;
            }
            conns.push(conn);
        }
        Ok(Db::from_conns(conns, None))
    }

    /// Connect to Postgres at `url` (postgres://user:pass@host:port/db), apply pending migrations, and keep `size` connections.
    pub fn open_pg(url: &str, size: usize) -> std::result::Result<Db, String> {
        let config: postgres::Config = url.parse().map_err(|e| format!("BROD_DATABASE_URL is not a valid Postgres URL: {e}"))?;
        Db::open_pg_config(config, size)
    }

    pub fn open_pg_config(config: postgres::Config, size: usize) -> std::result::Result<Db, String> {
        // The sync client runs its own small runtime, which cannot start inside an async task: connect from a plain thread.
        let c = config.clone();
        let conns = std::thread::spawn(move || -> std::result::Result<Vec<Connection>, String> {
            let mut conns = Vec::with_capacity(size);
            for i in 0..size.max(1) {
                let mut tries = 0;
                // Postgres started alongside Brod (Compose) may take a few seconds to accept connections.
                let conn = loop {
                    match Connection::pg(&c) {
                        Ok(conn) => break conn,
                        Err(e)
                            if i == 0
                                && tries < 30
                                && (e.as_db_error().is_none() || e.code() == Some(&postgres::error::SqlState::CANNOT_CONNECT_NOW)) =>
                        {
                            if tries == 0 {
                                eprintln!("waiting for Postgres: {e}");
                            }
                            tries += 1;
                            std::thread::sleep(Duration::from_secs(1));
                        }
                        Err(e) => return Err(format!("cannot connect to Postgres: {e}")),
                    }
                };
                if i == 0 {
                    migrate(&conn)?;
                }
                conns.push(conn);
            }
            Ok(conns)
        })
        .join()
        .map_err(|_| "connecting to Postgres panicked".to_string())??;
        Ok(Db::from_conns(conns, Some(config)))
    }

    fn from_conns(conns: Vec<Connection>, pg: Option<postgres::Config>) -> Db {
        Db { inner: Arc::new(Inner { permits: Semaphore::new(conns.len()), conns: Mutex::new(conns), pg }) }
    }

    /// Run `f` with a connection on the blocking pool.
    pub async fn call<R, F>(&self, f: F) -> Result<R>
    where
        R: Send + 'static,
        F: FnOnce(&mut Connection) -> Result<R> + Send + 'static,
    {
        let permit = self.inner.permits.acquire().await.map_err(Problem::internal)?;
        let inner = self.inner.clone();
        let result = tokio::task::spawn_blocking(move || {
            let mut conn = inner
                .conns
                .lock()
                .map_err(|_| Problem::internal("database pool poisoned"))?
                .pop()
                .ok_or_else(|| Problem::internal("database pool empty"))?;
            // Postgres may have restarted or dropped an idle connection: replace it rather than fail every call it serves.
            if let (Some(cfg), true) = (&inner.pg, conn.is_closed()) {
                match Connection::pg(cfg) {
                    Ok(fresh) => conn = fresh,
                    Err(e) => {
                        if let Ok(mut pool) = inner.conns.lock() {
                            pool.push(conn);
                        }
                        return Err(Problem::internal(format!("database: cannot reconnect: {e}")));
                    }
                }
            }
            let r = f(&mut conn);
            // A failed statement inside a transaction that was not rolled back must not leak into the next caller.
            if conn.in_transaction() {
                conn.rollback();
            }
            if let Ok(mut pool) = inner.conns.lock() {
                pool.push(conn);
            }
            r
        })
        .await
        .map_err(Problem::internal)?;
        drop(permit);
        result
    }
}

// ---------- values, parameters and rows ----------

/// One SQL value, the same five kinds as SQLite's storage classes. Postgres booleans read as 0 or 1, as SQLite stores them.
#[derive(Clone, Debug, PartialEq)]
pub enum Val {
    Null,
    Int(i64),
    Real(f64),
    Text(String),
    Blob(Vec<u8>),
}

/// Anything that binds as a statement parameter.
pub trait ToVal {
    fn to_val(&self) -> Val;
}

impl ToVal for Val {
    fn to_val(&self) -> Val {
        self.clone()
    }
}
impl ToVal for str {
    fn to_val(&self) -> Val {
        Val::Text(self.to_string())
    }
}
impl ToVal for String {
    fn to_val(&self) -> Val {
        Val::Text(self.clone())
    }
}
impl ToVal for i64 {
    fn to_val(&self) -> Val {
        Val::Int(*self)
    }
}
impl ToVal for i32 {
    fn to_val(&self) -> Val {
        Val::Int(i64::from(*self))
    }
}
impl ToVal for usize {
    fn to_val(&self) -> Val {
        Val::Int(i64::try_from(*self).unwrap_or(i64::MAX))
    }
}
impl ToVal for bool {
    fn to_val(&self) -> Val {
        Val::Int(i64::from(*self))
    }
}
impl ToVal for f64 {
    fn to_val(&self) -> Val {
        Val::Real(*self)
    }
}
impl ToVal for [u8] {
    fn to_val(&self) -> Val {
        Val::Blob(self.to_vec())
    }
}
impl ToVal for Vec<u8> {
    fn to_val(&self) -> Val {
        Val::Blob(self.clone())
    }
}
impl<T: ToVal + ?Sized> ToVal for &T {
    fn to_val(&self) -> Val {
        (**self).to_val()
    }
}
impl<T: ToVal> ToVal for Option<T> {
    fn to_val(&self) -> Val {
        self.as_ref().map_or(Val::Null, ToVal::to_val)
    }
}

/// A statement's parameters: an array of values (`[id]`, `params![a, b]`), a list, or `()` for none.
pub trait Params {
    fn vals(self) -> Vec<Val>;
}
impl<T: ToVal, const N: usize> Params for [T; N] {
    fn vals(self) -> Vec<Val> {
        self.iter().map(ToVal::to_val).collect()
    }
}
impl Params for Vec<Val> {
    fn vals(self) -> Vec<Val> {
        self
    }
}
impl Params for () {
    fn vals(self) -> Vec<Val> {
        Vec::new()
    }
}

/// `params![a, b, c]`: mixed parameter types for one statement, like rusqlite's macro of the same name.
macro_rules! params {
    ($($x:expr),* $(,)?) => { [$($crate::db::ToVal::to_val(&$x)),*] };
}
pub(crate) use params;

/// One result row, read by position or by column name.
pub struct Row<'a> {
    names: &'a [String],
    vals: Vec<Val>,
}

/// A column position, or a column name (matched without regard to case, as SQLite does).
pub trait RowIndex: std::fmt::Debug {
    fn idx(&self, names: &[String]) -> Option<usize>;
}
impl RowIndex for usize {
    fn idx(&self, names: &[String]) -> Option<usize> {
        (*self < names.len()).then_some(*self)
    }
}
impl RowIndex for &str {
    fn idx(&self, names: &[String]) -> Option<usize> {
        names.iter().position(|n| n.eq_ignore_ascii_case(self))
    }
}

/// A Rust type a column reads into. As strict as rusqlite: no text into numbers or numbers into text.
pub trait FromVal: Sized {
    fn from_val(v: &Val) -> Option<Self>;
}
impl FromVal for Val {
    fn from_val(v: &Val) -> Option<Self> {
        Some(v.clone())
    }
}
impl FromVal for i64 {
    fn from_val(v: &Val) -> Option<Self> {
        match v {
            Val::Int(i) => Some(*i),
            _ => None,
        }
    }
}
impl FromVal for f64 {
    fn from_val(v: &Val) -> Option<Self> {
        match v {
            Val::Real(f) => Some(*f),
            Val::Int(i) => Some(*i as f64),
            _ => None,
        }
    }
}
impl FromVal for bool {
    fn from_val(v: &Val) -> Option<Self> {
        match v {
            Val::Int(i) => Some(*i != 0),
            _ => None,
        }
    }
}
impl FromVal for String {
    fn from_val(v: &Val) -> Option<Self> {
        match v {
            Val::Text(s) => Some(s.clone()),
            _ => None,
        }
    }
}
impl FromVal for Vec<u8> {
    fn from_val(v: &Val) -> Option<Self> {
        match v {
            Val::Blob(b) => Some(b.clone()),
            Val::Text(s) => Some(s.as_bytes().to_vec()),
            _ => None,
        }
    }
}
impl<T: FromVal> FromVal for Option<T> {
    fn from_val(v: &Val) -> Option<Self> {
        match v {
            Val::Null => Some(None),
            v => T::from_val(v).map(Some),
        }
    }
}

impl Row<'_> {
    pub fn get<I: RowIndex, T: FromVal>(&self, i: I) -> Result<T> {
        let v = self.get_ref(&i)?;
        T::from_val(v).ok_or_else(|| {
            Problem::internal(format!("database: column {i:?} holds {v:?}, which does not read as {}", std::any::type_name::<T>()))
        })
    }
    pub fn get_ref(&self, i: &impl RowIndex) -> Result<&Val> {
        i.idx(self.names).map(|n| &self.vals[n]).ok_or_else(|| Problem::internal(format!("database: no column {i:?}")))
    }
    pub fn names(&self) -> &[String] {
        self.names
    }
    pub fn vals(&self) -> &[Val] {
        &self.vals
    }
}

impl rusqlite::ToSql for Val {
    fn to_sql(&self) -> rusqlite::Result<ToSqlOutput<'_>> {
        Ok(ToSqlOutput::Borrowed(match self {
            Val::Null => ValueRef::Null,
            Val::Int(i) => ValueRef::Integer(*i),
            Val::Real(f) => ValueRef::Real(*f),
            Val::Text(s) => ValueRef::Text(s.as_bytes()),
            Val::Blob(b) => ValueRef::Blob(b),
        }))
    }
}

impl From<ValueRef<'_>> for Val {
    fn from(v: ValueRef<'_>) -> Val {
        match v {
            ValueRef::Null => Val::Null,
            ValueRef::Integer(i) => Val::Int(i),
            ValueRef::Real(f) => Val::Real(f),
            ValueRef::Text(t) => Val::Text(String::from_utf8_lossy(t).into_owned()),
            ValueRef::Blob(b) => Val::Blob(b.to_vec()),
        }
    }
}

type BoxError = Box<dyn std::error::Error + Sync + Send>;

/// Binds to whatever type Postgres inferred for the parameter, the way SQLite's loose typing accepts any value.
impl ToSql for Val {
    fn to_sql(&self, ty: &Type, out: &mut bytes::BytesMut) -> std::result::Result<IsNull, BoxError> {
        let text = |s: &str, out: &mut bytes::BytesMut| -> std::result::Result<IsNull, BoxError> {
            if <&str as ToSql>::accepts(ty) { s.to_sql(ty, out) } else { Err(format!("cannot bind text to a {ty} parameter").into()) }
        };
        match self {
            Val::Null => Ok(IsNull::Yes),
            Val::Int(i) => match *ty {
                Type::INT8 => i.to_sql(ty, out),
                Type::INT4 => i32::try_from(*i)?.to_sql(ty, out),
                Type::INT2 => i16::try_from(*i)?.to_sql(ty, out),
                Type::FLOAT8 => (*i as f64).to_sql(ty, out),
                Type::FLOAT4 => (*i as f32).to_sql(ty, out),
                Type::BOOL => (*i != 0).to_sql(ty, out),
                _ => text(&i.to_string(), out),
            },
            Val::Real(f) => match *ty {
                Type::FLOAT8 => f.to_sql(ty, out),
                Type::FLOAT4 => (*f as f32).to_sql(ty, out),
                // SQLite keeps a whole number written as a float in an INTEGER column as a float.
                Type::INT8 if f.fract() == 0.0 && f.abs() < 9.0e15 => (*f as i64).to_sql(ty, out),
                _ => text(&f.to_string(), out),
            },
            Val::Text(s) => text(s, out),
            Val::Blob(b) if *ty == Type::BYTEA => b.as_slice().to_sql(ty, out),
            Val::Blob(_) => Err(format!("cannot bind a blob to a {ty} parameter").into()),
        }
    }
    fn accepts(_: &Type) -> bool {
        true
    }
    postgres::types::to_sql_checked!();
}

impl<'a> FromSql<'a> for Val {
    fn from_sql(ty: &Type, raw: &'a [u8]) -> std::result::Result<Val, BoxError> {
        Ok(match *ty {
            Type::INT8 => Val::Int(i64::from_sql(ty, raw)?),
            Type::INT4 => Val::Int(i32::from_sql(ty, raw)?.into()),
            Type::INT2 => Val::Int(i16::from_sql(ty, raw)?.into()),
            Type::BOOL => Val::Int(bool::from_sql(ty, raw)?.into()),
            Type::FLOAT8 => Val::Real(f64::from_sql(ty, raw)?),
            Type::FLOAT4 => Val::Real(f32::from_sql(ty, raw)?.into()),
            Type::BYTEA => Val::Blob(Vec::<u8>::from_sql(ty, raw)?),
            // SUM() over BIGINT is NUMERIC in Postgres, where SQLite gives an integer.
            Type::NUMERIC => numeric(raw)?,
            _ if <&str as FromSql>::accepts(ty) => Val::Text(String::from_sql(ty, raw)?),
            _ => return Err(format!("unsupported column type {ty}").into()),
        })
    }
    fn from_sql_null(_: &Type) -> std::result::Result<Val, BoxError> {
        Ok(Val::Null)
    }
    fn accepts(_: &Type) -> bool {
        true
    }
}

/// Postgres's binary NUMERIC: an integer when it is whole and fits, as SQLite's SUM gives, else a float.
fn numeric(raw: &[u8]) -> std::result::Result<Val, BoxError> {
    let word = |i: usize| -> std::result::Result<i16, BoxError> {
        raw.get(i..i + 2).map(|b| i16::from_be_bytes([b[0], b[1]])).ok_or_else(|| "short numeric".into())
    };
    let (ndigits, weight, sign) = (word(0)?, i64::from(word(2)?), word(4)? as u16);
    if sign == 0xC000 {
        return Ok(Val::Null); // NaN
    }
    let (mut f, mut int) = (0f64, Some(0i64));
    for d in 0..i64::from(ndigits) {
        let digit = i64::from(word(8 + 2 * d as usize)?);
        let exp = weight - d;
        f += digit as f64 * 10000f64.powi(exp as i32);
        int = match int {
            Some(n) if exp >= 0 => 10000i64.checked_pow(exp as u32).and_then(|p| p.checked_mul(digit)).and_then(|x| n.checked_add(x)),
            Some(n) if digit == 0 => Some(n),
            _ => None,
        };
    }
    let neg = sign == 0x4000;
    Ok(match int {
        Some(n) => Val::Int(if neg { -n } else { n }),
        None => Val::Real(if neg { -f } else { f }),
    })
}

// ---------- connections ----------

/// One database connection: SQLite or Postgres. Not shared between threads; the pool hands each call its own.
pub struct Connection(Backend);

enum Backend {
    Sqlite(rusqlite::Connection),
    Pg(Box<Pg>),
}

struct Pg {
    /// The sync client. Always Some until dropped (see `Drop`).
    client: RefCell<Option<postgres::Client>>,
    /// Prepared statements by their SQLite text, like rusqlite's prepare_cached.
    cache: RefCell<HashMap<String, postgres::Statement>>,
    /// Postgres does not report this on the wire the way SQLite's autocommit flag does, so `tx` keeps it.
    in_tx: Cell<bool>,
}

impl Drop for Pg {
    // The sync client blocks on its own runtime when it closes, which panics inside an async task. Close it on a plain thread.
    fn drop(&mut self) {
        if let Some(c) = self.client.get_mut().take() {
            let _ = std::thread::spawn(move || drop(c));
        }
    }
}

impl Connection {
    fn pg(config: &postgres::Config) -> std::result::Result<Connection, postgres::Error> {
        let client = config.connect(postgres::NoTls)?;
        Ok(Connection(Backend::Pg(Box::new(Pg { client: RefCell::new(Some(client)), cache: RefCell::default(), in_tx: Cell::new(false) }))))
    }

    /// One Postgres connection, outside the pool, for tools such as `brod migrate-to-postgres`. Not inside an async task.
    pub fn connect_pg(url: &str) -> std::result::Result<Connection, String> {
        let config: postgres::Config = url.parse().map_err(|e| format!("not a valid Postgres URL: {e}"))?;
        Connection::pg(&config).map_err(|e| format!("cannot connect to Postgres: {e}"))
    }

    pub fn is_postgres(&self) -> bool {
        matches!(self.0, Backend::Pg(_))
    }

    /// The SQLite file this connection has open, if it is SQLite.
    pub fn sqlite_path(&self) -> Option<String> {
        match &self.0 {
            Backend::Sqlite(c) => c.path().map(String::from),
            Backend::Pg(_) => None,
        }
    }

    fn is_closed(&self) -> bool {
        match &self.0 {
            Backend::Sqlite(_) => false,
            Backend::Pg(p) => p.client.borrow().as_ref().is_none_or(|c| c.is_closed()),
        }
    }

    fn in_transaction(&self) -> bool {
        match &self.0 {
            Backend::Sqlite(c) => !c.is_autocommit(),
            Backend::Pg(p) => p.in_tx.get(),
        }
    }

    /// Several statements separated by semicolons, without parameters.
    pub fn execute_batch(&self, sql: &str) -> Result<()> {
        match &self.0 {
            Backend::Sqlite(c) => Ok(c.execute_batch(sql)?),
            Backend::Pg(p) => Ok(p.with(|c| c.batch_execute(sql))?),
        }
    }

    fn begin(&self) -> Result<()> {
        match &self.0 {
            Backend::Sqlite(c) => Ok(c.execute_batch("BEGIN IMMEDIATE")?),
            Backend::Pg(p) => {
                p.with(|c| c.batch_execute(&format!("BEGIN; SELECT pg_advisory_xact_lock({PG_WRITE_LOCK})")))?;
                p.in_tx.set(true);
                Ok(())
            }
        }
    }

    fn commit(&self) -> Result<()> {
        match &self.0 {
            Backend::Sqlite(c) => Ok(c.execute_batch("COMMIT")?),
            Backend::Pg(p) => {
                let r = p.with(|c| c.batch_execute("COMMIT"));
                p.in_tx.set(false);
                Ok(r?)
            }
        }
    }

    fn rollback(&self) {
        match &self.0 {
            Backend::Sqlite(c) => {
                let _ = c.execute_batch("ROLLBACK");
            }
            Backend::Pg(p) => {
                let _ = p.with(|c| c.batch_execute("ROLLBACK"));
                p.in_tx.set(false);
            }
        }
    }

    /// Run a statement and hand each row to `each`, which returns false to stop early.
    fn query(&self, sql: &str, params: Vec<Val>, mut each: impl FnMut(Row) -> Result<bool>) -> Result<()> {
        match &self.0 {
            Backend::Sqlite(c) => {
                let mut stmt = c.prepare_cached(sql)?;
                let names: Vec<String> = stmt.column_names().into_iter().map(String::from).collect();
                let mut rows = stmt.query(rusqlite::params_from_iter(params.iter()))?;
                while let Some(row) = rows.next()? {
                    let vals = (0..names.len()).map(|i| row.get_ref(i).map(Val::from)).collect::<rusqlite::Result<Vec<Val>>>()?;
                    if !each(Row { names: &names, vals })? {
                        break;
                    }
                }
                Ok(())
            }
            Backend::Pg(p) => {
                let stmt = p.prepare(sql)?;
                let names: Vec<String> = stmt.columns().iter().map(|c| c.name().to_string()).collect();
                let refs: Vec<&(dyn ToSql + Sync)> = params.iter().map(|v| v as &(dyn ToSql + Sync)).collect();
                let rows = p.with(|c| c.query(&stmt, &refs))?;
                for row in rows {
                    let vals = (0..names.len()).map(|i| row.try_get::<_, Val>(i)).collect::<std::result::Result<Vec<Val>, _>>()?;
                    if !each(Row { names: &names, vals })? {
                        break;
                    }
                }
                Ok(())
            }
        }
    }

    /// Like `query`, but rows stream from Postgres as they arrive instead of being read into memory first, so a
    /// scan over many rows (analytics) holds one row at a time. `each` must not use this connection.
    fn stream(&self, sql: &str, params: Vec<Val>, mut each: impl FnMut(&Row) -> Result<()>) -> Result<()> {
        match &self.0 {
            Backend::Sqlite(_) => self.query(sql, params, |row| {
                each(&row)?;
                Ok(true)
            }),
            Backend::Pg(p) => {
                use postgres::fallible_iterator::FallibleIterator;
                let stmt = p.prepare(sql)?;
                let names: Vec<String> = stmt.columns().iter().map(|c| c.name().to_string()).collect();
                p.with(|c| {
                    let mut rows = c.query_raw(&stmt, params.iter())?;
                    let mut failed = None;
                    while let Some(row) = rows.next()? {
                        let vals = (0..names.len()).map(|i| row.try_get::<_, Val>(i)).collect::<std::result::Result<Vec<Val>, _>>()?;
                        if let Err(e) = each(&Row { names: &names, vals }) {
                            failed = Some(e);
                            break;
                        }
                    }
                    Ok(failed)
                })?
                .map_or(Ok(()), Err)
            }
        }
    }

    /// Run a statement that returns no rows; the number of rows it changed.
    fn execute(&self, sql: &str, params: Vec<Val>) -> Result<usize> {
        match &self.0 {
            Backend::Sqlite(c) => Ok(c.prepare_cached(sql)?.execute(rusqlite::params_from_iter(params.iter()))?),
            Backend::Pg(p) => {
                let stmt = p.prepare(sql)?;
                let refs: Vec<&(dyn ToSql + Sync)> = params.iter().map(|v| v as &(dyn ToSql + Sync)).collect();
                Ok(p.with(|c| c.execute(&stmt, &refs))? as usize)
            }
        }
    }
}

impl Pg {
    fn with<R>(&self, f: impl FnOnce(&mut postgres::Client) -> std::result::Result<R, postgres::Error>) -> Result<R> {
        let mut client = self.client.borrow_mut();
        let client = client.as_mut().ok_or_else(|| Problem::internal("database: connection closed"))?;
        Ok(f(client)?)
    }

    fn prepare(&self, sql: &str) -> Result<postgres::Statement> {
        if let Some(s) = self.cache.borrow().get(sql) {
            return Ok(s.clone());
        }
        let stmt = self.with(|c| c.prepare(&pg_sql(sql)))?;
        let mut cache = self.cache.borrow_mut();
        if cache.len() >= 256 {
            cache.clear();
        }
        cache.insert(sql.to_string(), stmt.clone());
        Ok(stmt)
    }
}

/// SQLite's dialect, as the domain code writes it, in Postgres's. Mechanical, and only for the
/// forms this code uses: `?` and `?N` placeholders; `x IS ?` (NULL-safe equality); `? IS NULL`, whose parameter Postgres
/// cannot type on its own (always text here); GROUP_CONCAT(x, sep); LIKE, which ignores ASCII case in SQLite;
/// INSERT OR IGNORE; and MAX(a, b) / MIN(a, b) with two or more arguments, SQLite's scalar forms of GREATEST and LEAST.
/// COLLATE NOCASE needs no change: migrations-pg/0005 makes a collation of that name. Quoted strings and identifiers
/// pass through untouched.
pub fn pg_sql(sql: &str) -> String {
    let mut src = sql.trim_start();
    let mut tail = "";
    if src.len() > 17 && src[..17].eq_ignore_ascii_case("INSERT OR IGNORE ") {
        src = &src[17..];
        tail = " ON CONFLICT DO NOTHING";
    }
    let mut out = String::with_capacity(sql.len() + 32);
    if !tail.is_empty() {
        out.push_str("INSERT ");
    }
    // SQLite numbers a bare ? one past the largest number used so far.
    let mut next = 1;
    let b = src.as_bytes();
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        if c == b'\'' || c == b'"' {
            let end = src[i + 1..].find(c as char).map_or(src.len(), |j| i + 1 + j + 1);
            out.push_str(&src[i..end]);
            i = end;
        } else if c == b'?' {
            let digits = src[i + 1..].bytes().take_while(u8::is_ascii_digit).count();
            let n = if digits == 0 { next } else { src[i + 1..i + 1 + digits].parse().unwrap_or(next) };
            next = next.max(n + 1);
            i += 1 + digits;
            let rest = src[i..].trim_start().to_ascii_uppercase();
            if rest.starts_with("IS NULL") || rest.starts_with("IS NOT NULL") {
                out.push_str(&format!("CAST(${n} AS TEXT)"));
                continue;
            }
            let upper = out.trim_end().to_ascii_uppercase();
            if ends_with_word(&upper, "IS NOT") {
                out.truncate(out.trim_end().len() - 3);
                out.push_str(&format!("DISTINCT FROM ${n}"));
            } else if ends_with_word(&upper, "IS") {
                out.truncate(out.trim_end().len());
                out.push_str(&format!(" NOT DISTINCT FROM ${n}"));
            } else {
                out.push_str(&format!("${n}"));
            }
        } else if c.is_ascii_alphabetic() || c == b'_' {
            let len = src[i..].bytes().take_while(|x| x.is_ascii_alphanumeric() || *x == b'_').count();
            let word = &src[i..i + len];
            if word.eq_ignore_ascii_case("GROUP_CONCAT") {
                out.push_str("string_agg");
            } else if word.eq_ignore_ascii_case("LIKE") {
                out.push_str("ILIKE");
            } else if (word.eq_ignore_ascii_case("MAX") || word.eq_ignore_ascii_case("MIN")) && has_two_args(&src[i + len..]) {
                out.push_str(if word.eq_ignore_ascii_case("MAX") { "GREATEST" } else { "LEAST" });
            } else {
                out.push_str(word);
            }
            i += len;
        } else {
            let len = src[i..].chars().next().map_or(1, char::len_utf8);
            out.push_str(&src[i..i + len]);
            i += len;
        }
    }
    out.push_str(tail);
    out
}

/// `rest` starts with a parenthesised argument list that has a comma at its top level.
fn has_two_args(rest: &str) -> bool {
    let Some(body) = rest.trim_start().strip_prefix('(') else {
        return false;
    };
    let (mut depth, mut quote) = (0, None);
    for c in body.chars() {
        match (quote, c) {
            (Some(q), _) if c == q => quote = None,
            (Some(_), _) => {}
            (None, '\'' | '"') => quote = Some(c),
            (None, '(') => depth += 1,
            (None, ')') if depth == 0 => return false,
            (None, ')') => depth -= 1,
            (None, ',') if depth == 0 => return true,
            _ => {}
        }
    }
    false
}

/// `s` (upper case) ends with the SQL words `w`, not as the tail of a longer word.
fn ends_with_word(s: &str, w: &str) -> bool {
    s.ends_with(w) && s[..s.len() - w.len()].chars().next_back().is_none_or(|c| !(c.is_ascii_alphanumeric() || c == '_'))
}

/// BROD_AUTO_MIGRATE: whether opening the database applies pending migrations (the default) or refuses to start
/// with a list of them. `brod migrate` applies them either way. Set once at start (main.rs).
static AUTO_MIGRATE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(true);
pub fn set_auto_migrate(on: bool) {
    AUTO_MIGRATE.store(on, std::sync::atomic::Ordering::Relaxed);
}

/// Apply the migrations in order, each in its own transaction, recorded in d1_migrations (a name kept from Brod's first, Cloudflare D1-based version).
pub fn migrate(conn: &Connection) -> std::result::Result<(), String> {
    let pg = conn.is_postgres();
    let (set, table) = if pg {
        // Two servers starting at once must not both apply the same migration.
        conn.execute_batch(&format!("SELECT pg_advisory_lock({PG_MIGRATE_LOCK})")).map_err(|e| e.to_string())?;
        (
            PG_MIGRATIONS,
            "CREATE TABLE IF NOT EXISTS d1_migrations (
               id BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY, name TEXT UNIQUE, applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL)",
        )
    } else {
        (
            MIGRATIONS,
            "CREATE TABLE IF NOT EXISTS d1_migrations (
               id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT UNIQUE, applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL)",
        )
    };
    let result = (|| {
        conn.execute_batch(table).map_err(|e| e.to_string())?;
        let mut pending = Vec::new();
        for (name, sql) in set {
            if !conn.exists("SELECT 1 FROM d1_migrations WHERE name = ?", [name]).map_err(|e| e.to_string())? {
                pending.push((name, sql));
            }
        }
        if pending.is_empty() {
            println!("database: schema up to date ({} migrations)", set.len());
            return Ok(());
        }
        if !AUTO_MIGRATE.load(std::sync::atomic::Ordering::Relaxed) {
            let names: Vec<&str> = pending.iter().map(|(n, _)| **n).collect();
            return Err(format!(
                "database: {} migrations are waiting ({}) and BROD_AUTO_MIGRATE is off. Back up the database, then run: brod migrate",
                names.len(),
                names.join(", ")
            ));
        }
        for (name, sql) in &pending {
            let script = format!("BEGIN;\n{sql}\n;INSERT INTO d1_migrations (name) VALUES ('{}');", name.replace('\'', "''"));
            // SQLite changes a constraint by rebuilding the table (0003, 0009). With foreign keys on, dropping the old
            // table counts every row that points at it as broken, though the new table takes its place with the same
            // ids. So, as SQLite's own procedure for this says, they are off while a migration runs and checked before
            // it commits. (PRAGMA foreign_keys does nothing inside a transaction, hence outside BEGIN.)
            if !pg {
                conn.execute_batch("PRAGMA foreign_keys = OFF").map_err(|e| e.to_string())?;
            }
            let applied = conn.execute_batch(&script).and_then(|_| {
                if !pg && conn.exists("PRAGMA foreign_key_check", ())? {
                    return Err(Problem::internal("it leaves rows pointing at rows that do not exist"));
                }
                conn.execute_batch("COMMIT")
            });
            if !pg {
                conn.execute_batch("PRAGMA foreign_keys = ON").map_err(|e| e.to_string())?;
            }
            if let Err(e) = applied {
                let _ = conn.execute_batch("ROLLBACK");
                return Err(format!("Migration {name} failed and was rolled back: {e}"));
            }
        }
        let (first, last) = (pending[0].0, pending[pending.len() - 1].0);
        let range = if pending.len() == 1 { first.to_string() } else { format!("{first} to {last}") };
        println!("database: applied {} new migrations ({range}); schema up to date", pending.len());
        Ok(())
    })();
    if pg {
        let _ = conn.execute_batch(&format!("SELECT pg_advisory_unlock({PG_MIGRATE_LOCK})"));
    }
    result
}

/// Copy the database to `to` with VACUUM INTO: consistent while the server keeps writing, and without the WAL file.
pub fn backup(from: &Path, to: &Path) -> std::result::Result<(), String> {
    if to.exists() {
        std::fs::remove_file(to).map_err(|e| format!("cannot replace {}: {e}", to.display()))?;
    }
    let conn = rusqlite::Connection::open_with_flags(from, OpenFlags::SQLITE_OPEN_READ_ONLY)
        .map_err(|e| format!("cannot open {}: {e}", from.display()))?;
    conn.busy_timeout(Duration::from_secs(30)).map_err(|e| e.to_string())?;
    conn.execute("VACUUM INTO ?", [to.to_string_lossy()]).map_err(|e| e.to_string())?;
    Ok(())
}

/// Several writes as one transaction: all apply or none do. SQLite's BEGIN IMMEDIATE takes the
/// write lock up front, so two writers queue on the busy timeout instead of failing on a lock upgrade. On Postgres
/// every transaction takes one advisory lock for the same effect: writers go one at a time, so a check and the write
/// that depends on it (limits, last admin, version numbers) cannot interleave with another writer's.
pub fn tx<R>(conn: &Connection, f: impl FnOnce(&Connection) -> Result<R>) -> Result<R> {
    conn.begin()?;
    match f(conn) {
        Ok(r) => {
            conn.commit()?;
            Ok(r)
        }
        Err(e) => {
            conn.rollback();
            Err(e)
        }
    }
}

/// Query helpers: first(), all() and run().
pub trait Sql {
    fn first<T, P: Params>(&self, sql: &str, params: P, map: impl FnOnce(&Row) -> Result<T>) -> Result<Option<T>>;
    fn all<T, P: Params>(&self, sql: &str, params: P, map: impl FnMut(&Row) -> Result<T>) -> Result<Vec<T>>;
    fn run<P: Params>(&self, sql: &str, params: P) -> Result<usize>;
    fn exists<P: Params>(&self, sql: &str, params: P) -> Result<bool>;
    fn count<P: Params>(&self, sql: &str, params: P) -> Result<i64>;
    /// Rows as JSON objects with the columns in order.
    fn rows_json<P: Params>(&self, sql: &str, params: P) -> Result<Vec<Value>>;
    /// Hand each row to `f` as it is read, without collecting them (see `Connection::stream`).
    fn each<P: Params>(&self, sql: &str, params: P, f: impl FnMut(&Row) -> Result<()>) -> Result<()>;
}

impl Sql for Connection {
    fn first<T, P: Params>(&self, sql: &str, params: P, map: impl FnOnce(&Row) -> Result<T>) -> Result<Option<T>> {
        let mut map = Some(map);
        let mut out = None;
        self.query(sql, params.vals(), |row| {
            if let Some(m) = map.take() {
                out = Some(m(&row)?);
            }
            Ok(false)
        })?;
        Ok(out)
    }
    fn all<T, P: Params>(&self, sql: &str, params: P, mut map: impl FnMut(&Row) -> Result<T>) -> Result<Vec<T>> {
        let mut out = Vec::new();
        self.query(sql, params.vals(), |row| {
            out.push(map(&row)?);
            Ok(true)
        })?;
        Ok(out)
    }
    fn run<P: Params>(&self, sql: &str, params: P) -> Result<usize> {
        self.execute(sql, params.vals())
    }
    fn exists<P: Params>(&self, sql: &str, params: P) -> Result<bool> {
        Ok(self.first(sql, params, |_| Ok(()))?.is_some())
    }
    fn count<P: Params>(&self, sql: &str, params: P) -> Result<i64> {
        Ok(self.first(sql, params, |r| r.get::<_, Option<i64>>(0))?.flatten().unwrap_or(0))
    }
    fn each<P: Params>(&self, sql: &str, params: P, f: impl FnMut(&Row) -> Result<()>) -> Result<()> {
        self.stream(sql, params.vals(), f)
    }
    fn rows_json<P: Params>(&self, sql: &str, params: P) -> Result<Vec<Value>> {
        self.all(sql, params, |row| {
            let mut m = Map::new();
            for (name, v) in row.names().iter().zip(row.vals()) {
                m.insert(name.clone(), value_json(v));
            }
            Ok(Value::Object(m))
        })
    }
}

pub fn value_json(v: &Val) -> Value {
    match v {
        Val::Null => Value::Null,
        Val::Int(i) => Value::from(*i),
        Val::Real(f) => serde_json::Number::from_f64(*f).map(Value::Number).unwrap_or(Value::Null),
        Val::Text(t) => Value::String(t.clone()),
        Val::Blob(b) => Value::Array(b.iter().map(|x| Value::from(*x)).collect()),
    }
}

/// INSERT INTO events: the one audit log. Called inside the same transaction as the change it records.
pub fn event(conn: &Connection, workspace_id: &str, actor: &str, app_id: Option<&str>, action: &str, detail: &str) -> Result<()> {
    conn.run(
        "INSERT INTO events (workspace_id, app_id, at, actor, action, detail) VALUES (?,?,?,?,?,?)",
        params![workspace_id, app_id, crate::util::now(), actor, action, detail],
    )?;
    Ok(())
}

/// A fresh, migrated database for a test: SQLite in a temporary folder, or, when BROD_TEST_DATABASE_URL is set,
/// a new schema in that Postgres database (tests run in parallel, so each gets its own).
#[cfg(test)]
pub fn test_db() -> Db {
    match std::env::var("BROD_TEST_DATABASE_URL").ok().filter(|u| !u.is_empty()) {
        Some(url) => {
            let schema = format!("brod_test_{}", crate::util::random_id("", 8));
            let mut config: postgres::Config = url.parse().expect("BROD_TEST_DATABASE_URL is a Postgres URL");
            let c = config.clone();
            let s = schema.clone();
            std::thread::spawn(move || c.connect(postgres::NoTls)?.batch_execute(&format!("CREATE SCHEMA {s}")))
                .join()
                .expect("schema thread")
                .expect("test schema is created");
            config.options(&format!("-c search_path={schema}"));
            Db::open_pg_config(config, 2).expect("test database opens")
        }
        None => {
            let dir = std::env::temp_dir().join(format!("brod-test-{}", crate::util::random_id("", 8)));
            Db::open(&dir.join("brod.db"), 2).expect("test database opens")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn migrates_once_and_records_it() {
        let db = test_db();
        let names = db.call(|c| c.all("SELECT name FROM d1_migrations ORDER BY id", (), |r| r.get::<_, String>(0))).await.unwrap();
        assert_eq!(names, MIGRATIONS.iter().map(|(n, _)| *n).collect::<Vec<_>>());
        assert_eq!(names.last().map(String::as_str), Some("0019_files_and_editing.sql"));
        db.call(|c| migrate(c).map_err(Problem::internal)).await.unwrap();
        let path = db.call(|c| Ok(c.sqlite_path())).await.unwrap();
        let Some(path) = path else {
            return;
        };
        let fk = db.call(|c| c.count("PRAGMA foreign_keys", ())).await.unwrap();
        assert_eq!(fk, 1);
        let copy = std::path::Path::new(&path).with_file_name("copy.db");
        backup(std::path::Path::new(&path), &copy).unwrap();
        let n: i64 = rusqlite::Connection::open(&copy).unwrap().query_row("SELECT COUNT(*) FROM d1_migrations", [], |r| r.get(0)).unwrap();
        assert_eq!(n, MIGRATIONS.len() as i64);
    }

    #[tokio::test]
    async fn rebuilds_a_table_that_other_rows_point_at() {
        // 0009 rebuilds apps, which grants and versions point at. Run it again over rows like a live server's.
        let db = test_db();
        let kept = db
            .call(|c| {
                if c.is_postgres() {
                    return Ok(None);
                }
                c.execute_batch(
                    "INSERT INTO users (id, email, name, created_at) VALUES ('usr_m', 'm@x.test', '', 1);
                     INSERT INTO workspaces (id, slug, name, created_at) VALUES ('ws_m', 'mig', 'Mig', 1);
                     INSERT INTO apps (id, workspace_id, owner_id, slug, name, access, created_at, data_bytes) VALUES ('app_m', 'ws_m', 'usr_m', 'm', 'M', 'people', 1, 7);
                     INSERT INTO grants (app_id, subject, role, created_at) VALUES ('app_m', 'user:usr_m', 'viewer', 1);
                     INSERT INTO versions (app_id, n, note, actor, file_count, bytes, created_at) VALUES ('app_m', 1, '', 'm', 1, 1, 1);
                     DELETE FROM d1_migrations WHERE name = '0009_app_password.sql';",
                )?;
                migrate(c).map_err(Problem::internal)?;
                c.run("UPDATE apps SET access = 'password', password_hash = 'x' WHERE id = 'app_m'", ())?;
                Ok(Some((
                    c.count("SELECT data_bytes FROM apps WHERE id = 'app_m'", ())?,
                    c.count("SELECT COUNT(*) FROM grants WHERE app_id = 'app_m'", ())?,
                    c.count("PRAGMA foreign_keys", ())?,
                )))
            })
            .await
            .unwrap();
        if let Some(kept) = kept {
            assert_eq!(kept, (7, 1, 1));
        }
    }

    #[test]
    fn both_backends_know_the_same_migrations() {
        let names = |m: &[(&'static str, &'static str)]| m.iter().map(|(n, _)| *n).collect::<Vec<_>>();
        assert_eq!(names(MIGRATIONS), names(PG_MIGRATIONS));
    }

    #[test]
    fn translates_sqlite_sql_for_postgres() {
        assert_eq!(pg_sql("SELECT a FROM t WHERE x = ? AND y = ?"), "SELECT a FROM t WHERE x = $1 AND y = $2");
        assert_eq!(pg_sql("SELECT ?1 + ?2 + ?1, ?"), "SELECT $1 + $2 + $1, $3");
        assert_eq!(pg_sql("WHERE s.app_id IS ? AND b IS NOT ?"), "WHERE s.app_id IS NOT DISTINCT FROM $1 AND b IS DISTINCT FROM $2");
        assert_eq!(pg_sql("WHERE (? IS NULL OR w.slug = ?)"), "WHERE (CAST($1 AS TEXT) IS NULL OR w.slug = $2)");
        assert_eq!(pg_sql("SELECT GROUP_CONCAT(g.name, ', ') FROM g"), "SELECT string_agg(g.name, ', ') FROM g");
        assert_eq!(pg_sql("SET b = MAX(0, b + ?), c = MIN(f(x, y), 3)"), "SET b = GREATEST(0, b + $1), c = LEAST(f(x, y), 3)");
        assert_eq!(pg_sql("SELECT MAX(n), MIN(f(a, b)) FROM v"), "SELECT MAX(n), MIN(f(a, b)) FROM v");
        assert_eq!(pg_sql("WHERE logs LIKE ? ESCAPE '\\'"), "WHERE logs ILIKE $1 ESCAPE '\\'");
        assert_eq!(pg_sql("INSERT OR IGNORE INTO gm (a, b) VALUES (?,?)"), "INSERT INTO gm (a, b) VALUES ($1,$2) ON CONFLICT DO NOTHING");
        assert_eq!(pg_sql("SELECT '?', \"IS\" FROM this WHERE x = ?"), "SELECT '?', \"IS\" FROM this WHERE x = $1");
        assert_eq!(pg_sql("SELECT 'it''s ?' WHERE x = ?"), "SELECT 'it''s ?' WHERE x = $1");
    }

    #[tokio::test]
    async fn reads_and_binds_the_same_on_both() {
        let db = test_db();
        let row = db
            .call(|c| {
                c.run(
                    "INSERT INTO users (id, email, name, email_verified_at, created_at) VALUES (?,?,?,?,?)",
                    params!["u1", "a@b.c", "A", None::<i64>, 5],
                )?;
                c.first("SELECT id, email_verified_at, created_at, name = 'A' AS named FROM users WHERE email IS ?", ["a@b.c"], |r| {
                    Ok((r.get::<_, String>("ID")?, r.get::<_, Option<i64>>(1)?, r.get::<_, i64>("created_at")?, r.get::<_, bool>(3)?))
                })
            })
            .await
            .unwrap();
        assert_eq!(row, Some(("u1".to_string(), None, 5, true)));
        let sums = db
            .call(|c| {
                c.first(
                    "SELECT SUM(created_at), COALESCE(SUM(email_verified_at), 0), CAST(SUM(created_at) AS REAL) / 2 FROM users",
                    (),
                    |r| Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?, r.get::<_, f64>(2)?)),
                )
            })
            .await
            .unwrap();
        assert_eq!(sums, Some((5, 0, 2.5)));
        let json = db.call(|c| c.rows_json("SELECT id, created_at, email_verified_at FROM users", ())).await.unwrap();
        assert_eq!(json, vec![serde_json::json!({ "id": "u1", "created_at": 5, "email_verified_at": null })]);
        // A failed transaction leaves nothing behind, and the connection works for the next call.
        let failed = db
            .call(|c| {
                tx(c, |x| {
                    x.run("UPDATE users SET name = 'B'", ())?;
                    x.run("INSERT INTO users (id, email, created_at) VALUES ('u1', 'x', 1)", ())
                })
            })
            .await;
        assert!(failed.is_err());
        let name = db.call(|c| c.first("SELECT name FROM users", (), |r| r.get::<_, String>(0))).await.unwrap();
        assert_eq!(name.as_deref(), Some("A"));
        // RETURNING claims a row once.
        let claim = |db: Db| async move {
            db.call(|c| {
                c.first("UPDATE users SET email_verified_at = ? WHERE id = 'u1' AND email_verified_at IS NULL RETURNING id", [9], |r| {
                    r.get::<_, String>(0)
                })
            })
            .await
            .unwrap()
        };
        assert_eq!(claim(db.clone()).await.as_deref(), Some("u1"));
        assert_eq!(claim(db.clone()).await, None);
    }
}
