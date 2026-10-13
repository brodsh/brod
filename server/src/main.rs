// SPDX-License-Identifier: AGPL-3.0-only
// brod: start the server. Configuration comes from the environment and an optional .env file (see .env.example and docs/configuration.md).
use std::time::Duration;

use brod::config::Config;
use brod::db::Db;
use brod::state::AppState;
use tokio::net::TcpListener;

fn main() {
    // `brod healthcheck`: for the container healthcheck, since the image has no shell or curl.
    if std::env::args().nth(1).as_deref() == Some("healthcheck") {
        std::process::exit(healthcheck());
    }
    // `brod migrate-to-postgres <sqlite-file> <postgres-url>`: the one-time move from SQLite to Postgres (see README).
    if std::env::args().nth(1).as_deref() == Some("migrate-to-postgres") {
        let (Some(from), Some(url)) = (std::env::args().nth(2), std::env::args().nth(3)) else {
            eprintln!("usage: brod migrate-to-postgres <sqlite-file> <postgres-url>");
            std::process::exit(2);
        };
        match brod::copy::sqlite_to_postgres(std::path::Path::new(&from), &url) {
            Ok(tables) => {
                for (t, n) in &tables {
                    println!("{t:>14}  {n} rows");
                }
                println!("copied {from} into Postgres. Set BROD_DATABASE_URL and restart brod.");
            }
            Err(e) => {
                eprintln!("copy failed, nothing was kept: {e}");
                std::process::exit(1);
            }
        }
        return;
    }
    let cfg = match Config::from_env() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(2);
        }
    };
    brod::db::set_auto_migrate(cfg.auto_migrate);
    // `brod migrate`: apply pending migrations and stop, for servers that run with BROD_AUTO_MIGRATE=false.
    if std::env::args().nth(1).as_deref() == Some("migrate") {
        brod::db::set_auto_migrate(true);
        open_db(&cfg);
        return;
    }
    // `brod setup-link`: a fresh one-time sign-in link for BROD_ADMIN_EMAIL, for when the first one was lost or expired.
    if std::env::args().nth(1).as_deref() == Some("setup-link") {
        if cfg.admin_email.is_none() {
            eprintln!("Set BROD_ADMIN_EMAIL to the admin's email address first.");
            std::process::exit(2);
        }
        let db = open_db(&cfg);
        let c2 = cfg.clone();
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().expect("tokio runtime starts");
        match rt.block_on(db.call(move |c| brod::setup::prepare(c, &c2, true))) {
            Ok(setup) => println!("{}", brod::setup::banner(&cfg, &setup).unwrap_or_default()),
            Err(e) => {
                eprintln!("could not make a sign-in link: {}", e.message);
                std::process::exit(1);
            }
        }
        return;
    }
    // `brod backup <file>`: a consistent copy of the database while the server keeps running.
    if std::env::args().nth(1).as_deref() == Some("backup") {
        let Some(to) = std::env::args().nth(2) else {
            eprintln!("usage: brod backup <file>");
            std::process::exit(2);
        };
        if cfg.database_url.is_some() {
            eprintln!(
                "brod backup copies the SQLite database, and BROD_DATABASE_URL says this server uses Postgres. Back it up with pg_dump: pg_dump --format=custom --file=brod.dump \"$BROD_DATABASE_URL\""
            );
            std::process::exit(2);
        }
        match brod::db::backup(&cfg.data_dir.join("brod.db"), std::path::Path::new(&to)) {
            Ok(()) => println!("backed up to {to}"),
            Err(e) => {
                eprintln!("backup failed: {e}");
                std::process::exit(1);
            }
        }
        return;
    }
    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().max_blocking_threads(64).build().expect("tokio runtime starts");
    rt.block_on(run(cfg));
}

async fn run(cfg: Config) {
    // One crypto provider for every TLS user in the process: Brod's own HTTPS (tls.rs) and its ACME client.
    let _ = rustls::crypto::ring::default_provider().install_default();
    let mode = match cfg.mode {
        brod::config::Mode::SelfHosted => "self-hosted",
        brod::config::Mode::Hosted => "hosted",
    };
    println!("Brod {} ({mode})", env!("CARGO_PKG_VERSION"));
    if !cfg.generated_secrets.is_empty() {
        println!("config: {} generated and kept in {}", cfg.generated_secrets.join(", "), cfg.data_dir.join("secrets.env").display());
    }
    for w in &cfg.warnings {
        eprintln!("warning: {w}");
    }
    if cfg.dev_mode && cfg.api_origin.starts_with("https://") {
        eprintln!("warning: DEV_MODE=1 returns sign-in links in API responses. Do not use it on a public server.");
    }
    let db = open_db(&cfg);
    let listen = cfg.listen;
    brod::model::set_self_hosted(cfg.mode == brod::config::Mode::SelfHosted);
    if let Some(mb) = cfg.dev_free_storage_mb {
        brod::model::set_free_storage(mb * brod::model::MB);
    }
    let st = AppState::new(cfg, db);
    let listener = match TcpListener::bind(listen).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("cannot listen on {listen}: {e}");
            std::process::exit(1);
        }
    };
    println!("email: {}", brod::email::describe(&st.cfg));
    println!("listening on {listen}; open {} (apps at *.{})", st.cfg.api_origin, st.cfg.apps_domain);
    let c2 = st.cfg.clone();
    match st.db.call(move |c| brod::setup::prepare(c, &c2, false)).await {
        Ok(setup) => {
            if let Some(text) = brod::setup::banner(&st.cfg, &setup) {
                println!("\n{text}\n");
            }
        }
        Err(e) => eprintln!("warning: first-start setup failed: {}", e.message),
    }
    if let Some(tls) = st.cfg.tls.clone()
        && let Err(e) = brod::tls::start(st.clone(), tls).await
    {
        eprintln!("{e}");
        std::process::exit(1);
    }

    let shutdown = shutdown_signal();
    tokio::pin!(shutdown);
    let tracker = tokio_util::task::TaskTracker::new();
    // Page views are counted in memory and written every few seconds.
    {
        let st = st.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(10));
            loop {
                tick.tick().await;
                if let Err(e) = brod::usage::flush(&st).await {
                    eprintln!("could not save visit counts: {}", e.message);
                }
                if let Err(e) = brod::analytics::flush(&st).await {
                    eprintln!("could not save analytics: {}", e.message);
                }
            }
        });
    }
    // Analytics older than each workspace's plan keeps are deleted every hour.
    {
        let st = st.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(60)).await;
            let mut tick = tokio::time::interval(Duration::from_secs(3600));
            loop {
                tick.tick().await;
                if let Err(e) = st.db.call(|c| brod::analytics::purge(c)).await {
                    eprintln!("could not delete old analytics: {}", e.message);
                }
            }
        });
    }
    // Server apps' databases are measured in the runtime: refresh their sizes every 10 minutes.
    if st.cfg.runtime.is_some() {
        let st = st.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(30)).await;
            let mut tick = tokio::time::interval(Duration::from_secs(600));
            loop {
                tick.tick().await;
                if let Err(e) = brod::usage::sync_data_sizes(&st).await {
                    eprintln!("could not refresh app database sizes: {}", e.message);
                }
            }
        });
    }
    loop {
        let (stream, peer) = tokio::select! {
            r = listener.accept() => match r {
                Ok(s) => s,
                Err(e) => { eprintln!("accept failed: {e}"); continue; }
            },
            _ = &mut shutdown => break,
        };
        let _ = stream.set_nodelay(true);
        tracker.spawn(brod::app::serve_connection(st.clone(), stream, peer.ip(), brod::http::Via::Internal));
    }
    tracker.close();
    // Give requests in flight a moment to finish.
    let _ = tokio::time::timeout(Duration::from_secs(10), tracker.wait()).await;
    let _ = brod::usage::flush(&st).await;
    let _ = brod::analytics::flush(&st).await;
    println!("Brod stopped");
}

/// Open the database named by the configuration, applying migrations as BROD_AUTO_MIGRATE says, or exit.
fn open_db(cfg: &Config) -> Db {
    let connections = std::env::var("BROD_DB_CONNECTIONS").ok().and_then(|v| v.parse().ok()).unwrap_or(8);
    let opened = match &cfg.database_url {
        Some(url) => {
            println!("database: Postgres");
            Db::open_pg(url, connections)
        }
        None => {
            let path = cfg.data_dir.join("brod.db");
            println!("database: SQLite at {}", path.display());
            Db::open(&path, connections)
        }
    };
    match opened {
        Ok(db) => db,
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1);
        }
    }
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let term = async {
        if let Ok(mut s) = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            s.recv().await;
        }
    };
    #[cfg(not(unix))]
    let term = std::future::pending::<()>();
    tokio::select! { _ = ctrl_c => {}, _ = term => {} }
}

/// GET /healthz on the local listener; 0 when it answers 200.
fn healthcheck() -> i32 {
    use std::io::{Read, Write};
    let listen = std::env::var("BROD_LISTEN").unwrap_or_else(|_| "0.0.0.0:8080".into());
    let port = listen.rsplit(':').next().unwrap_or("8080");
    let Ok(mut s) =
        std::net::TcpStream::connect_timeout(&format!("127.0.0.1:{port}").parse().expect("valid address"), Duration::from_secs(3))
    else {
        return 1;
    };
    let _ = s.set_read_timeout(Some(Duration::from_secs(3)));
    if s.write_all(b"GET /healthz HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n").is_err() {
        return 1;
    }
    let mut buf = [0u8; 16];
    match s.read(&mut buf) {
        Ok(n) if buf[..n].starts_with(b"HTTP/1.1 200") => 0,
        _ => 1,
    }
}
