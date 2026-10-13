// Everything a request handler needs, built once at startup and shared.
use std::sync::Arc;
use std::time::Duration;

use crate::config::Config;
use crate::db::Db;
use crate::storage::Storage;

pub struct AppState {
    pub cfg: Config,
    pub db: Db,
    pub store: Storage,
    /// For Resend, Google and the server-app runtime.
    pub http: reqwest::Client,
    /// Page views counted since the last flush (usage.rs).
    pub visits: crate::usage::Visits,
    /// Page views, browser events and request counters collected since the last flush (analytics.rs).
    pub analytics: crate::analytics::Analytics,
    /// Marketplace preview sandboxes open for a capture (preview.rs).
    pub previews: crate::preview::Previews,
    /// Server-app requests in flight to the runtime, and apps stopped for stalling it (watchdog.rs).
    pub watchdog: crate::watchdog::Watchdog,
}

pub type State = Arc<AppState>;

impl AppState {
    pub fn new(cfg: Config, db: Db) -> State {
        let store = Storage::from_config(&cfg.storage);
        let http = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(60))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("HTTP client builds");
        Arc::new(AppState {
            cfg,
            db,
            store,
            http,
            visits: Default::default(),
            analytics: Default::default(),
            previews: Default::default(),
            watchdog: Default::default(),
        })
    }
}
