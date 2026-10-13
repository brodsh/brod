// Server apps that hold the runtime: who was running when it had to be restarted, and stopping them for a while.
//
// Open-source workerd runs every app on one thread and does not enforce the CPU limit, so an app stuck in a loop stops
// every server app on the host, and one that runs out of memory takes the runtime down. The runtime's supervisor
// (deploy/runtime/supervisor/) restarts workerd when that happens, and first tells Brod why (POST /_runtime/stopped).
// Nothing inside workerd can say which app it was, but the gateway knows which requests it has in flight, so the
// blame is worked out here:
//
// - workerd takes requests in the order they come, on one thread. The request that stalled it is the first one sent
//   after its last answer to a health check; those sent later only queued behind it. Requests sent before that last
//   answer were waiting on something (a fetch, the database) and may have resumed and stalled it too, so they are
//   suspects as well.
// - when workerd exited on its own (V8 aborts it when an isolate runs out of memory), the requests failed before the
//   supervisor could say why, so those that lost their connection in the last few seconds count too.
//
// Requests that only queued never ran: those without a body are sent again once workerd is back.
//
// When one app is the only suspect, it is stopped at once: its server code gets a 503 for a minute, then 5, then 30
// while it keeps doing it (static files keep serving). When several apps had requests in flight, each gets a strike
// and is stopped only after three in ten minutes, so a busy app that happened to be waiting is not stopped for
// another's loop. Each suspect's logs say what happened, so its owner, or the agent reading get_logs, can fix it.
//
// This is kept in memory: a restart of Brod forgives everyone.
use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use serde_json::{Value, json};

use crate::db::{Sql, params, tx};
use crate::problem::{Problem, Result};
use crate::state::State;
use crate::util::now;

/// Requests that lost their connection to the runtime this recently are suspects when it reports it exited.
const DROPPED_WINDOW: Duration = Duration::from_secs(5);
/// How much earlier than the runtime's last answer the request that stalled it may have been sent: the answer was read
/// at most this long after the runtime wrote it.
const QUIET_SLACK: Duration = Duration::from_millis(1000);
/// Shared strikes, within this window, that stop an app.
const SHARED_STRIKES: usize = 3;
const STRIKE_WINDOW: Duration = Duration::from_secs(10 * 60);
/// How long an app is stopped: the first time, the second, and from the third on, within REPEAT_WINDOW.
const STOPS: [Duration; 3] = [Duration::from_secs(60), Duration::from_secs(5 * 60), Duration::from_secs(30 * 60)];
const REPEAT_WINDOW: Duration = Duration::from_secs(3600);

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Reason {
    Cpu,
    Memory,
    Crashed,
}

impl Reason {
    /// "start" (the runtime never answered after a restart) blames whatever was waiting, like an exit.
    pub fn parse(s: &str) -> Option<Reason> {
        match s {
            "cpu" => Some(Reason::Cpu),
            "memory" => Some(Reason::Memory),
            "crashed" | "start" => Some(Reason::Crashed),
            _ => None,
        }
    }
    /// The outcome in the app's logs, in the vocabulary of Workers' tail events.
    fn outcome(self) -> &'static str {
        match self {
            Reason::Cpu => "exceededCpu",
            Reason::Memory => "exceededMemory",
            Reason::Crashed => "exception",
        }
    }
    fn explain(self, quiet: Duration) -> String {
        match self {
            Reason::Cpu => format!(
                "Brod stopped this request: the server code ran for {:.1} s without pausing (a loop that does not end, or work that is far too slow), which holds up every server app on this host. Server code may use 50 ms of CPU per request.",
                quiet.as_secs_f64()
            ),
            Reason::Memory => "Brod stopped this request: the server code used too much memory.".to_string(),
            Reason::Crashed => {
                "Brod stopped this request: the runtime crashed while it ran, most likely because the server code used too much memory."
                    .to_string()
            }
        }
    }
}

struct Flight {
    app_id: String,
    version: Option<i64>,
    method: String,
    path: String,
    started: Instant,
    stopped: Option<Reason>,
    /// Queued behind the request that stalled the runtime: it never ran.
    queued: bool,
}

#[derive(Default)]
struct Record {
    strikes: Vec<Instant>,
    stops: Vec<Instant>,
    until: Option<Instant>,
}

#[derive(Default)]
struct Inner {
    flights: HashMap<u64, Flight>,
    dropped: VecDeque<(Instant, Flight)>,
    apps: HashMap<String, Record>,
}

#[derive(Default)]
pub struct Watchdog {
    next: AtomicU64,
    inner: Mutex<Inner>,
}

/// One request in flight to the runtime. Dropping it (when the answer has been passed on) ends the flight.
pub struct Ticket {
    st: State,
    id: u64,
}

impl Ticket {
    /// Why the runtime was restarted under this request, when it was blamed for it.
    pub fn stopped(&self) -> Option<Reason> {
        self.st.watchdog.lock().flights.get(&self.id).and_then(|f| f.stopped)
    }
    /// Whether the request only queued behind the one that stalled the runtime, and so can be sent again. Asking
    /// clears it: it is sent again once.
    pub fn take_queued(&self) -> bool {
        self.st.watchdog.lock().flights.get_mut(&self.id).is_some_and(|f| std::mem::take(&mut f.queued))
    }
    /// The connection to the runtime broke: keep the request a few seconds, in case the runtime reports it exited.
    pub fn dropped(self) {
        let mut w = self.st.watchdog.lock();
        if let Some(f) = w.flights.remove(&self.id) {
            let t = Instant::now();
            w.dropped.push_back((t, f));
            while w.dropped.front().is_some_and(|(at, _)| t.duration_since(*at) > DROPPED_WINDOW) {
                w.dropped.pop_front();
            }
        }
    }
}

impl Drop for Ticket {
    fn drop(&mut self) {
        self.st.watchdog.lock().flights.remove(&self.id);
    }
}

/// What the gateway tells a visitor of a stopped app, and for how much longer.
pub struct Paused {
    pub left: Duration,
}

/// A suspect for one restart: the app, the request, and whether it was the only app running.
struct Blame {
    app_id: String,
    version: Option<i64>,
    method: String,
    path: String,
    alone: bool,
    until: Option<Instant>,
}

impl Watchdog {
    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Whether an app's server code is stopped right now.
    pub fn paused(&self, app_id: &str) -> Option<Paused> {
        self.paused_at(app_id, Instant::now())
    }

    fn paused_at(&self, app_id: &str, t: Instant) -> Option<Paused> {
        let w = self.lock();
        let until = w.apps.get(app_id)?.until?;
        (until > t).then(|| Paused { left: until - t })
    }

    fn start(&self, app_id: &str, version: Option<i64>, method: &str, path: &str, t: Instant) -> u64 {
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        let flight =
            Flight { app_id: app_id.into(), version, method: method.into(), path: path.into(), started: t, stopped: None, queued: false };
        self.lock().flights.insert(id, flight);
        id
    }

    /// Work out who was running, mark their requests, and stop the apps that earned it.
    fn blame(&self, reason: Reason, quiet: Duration, t: Instant) -> Vec<Blame> {
        let mut w = self.lock();
        let inner = &mut *w;
        let since = t.checked_sub(quiet + QUIET_SLACK).unwrap_or(t);
        // When the runtime exited on its own, the requests have already failed: those from the last few seconds count.
        let recent: Vec<Flight> =
            inner.dropped.drain(..).filter(|(at, _)| t.duration_since(*at) <= DROPPED_WINDOW).map(|(_, f)| f).collect();
        // (started, flight id or None for one already dropped, index into recent)
        let mut all: Vec<(Instant, Option<u64>, usize)> = inner.flights.iter().map(|(id, f)| (f.started, Some(*id), 0)).collect();
        all.extend(recent.iter().enumerate().map(|(i, f)| (f.started, None, i)));
        all.sort_by_key(|(started, id, i)| (*started, *id, *i));
        // Waiting since before the runtime went quiet, and the first one sent after.
        let first_after = all.iter().position(|(started, ..)| *started > since);
        let mut suspects: Vec<(String, Option<i64>, String, String)> = Vec::new();
        for (n, (started, id, i)) in all.iter().enumerate() {
            let suspect = *started <= since || Some(n) == first_after;
            match id {
                Some(id) => {
                    let Some(f) = inner.flights.get_mut(id) else { continue };
                    if suspect {
                        f.stopped = Some(reason);
                        suspects.push((f.app_id.clone(), f.version, f.method.clone(), f.path.clone()));
                    } else {
                        f.queued = true;
                    }
                }
                None if suspect => {
                    let f = &recent[*i];
                    suspects.push((f.app_id.clone(), f.version, f.method.clone(), f.path.clone()));
                }
                None => {}
            }
        }
        // One blame per app: its first request.
        let mut seen = std::collections::HashSet::new();
        suspects.retain(|(app, ..)| seen.insert(app.clone()));
        let alone = suspects.len() == 1;
        suspects
            .into_iter()
            .map(|(app_id, version, method, path)| {
                let until = if app_id.is_empty() { None } else { strike(inner.apps.entry(app_id.clone()).or_default(), alone, t) };
                Blame { app_id, version, method, path, alone, until }
            })
            .collect()
    }
}

/// Count a strike against an app; returns until when it is stopped, if this strike stops it.
fn strike(r: &mut Record, alone: bool, t: Instant) -> Option<Instant> {
    r.strikes.retain(|s| t.duration_since(*s) < STRIKE_WINDOW);
    r.stops.retain(|s| t.duration_since(*s) < REPEAT_WINDOW);
    r.strikes.push(t);
    if !alone && r.strikes.len() < SHARED_STRIKES {
        return None;
    }
    let until = t + STOPS[r.stops.len().min(STOPS.len() - 1)];
    r.stops.push(t);
    r.strikes.clear();
    r.until = Some(until);
    Some(until)
}

/// Note a request to the runtime for the app (empty for a deploy's start-up check).
pub fn start(st: &State, app_id: &str, version: Option<i64>, method: &str, path: &str) -> Ticket {
    Ticket { st: st.clone(), id: st.watchdog.start(app_id, version, method, path, Instant::now()) }
}

/// POST /_runtime/stopped from the supervisor, just before it restarts workerd (or just after, when it exited).
pub async fn stopped(st: &State, body: &Value) -> Result<Value> {
    let reason = Reason::parse(body.get("reason").and_then(Value::as_str).unwrap_or(""))
        .ok_or_else(|| Problem::new(400, "bad_reason", "reason is cpu, memory, crashed or start."))?;
    let quiet = Duration::from_millis(body.get("stalled_ms").and_then(Value::as_u64).unwrap_or(0));
    let blamed = st.watchdog.blame(reason, quiet, Instant::now());
    let rows: Vec<(String, Option<i64>, String, String, String)> = blamed
        .iter()
        .filter(|b| !b.app_id.is_empty())
        .map(|b| {
            let mut message = reason.explain(quiet);
            if !b.alone {
                message.push_str(" Other apps had requests running at the same time, so it may have been one of them.");
            }
            if let Some(until) = b.until {
                let mins = until.saturating_duration_since(Instant::now()).as_secs().div_ceil(60);
                message.push_str(&format!(" The app's server code is stopped for {mins} min; its static files still serve."));
            }
            let exceptions = json!([{ "name": "BrodStopped", "message": message, "at": now() }]).to_string();
            (b.app_id.clone(), b.version, b.method.clone(), b.path.clone(), exceptions)
        })
        .collect();
    if !rows.is_empty() {
        st.db
            .call(move |c| {
                tx(c, |x| {
                    for (app, version, method, path, exceptions) in &rows {
                        x.run(
                            "INSERT INTO app_logs (app_id, at, version, method, path, status, outcome, logs, exceptions) VALUES (?,?,?,?,?,?,?,?,?)",
                            params![app, now(), version, method, path, None::<i64>, reason.outcome(), "[]", exceptions],
                        )?;
                    }
                    Ok(())
                })
            })
            .await?;
    }
    for b in &blamed {
        let who = if b.app_id.is_empty() { "a deploy's start-up check" } else { b.app_id.as_str() };
        let stop =
            b.until.map(|u| format!(", stopped for {} s", u.saturating_duration_since(Instant::now()).as_secs())).unwrap_or_default();
        eprintln!("runtime restarted ({reason:?}): {who} was running {} {}{stop}", b.method, b.path);
    }
    Ok(json!({
        "blamed": blamed.iter().map(|b| json!({ "app": b.app_id, "request": format!("{} {}", b.method, b.path), "stopped": b.until.is_some() })).collect::<Vec<_>>()
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    const S: Duration = Duration::from_secs(1);

    #[test]
    fn a_lone_loop_is_stopped_at_once_and_for_longer_each_time() {
        let w = Watchdog::default();
        let t0 = Instant::now();
        let id = w.start("app_spin", Some(1), "GET", "/spin", t0);
        let b = w.blame(Reason::Cpu, 5 * S, t0 + 5 * S);
        assert_eq!((b.len(), b[0].app_id.as_str(), b[0].alone), (1, "app_spin", true));
        assert_eq!(w.lock().flights[&id].stopped, Some(Reason::Cpu));
        assert_eq!(w.paused_at("app_spin", t0 + 6 * S).map(|p| p.left), Some(59 * S));
        assert!(w.paused_at("app_spin", t0 + 66 * S).is_none());
        assert!(w.paused_at("app_other", t0 + 6 * S).is_none());

        w.lock().flights.clear();
        let t1 = t0 + 100 * S;
        w.start("app_spin", Some(1), "GET", "/spin", t1);
        w.blame(Reason::Cpu, 5 * S, t1 + 5 * S);
        assert_eq!(w.paused_at("app_spin", t1 + 5 * S).map(|p| p.left), Some(300 * S));
        w.lock().flights.clear();
        let t2 = t1 + 400 * S;
        w.start("app_spin", Some(1), "GET", "/spin", t2);
        w.blame(Reason::Cpu, 5 * S, t2 + 5 * S);
        assert_eq!(w.paused_at("app_spin", t2 + 5 * S).map(|p| p.left), Some(1800 * S));
    }

    #[test]
    fn requests_that_queued_behind_the_loop_are_not_blamed_and_are_sent_again() {
        let w = Watchdog::default();
        let t0 = Instant::now();
        // The runtime last answered at t0 + 1; the loop was the next request, the others queued behind it.
        let spin = w.start("app_spin", None, "GET", "/spin", t0 + 2 * S);
        let ok = w.start("app_ok", None, "GET", "/", t0 + 3 * S);
        let ok2 = w.start("app_ok2", None, "GET", "/", t0 + 5 * S / 2);
        let b = w.blame(Reason::Cpu, 6 * S, t0 + 7 * S);
        assert_eq!(b.iter().map(|b| b.app_id.as_str()).collect::<Vec<_>>(), ["app_spin"]);
        assert!(b[0].alone && b[0].until.is_some());
        assert!(w.paused_at("app_ok", t0 + 7 * S).is_none());
        let inner = w.lock();
        assert!(!inner.flights[&spin].queued && inner.flights[&ok].queued && inner.flights[&ok2].queued);
        assert_eq!((inner.flights[&ok].stopped, inner.flights[&spin].stopped), (None, Some(Reason::Cpu)));
    }

    #[test]
    fn several_apps_in_flight_are_stopped_only_after_three_strikes() {
        let w = Watchdog::default();
        let t0 = Instant::now() + 100 * S;
        for i in 0..3u32 {
            w.lock().flights.clear();
            let t = t0 + i * 60 * S;
            w.start("app_spin", None, "GET", "/spin", t);
            // Waiting on a slow fetch since before the runtime went quiet: it may have resumed and stalled it.
            w.start("app_slow", None, "GET", "/fetch", t - 20 * S);
            let b = w.blame(Reason::Cpu, 5 * S, t + 5 * S);
            assert_eq!(b.len(), 2);
            assert!(b.iter().all(|b| !b.alone));
            assert_eq!(b.iter().all(|b| b.until.is_some()), i == 2, "strike {i}");
        }
        // Strikes older than ten minutes are forgotten.
        let w = Watchdog::default();
        for i in 0..3u32 {
            w.lock().flights.clear();
            let t = t0 + i * 400 * S;
            w.start("app_a", None, "GET", "/", t);
            w.start("app_b", None, "GET", "/", t - 20 * S);
            assert!(w.blame(Reason::Cpu, 5 * S, t + 5 * S).iter().all(|b| b.until.is_none()));
        }
    }

    #[test]
    fn a_crash_blames_requests_that_just_lost_their_connection() {
        let w = Watchdog::default();
        let t0 = Instant::now();
        // The request was dropped (connection reset) before the supervisor could report the exit.
        let id = w.start("app_mem", Some(3), "POST", "/grow", t0);
        let f = w.lock().flights.remove(&id).unwrap();
        w.lock().dropped.push_back((t0 + S, f));
        // Queued behind it: started after the runtime went quiet.
        let id2 = w.start("app_ok", None, "GET", "/", t0 + 2 * S);
        let f2 = w.lock().flights.remove(&id2).unwrap();
        w.lock().dropped.push_back((t0 + S, f2));
        let b = w.blame(Reason::Crashed, 3 * S, t0 + 3 * S);
        assert_eq!((b.len(), b[0].app_id.as_str(), b[0].version, b[0].alone), (1, "app_mem", Some(3), true));
        assert!(w.paused_at("app_mem", t0 + 3 * S).is_some());
        // Dropped too long ago: not a suspect.
        let w = Watchdog::default();
        let id = w.start("app_old", None, "GET", "/", t0);
        let f = w.lock().flights.remove(&id).unwrap();
        w.lock().dropped.push_back((t0, f));
        assert!(w.blame(Reason::Memory, Duration::ZERO, t0 + 10 * S).is_empty());
    }

    #[test]
    fn a_deploy_check_is_blamed_but_stops_no_app() {
        let w = Watchdog::default();
        let t0 = Instant::now();
        let id = w.start("", None, "POST", "/_runtime/check", t0);
        let b = w.blame(Reason::Cpu, 5 * S, t0 + 5 * S);
        assert_eq!((b.len(), b[0].until), (1, None));
        assert_eq!(w.lock().flights[&id].stopped, Some(Reason::Cpu));
        assert!(w.lock().apps.is_empty());
    }

    #[test]
    fn reasons() {
        assert_eq!(Reason::parse("cpu"), Some(Reason::Cpu));
        assert_eq!(Reason::parse("start"), Some(Reason::Crashed));
        assert_eq!(Reason::parse("other"), None);
        assert!(Reason::Cpu.explain(Duration::from_millis(5200)).contains("5.2 s"));
    }
}
