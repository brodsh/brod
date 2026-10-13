//! brod-runtime: runs workerd (the server-app runtime, deploy/runtime/) and keeps it answering.
//!
//! Open-source workerd runs every app's isolate on one thread and does not enforce the CPU limit Brod asks the Worker
//! Loader for. So one app stuck in a loop stops every other server app on the machine, and one app that runs out of
//! memory takes the whole process down. Nothing inside workerd can interrupt a loop, so this process watches from
//! outside:
//!
//! - every half second it asks workerd's /_runtime/health; when workerd has not answered for RUNTIME_STALL_MS, an app
//!   is holding the thread;
//! - it reads workerd's resident memory; above RUNTIME_MEMORY_MB, an app is using too much;
//! - it notices when workerd exits on its own (V8 aborts the process when an isolate passes its heap limit).
//!
//! Each time, it first tells Brod (POST /_runtime/stopped), which works out which app was running and stops serving it
//! for a while (server/src/watchdog.rs), then kills workerd and starts it again. Apps' data is in SQLite on disk, so a
//! restart loses only the requests in flight.
//!
//! Usage: brod-runtime <command...>, for example brod-runtime workerd serve config.capnp --experimental
//! Environment: BROD_RUNTIME_SECRET (required), BROD_INTERNAL_URL (default http://brod:8080), RUNTIME_PORT (the port
//! workerd listens on, default 8081), RUNTIME_STALL_MS (default 5000), RUNTIME_MEMORY_MB (default 1536; 0 turns it off).
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::process::{Child, Command, ExitCode};
use std::time::{Duration, Instant};

const PING_EVERY: Duration = Duration::from_millis(500);
const PING_TIMEOUT: Duration = Duration::from_millis(1000);
/// How long workerd may take to answer its first health check after a start.
const START_GRACE: Duration = Duration::from_secs(30);
const NOTIFY_TIMEOUT: Duration = Duration::from_secs(2);

struct Config {
    command: Vec<String>,
    secret: String,
    brod: String,
    port: u16,
    stall: Duration,
    memory_bytes: u64,
}

/// Why workerd was (or had to be) restarted. The names are what Brod's /_runtime/stopped expects.
#[derive(Clone, Copy, Debug, PartialEq)]
enum Reason {
    Cpu,
    Memory,
    Crashed,
    Start,
}

impl Reason {
    fn name(self) -> &'static str {
        match self {
            Reason::Cpu => "cpu",
            Reason::Memory => "memory",
            Reason::Crashed => "crashed",
            Reason::Start => "start",
        }
    }
}

fn main() -> ExitCode {
    let cfg = match config(std::env::args().skip(1).collect(), |k| std::env::var(k).ok()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("brod-runtime: {e}");
            return ExitCode::from(2);
        }
    };
    let mut quick_exits = 0u32;
    loop {
        let started = Instant::now();
        let mut child = match spawn(&cfg.command) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("brod-runtime: could not start {}: {e}", cfg.command[0]);
                return ExitCode::from(1);
            }
        };
        let (reason, stalled) = watch(&cfg, &mut child, started);
        let what = match reason {
            Reason::Cpu => format!("workerd did not answer for {:.1} s: an app is holding it", stalled.as_secs_f64()),
            Reason::Memory => format!("workerd uses more than {} MB", cfg.memory_bytes / 1024 / 1024),
            Reason::Crashed => "workerd exited".to_string(),
            Reason::Start => format!("workerd did not answer within {} s of starting", START_GRACE.as_secs()),
        };
        eprintln!("brod-runtime: {what}; restarting it");
        // A runtime that keeps dying straight after it starts is not helped by restarting it in a tight loop.
        quick_exits = if started.elapsed() < Duration::from_secs(10) { quick_exits + 1 } else { 0 };
        std::thread::sleep(backoff(quick_exits));
    }
}

fn config(args: Vec<String>, get: impl Fn(&str) -> Option<String>) -> Result<Config, String> {
    if args.is_empty() {
        return Err("usage: brod-runtime <command...>, for example brod-runtime workerd serve config.capnp --experimental".into());
    }
    let secret = get("BROD_RUNTIME_SECRET").filter(|s| s.len() >= 16).ok_or("BROD_RUNTIME_SECRET must be set (at least 16 characters).")?;
    let number = |k: &str, default: u64| -> Result<u64, String> {
        match get(k).filter(|v| !v.is_empty()) {
            None => Ok(default),
            Some(v) => v.parse().map_err(|_| format!("{k} must be a whole number.")),
        }
    };
    let stall = number("RUNTIME_STALL_MS", 5000)?;
    if stall < 1000 {
        return Err("RUNTIME_STALL_MS must be at least 1000.".into());
    }
    let port = u16::try_from(number("RUNTIME_PORT", 8081)?).map_err(|_| "RUNTIME_PORT must be a port number.")?;
    Ok(Config {
        command: args,
        secret,
        brod: get("BROD_INTERNAL_URL").unwrap_or_else(|| "http://brod:8080".into()),
        port,
        stall: Duration::from_millis(stall),
        memory_bytes: number("RUNTIME_MEMORY_MB", 1536)? * 1024 * 1024,
    })
}

fn spawn(command: &[String]) -> std::io::Result<Child> {
    let mut cmd = Command::new(&command[0]);
    cmd.args(&command[1..]);
    // If this process dies, workerd goes with it rather than keeping the port.
    #[cfg(target_os = "linux")]
    unsafe {
        use std::os::unix::process::CommandExt;
        cmd.pre_exec(|| {
            libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL);
            Ok(())
        });
    }
    cmd.spawn()
}

/// Watch workerd until it has to be restarted. Returns why, and how long it had gone without answering.
fn watch(cfg: &Config, child: &mut Child, started: Instant) -> (Reason, Duration) {
    // The stall clock runs from the last answer, or from when workerd first took a connection: an app can hold it
    // before it has answered a single health check (a visitor retrying the page that stalled it a moment ago).
    let mut last_ok: Option<Instant> = None;
    let mut listening: Option<Instant> = None;
    loop {
        let tick = Instant::now();
        if let Ok(Some(_)) = child.try_wait() {
            // Already gone: Brod hears about it after the fact.
            let quiet = last_ok.or(listening).unwrap_or(started).elapsed();
            notify(cfg, Reason::Crashed, quiet, 0);
            return (Reason::Crashed, quiet);
        }
        match ping(cfg) {
            Health::Answered => last_ok = Some(Instant::now()),
            Health::Silent => {
                listening.get_or_insert(tick);
            }
            Health::Down => {}
        }
        let quiet = last_ok.or(listening).unwrap_or(started).elapsed();
        let stop = match last_ok.or(listening) {
            None if quiet > START_GRACE => Some(Reason::Start),
            Some(_) if quiet > cfg.stall => Some(Reason::Cpu),
            _ => None,
        };
        let rss = resident_bytes(child.id());
        let stop = stop.or((cfg.memory_bytes > 0 && rss > cfg.memory_bytes).then_some(Reason::Memory));
        if let Some(reason) = stop {
            // Tell Brod before the kill: the requests in flight show it which app was running.
            notify(cfg, reason, quiet, rss);
            let _ = child.kill();
            let _ = child.wait();
            return (reason, quiet);
        }
        std::thread::sleep(PING_EVERY.saturating_sub(tick.elapsed()));
    }
}

enum Health {
    /// It answered its health check.
    Answered,
    /// It took the connection but did not answer in time.
    Silent,
    /// Nothing is listening yet.
    Down,
}

fn ping(cfg: &Config) -> Health {
    let addr = SocketAddr::from(([127, 0, 0, 1], cfg.port));
    let Ok(stream) = TcpStream::connect_timeout(&addr, PING_TIMEOUT) else {
        return Health::Down;
    };
    let req =
        format!("GET /_runtime/health HTTP/1.1\r\nHost: 127.0.0.1\r\nx-brod-runtime-secret: {}\r\nConnection: close\r\n\r\n", cfg.secret);
    match exchange_on(stream, req.as_bytes(), PING_TIMEOUT) {
        Ok(r) if r.starts_with("HTTP/1.1 200") => Health::Answered,
        _ => Health::Silent,
    }
}

/// Tell Brod the runtime is about to restart, so it can stop the app that caused it. Best effort: the restart
/// happens whether or not Brod answers.
fn notify(cfg: &Config, reason: Reason, quiet: Duration, rss: u64) {
    let Some((host, path)) = split_url(&cfg.brod) else {
        eprintln!("brod-runtime: BROD_INTERNAL_URL must look like http://host:port");
        return;
    };
    let Some(addr) = host.to_socket_addrs().ok().and_then(|mut a| a.next()) else {
        eprintln!("brod-runtime: cannot resolve {host}");
        return;
    };
    let body = format!(r#"{{"reason":"{}","stalled_ms":{},"rss_bytes":{rss}}}"#, reason.name(), quiet.as_millis());
    let req = format!(
        "POST {path}_runtime/stopped HTTP/1.1\r\nHost: {host}\r\nx-brod-runtime-secret: {}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nConnection: close\r\n\r\n{body}",
        cfg.secret,
        body.len()
    );
    match exchange(addr, req.as_bytes(), NOTIFY_TIMEOUT) {
        Ok(r) => {
            let answer = r.split("\r\n\r\n").nth(1).unwrap_or("").trim();
            if !answer.is_empty() {
                eprintln!("brod-runtime: Brod says {answer}");
            }
        }
        Err(e) => eprintln!("brod-runtime: could not tell Brod: {e}"),
    }
}

fn exchange(addr: SocketAddr, req: &[u8], timeout: Duration) -> std::io::Result<String> {
    exchange_on(TcpStream::connect_timeout(&addr, timeout)?, req, timeout)
}

fn exchange_on(mut s: TcpStream, req: &[u8], timeout: Duration) -> std::io::Result<String> {
    s.set_read_timeout(Some(timeout))?;
    s.set_write_timeout(Some(timeout))?;
    s.write_all(req)?;
    // Read until the response is complete rather than until the server closes: it may keep the connection open.
    let mut out = Vec::new();
    let mut buf = [0u8; 4096];
    while !complete(&out) && out.len() < 64 * 1024 {
        match s.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => out.extend_from_slice(&buf[..n]),
            Err(e) if out.is_empty() => return Err(e),
            Err(_) => break,
        }
    }
    Ok(String::from_utf8_lossy(&out).into_owned())
}

/// Whether an HTTP response has all its headers and as much body as its Content-Length says.
fn complete(r: &[u8]) -> bool {
    let Some(end) = r.windows(4).position(|w| w == b"\r\n\r\n") else {
        return false;
    };
    let head = String::from_utf8_lossy(&r[..end]).to_ascii_lowercase();
    let length = head.lines().find_map(|l| l.strip_prefix("content-length:")).and_then(|v| v.trim().parse::<usize>().ok());
    r.len() >= end + 4 + length.unwrap_or(0)
}

/// "http://brod:8080" → ("brod:8080", "/"); "http://127.0.0.1:8787/base" → ("127.0.0.1:8787", "/base/").
fn split_url(url: &str) -> Option<(String, String)> {
    let rest = url.strip_prefix("http://")?;
    let (host, path) = rest.split_once('/').map(|(h, p)| (h, format!("/{p}"))).unwrap_or((rest, "/".into()));
    let host = if host.contains(':') { host.to_string() } else { format!("{host}:80") };
    let path = if path.ends_with('/') { path } else { format!("{path}/") };
    (!host.starts_with(':')).then_some((host, path))
}

fn resident_bytes(pid: u32) -> u64 {
    std::fs::read_to_string(format!("/proc/{pid}/status")).map(|s| vm_rss(&s)).unwrap_or(0)
}

/// The VmRSS line of /proc/<pid>/status, in bytes.
fn vm_rss(status: &str) -> u64 {
    status
        .lines()
        .find_map(|l| l.strip_prefix("VmRSS:"))
        .and_then(|v| v.split_whitespace().next())
        .and_then(|kb| kb.parse::<u64>().ok())
        .map(|kb| kb * 1024)
        .unwrap_or(0)
}

/// Nothing after a normal run; then 0.25 s, 0.5 s, 1 s … up to 10 s while workerd keeps exiting soon after starting.
fn backoff(quick_exits: u32) -> Duration {
    if quick_exits <= 1 {
        return Duration::ZERO;
    }
    Duration::from_millis(250u64.saturating_mul(1 << (quick_exits - 2).min(6))).min(Duration::from_secs(10))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let pairs: Vec<(String, String)> = pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        move |k| pairs.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone())
    }
    const SECRET: (&str, &str) = ("BROD_RUNTIME_SECRET", "0123456789abcdef");

    #[test]
    fn reads_its_settings() {
        let c = config(vec!["workerd".into(), "serve".into()], env(&[SECRET])).unwrap();
        assert_eq!((c.port, c.stall, c.memory_bytes, c.brod.as_str()), (8081, Duration::from_secs(5), 1536 << 20, "http://brod:8080"));
        let c =
            config(vec!["w".into()], env(&[SECRET, ("RUNTIME_STALL_MS", "2000"), ("RUNTIME_MEMORY_MB", "0"), ("RUNTIME_PORT", "8789")]))
                .unwrap();
        assert_eq!((c.port, c.stall, c.memory_bytes), (8789, Duration::from_secs(2), 0));
        assert!(config(vec![], env(&[SECRET])).is_err());
        assert!(config(vec!["w".into()], env(&[])).is_err());
        assert!(config(vec!["w".into()], env(&[("BROD_RUNTIME_SECRET", "short")])).is_err());
        assert!(config(vec!["w".into()], env(&[SECRET, ("RUNTIME_STALL_MS", "10")])).is_err());
        assert!(config(vec!["w".into()], env(&[SECRET, ("RUNTIME_MEMORY_MB", "lots")])).is_err());
        assert!(config(vec!["w".into()], env(&[SECRET, ("RUNTIME_PORT", "70000")])).is_err());
    }

    #[test]
    fn splits_brods_address() {
        assert_eq!(split_url("http://brod:8080"), Some(("brod:8080".into(), "/".into())));
        assert_eq!(split_url("http://brod"), Some(("brod:80".into(), "/".into())));
        assert_eq!(split_url("http://127.0.0.1:8787/base"), Some(("127.0.0.1:8787".into(), "/base/".into())));
        assert_eq!(split_url("https://brod:8080"), None);
        assert_eq!(split_url("http://:8080"), None);
    }

    #[test]
    fn reads_resident_memory() {
        assert_eq!(vm_rss("Name:\tworkerd\nVmPeak:\t 900 kB\nVmRSS:\t   59836 kB\nThreads: 9\n"), 59836 * 1024);
        assert_eq!(vm_rss("Name:\tzombie\n"), 0);
        assert!(resident_bytes(std::process::id()) > 0);
    }

    #[test]
    fn knows_when_a_response_is_complete() {
        assert!(!complete(b"HTTP/1.1 200 OK\r\ncontent-length: 11\r\n"));
        assert!(!complete(b"HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\n{\"ok\":"));
        assert!(complete(b"HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\n{\"ok\":true}"));
        assert!(complete(b"HTTP/1.1 204 No Content\r\n\r\n"));
    }

    #[test]
    fn backs_off_when_it_keeps_dying() {
        assert_eq!(backoff(0), Duration::ZERO);
        assert_eq!(backoff(1), Duration::ZERO);
        assert_eq!(backoff(2), Duration::from_millis(250));
        assert_eq!(backoff(3), Duration::from_millis(500));
        assert_eq!(backoff(20), Duration::from_secs(10));
    }
}
