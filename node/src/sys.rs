// SPDX-License-Identifier: AGPL-3.0-only
//! What the node is (capabilities) and how busy it is (usage), for heartbeats and GET /v1/info. Read from /proc and
//! statvfs on Linux; on other systems (macOS, for development) whatever can be read cheaply, and null for the rest.
use std::path::Path;

use serde_json::{Value, json};

/// The architecture as container images name it (amd64, arm64), else Rust's name for it.
pub fn arch() -> &'static str {
    match std::env::consts::ARCH {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        other => other,
    }
}

/// "docker" when the Docker socket is there, else "none". BROD_NODE_DOCKER_SOCKET overrides the path.
pub fn engine() -> &'static str {
    let socket = std::env::var("BROD_NODE_DOCKER_SOCKET").unwrap_or_else(|_| "/var/run/docker.sock".into());
    if Path::new(&socket).exists() { "docker" } else { "none" }
}

pub fn capabilities() -> Value {
    json!({
        "arch": arch(),
        "os": std::env::consts::OS,
        "engine": engine(),
        "cpus": std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1),
        "memory_bytes": memory().map(|m| m.0),
    })
}

/// Load averages, memory and the disk that holds `dir`.
pub fn usage(dir: &Path) -> Value {
    let (memory_total, memory_used) = match memory() {
        Some((t, u)) => (Some(t), u),
        None => (None, None),
    };
    let (disk_total, disk_used) = disk(dir).map_or((None, None), |(t, u)| (Some(t), Some(u)));
    let load = load();
    json!({
        "load1": load.map(|l| l[0]), "load5": load.map(|l| l[1]), "load15": load.map(|l| l[2]),
        "memory_total": memory_total, "memory_used": memory_used,
        "disk_total": disk_total, "disk_used": disk_used,
    })
}

fn load() -> Option<[f64; 3]> {
    let mut l = [0f64; 3];
    // SAFETY: getloadavg writes at most 3 values into the array it is given.
    let n = unsafe { libc::getloadavg(l.as_mut_ptr(), 3) };
    (n == 3).then_some(l)
}

/// Total memory, and memory in use when it can be read (MemTotal - MemAvailable), in bytes.
#[cfg(target_os = "linux")]
fn memory() -> Option<(u64, Option<u64>)> {
    let info = std::fs::read_to_string("/proc/meminfo").ok()?;
    let (total, available) = meminfo(&info);
    Some((total?, available.map(|a| total.unwrap_or(0).saturating_sub(a))))
}

#[cfg(target_os = "macos")]
fn memory() -> Option<(u64, Option<u64>)> {
    let mut size: u64 = 0;
    let mut len = std::mem::size_of::<u64>();
    // SAFETY: hw.memsize is a u64, and len says how much room there is.
    let ok = unsafe { libc::sysctlbyname(c"hw.memsize".as_ptr(), (&mut size as *mut u64).cast(), &mut len, std::ptr::null_mut(), 0) } == 0;
    ok.then_some((size, None))
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn memory() -> Option<(u64, Option<u64>)> {
    None
}

/// MemTotal and MemAvailable from /proc/meminfo, in bytes.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn meminfo(text: &str) -> (Option<u64>, Option<u64>) {
    let field = |name: &str| {
        text.lines()
            .find_map(|l| l.strip_prefix(name)?.strip_prefix(':')?.trim().strip_suffix("kB")?.trim().parse::<u64>().ok())
            .map(|kb| kb * 1024)
    };
    (field("MemTotal"), field("MemAvailable"))
}

/// The size of the file system that holds `dir`, and how much of it is used, in bytes.
fn disk(dir: &Path) -> Option<(u64, u64)> {
    use std::os::unix::ffi::OsStrExt;
    let path = std::ffi::CString::new(dir.as_os_str().as_bytes()).ok()?;
    // SAFETY: statvfs fills the struct it is given; it is zeroed first and read only on success.
    let mut s: libc::statvfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statvfs(path.as_ptr(), &mut s) } != 0 {
        return None;
    }
    let unit = s.f_frsize as u64;
    let total = s.f_blocks as u64 * unit;
    Some((total, total.saturating_sub(s.f_bfree as u64 * unit)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_meminfo() {
        let text = "MemTotal:       16303428 kB\nMemFree:          100 kB\nMemAvailable:    8151714 kB\n";
        assert_eq!(meminfo(text), (Some(16303428 * 1024), Some(8151714 * 1024)));
        assert_eq!(meminfo(""), (None, None));
    }

    #[test]
    fn reports_what_it_can_read() {
        let u = usage(&std::env::temp_dir());
        assert!(u["disk_total"].as_u64().unwrap() > 0);
        assert!(u["disk_used"].as_u64().unwrap() <= u["disk_total"].as_u64().unwrap());
        assert!(u["load1"].as_f64().is_some());
        let c = capabilities();
        assert!(c["cpus"].as_u64().unwrap() >= 1);
        assert!(c["memory_bytes"].as_u64().unwrap() > 0);
        assert!(["docker", "none"].contains(&c["engine"].as_str().unwrap()));
    }
}
