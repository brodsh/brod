// SPDX-License-Identifier: AGPL-3.0-only
//! Network rules for an app's bridge (Linux only, best effort): a container may reach the internet, but not private
//! networks (RFC 1918, carrier-grade NAT), link-local addresses (the cloud metadata service at 169.254.169.254 among
//! them), other apps' bridges (they are private addresses too) or the node itself.
//!
//! The rules go into Docker's DOCKER-USER chain (forwarded traffic) and INPUT (traffic to the node's own addresses).
//! They need iptables and root; without them the node logs a warning and runs the container without the rules, and
//! the deployment says so. On macOS and Windows (Docker Desktop) there are no such rules: a development setup only.

/// Addresses a container may not reach.
pub const BLOCKED: [&str; 5] = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "100.64.0.0/10"];

/// The rules for a bridge's subnet as (chain, rule) pairs, in the order they must be evaluated.
pub fn rules(subnet: &str) -> Vec<(&'static str, Vec<String>)> {
    let r = |parts: &[&str]| parts.iter().map(|s| s.to_string()).collect::<Vec<_>>();
    let mut out = vec![
        // Replies to connections from outside (Brod's requests via the node) and traffic inside the bridge pass.
        ("DOCKER-USER", r(&["-s", subnet, "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "RETURN"])),
        ("DOCKER-USER", r(&["-s", subnet, "-d", subnet, "-j", "RETURN"])),
    ];
    for b in BLOCKED {
        out.push(("DOCKER-USER", r(&["-s", subnet, "-d", b, "-j", "DROP"])));
    }
    // New connections from the bridge to the node itself (its gateway address included).
    out.push(("INPUT", r(&["-s", subnet, "-m", "conntrack", "--ctstate", "NEW", "-j", "DROP"])));
    out
}

/// Put the rules in place for a subnet. Ok(None) when they are in place, Ok(Some(warning)) when they could not be.
pub async fn apply(subnet: &str) -> Option<String> {
    if !cfg!(target_os = "linux") {
        return Some(format!(
            "No network rules on {}: containers can reach private addresses. Run nodes on Linux for isolation.",
            std::env::consts::OS
        ));
    }
    // SAFETY: geteuid has no preconditions.
    if unsafe { libc::geteuid() } != 0 {
        return Some("No network rules: the node does not run as root, so it cannot change iptables.".into());
    }
    let mut position = std::collections::HashMap::new();
    for (chain, rule) in rules(subnet) {
        let exists = run(&[&["-C", chain], &rule[..].iter().map(String::as_str).collect::<Vec<_>>()[..]].concat()).await;
        let pos = position.entry(chain).or_insert(0u32);
        *pos += 1;
        if exists.is_ok() {
            continue;
        }
        let at = pos.to_string();
        let args = [&["-I", chain, at.as_str()], &rule.iter().map(String::as_str).collect::<Vec<_>>()[..]].concat();
        if let Err(e) = run(&args).await {
            return Some(format!("No network rules: iptables failed ({e}). Containers can reach private addresses."));
        }
    }
    None
}

async fn run(args: &[&str]) -> Result<(), String> {
    let out = tokio::process::Command::new("iptables").args(args).output().await.map_err(|e| format!("iptables: {e}"))?;
    if out.status.success() { Ok(()) } else { Err(String::from_utf8_lossy(&out.stderr).trim().to_string()) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn denies_private_and_metadata_addresses_but_lets_replies_through() {
        let r = rules("172.30.0.0/16");
        let joined: Vec<String> = r.iter().map(|(c, a)| format!("{c} {}", a.join(" "))).collect();
        assert_eq!(joined[0], "DOCKER-USER -s 172.30.0.0/16 -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN");
        assert_eq!(joined[1], "DOCKER-USER -s 172.30.0.0/16 -d 172.30.0.0/16 -j RETURN");
        assert!(joined.contains(&"DOCKER-USER -s 172.30.0.0/16 -d 169.254.0.0/16 -j DROP".to_string()));
        assert!(joined.contains(&"DOCKER-USER -s 172.30.0.0/16 -d 10.0.0.0/8 -j DROP".to_string()));
        assert!(joined.contains(&"DOCKER-USER -s 172.30.0.0/16 -d 192.168.0.0/16 -j DROP".to_string()));
        assert_eq!(joined.last().unwrap(), "INPUT -s 172.30.0.0/16 -m conntrack --ctstate NEW -j DROP");
        // Every DROP comes after the RETURNs.
        let first_drop = joined.iter().position(|j| j.ends_with("DROP")).unwrap();
        assert!(joined[..first_drop].iter().all(|j| j.ends_with("RETURN")));
    }
}
