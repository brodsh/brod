// SPDX-License-Identifier: AGPL-3.0-only
// Which node runs a deployment. A node qualifies when it is online and connected (not joining, draining, offline or
// disabled), runs Docker, has the image's architecture, and has the CPU and memory free: its capacity from its last
// heartbeat (memory in use when it reports it), less what Brod already reserved there for deployments that are not
// stopped. Among those, the node already running the app's live version wins, so an update stays where it was; else
// the node with the most memory free.
use serde_json::Value;

use crate::db::{Connection, Sql};
use crate::problem::{Problem, Result};

/// A node as the scheduler sees it.
#[derive(Clone, Debug)]
pub struct Candidate {
    pub id: String,
    pub status: String,
    pub connected: bool,
    pub capabilities: Value,
    pub usage: Value,
    /// CPUs and MB reserved by the node's deployments that are not stopped.
    pub reserved_cpu: f64,
    pub reserved_mb: i64,
}

/// What a deployment needs.
#[derive(Clone, Debug, Default)]
pub struct Need {
    pub cpu: f64,
    pub memory_mb: i64,
    /// amd64 or arm64 when the image is already built for one.
    pub arch: Option<String>,
    /// The node to keep it on when it fits.
    pub prefer: Option<String>,
}

/// CPUs and MB free on a node, after reservations.
pub fn free(c: &Candidate) -> (f64, i64) {
    let cpus = c.capabilities["cpus"].as_f64().unwrap_or(0.0);
    let mb = |b: &Value| b.as_f64().map(|b| (b / 1024.0 / 1024.0) as i64);
    let total = mb(&c.usage["memory_total"]).or(mb(&c.capabilities["memory_bytes"])).unwrap_or(0);
    let used = mb(&c.usage["memory_used"]).unwrap_or(0);
    (cpus - c.reserved_cpu, total - used - c.reserved_mb)
}

/// Why a node cannot take the deployment, or None when it can.
pub fn unfit(c: &Candidate, need: &Need) -> Option<String> {
    if c.status != "online" || !c.connected {
        return Some(format!("{} is {}", c.id, if c.connected { c.status.as_str() } else { "not connected" }));
    }
    if c.capabilities["engine"].as_str() != Some("docker") {
        return Some(format!("{} has no Docker", c.id));
    }
    if let Some(a) = &need.arch
        && c.capabilities["arch"].as_str() != Some(a.as_str())
    {
        return Some(format!("{} is not {a}", c.id));
    }
    let (cpu, mb) = free(c);
    if cpu + 1e-9 < need.cpu {
        return Some(format!("{} has {cpu:.2} CPUs free", c.id));
    }
    if mb < need.memory_mb {
        return Some(format!("{} has {mb} MB free", c.id));
    }
    None
}

/// The node to run on, or every node's reason for refusing.
pub fn pick(candidates: &[Candidate], need: &Need) -> std::result::Result<String, Vec<String>> {
    let mut fit: Vec<&Candidate> = Vec::new();
    let mut why = Vec::new();
    for c in candidates {
        match unfit(c, need) {
            None => fit.push(c),
            Some(w) => why.push(w),
        }
    }
    if let Some(p) = need.prefer.as_deref().and_then(|p| fit.iter().find(|c| c.id == p)) {
        return Ok(p.id.clone());
    }
    fit.sort_by(|a, b| free(b).1.cmp(&free(a).1).then(a.id.cmp(&b.id)));
    fit.first().map(|c| c.id.clone()).ok_or(why)
}

/// The states in which a deployment holds its node's CPU and memory.
pub const RESERVING: &str = "('scheduled','building','pulling','starting','healthy','serving','draining')";

/// Every node, with its reservations, for `pick`.
pub fn candidates(conn: &Connection, connected: &[String]) -> Result<Vec<Candidate>> {
    let sql = format!(
        "SELECT n.id, n.status, n.capabilities, n.resources,
           CAST(COALESCE((SELECT SUM(d.cpu) FROM deployments d WHERE d.node_id = n.id AND d.state IN {RESERVING}), 0) AS DOUBLE PRECISION) AS cpu,
           CAST(COALESCE((SELECT SUM(d.memory_mb) FROM deployments d WHERE d.node_id = n.id AND d.state IN {RESERVING}), 0) AS BIGINT) AS mb
         FROM nodes n ORDER BY n.id"
    );
    conn.all(&sql, (), |r| {
        let id: String = r.get(0)?;
        let parse = |s: Option<String>| s.and_then(|s| serde_json::from_str(&s).ok()).unwrap_or(Value::Null);
        Ok(Candidate {
            connected: connected.contains(&id),
            id,
            status: r.get(1)?,
            capabilities: parse(r.get(2)?),
            usage: parse(r.get(3)?),
            reserved_cpu: r.get(4)?,
            reserved_mb: r.get(5)?,
        })
    })
}

/// Choose a node for a deployment, or refuse with why no node can take it.
pub fn choose(conn: &Connection, connected: &[String], need: &Need) -> Result<String> {
    let all = candidates(conn, connected)?;
    pick(&all, need).map_err(|why| {
        let detail = if why.is_empty() { "No node has joined Brod.".to_string() } else { format!("{}.", why.join("; ")) };
        Problem::new(
            503,
            "no_node",
            format!(
                "No node can run this container ({} CPU, {} MB): {detail} Free capacity, lower \"cpu\" or \"memory_mb\", or join a node.",
                need.cpu, need.memory_mb
            ),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn node(id: &str, cpus: f64, mem_mb: i64) -> Candidate {
        Candidate {
            id: id.into(),
            status: "online".into(),
            connected: true,
            capabilities: json!({ "engine": "docker", "arch": "arm64", "cpus": cpus, "memory_bytes": mem_mb * 1024 * 1024 }),
            usage: json!({}),
            reserved_cpu: 0.0,
            reserved_mb: 0,
        }
    }

    #[test]
    fn picks_a_node_that_fits() {
        let need = Need { cpu: 0.5, memory_mb: 512, ..Need::default() };
        let mut nodes = vec![node("a", 2.0, 1024), node("b", 4.0, 8192)];
        assert_eq!(pick(&nodes, &need).unwrap(), "b", "most memory free wins");
        assert_eq!(pick(&nodes, &Need { prefer: Some("a".into()), ..need.clone() }).unwrap(), "a", "the current node wins when it fits");
        // Reservations and memory in use count against a node.
        nodes[1].reserved_mb = 7900;
        assert_eq!(pick(&nodes, &need).unwrap(), "a");
        nodes[0].usage = json!({ "memory_total": 1024u64 * 1024 * 1024, "memory_used": 800u64 * 1024 * 1024 });
        let why = pick(&nodes, &need).unwrap_err();
        assert_eq!(why, vec!["a has 224 MB free".to_string(), "b has 292 MB free".to_string()]);
        nodes[1].reserved_mb = 0;
        nodes[1].reserved_cpu = 3.8;
        assert_eq!(pick(&nodes, &need).unwrap_err()[1], "b has 0.20 CPUs free");
    }

    #[test]
    fn skips_nodes_that_cannot_run_containers() {
        let need = Need { cpu: 0.5, memory_mb: 256, arch: Some("arm64".into()), prefer: Some("draining".into()) };
        let mut draining = node("draining", 8.0, 8192);
        draining.status = "draining".into();
        let mut gone = node("gone", 8.0, 8192);
        gone.connected = false;
        let mut amd = node("amd", 8.0, 8192);
        amd.capabilities["arch"] = json!("amd64");
        let mut bare = node("bare", 8.0, 8192);
        bare.capabilities["engine"] = json!("none");
        let mut disabled = node("disabled", 8.0, 8192);
        disabled.status = "disabled".into();
        let all = vec![draining, gone, amd, bare, disabled];
        let why = pick(&all, &need).unwrap_err();
        assert_eq!(why.len(), 5, "{why:?}");
        assert!(why[1].contains("not connected") && why[2].contains("not arm64") && why[3].contains("no Docker"));
        let mut ok = all.clone();
        ok.push(node("ok", 1.0, 512));
        assert_eq!(pick(&ok, &need).unwrap(), "ok");
    }
}
