// SPDX-License-Identifier: AGPL-3.0-only
// Which node runs a deployment. A node qualifies when it is online and connected (not joining, draining, offline or
// disabled), runs Docker, has the image's architecture, and has the CPU and memory free: its capacity from its last
// heartbeat (memory in use when it reports it), less what Brod already reserved there for deployments that are not
// stopped. Among those, the node already running the app's live version wins, so an update stays where it was; else
// the workspace's own nodes before instance nodes, and then the node with the most memory free.
//
// Only nodes the app's workspace may use are considered at all: the nodes it owns, and instance nodes (no owner) when
// BROD_SHARED_NODES is on. A node another workspace owns is never a candidate and is never named to this workspace,
// not even in why no node can take a deployment. This is what keeps one tenant's containers off another tenant's
// machine once customers join their own nodes or Brod sells them nodes (docs/security.md).
use serde_json::Value;

use crate::db::{Connection, Sql};
use crate::problem::{Problem, Result};

/// A node as the scheduler sees it.
#[derive(Clone, Debug)]
pub struct Candidate {
    pub id: String,
    /// The workspace that owns the node, or None for an instance node.
    pub workspace: Option<String>,
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
    /// The workspace whose workload this is.
    pub workspace: String,
    /// Whether instance nodes may take it (BROD_SHARED_NODES).
    pub shared: bool,
}

/// Whether the workload's workspace may use the node at all: it owns it, or it is an instance node and instance nodes
/// are shared.
pub fn usable(c: &Candidate, need: &Need) -> bool {
    match &c.workspace {
        Some(w) => *w == need.workspace,
        None => need.shared,
    }
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

/// The node to run on, or the reason each node the workspace may use refuses. Nodes it may not use are skipped
/// without a reason, so their names never reach it.
pub fn pick(candidates: &[Candidate], need: &Need) -> std::result::Result<String, Vec<String>> {
    let mut fit: Vec<&Candidate> = Vec::new();
    let mut why = Vec::new();
    for c in candidates.iter().filter(|c| usable(c, need)) {
        match unfit(c, need) {
            None => fit.push(c),
            Some(w) => why.push(w),
        }
    }
    if let Some(p) = need.prefer.as_deref().and_then(|p| fit.iter().find(|c| c.id == p)) {
        return Ok(p.id.clone());
    }
    fit.sort_by(|a, b| (b.workspace.is_some().cmp(&a.workspace.is_some())).then(free(b).1.cmp(&free(a).1)).then(a.id.cmp(&b.id)));
    fit.first().map(|c| c.id.clone()).ok_or(why)
}

/// The states in which a deployment holds its node's CPU and memory.
pub const RESERVING: &str = "('scheduled','building','pulling','starting','healthy','serving','draining')";

/// The nodes `workspace` may use (its own, and instance nodes when `shared`), with their reservations, for `pick`.
pub fn candidates(conn: &Connection, connected: &[String], workspace: &str, shared: bool) -> Result<Vec<Candidate>> {
    let instance = if shared { " OR n.workspace_id IS NULL" } else { "" };
    let sql = format!(
        "SELECT n.id, n.status, n.capabilities, n.resources,
           CAST(COALESCE((SELECT SUM(d.cpu) FROM deployments d WHERE d.node_id = n.id AND d.state IN {RESERVING}), 0) AS DOUBLE PRECISION) AS cpu,
           CAST(COALESCE((SELECT SUM(d.memory_mb) FROM deployments d WHERE d.node_id = n.id AND d.state IN {RESERVING}), 0) AS BIGINT) AS mb
           , n.workspace_id
         FROM nodes n WHERE n.workspace_id = ?{instance} ORDER BY n.id"
    );
    conn.all(&sql, [workspace], |r| {
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
            workspace: r.get(6)?,
        })
    })
}

/// Choose a node for a deployment, or refuse with why no node can take it.
pub fn choose(conn: &Connection, connected: &[String], need: &Need) -> Result<String> {
    let all = candidates(conn, connected, &need.workspace, need.shared)?;
    pick(&all, need).map_err(|why| {
        let detail = match (why.is_empty(), need.shared) {
            (false, _) => format!("{}.", why.join("; ")),
            (true, true) => "No node has joined Brod.".to_string(),
            (true, false) => "This workspace has no nodes of its own.".to_string(),
        };
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
            workspace: None,
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
        let need = Need { cpu: 0.5, memory_mb: 512, shared: true, ..Need::default() };
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
        let need = Need {
            cpu: 0.5,
            memory_mb: 256,
            arch: Some("arm64".into()),
            prefer: Some("draining".into()),
            workspace: "ws_a".into(),
            shared: true,
        };
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

    fn owned(id: &str, workspace: &str, mem_mb: i64) -> Candidate {
        Candidate { workspace: Some(workspace.into()), ..node(id, 8.0, mem_mb) }
    }

    #[test]
    fn never_places_on_another_workspaces_node() {
        // b's node is the biggest, idle, and even the "current" node: a's workload still never lands there, and its
        // name is not in a's reasons.
        let need =
            |shared| Need { cpu: 0.5, memory_mb: 256, workspace: "ws_a".into(), shared, prefer: Some("b-node".into()), ..Need::default() };
        let nodes = vec![owned("b-node", "ws_b", 65536), owned("a-node", "ws_a", 1024), node("instance", 8.0, 32768)];
        for shared in [true, false] {
            assert_eq!(pick(&nodes, &need(shared)).unwrap(), "a-node", "own nodes first (shared: {shared})");
        }
        let mut full = nodes.clone();
        full[1].reserved_mb = 1024;
        assert_eq!(pick(&full, &need(true)).unwrap(), "instance", "then instance nodes, when shared");
        let why = pick(&full, &need(false)).unwrap_err();
        assert_eq!(why, vec!["a-node has 0 MB free".to_string()], "hosted: no instance node, and b's is never named");
        let only_b = vec![owned("b-node", "ws_b", 65536)];
        assert_eq!(pick(&only_b, &need(true)).unwrap_err(), Vec::<String>::new());
    }

    #[test]
    fn self_hosted_instance_nodes_serve_every_workspace() {
        // The self-hosted default: no node has an owner and BROD_SHARED_NODES is on, so every workspace uses them.
        let nodes = vec![node("n1", 4.0, 4096), node("n2", 4.0, 8192)];
        for ws in ["ws_a", "ws_b"] {
            let need = Need { cpu: 1.0, memory_mb: 512, workspace: ws.into(), shared: true, ..Need::default() };
            assert_eq!(pick(&nodes, &need).unwrap(), "n2");
        }
        let hosted = Need { cpu: 1.0, memory_mb: 512, workspace: "ws_a".into(), shared: false, ..Need::default() };
        assert!(pick(&nodes, &hosted).unwrap_err().is_empty(), "hosted: instance nodes take nothing");
    }

    #[tokio::test]
    async fn choose_reads_ownership_from_the_database() {
        crate::db::test_db()
            .call(|c| {
                let caps = r#"{"engine":"docker","arch":"amd64","cpus":8,"memory_bytes":17179869184}"#;
                for (id, ws) in [("node_a", Some("ws_a")), ("node_b", Some("ws_b")), ("node_i", None)] {
                    c.run(
                        "INSERT INTO nodes (id, public_key, name, status, capabilities, created_at, workspace_id) VALUES (?,?,?,'online',?,1,?)",
                        crate::db::params![id, format!("pk-{id}"), id, caps, ws],
                    )?;
                }
                let connected: Vec<String> = ["node_a", "node_b", "node_i"].map(String::from).to_vec();
                let need = |ws: &str, shared| Need { cpu: 1.0, memory_mb: 512, workspace: ws.into(), shared, ..Need::default() };
                assert_eq!(choose(c, &connected, &need("ws_a", true))?, "node_a");
                assert_eq!(choose(c, &connected, &need("ws_b", false))?, "node_b");
                assert_eq!(choose(c, &connected, &need("ws_c", true))?, "node_i", "a workspace without nodes gets instance nodes");
                let e = choose(c, &connected, &need("ws_c", false)).unwrap_err();
                assert_eq!(e.status, 503);
                assert!(e.message.contains("no nodes of its own") && !e.message.contains("node_a") && !e.message.contains("node_b"), "{}", e.message);
                // Its own node offline: a's workload waits rather than spilling onto b's node.
                c.run("UPDATE nodes SET status = 'offline' WHERE id = 'node_a'", ())?;
                let e = choose(c, &connected, &need("ws_a", false)).unwrap_err();
                assert!(e.message.contains("node_a is offline") && !e.message.contains("node_b"), "{}", e.message);
                Ok(())
            })
            .await
            .unwrap();
    }
}
