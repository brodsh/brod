-- Who may use a node (server/src/scheduler.rs, docs/security.md). nodes.workspace_id NULL: an instance node, run by the
-- operator for the whole server; it takes every workspace's workloads when BROD_SHARED_NODES is on (the self-hosted
-- default) and none otherwise (the hosted default), until the operator gives it to a workspace. Otherwise the node
-- belongs to that workspace, and only that workspace's workloads are placed on it. A join token minted for a workspace
-- (node_join_tokens.workspace_id) makes the node that joins with it that workspace's.
-- Later, an agency's nodes shared with its client workspaces become a grant table (node_id, workspace_id) next to the
-- owner; the owner column stays.
ALTER TABLE nodes ADD COLUMN workspace_id TEXT;
ALTER TABLE node_join_tokens ADD COLUMN workspace_id TEXT;
CREATE INDEX nodes_workspace ON nodes (workspace_id);
