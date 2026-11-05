-- Who may use a node, as migrations/0030_node_owners.sql.
ALTER TABLE nodes ADD COLUMN workspace_id TEXT;
ALTER TABLE node_join_tokens ADD COLUMN workspace_id TEXT;
CREATE INDEX nodes_workspace ON nodes (workspace_id);
