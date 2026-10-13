-- An app's slug only needs to be unique inside its workspace, as migrations/0003_app_slug_per_workspace.sql.
-- Postgres drops a constraint in place, so there is no table rebuild and no deferred foreign keys. SQLite's rebuild
-- also loses the apps_workspace index, which the new unique index covers; drop it here too so both schemas match.
ALTER TABLE apps DROP CONSTRAINT apps_slug_key;
ALTER TABLE apps ADD CONSTRAINT apps_workspace_id_slug_key UNIQUE (workspace_id, slug);
DROP INDEX apps_workspace;
