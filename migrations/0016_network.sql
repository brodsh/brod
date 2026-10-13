-- Outside addresses: the hosts an app declares it talks to, in the "network" list of its brod.json. versions.network
-- keeps the declaration (a JSON list of hosts, NULL when it declares none), and a release keeps its version's, so an
-- installer sees and approves where an app sends data before installing it, and again when an update adds a host.
ALTER TABLE versions ADD COLUMN network TEXT;
ALTER TABLE releases ADD COLUMN network TEXT;

-- Each outside host an app reached, or tried to reach, without declaring it: from its server code (the runtime's
-- outbound gate) or from the browser (Content-Security-Policy reports). One row per app, host and source, counted.
-- blocked is 1 when the attempt was refused (BROD_NETWORK=enforce), 0 when it was only logged.
CREATE TABLE network_reports (
  app_id TEXT NOT NULL REFERENCES apps(id), host TEXT NOT NULL, source TEXT NOT NULL CHECK (source IN ('server', 'browser')),
  version INTEGER, count INTEGER NOT NULL, blocked INTEGER NOT NULL DEFAULT 0, first_at INTEGER NOT NULL, last_at INTEGER NOT NULL,
  PRIMARY KEY (app_id, host, source)
);
