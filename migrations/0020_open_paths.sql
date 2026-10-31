-- Open paths: addresses of an app anyone may reach without signing in (open_paths.rs). versions.open_paths keeps what a
-- version's brod.json declares (a JSON list, NULL when it declares none); apps.open_paths keeps what a person approved.
-- A path is open only while the served version declares it and an approved entry covers it.
ALTER TABLE apps ADD COLUMN open_paths TEXT NOT NULL DEFAULT '[]';
ALTER TABLE versions ADD COLUMN open_paths TEXT;
