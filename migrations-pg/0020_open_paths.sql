-- Open paths, as migrations/0020_open_paths.sql.
ALTER TABLE apps ADD COLUMN open_paths TEXT NOT NULL DEFAULT '[]';
ALTER TABLE versions ADD COLUMN open_paths TEXT;
