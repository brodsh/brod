-- Access mode "password", as migrations/0009_app_password.sql. Postgres changes the CHECK constraint in place.
ALTER TABLE apps DROP CONSTRAINT apps_access_check;
ALTER TABLE apps ADD CONSTRAINT apps_access_check CHECK (access IN ('private', 'people', 'workspace', 'password', 'signed_in', 'public'));
ALTER TABLE apps ADD COLUMN password_hash TEXT;
