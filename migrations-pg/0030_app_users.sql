-- Sign-in codes asked for from an app's own login page (server/src/app_signin.rs). A code signs a person in to that one
-- app only, never to the platform. hash: SHA-256 of the app, the address and the code. A new code ends the earlier one.
CREATE TABLE app_sign_in_codes (
  id TEXT PRIMARY KEY, app_id TEXT NOT NULL, email TEXT NOT NULL, hash TEXT NOT NULL, attempts BIGINT NOT NULL DEFAULT 0,
  created_at BIGINT NOT NULL, expires_at BIGINT NOT NULL, used_at BIGINT
);
CREATE INDEX app_sign_in_codes_lookup ON app_sign_in_codes (app_id, email, created_at);
-- App users (server/src/people.rs): what a grant carries besides a role, such as {"tenant": "acme"}, as JSON. It reaches the
-- app in the identity token, and the app applies it to its data. NULL: this grant has none.
ALTER TABLE grants ADD COLUMN filters TEXT;
