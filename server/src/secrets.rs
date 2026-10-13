// SPDX-License-Identifier: AGPL-3.0-only
// Per-app secrets. Encrypted at rest with AES-256-GCM under a key derived from SECRETS_KEY with HKDF-SHA256,
// with the app id as associated data.
// Stored as base64(iv) + "." + base64(ciphertext and tag).
use crate::db::{Connection, params};
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use hkdf::Hkdf;
use serde_json::{Value, json};
use sha2::Sha256;

use crate::db::Sql;
use crate::problem::{Problem, Result};
use crate::util::{iso, now, random_bytes};

const RESERVED: &[&str] = &["DB", "KV", "FILES", "SETTINGS"];
const MAX_BYTES: usize = 5 * 1024;

fn key(secrets_key: &str) -> Result<Aes256Gcm> {
    // SECRETS_KEY.length counts UTF-16 code units in JavaScript.
    if secrets_key.encode_utf16().count() < 16 {
        return Err(Problem::new(503, "secrets_unavailable", "Secrets are not configured on this server (SECRETS_KEY)."));
    }
    let hk = Hkdf::<Sha256>::new(Some(&[]), secrets_key.as_bytes());
    let mut okm = [0u8; 32];
    hk.expand(b"brod app secrets v1", &mut okm).map_err(Problem::internal)?;
    Aes256Gcm::new_from_slice(&okm).map_err(Problem::internal)
}

pub fn seal(secrets_key: &str, app_id: &str, value: &str) -> Result<String> {
    let cipher = key(secrets_key)?;
    let iv = random_bytes(12);
    let ct = cipher
        .encrypt(Nonce::from_slice(&iv), Payload { msg: value.as_bytes(), aad: app_id.as_bytes() })
        .map_err(|_| Problem::internal("encrypt"))?;
    Ok(format!("{}.{}", STANDARD.encode(iv), STANDARD.encode(ct)))
}

pub fn open(secrets_key: &str, app_id: &str, sealed: &str) -> Result<String> {
    let cipher = key(secrets_key)?;
    let (iv, ct) = sealed.split_once('.').ok_or_else(|| Problem::internal("sealed secret has no iv"))?;
    let iv = STANDARD.decode(iv).map_err(Problem::internal)?;
    let ct = STANDARD.decode(ct).map_err(Problem::internal)?;
    if iv.len() != 12 {
        return Err(Problem::internal("sealed secret iv is not 12 bytes"));
    }
    let plain = cipher
        .decrypt(Nonce::from_slice(&iv), Payload { msg: &ct, aad: app_id.as_bytes() })
        .map_err(|_| Problem::internal("a secret could not be decrypted (wrong SECRETS_KEY or app)"))?;
    String::from_utf8(plain).map_err(Problem::internal)
}

/// UPPER_SNAKE_CASE, 1 to 64 characters, not reserved.
pub fn check_name(name: &str) -> Result<()> {
    let b = name.as_bytes();
    let ok = !b.is_empty()
        && b.len() <= 64
        && b[0].is_ascii_uppercase()
        && b.iter().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || *c == b'_');
    if !ok || RESERVED.contains(&name) || name.starts_with("BROD_") {
        return Err(Problem::new(
            400,
            "bad_name",
            "A secret name is UPPER_SNAKE_CASE, for example \"STRIPE_KEY\". DB, KV, FILES, SETTINGS and names starting with BROD_ are reserved.",
        ));
    }
    Ok(())
}

/// Set or replace one secret, inside the caller's transaction.
pub fn put(conn: &Connection, secrets_key: &str, app_id: &str, name: &str, value: &str, actor: &str) -> Result<()> {
    check_name(name)?;
    if value.is_empty() {
        return Err(Problem::new(400, "bad_value", "Give the secret a non-empty string value."));
    }
    if value.len() > MAX_BYTES {
        return Err(Problem::new(413, "too_large", "A secret can be at most 5 KB."));
    }
    if conn.count("SELECT COUNT(*) AS n FROM secrets WHERE app_id = ? AND name != ?", params![app_id, name])? >= 50 {
        return Err(Problem::new(409, "too_many", "An app can have at most 50 secrets."));
    }
    let sealed = seal(secrets_key, app_id, value)?;
    conn.run(
        "INSERT INTO secrets (app_id, name, value, updated_at, updated_by) VALUES (?,?,?,?,?) ON CONFLICT(app_id, name) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at, updated_by = excluded.updated_by",
        params![app_id, name, sealed, now(), actor],
    )?;
    conn.run("UPDATE apps SET secrets_rev = secrets_rev + 1 WHERE id = ?", [app_id])?;
    Ok(())
}

pub fn delete(conn: &Connection, app_id: &str, name: &str) -> Result<()> {
    conn.run("DELETE FROM secrets WHERE app_id = ? AND name = ?", params![app_id, name])?;
    conn.run("UPDATE apps SET secrets_rev = secrets_rev + 1 WHERE id = ?", [app_id])?;
    Ok(())
}

/// Names only: values are never returned.
pub fn list(conn: &Connection, app_id: &str) -> Result<Value> {
    let rows = conn.all("SELECT name, updated_at, updated_by FROM secrets WHERE app_id = ? ORDER BY name", [app_id], |r| {
        Ok(json!({ "name": r.get::<_, String>(0)?, "updated": iso(r.get(1)?), "by": r.get::<_, String>(2)? }))
    })?;
    Ok(Value::Array(rows))
}

/// Decrypted secrets for the app's server code. Only the runtime endpoint calls this.
pub fn read_all(conn: &Connection, secrets_key: &str, app_id: &str) -> Result<Vec<(String, String)>> {
    let rows =
        conn.all("SELECT name, value FROM secrets WHERE app_id = ?", [app_id], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?;
    rows.into_iter().map(|(n, v)| Ok((n, open(secrets_key, app_id, &v)?))).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "dev-secrets-key-0123456789";

    #[test]
    fn round_trips_and_binds_the_app() {
        let s = seal(KEY, "app_1", "tok-123").unwrap();
        assert_eq!(open(KEY, "app_1", &s).unwrap(), "tok-123");
        assert!(open(KEY, "app_2", &s).is_err());
        assert!(open("another-key-0123456789", "app_1", &s).is_err());
        assert_eq!(seal("short", "app_1", "x").unwrap_err().code, "secrets_unavailable");
    }

    #[test]
    fn opens_a_value_sealed_by_an_earlier_version() {
        // Sealed by Brod's first (TypeScript) version under SECRETS_KEY "dev-secrets-key-0123456789" for app
        // "app_compat". Stored secrets must keep opening after an upgrade.
        let sealed = include_str!("../tests/fixtures/sealed-v1.txt").trim();
        assert_eq!(open(KEY, "app_compat", sealed).unwrap(), "sk_live_ünïcode ✓");
    }

    #[test]
    fn checks_names() {
        for ok in ["API_TOKEN", "A", "STRIPE_KEY_2"] {
            assert!(check_name(ok).is_ok(), "{ok}");
        }
        for bad in ["lowercase", "DB", "KV", "FILES", "BROD_X", "1ABC", "", &"A".repeat(65)] {
            assert_eq!(check_name(bad).unwrap_err().code, "bad_name", "{bad}");
        }
    }
}
