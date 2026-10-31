// SPDX-License-Identifier: AGPL-3.0-only
//! The node's identity and what it remembers, in its state directory (BROD_NODE_DIR):
//! - `node.key`: the Ed25519 key pair (PKCS#8), made once, mode 0600. The node id is derived from its public key, so the
//!   node stays the same node whatever its address.
//! - `node.json`: the Brod it joined and the name it joined with, written after a successful join.
//!
//! What the node signs must match server/src/nodes.rs byte for byte.
use std::io::Write;
use std::path::{Path, PathBuf};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ring::signature::{Ed25519KeyPair, KeyPair};

/// The Upgrade token and the prefix of every message the node signs.
pub const PROTOCOL: &str = "brod-node/1";

pub struct Identity {
    key: Ed25519KeyPair,
    pub id: String,
}

/// A node's id: "node_" and the first 16 bytes of the SHA-256 of its raw 32-byte public key, in hex.
pub fn node_id(public_key: &[u8]) -> String {
    format!("node_{}", hex(&ring::digest::digest(&ring::digest::SHA256, public_key).as_ref()[..16]))
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    hex(ring::digest::digest(&ring::digest::SHA256, bytes).as_ref())
}

/// What the node signs to join with `token`.
pub fn join_message(token: &str) -> String {
    format!("{PROTOCOL} join\n{token}")
}

/// What the node signs to connect with a challenge.
pub fn connect_message(node: &str, challenge: &str) -> String {
    format!("{PROTOCOL} connect\n{node}\n{challenge}")
}

/// What the node signs for a request to Brod: the method, the path, its id, the time (ms) and the body's SHA-256.
pub fn request_message(method: &str, path: &str, node: &str, timestamp: i64, body: &[u8]) -> String {
    format!("{PROTOCOL} {method} {path}\n{node}\n{timestamp}\n{}", sha256_hex(body))
}

impl Identity {
    /// The key pair in `dir`, made (with the directory) the first time.
    pub fn load_or_create(dir: &Path) -> Result<Identity, String> {
        let path = dir.join("node.key");
        let pkcs8 = match std::fs::read(&path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                create_dir(dir)?;
                let doc = Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new()).map_err(|_| "could not make a key pair")?;
                write_private(&path, doc.as_ref(), true).map_err(|e| format!("could not write {}: {e}", path.display()))?;
                doc.as_ref().to_vec()
            }
            Err(e) => return Err(format!("could not read {}: {e}", path.display())),
        };
        let key = Ed25519KeyPair::from_pkcs8(&pkcs8).map_err(|_| format!("{} is not an Ed25519 key pair", path.display()))?;
        let id = node_id(key.public_key().as_ref());
        Ok(Identity { key, id })
    }

    pub fn public_key(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.key.public_key().as_ref())
    }

    pub fn sign(&self, message: &str) -> String {
        URL_SAFE_NO_PAD.encode(self.key.sign(message.as_bytes()).as_ref())
    }
}

/// What `node.json` holds.
#[derive(Clone, Debug, PartialEq)]
pub struct Joined {
    pub brod: String,
    pub name: String,
}

pub fn joined_path(dir: &Path) -> PathBuf {
    dir.join("node.json")
}

/// The Brod this node joined, if it has.
pub fn load_joined(dir: &Path) -> Result<Option<Joined>, String> {
    let path = joined_path(dir);
    let raw = match std::fs::read(&path) {
        Ok(r) => r,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("could not read {}: {e}", path.display())),
    };
    let v: serde_json::Value = serde_json::from_slice(&raw).map_err(|e| format!("{} is not JSON: {e}", path.display()))?;
    let text = |k: &str| v.get(k).and_then(|x| x.as_str()).unwrap_or("").to_string();
    Ok(Some(Joined { brod: text("brod"), name: text("name") }))
}

pub fn save_joined(dir: &Path, j: &Joined) -> Result<(), String> {
    let path = joined_path(dir);
    let text = serde_json::json!({ "brod": j.brod, "name": j.name }).to_string();
    write_private(&path, text.as_bytes(), false).map_err(|e| format!("could not write {}: {e}", path.display()))
}

fn create_dir(dir: &Path) -> Result<(), String> {
    let mut b = std::fs::DirBuilder::new();
    b.recursive(true);
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut b, 0o700);
    b.create(dir).map_err(|e| format!("could not create {}: {e}", dir.display()))
}

/// Write a file only its owner can read. `new`: refuse to replace one that exists.
fn write_private(path: &Path, bytes: &[u8], new: bool) -> std::io::Result<()> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true);
    if new {
        opts.create_new(true);
    } else {
        opts.create(true).truncate(true);
    }
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut opts, 0o600);
    let mut f = opts.open(path)?;
    f.write_all(bytes)?;
    f.sync_all()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir() -> PathBuf {
        let mut b = [0u8; 8];
        ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut b).unwrap();
        std::env::temp_dir().join(format!("brod-node-test-{}", hex(&b))).join("state")
    }

    #[test]
    fn id_is_the_first_half_of_the_keys_sha256() {
        // SHA-256 of 32 zero bytes is 66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925.
        assert_eq!(node_id(&[0u8; 32]), "node_66687aadf862bd776c8fc18b8e9f8e20");
    }

    #[test]
    fn the_key_is_made_once_privately_and_keeps_the_id() {
        let dir = temp_dir();
        let a = Identity::load_or_create(&dir).unwrap();
        let b = Identity::load_or_create(&dir).unwrap();
        assert_eq!(a.id, b.id);
        assert_eq!(a.public_key(), b.public_key());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(dir.join("node.key")).unwrap().permissions().mode() & 0o777, 0o600);
            assert_eq!(std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777, 0o700);
        }
        assert_eq!(load_joined(&dir).unwrap(), None);
        let j = Joined { brod: "https://brod.example".into(), name: "n1".into() };
        save_joined(&dir, &j).unwrap();
        assert_eq!(load_joined(&dir).unwrap(), Some(j));
    }

    #[test]
    fn signatures_verify_with_the_public_key() {
        let dir = temp_dir();
        let me = Identity::load_or_create(&dir).unwrap();
        let msg = request_message("POST", "/_node/heartbeat", &me.id, 5, b"{}");
        assert!(msg.ends_with("44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"), "{msg}");
        let sig = URL_SAFE_NO_PAD.decode(me.sign(&msg)).unwrap();
        let key = URL_SAFE_NO_PAD.decode(me.public_key()).unwrap();
        let pk = ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, &key);
        assert!(pk.verify(msg.as_bytes(), &sig).is_ok());
        assert!(pk.verify(connect_message(&me.id, "x").as_bytes(), &sig).is_err());
    }
}
