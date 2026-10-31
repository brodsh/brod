// SPDX-License-Identifier: AGPL-3.0-only
// The identity token: who is signed in to an app, as a JWT signed with Brod's Ed25519 key (alg EdDSA).
//
// The gateway hands it to server code as the x-brod-identity header and to the browser as the "token" of /_brod/me.
// Anyone can check it with an off-the-shelf JWT library and the public key from <BROD_PUBLIC_URL>/.well-known/jwks.json
// (server apps also get the key set inline, as env.BROD_IDENTITY_JWKS), so no app ever holds a secret that could mint
// identities, and a token made for one app (aud "brod:app:<app id>") is refused by every other.
//
// The signing key is IDENTITY_SIGNING_KEY: a 32-byte Ed25519 seed (64 hex characters, or base64) or a PKCS#8 document
// in base64. A self-hosted Brod generates one into secrets.env; a hosted one must be given it.
use std::sync::Arc;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ring::signature::{ED25519, Ed25519KeyPair, KeyPair, UnparsedPublicKey};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::util::b64url;

/// Brod's identity signing key, with its key id (the RFC 7638 thumbprint of its public JWK).
#[derive(Clone)]
pub struct IdentityKey {
    pair: Arc<Ed25519KeyPair>,
    /// The public key, base64url: the JWK's "x".
    x: String,
    pub kid: String,
}

impl std::fmt::Debug for IdentityKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "IdentityKey({})", self.kid)
    }
}

impl IdentityKey {
    /// Read IDENTITY_SIGNING_KEY. The error names the variable, never its value.
    pub fn parse(text: &str) -> Result<IdentityKey, String> {
        let text = text.trim();
        let bad = || {
            "IDENTITY_SIGNING_KEY must be an Ed25519 key: 32 random bytes as 64 hex characters (openssl rand -hex 32), or a PKCS#8 key in base64."
                .to_string()
        };
        let bytes = if text.len() == 64 && text.bytes().all(|b| b.is_ascii_hexdigit()) {
            hex::decode(text).map_err(|_| bad())?
        } else {
            let clean = text.trim_end_matches('=');
            base64::engine::general_purpose::STANDARD_NO_PAD.decode(clean).or_else(|_| URL_SAFE_NO_PAD.decode(clean)).map_err(|_| bad())?
        };
        let pair = if bytes.len() == 32 {
            Ed25519KeyPair::from_seed_unchecked(&bytes).map_err(|_| bad())?
        } else {
            Ed25519KeyPair::from_pkcs8_maybe_unchecked(&bytes).map_err(|_| bad())?
        };
        let x = b64url(pair.public_key().as_ref());
        // RFC 7638: the SHA-256 of the required members in lexicographic order, without spaces.
        let kid = b64url(&Sha256::digest(format!("{{\"crv\":\"Ed25519\",\"kty\":\"OKP\",\"x\":\"{x}\"}}").as_bytes()));
        Ok(IdentityKey { pair: Arc::new(pair), x, kid })
    }

    /// The public key as a JWK.
    pub fn jwk(&self) -> Value {
        json!({ "kty": "OKP", "crv": "Ed25519", "x": self.x, "kid": self.kid, "use": "sig", "alg": "EdDSA" })
    }

    /// The JWK set served at /.well-known/jwks.json.
    pub fn jwks(&self) -> Value {
        json!({ "keys": [self.jwk()] })
    }

    /// A compact JWS of `claims`, with the header {alg: EdDSA, typ: JWT, kid}.
    pub fn sign(&self, claims: &Value) -> String {
        let header = json!({ "alg": "EdDSA", "typ": "JWT", "kid": self.kid });
        let input = format!("{}.{}", b64url(header.to_string().as_bytes()), b64url(claims.to_string().as_bytes()));
        let sig = self.pair.sign(input.as_bytes());
        format!("{input}.{}", b64url(sig.as_ref()))
    }

    /// Check a token Brod signed, the way an app would: signature, kid, issuer, audience and expiry. Returns the claims.
    pub fn verify(&self, token: &str, issuer: &str, audience: &str, now_sec: i64) -> Result<Value, &'static str> {
        verify_with(&self.jwks(), token, issuer, audience, now_sec)
    }
}

/// Check a token against a JWK set, as an app does with a JWT library.
pub fn verify_with(jwks: &Value, token: &str, issuer: &str, audience: &str, now_sec: i64) -> Result<Value, &'static str> {
    let mut parts = token.split('.');
    let (Some(h), Some(c), Some(s), None) = (parts.next(), parts.next(), parts.next(), parts.next()) else {
        return Err("not a compact JWT");
    };
    let decode = |p: &str| URL_SAFE_NO_PAD.decode(p).map_err(|_| "bad base64url");
    let header: Value = serde_json::from_slice(&decode(h)?).map_err(|_| "bad header")?;
    if header["alg"] != "EdDSA" {
        return Err("wrong alg");
    }
    let key = jwks["keys"]
        .as_array()
        .and_then(|keys| keys.iter().find(|k| k["kid"] == header["kid"] && k["kty"] == "OKP" && k["crv"] == "Ed25519"))
        .ok_or("unknown kid")?;
    let public = decode(key["x"].as_str().unwrap_or(""))?;
    UnparsedPublicKey::new(&ED25519, public).verify(format!("{h}.{c}").as_bytes(), &decode(s)?).map_err(|_| "bad signature")?;
    let claims: Value = serde_json::from_slice(&decode(c)?).map_err(|_| "bad claims")?;
    if claims["iss"] != issuer {
        return Err("wrong iss");
    }
    if claims["aud"] != audience {
        return Err("wrong aud");
    }
    if claims["exp"].as_i64().is_none_or(|exp| exp <= now_sec) {
        return Err("expired");
    }
    Ok(claims)
}

/// The audience of an app's identity tokens.
pub fn audience(app_id: &str) -> String {
    format!("brod:app:{app_id}")
}

/// A fresh random signing key, as IDENTITY_SIGNING_KEY: a 32-byte seed in hex.
pub fn generate() -> String {
    hex::encode(crate::util::random_bytes(32))
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::STANDARD;

    /// Base64 (standard, padded) of a PKCS#8 document, for operators who keep keys in that form.
    fn pkcs8_base64(seed_hex: &str) -> Option<String> {
        // ring only writes PKCS#8 for keys it generates, so this wraps the seed in the fixed RFC 8410 prefix.
        let seed = hex::decode(seed_hex).ok().filter(|s| s.len() == 32)?;
        let mut der = vec![0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20];
        der.extend_from_slice(&seed);
        Some(STANDARD.encode(der))
    }

    const SEED: &str = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";

    #[test]
    fn signs_tokens_that_verify_against_the_jwks() {
        let key = IdentityKey::parse(SEED).unwrap();
        // RFC 8032 test vector 1: this seed has this public key.
        assert_eq!(
            hex::encode(URL_SAFE_NO_PAD.decode(&key.x).unwrap()),
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
        );
        let claims = json!({ "iss": "https://brod.test", "aud": audience("app_1"), "sub": "usr_1", "exp": 2_000, "iat": 1_700 });
        let token = key.sign(&claims);
        let header: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(token.split('.').next().unwrap()).unwrap()).unwrap();
        assert_eq!(header, json!({ "alg": "EdDSA", "typ": "JWT", "kid": key.kid }));
        assert_eq!(key.verify(&token, "https://brod.test", "brod:app:app_1", 1_800).unwrap()["sub"], "usr_1");
        assert_eq!(key.verify(&token, "https://brod.test", "brod:app:app_2", 1_800), Err("wrong aud"));
        assert_eq!(key.verify(&token, "https://other.test", "brod:app:app_1", 1_800), Err("wrong iss"));
        assert_eq!(key.verify(&token, "https://brod.test", "brod:app:app_1", 2_000), Err("expired"));
        // A changed claim, or another key, fails the signature.
        let (h, rest) = token.split_once('.').unwrap();
        let (_, s) = rest.split_once('.').unwrap();
        let forged = format!(
            "{h}.{}.{s}",
            b64url(json!({ "iss": "https://brod.test", "aud": "brod:app:app_1", "sub": "usr_2", "exp": 2_000 }).to_string().as_bytes())
        );
        assert_eq!(key.verify(&forged, "https://brod.test", "brod:app:app_1", 1_800), Err("bad signature"));
        let other = IdentityKey::parse(&generate()).unwrap();
        assert_eq!(verify_with(&other.jwks(), &token, "https://brod.test", "brod:app:app_1", 1_800), Err("unknown kid"));
        let mut swapped = other.jwks();
        swapped["keys"][0]["kid"] = json!(key.kid);
        assert_eq!(verify_with(&swapped, &token, "https://brod.test", "brod:app:app_1", 1_800), Err("bad signature"));
    }

    #[test]
    fn the_jwks_is_one_okp_ed25519_key() {
        let key = IdentityKey::parse(SEED).unwrap();
        let jwks = key.jwks();
        let k = &jwks["keys"][0];
        assert_eq!(jwks["keys"].as_array().unwrap().len(), 1);
        assert_eq!(
            (k["kty"].as_str(), k["crv"].as_str(), k["alg"].as_str(), k["use"].as_str()),
            (Some("OKP"), Some("Ed25519"), Some("EdDSA"), Some("sig"))
        );
        assert_eq!(URL_SAFE_NO_PAD.decode(k["x"].as_str().unwrap()).unwrap().len(), 32);
        assert!(k.get("d").is_none(), "the private key never leaves");
        // RFC 8037 appendix A.3: the thumbprint of this key.
        assert_eq!(key.kid, "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k");
    }

    #[test]
    fn reads_the_key_as_hex_base64_or_pkcs8() {
        let kid = IdentityKey::parse(SEED).unwrap().kid;
        let seed = hex::decode(SEED).unwrap();
        assert_eq!(IdentityKey::parse(&STANDARD.encode(&seed)).unwrap().kid, kid);
        assert_eq!(IdentityKey::parse(&URL_SAFE_NO_PAD.encode(&seed)).unwrap().kid, kid);
        assert_eq!(IdentityKey::parse(&pkcs8_base64(SEED).unwrap()).unwrap().kid, kid);
        for bad in ["", "short", &"z".repeat(64), &STANDARD.encode([1u8; 31])] {
            let e = IdentityKey::parse(bad).unwrap_err();
            assert!(e.starts_with("IDENTITY_SIGNING_KEY"), "{e}");
        }
        assert_eq!(generate().len(), 64);
    }
}
