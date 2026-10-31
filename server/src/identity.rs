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

/// The frameworks get_auth_integration has a snippet for.
pub const FRAMEWORKS: [&str; 6] = ["nextjs", "node", "python", "go", "rust", "workerd"];

/// One framework's snippet. `{ISS}` and `{JWKS_URL}` are filled in by `integration`.
struct Snippet {
    install: &'static str,
    code: &'static str,
    /// The same with jose alone, for code that cannot take the @brod/auth package.
    fallback: Option<(&'static str, &'static str)>,
}

/// One framework's install line and verification code.
fn snippet(framework: &str) -> Snippet {
    let plain = |install, code| Snippet { install, code, fallback: None };
    match framework {
        "nextjs" => Snippet {
            install: "npm install @brod/auth",
            code: r#"// The signed-in person, from the token the Brod gateway adds to every request (x-brod-identity).
// @brod/auth checks it against BROD_ISSUER, BROD_APP_ID and BROD_IDENTITY_JWKS from env (EdDSA only).

// app/page.tsx. Server components, route handlers and server actions all use the same call.
import { currentUserFromHeaders, requireUserFromHeaders } from '@brod/auth/next';

export default async function Page() {
  const user = await currentUserFromHeaders(); // null: anonymous (an open path, or a public app with nobody signed in)
  return <p>Hello {user?.name ?? 'stranger'}</p>; // user: { id, email, name, workspace: { id, slug }, role, groups }
}

// app/api/me/route.ts: someone must be signed in. A missing or invalid token is a BrodAuthError with status 401.
import { BrodAuthError } from '@brod/auth';
export async function GET() {
  try {
    const user = await requireUserFromHeaders();
    return Response.json({ email: user.email, role: user.role });
  } catch (e) {
    if (e instanceof BrodAuthError) return Response.json({ error: e.code }, { status: e.status });
    throw e;
  }
}

// middleware.ts (proxy.ts in Next.js 16) gets the request: currentUser(request) from '@brod/auth'.
// Without env (outside Brod): currentUser(request, { issuer: '{ISS}', appId: '<app id>' }) fetches {JWKS_URL}."#,
            fallback: Some((
                "npm install jose",
                r#"// lib/brod.ts: the same with jose alone.
import { headers } from 'next/headers';
import { createLocalJWKSet, createRemoteJWKSet, jwtVerify, type JWTPayload } from 'jose';

const jwks = process.env.BROD_IDENTITY_JWKS
  ? createLocalJWKSet(JSON.parse(process.env.BROD_IDENTITY_JWKS))
  : createRemoteJWKSet(new URL('{JWKS_URL}'));

export async function brodUser(): Promise<JWTPayload | null> {
  const token = (await headers()).get('x-brod-identity');
  if (!token) return null; // anonymous: an open path, or a public app with nobody signed in
  const { payload } = await jwtVerify(token, jwks, {
    issuer: process.env.BROD_ISSUER ?? '{ISS}',
    audience: `brod:app:${process.env.BROD_APP_ID}`,
    algorithms: ['EdDSA'],
  });
  return payload; // { sub, email, name, role, groups, workspace: { id, slug } }
}"#,
            )),
        },
        "node" => Snippet {
            install: "npm install @brod/auth",
            code: r#"import { currentUser, requireUser } from '@brod/auth';

// req: a Node http.IncomingMessage, an Express or Fastify request, a fetch Request, or Headers.
// Checks x-brod-identity against BROD_ISSUER, BROD_APP_ID and BROD_IDENTITY_JWKS from env (EdDSA only).
const user = await currentUser(req); // null: anonymous (an open path, or a public app with nobody signed in)
// user: { id, email, name, workspace: { id, slug }, role, groups }. An invalid token throws a BrodAuthError (status 401).

// Express: every route below needs someone signed in.
app.use(async (req, res, next) => {
  try { req.user = await requireUser(req); next(); }
  catch (e) { res.status(e.status ?? 500).json({ error: e.code ?? 'error' }); }
});
// Without env (outside Brod): currentUser(req, { issuer: '{ISS}', appId: '<app id>' }) fetches {JWKS_URL}."#,
            fallback: Some((
                "npm install jose",
                r#"import { createLocalJWKSet, createRemoteJWKSet, jwtVerify } from 'jose';

const jwks = process.env.BROD_IDENTITY_JWKS
  ? createLocalJWKSet(JSON.parse(process.env.BROD_IDENTITY_JWKS))
  : createRemoteJWKSet(new URL('{JWKS_URL}'));

// req: a Node http.IncomingMessage (Express, Fastify and Hono expose the same header).
export async function brodUser(req) {
  const token = req.headers['x-brod-identity'];
  if (!token) return null; // anonymous: an open path, or a public app with nobody signed in
  const { payload } = await jwtVerify(token, jwks, {
    issuer: process.env.BROD_ISSUER ?? '{ISS}',
    audience: `brod:app:${process.env.BROD_APP_ID}`,
    algorithms: ['EdDSA'],
  });
  return payload; // { sub, email, name, role, groups, workspace: { id, slug } }
}"#,
            )),
        },
        "python" => plain(
            "pip install \"pyjwt[crypto]\"",
            r#"import json, os
import jwt  # PyJWT

ISSUER = os.environ.get("BROD_ISSUER", "{ISS}")
AUDIENCE = f"brod:app:{os.environ['BROD_APP_ID']}"
_inline = os.environ.get("BROD_IDENTITY_JWKS")
_keys = {k["kid"]: jwt.PyJWK(k) for k in json.loads(_inline)["keys"]} if _inline else None
_remote = None if _inline else jwt.PyJWKClient("{JWKS_URL}")

def brod_user(headers):
    """The signed-in person, or None for an anonymous request (an open path, or a public app)."""
    token = headers.get("x-brod-identity")
    if not token:
        return None
    if _keys is not None:
        key = _keys[jwt.get_unverified_header(token)["kid"]].key
    else:
        key = _remote.get_signing_key_from_jwt(token).key
    return jwt.decode(token, key, algorithms=["EdDSA"], audience=AUDIENCE, issuer=ISSUER)"#,
        ),
        "go" => plain(
            "go get github.com/golang-jwt/jwt/v5",
            r#"package brod

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"os"

	"github.com/golang-jwt/jwt/v5"
)

// Keys reads the key set Brod passes in BROD_IDENTITY_JWKS (or fetch {JWKS_URL} and decode it the same way).
func Keys() (map[string]ed25519.PublicKey, error) {
	var set struct{ Keys []struct{ Kid, X string } }
	if err := json.Unmarshal([]byte(os.Getenv("BROD_IDENTITY_JWKS")), &set); err != nil {
		return nil, err
	}
	keys := map[string]ed25519.PublicKey{}
	for _, k := range set.Keys {
		x, err := base64.RawURLEncoding.DecodeString(k.X)
		if err != nil {
			return nil, err
		}
		keys[k.Kid] = ed25519.PublicKey(x)
	}
	return keys, nil
}

// User returns the signed-in person's claims, or nil for an anonymous request (an open path, or a public app).
func User(r *http.Request, keys map[string]ed25519.PublicKey) (jwt.MapClaims, error) {
	token := r.Header.Get("X-Brod-Identity")
	if token == "" {
		return nil, nil
	}
	claims := jwt.MapClaims{}
	_, err := jwt.ParseWithClaims(token, claims, func(t *jwt.Token) (any, error) {
		kid, _ := t.Header["kid"].(string)
		if k, ok := keys[kid]; ok {
			return k, nil
		}
		return nil, errors.New("unknown key")
	}, jwt.WithValidMethods([]string{"EdDSA"}), jwt.WithIssuer("{ISS}"),
		jwt.WithAudience("brod:app:"+os.Getenv("BROD_APP_ID")), jwt.WithExpirationRequired())
	if err != nil {
		return nil, err
	}
	return claims, nil
}"#,
        ),
        "rust" => plain(
            "cargo add jsonwebtoken serde_json",
            r#"use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header, jwk::JwkSet};

/// The signed-in person's claims, or None for an anonymous request (an open path, or a public app).
/// `jwks` is BROD_IDENTITY_JWKS parsed once (or the JSON from {JWKS_URL}).
pub fn brod_user(token: Option<&str>, jwks: &JwkSet) -> Result<Option<serde_json::Value>, Box<dyn std::error::Error>> {
    let Some(token) = token else { return Ok(None) };
    let kid = decode_header(token)?.kid.ok_or("no kid")?;
    let jwk = jwks.find(&kid).ok_or("unknown key")?;
    let mut v = Validation::new(Algorithm::EdDSA);
    v.set_issuer(&["{ISS}"]);
    v.set_audience(&[format!("brod:app:{}", std::env::var("BROD_APP_ID")?)]);
    Ok(Some(decode::<serde_json::Value>(token, &DecodingKey::from_jwk(jwk)?, &v)?.claims))
}"#,
        ),
        _ => Snippet {
            install: "npm install @brod/auth, then bundle it into _worker.js (npx esbuild src/worker.js --bundle --format=esm --outfile=_worker.js), or use the x-brod-user-* headers directly (see the note below).",
            code: r#"import { currentUser } from '@brod/auth';

export default {
  async fetch(request, env) {
    // A Worker has no process.env: pass env (BROD_ISSUER, BROD_APP_ID, BROD_IDENTITY_JWKS). EdDSA only.
    const user = await currentUser(request, { env }); // null: anonymous (an open path, or a public app)
    return Response.json({ hello: user?.name ?? 'stranger' });
  },
};"#,
            fallback: Some((
                "Bundle jose into _worker.js (esbuild).",
                r#"import { createLocalJWKSet, jwtVerify } from 'jose';

export default {
  async fetch(request, env) {
    const token = request.headers.get('x-brod-identity');
    let user = null; // anonymous: an open path, or a public app with nobody signed in
    if (token) {
      ({ payload: user } = await jwtVerify(token, createLocalJWKSet(JSON.parse(env.BROD_IDENTITY_JWKS)), {
        issuer: env.BROD_ISSUER,
        audience: `brod:app:${env.BROD_APP_ID}`,
        algorithms: ['EdDSA'],
      }));
    }
    return Response.json({ hello: user?.name ?? 'stranger' });
  },
};"#,
            )),
        },
    }
}

/// What get_auth_integration returns: the identity contract, how access works, and how to verify the token in one
/// framework (or all of them). `audience` is the app's own when the caller named an app.
pub fn integration(cfg: &crate::config::Config, framework: Option<&str>, runtime: Option<&str>, audience: Option<String>) -> Value {
    let jwks_url = format!("{}/.well-known/jwks.json", cfg.api_origin);
    let fill = |code: &str| code.replace("{ISS}", &cfg.api_origin).replace("{JWKS_URL}", &jwks_url);
    let chosen: Vec<&str> = match framework {
        Some(f) => vec![f],
        None => FRAMEWORKS.to_vec(),
    };
    let mut snippets = serde_json::Map::new();
    for f in chosen {
        let s = snippet(f);
        let mut entry = json!({ "install": s.install, "code": fill(s.code) });
        if let Some((install, code)) = s.fallback {
            entry["without_package"] = json!({ "install": install, "code": fill(code) });
        }
        snippets.insert(f.into(), entry);
    }
    let workerd_note = "Inside a Brod server app (_worker.js on workerd) the gateway is the only way in and strips any x-brod-* header a visitor sends, so the x-brod-user-id, x-brod-user-email, x-brod-user-name (URI-encoded), x-brod-role and x-brod-groups headers can be used as they are. Verify the token when identity must be trusted beyond that: when you pass it on to another service, or in code that could also be reached some other way.";
    json!({
        "identity": {
            "header": "x-brod-identity",
            "browser": "GET /_brod/me on the app's own address returns { user, role, groups, app, workspace, token }; token is the same JWT. 401 when nobody allowed is signed in.",
            "format": "A compact JWT (JWS) signed with Ed25519: header { alg: \"EdDSA\", typ: \"JWT\", kid }.",
            "issuer": cfg.api_origin,
            "audience": audience.unwrap_or_else(|| "brod:app:<app id> (BROD_APP_ID)".into()),
            "jwks_url": jwks_url,
            "lifetime_seconds": crate::model::limits::IDENTITY_TTL_SEC,
            "claims": {
                "iss": "Brod's public URL.", "aud": "brod:app:<app id>: refuse any other, so a token made for one app never works in another.",
                "sub": "The person's user id (stable).", "email": "Their email address.", "name": "Their display name.",
                "workspace": "{ id, slug } of the app's workspace.", "role": "Their role in this app (null when the app gives them none, as on a public app).",
                "groups": "Their workspace groups.", "iat": "Issued at (seconds).", "exp": "Expires at: 5 minutes after iat.", "jti": "A unique id per token.",
            },
            "env": {
                "BROD_ISSUER": "The expected iss.", "BROD_APP_ID": "The app's id: the audience is brod:app:<BROD_APP_ID>.",
                "BROD_IDENTITY_JWKS": "The JWK set as JSON, so verification needs no network call.",
            },
            "env_note": match runtime {
                Some("container") => "Container apps are coming; they will get the same env vars. Until then, hard-code the issuer and audience and fetch the key set from jwks_url.",
                _ => "Brod sets these in env for server apps (_worker.js).",
            },
            "how_to_verify": [
                "Read the x-brod-identity header. No header: the request is anonymous.",
                "Check the signature with alg EdDSA only, using the key whose kid matches, from BROD_IDENTITY_JWKS or jwks_url.",
                "Check iss equals BROD_ISSUER, aud equals brod:app:<BROD_APP_ID>, and exp is in the future.",
                "Use sub as the user id. Never keep passwords or a user table: Brod signs people in.",
            ],
        },
        "access": {
            "default": "Apps are private by default: only the owner (and workspace admins) can open them until set_access shares them.",
            "gateway": "The Brod gateway signs people in and decides access before any request reaches the app's code, then adds the identity. An app never sees a request from someone it was not shared with.",
            "open_paths": "Paths that must work without sign-in (webhooks, an MCP endpoint with its own auth) go in brod.json: { \"open_paths\": [\"/api/webhooks/*\", { \"path\": \"/api/mcp\", \"methods\": [\"POST\"] }] }. They open once a person approves them (deploy_app returns a confirm_url when an agent adds one; set_open_paths changes them).",
            "anonymous": "Requests on an open path, and to a public app from someone not signed in, carry no x-brod-identity and no x-brod-user-* headers. Treat them as untrusted and authenticate them yourself (a webhook signature, an API key).",
        },
        "workerd_note": workerd_note,
        "snippets": snippets,
        "package": "@brod/auth (npm install @brod/auth) does all of this in one call for Node, Next.js (server components, route handlers, middleware) and Workers: currentUser(request) returns { id, email, name, workspace, role, groups, app } or null when anonymous, and throws a BrodAuthError (status 401) for a token that does not verify. The nextjs, node and workerd snippets use it; each also has without_package, the same with jose alone. Python, Go and Rust use their usual JWT library.",
    })
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

    #[test]
    fn the_auth_integration_fills_in_this_server() {
        let cfg = crate::config::Config::for_tests();
        let all = integration(&cfg, None, None, Some("brod:app:app_1".into()));
        assert_eq!(all["identity"]["jwks_url"], "http://localhost:8787/.well-known/jwks.json");
        assert_eq!(all["identity"]["audience"], "brod:app:app_1");
        assert_eq!(all["snippets"].as_object().unwrap().keys().collect::<Vec<_>>(), FRAMEWORKS);
        for (f, s) in all["snippets"].as_object().unwrap() {
            let code = s["code"].as_str().unwrap();
            assert!(!code.contains("{ISS}") && !code.contains("{JWKS_URL}"), "{f}");
            if ["nextjs", "node", "workerd"].contains(&f.as_str()) {
                // The JavaScript ones use the package, and keep the jose-only code beside it.
                assert!(s["install"].as_str().unwrap().contains("@brod/auth") && code.contains("from '@brod/auth"), "{f}");
                let raw = s["without_package"]["code"].as_str().unwrap();
                assert!(raw.contains("from 'jose'") && raw.contains("'EdDSA'") && raw.contains("x-brod-identity"), "{f}");
                assert!(!raw.contains("{ISS}") && !raw.contains("{JWKS_URL}"), "{f}");
            } else {
                assert!(
                    code.contains("EdDSA") && (code.contains("x-brod-identity") || code.contains("X-Brod-Identity") || f == "rust"),
                    "{f}"
                );
                assert!(s.get("without_package").is_none(), "{f}");
            }
        }
        let one = integration(&cfg, Some("python"), Some("container"), None);
        assert_eq!(one["snippets"].as_object().unwrap().len(), 1);
        assert!(one["snippets"]["python"]["code"].as_str().unwrap().contains("audience=AUDIENCE"));
        assert!(one["package"].as_str().unwrap().contains("@brod/auth"));
    }
}
