// Keys and tokens shaped exactly like Brod's (server/src/identity.rs and gateway.rs identity_for).
import { SignJWT, base64url, calculateJwkThumbprint, exportJWK, generateKeyPair, importJWK, type JWK, type JWTPayload } from 'jose';

export const ISSUER = 'https://brod.test';
export const APP_ID = 'app_1';
export const AUDIENCE = `brod:app:${APP_ID}`;

// RFC 8032 test vector 1, the seed server/src/identity.rs tests and scripts/e2e-rust.mjs use.
export const SEED_HEX = '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60';
export const PUBLIC_HEX = 'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a';
// RFC 8037 appendix A.3: that key's thumbprint, which Brod uses as kid.
export const RUST_KID = 'kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k';

const hex = (h: string) => Uint8Array.from(h.match(/../g)!.map((b) => parseInt(b, 16)));

export interface TestKey {
  kid: string;
  privateKey: CryptoKey;
  publicJwk: JWK;
}

/** Brod's key from its seed, the way identity.rs builds it. */
export async function brodKey(): Promise<TestKey> {
  const x = base64url.encode(hex(PUBLIC_HEX));
  const publicJwk: JWK = { kty: 'OKP', crv: 'Ed25519', x };
  const kid = await calculateJwkThumbprint(publicJwk, 'sha256');
  const privateKey = (await importJWK({ ...publicJwk, d: base64url.encode(hex(SEED_HEX)) }, 'EdDSA')) as CryptoKey;
  return { kid, privateKey, publicJwk: { ...publicJwk, kid, use: 'sig', alg: 'EdDSA' } };
}

/** A fresh Ed25519 key. */
export async function freshKey(): Promise<TestKey> {
  const { privateKey, publicKey } = await generateKeyPair('EdDSA', { crv: 'Ed25519', extractable: true });
  const jwk = await exportJWK(publicKey);
  const kid = await calculateJwkThumbprint(jwk, 'sha256');
  return { kid, privateKey: privateKey as CryptoKey, publicJwk: { ...jwk, kid, use: 'sig', alg: 'EdDSA' } };
}

export const jwksOf = (...keys: TestKey[]) => ({ keys: keys.map((k) => k.publicJwk) });

export const now = () => Math.floor(Date.now() / 1000);

export function claims(over: JWTPayload = {}): JWTPayload {
  const t = now();
  return {
    iss: ISSUER,
    aud: AUDIENCE,
    sub: 'usr_1',
    email: 'ada@example.com',
    name: 'Ada Lovelace',
    workspace: { id: 'wsp_1', slug: 'acme' },
    role: 'editor',
    groups: ['finance'],
    iat: t,
    exp: t + 300,
    jti: 'abc123',
    ...over,
  };
}

/** Sign like Brod: header { alg: EdDSA, typ: JWT, kid }. */
export function sign(key: TestKey, payload: JWTPayload = claims(), header: { kid?: string } = {}) {
  return new SignJWT(payload).setProtectedHeader({ alg: 'EdDSA', typ: 'JWT', kid: header.kid ?? key.kid }).sign(key.privateKey);
}
