// Per-app secrets. Encrypted at rest with AES-GCM under a key derived from SECRETS_KEY; handed to the app's
// server code as env vars; never returned by the API, the MCP tools, or the logs.
import { Env, Problem, now } from './lib';

const NAME = /^[A-Z][A-Z0-9_]{0,63}$/;
const RESERVED = new Set(['DB', 'KV', 'FILES']);
const MAX_BYTES = 5 * 1024;

async function key(env: Env): Promise<CryptoKey> {
  if (!env.SECRETS_KEY || env.SECRETS_KEY.length < 16) throw new Problem(503, 'secrets_unavailable', 'Secrets are not configured on this server (SECRETS_KEY).');
  const base = await crypto.subtle.importKey('raw', new TextEncoder().encode(env.SECRETS_KEY), 'HKDF', false, ['deriveKey']);
  return crypto.subtle.deriveKey({ name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(), info: new TextEncoder().encode('brod app secrets v1') },
    base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}
const b64 = (b: Uint8Array) => btoa(String.fromCharCode(...b));
const unb64 = (s: string) => Uint8Array.from(atob(s), c => c.charCodeAt(0));

async function seal(env: Env, appId: string, value: string) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  // The app id is bound in as associated data, so a value copied to another app's row does not decrypt.
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: new TextEncoder().encode(appId) }, await key(env), new TextEncoder().encode(value)));
  return `${b64(iv)}.${b64(ct)}`;
}
async function open(k: CryptoKey, appId: string, sealed: string) {
  const [iv, ct] = sealed.split('.');
  return new TextDecoder().decode(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: unb64(iv), additionalData: new TextEncoder().encode(appId) }, k, unb64(ct)));
}

export function checkSecretName(name: string) {
  if (!NAME.test(name) || RESERVED.has(name) || name.startsWith('BROD_'))
    throw new Problem(400, 'bad_name', 'A secret name is UPPER_SNAKE_CASE, for example "STRIPE_KEY". DB, KV, FILES and names starting with BROD_ are reserved.');
}

/** Set or replace one secret. Returns only its name: values are write-only. */
export async function putSecret(env: Env, appId: string, name: string, value: string, actor: string) {
  checkSecretName(name);
  if (typeof value !== 'string' || !value) throw new Problem(400, 'bad_value', 'Give the secret a non-empty string value.');
  if (new TextEncoder().encode(value).byteLength > MAX_BYTES) throw new Problem(413, 'too_large', 'A secret can be at most 5 KB.');
  const count = await env.DB.prepare('SELECT COUNT(*) AS n FROM secrets WHERE app_id = ? AND name != ?').bind(appId, name).first<{ n: number }>();
  if ((count?.n ?? 0) >= 50) throw new Problem(409, 'too_many', 'An app can have at most 50 secrets.');
  return [
    env.DB.prepare('INSERT INTO secrets (app_id, name, value, updated_at, updated_by) VALUES (?,?,?,?,?) ON CONFLICT(app_id, name) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at, updated_by = excluded.updated_by')
      .bind(appId, name, await seal(env, appId, value), now(), actor),
    env.DB.prepare('UPDATE apps SET secrets_rev = secrets_rev + 1 WHERE id = ?').bind(appId),
  ];
}
export function deleteSecret(env: Env, appId: string, name: string) {
  return [
    env.DB.prepare('DELETE FROM secrets WHERE app_id = ? AND name = ?').bind(appId, name),
    env.DB.prepare('UPDATE apps SET secrets_rev = secrets_rev + 1 WHERE id = ?').bind(appId),
  ];
}
export async function listSecrets(env: Env, appId: string) {
  const r = await env.DB.prepare('SELECT name, updated_at, updated_by FROM secrets WHERE app_id = ? ORDER BY name').bind(appId).all<{ name: string; updated_at: number; updated_by: string }>();
  return r.results.map(s => ({ name: s.name, updated: new Date(s.updated_at).toISOString(), by: s.updated_by }));
}

/** Decrypted secrets for the app's server code. Only the loader calls this. */
export async function readSecrets(env: Env, appId: string): Promise<Record<string, string>> {
  const r = await env.DB.prepare('SELECT name, value FROM secrets WHERE app_id = ?').bind(appId).all<{ name: string; value: string }>();
  if (!r.results.length) return {};
  const k = await key(env);
  return Object.fromEntries(await Promise.all(r.results.map(async s => [s.name, await open(k, appId, s.value)])));
}
