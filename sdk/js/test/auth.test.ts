import { IncomingMessage } from 'node:http';
import { Socket } from 'node:net';
import { SignJWT, base64url } from 'jose';
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  BrodAuthError,
  clearKeyCache,
  currentUser,
  identityToken,
  requireUser,
  verifyIdentityToken,
  type BrodAuthOptions,
} from '../src/index';
import { APP_ID, AUDIENCE, ISSUER, RUST_KID, brodKey, claims, freshKey, jwksOf, now, sign, type TestKey } from './helpers';

let key: TestKey;
let other: TestKey;
let opts: BrodAuthOptions;

beforeAll(async () => {
  key = await brodKey();
  other = await freshKey();
});

beforeEach(() => {
  clearKeyCache();
  // Explicit env so the machine's own variables never leak in.
  opts = { env: { BROD_ISSUER: ISSUER, BROD_APP_ID: APP_ID, BROD_IDENTITY_JWKS: JSON.stringify(jwksOf(key)) } };
});

afterEach(() => {
  vi.unstubAllEnvs();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

/** The BrodAuthError a promise rejects with. */
async function failure(p: Promise<unknown>): Promise<BrodAuthError> {
  const e = await p.then(
    () => null,
    (err: unknown) => err,
  );
  expect(e).toBeInstanceOf(BrodAuthError);
  return e as BrodAuthError;
}

const withToken = (token: string) => new Headers({ 'x-brod-identity': token });

describe('verifying a Brod token', () => {
  it('uses the same key id as Brod (RFC 7638 thumbprint)', () => {
    expect(key.kid).toBe(RUST_KID);
  });

  it('returns the person for a valid token', async () => {
    const user = await currentUser(withToken(await sign(key)), opts);
    expect(user).toMatchObject({
      id: 'usr_1',
      email: 'ada@example.com',
      name: 'Ada Lovelace',
      workspace: { id: 'wsp_1', slug: 'acme' },
      role: 'editor',
      groups: ['finance'],
      app: APP_ID,
    });
    expect(user?.claims.jti).toBe('abc123');
    expect(user?.claims.aud).toBe(AUDIENCE);
  });

  it('reads the filters a grant carries, and none from an older server', async () => {
    const withFilters = await currentUser(withToken(await sign(key, claims({ filters: { tenant: 'acme', region: ['np', 'in'] } }))), opts);
    expect(withFilters?.filters).toEqual({ tenant: 'acme', region: ['np', 'in'] });
    const older = await currentUser(withToken(await sign(key, claims())), opts);
    expect(older?.filters).toEqual({});
  });

  it('keeps a null role (a public app)', async () => {
    const user = await currentUser(withToken(await sign(key, claims({ role: null, groups: [] }))), opts);
    expect(user?.role).toBeNull();
    expect(user?.groups).toEqual([]);
  });

  it('refuses a token made for another app', async () => {
    const e = await failure(currentUser(withToken(await sign(key, claims({ aud: 'brod:app:app_2' }))), opts));
    expect(e.code).toBe('wrong_audience');
    expect(e.status).toBe(401);
  });

  it('refuses a token from another issuer', async () => {
    const e = await failure(currentUser(withToken(await sign(key, claims({ iss: 'https://evil.test' }))), opts));
    expect(e.code).toBe('wrong_issuer');
  });

  it('refuses an expired token', async () => {
    const t = now();
    const e = await failure(currentUser(withToken(await sign(key, claims({ iat: t - 400, exp: t - 60 }))), opts));
    expect(e.code).toBe('expired');
  });

  it('accepts a token expired within the 30 s clock tolerance, and not with none', async () => {
    const t = now();
    const token = await sign(key, claims({ iat: t - 310, exp: t - 10 }));
    expect((await currentUser(withToken(token), opts))?.id).toBe('usr_1');
    const e = await failure(currentUser(withToken(token), { ...opts, clockTolerance: 0 }));
    expect(e.code).toBe('expired');
  });

  it('refuses a token issued in the future beyond the tolerance', async () => {
    const t = now();
    const e = await failure(currentUser(withToken(await sign(key, claims({ iat: t + 120, exp: t + 420 }))), opts));
    expect(e.code).toBe('not_yet_valid');
  });

  it('refuses alg none', async () => {
    const enc = (o: object) => base64url.encode(JSON.stringify(o));
    const token = `${enc({ alg: 'none', typ: 'JWT' })}.${enc(claims())}.`;
    const e = await failure(currentUser(withToken(token), opts));
    expect(['alg_not_allowed', 'invalid_token']).toContain(e.code);
  });

  it('refuses HS256, including one keyed with the public key', async () => {
    const hs = (secret: Uint8Array) =>
      new SignJWT(claims()).setProtectedHeader({ alg: 'HS256', typ: 'JWT', kid: key.kid }).sign(secret);
    for (const secret of [new TextEncoder().encode('a-shared-secret-of-32-bytes-or-more'), base64url.decode(key.publicJwk.x!)]) {
      const e = await failure(currentUser(withToken(await hs(secret)), opts));
      expect(e.code).toBe('alg_not_allowed');
    }
  });

  it('refuses a key id it does not know', async () => {
    const e = await failure(currentUser(withToken(await sign(other)), opts));
    expect(e.code).toBe('unknown_key');
  });

  it('refuses another key that claims a known key id', async () => {
    const e = await failure(currentUser(withToken(await sign(other, claims(), { kid: key.kid })), opts));
    expect(e.code).toBe('bad_signature');
  });

  it('refuses a tampered payload', async () => {
    const [h, , s] = (await sign(key)).split('.');
    const forged = `${h}.${base64url.encode(JSON.stringify(claims({ sub: 'usr_admin' })))}.${s}`;
    expect((await failure(currentUser(withToken(forged), opts))).code).toBe('bad_signature');
  });

  it('refuses garbage', async () => {
    for (const t of ['nope', 'a.b.c', 'a.b']) expect((await failure(currentUser(withToken(t), opts))).code).toBe('invalid_token');
  });

  it('refuses a signed token without the Brod claims', async () => {
    const { workspace: _w, ...rest } = claims();
    const e = await failure(currentUser(withToken(await sign(key, rest)), opts));
    expect(e.code).toBe('invalid_claims');
  });

  it('works with several keys in the set (rotation)', async () => {
    const both = { ...opts, jwks: jwksOf(other, key) };
    expect((await currentUser(withToken(await sign(key)), both))?.id).toBe('usr_1');
    expect((await currentUser(withToken(await sign(other)), both))?.id).toBe('usr_1');
  });

  it('verifyIdentityToken checks a bare token', async () => {
    expect((await verifyIdentityToken(await sign(key), opts)).email).toBe('ada@example.com');
    expect((await failure(verifyIdentityToken('', opts))).code).toBe('invalid_token');
  });
});

describe('inputs', () => {
  it('returns null when there is no token, or an empty one', async () => {
    expect(await currentUser(new Headers(), opts)).toBeNull();
    expect(await currentUser(new Headers({ 'x-brod-identity': '' }), opts)).toBeNull();
    expect(await currentUser(new Request('https://app.test/'), opts)).toBeNull();
    expect(await currentUser({ headers: {} }, opts)).toBeNull();
    expect(await currentUser(undefined, opts)).toBeNull();
    expect(await currentUser('', opts)).toBeNull();
  });

  it('reads a Headers, a Request, { headers }, a header record, a Node request and the token itself', async () => {
    const token = await sign(key);
    const node = new IncomingMessage(new Socket());
    node.headers = { 'x-brod-identity': token, host: 'app.test' };
    const inputs = [
      withToken(token),
      new Request('https://app.test/', { headers: { 'X-Brod-Identity': token } }),
      { headers: withToken(token) },
      { headers: { 'x-brod-identity': token } },
      { 'X-Brod-Identity': token },
      node,
      token,
    ];
    for (const input of inputs) expect((await currentUser(input, opts))?.id).toBe('usr_1');
    expect(identityToken(node)).toBe(token);
  });

  it('refuses two identity headers', async () => {
    const token = await sign(key);
    const e = await failure(currentUser({ headers: { 'x-brod-identity': [token, token] } }, opts));
    expect(e.code).toBe('invalid_token');
  });

  it('requireUser throws a 401 for an anonymous request and returns the person otherwise', async () => {
    const e = await failure(requireUser(new Headers(), opts));
    expect(e.code).toBe('unauthenticated');
    expect(e.status).toBe(401);
    expect((await requireUser(withToken(await sign(key)), opts)).id).toBe('usr_1');
  });
});

describe('configuration', () => {
  it('reads BROD_ISSUER, BROD_APP_ID and BROD_IDENTITY_JWKS from process.env by default', async () => {
    vi.stubEnv('BROD_ISSUER', ISSUER);
    vi.stubEnv('BROD_APP_ID', APP_ID);
    vi.stubEnv('BROD_IDENTITY_JWKS', JSON.stringify(jwksOf(key)));
    expect((await currentUser(withToken(await sign(key))))?.id).toBe('usr_1');
  });

  it('takes issuer, audience and keys as options', async () => {
    const token = await sign(key, claims({ aud: 'brod:app:app_9' }));
    const user = await currentUser(withToken(token), { env: {}, issuer: ISSUER, appId: 'app_9', jwks: JSON.stringify(jwksOf(key)) });
    expect(user?.app).toBe('app_9');
    const viaAudience = await currentUser(withToken(token), { env: {}, issuer: ISSUER, audience: 'brod:app:app_9', jwks: jwksOf(key) });
    expect(viaAudience?.id).toBe('usr_1');
  });

  it('is a 500 when the app is not configured', async () => {
    const token = await sign(key);
    const noIssuer = await failure(currentUser(withToken(token), { env: { BROD_APP_ID: APP_ID } }));
    expect([noIssuer.code, noIssuer.status]).toEqual(['misconfigured', 500]);
    const noApp = await failure(currentUser(withToken(token), { env: { BROD_ISSUER: ISSUER } }));
    expect(noApp.code).toBe('misconfigured');
    const badJwks = await failure(currentUser(withToken(token), { env: { ...opts.env, BROD_IDENTITY_JWKS: '{nope' } }));
    expect(badJwks.code).toBe('misconfigured');
  });
});

describe('remote key set', () => {
  const remoteOpts = (): BrodAuthOptions => ({ env: { BROD_ISSUER: ISSUER, BROD_APP_ID: APP_ID } });

  it('fetches <issuer>/.well-known/jwks.json once and caches it', async () => {
    const fetchMock = vi.fn(async (_url: string | URL | Request) => Response.json(jwksOf(key)));
    vi.stubGlobal('fetch', fetchMock);
    expect((await currentUser(withToken(await sign(key)), remoteOpts()))?.id).toBe('usr_1');
    expect((await currentUser(withToken(await sign(key, claims({ sub: 'usr_2' }))), remoteOpts()))?.id).toBe('usr_2');
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const first = fetchMock.mock.calls[0]![0];
    expect(String(first instanceof Request ? first.url : first)).toBe(`${ISSUER}/.well-known/jwks.json`);
  });

  it('uses jwksUrl when given', async () => {
    const fetchMock = vi.fn(async (_url: string | URL | Request) => Response.json(jwksOf(key)));
    vi.stubGlobal('fetch', fetchMock);
    await currentUser(withToken(await sign(key)), { ...remoteOpts(), jwksUrl: 'https://keys.test/jwks' });
    const first = fetchMock.mock.calls[0]![0];
    expect(String(first instanceof Request ? first.url : first)).toBe('https://keys.test/jwks');
  });

  it('is a 503 when the key set cannot be fetched', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response('down', { status: 502 })));
    const e = await failure(currentUser(withToken(await sign(key)), remoteOpts()));
    expect([e.code, e.status]).toEqual(['jwks_unavailable', 503]);
    clearKeyCache();
    vi.stubGlobal('fetch', vi.fn(async () => { throw new TypeError('fetch failed'); }));
    expect((await failure(currentUser(withToken(await sign(key)), remoteOpts()))).code).toBe('jwks_unavailable');
  });

  it('refuses a token whose key the fetched set lacks', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => Response.json(jwksOf(key))));
    expect((await failure(currentUser(withToken(await sign(other)), remoteOpts()))).code).toBe('unknown_key');
  });
});

describe('BROD_DEV_USER', () => {
  const devEnv = (env: Record<string, string>) => ({ env: { BROD_ISSUER: ISSUER, BROD_APP_ID: APP_ID, ...env } });

  beforeEach(() => {
    vi.spyOn(console, 'warn').mockImplementation(() => {});
  });

  it('stands in for the token outside production, as an email', async () => {
    const user = await currentUser(new Headers(), devEnv({ NODE_ENV: 'development', BROD_DEV_USER: 'dev@example.com' }));
    expect(user).toMatchObject({ email: 'dev@example.com', name: 'dev', role: 'owner', app: APP_ID });
    expect(user?.claims.brod_dev).toBe(true);
  });

  it('or as JSON', async () => {
    const dev = JSON.stringify({ email: 'ann@example.com', name: 'Ann', role: 'viewer', groups: ['ops'] });
    const user = await currentUser(new Headers(), devEnv({ NODE_ENV: 'development', BROD_DEV_USER: dev }));
    expect(user).toMatchObject({ email: 'ann@example.com', name: 'Ann', role: 'viewer', groups: ['ops'] });
  });

  it('never applies in production', async () => {
    expect(await currentUser(new Headers(), devEnv({ NODE_ENV: 'production', BROD_DEV_USER: 'dev@example.com' }))).toBeNull();
    // A Worker env without NODE_ENV, in a process (or a bundle) built for production.
    vi.stubEnv('NODE_ENV', 'production');
    expect(await currentUser(new Headers(), devEnv({ BROD_DEV_USER: 'dev@example.com' }))).toBeNull();
    await expect(requireUser(new Headers(), devEnv({ BROD_DEV_USER: 'dev@example.com' }))).rejects.toMatchObject({ status: 401 });
  });

  it('does not replace a token, valid or not', async () => {
    const env = { ...opts.env, NODE_ENV: 'development', BROD_DEV_USER: 'dev@example.com' };
    expect((await currentUser(withToken(await sign(key)), { env }))?.email).toBe('ada@example.com');
    expect((await failure(currentUser(withToken('garbage'), { env }))).code).toBe('invalid_token');
  });

  it('needs an email address', async () => {
    const e = await failure(currentUser(new Headers(), devEnv({ NODE_ENV: 'development', BROD_DEV_USER: '{"name":"x"}' })));
    expect(e.code).toBe('misconfigured');
  });
});
