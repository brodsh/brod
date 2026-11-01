// @brod/auth: the person Brod signed in, read from the x-brod-identity JWT the Brod gateway adds to every request.
//
// The token is a compact JWS signed with Ed25519 (alg EdDSA), with iss = Brod's public URL, aud = brod:app:<app id>,
// sub = the user id, and email, name, workspace { id, slug }, role, groups, iat, exp (iat + 300), jti. Brod gives
// every app BROD_ISSUER, BROD_APP_ID and BROD_IDENTITY_JWKS (the public key set, inline) in its environment, so this
// verifies without a network call by default. Only EdDSA is accepted.
import {
  createLocalJWKSet,
  createRemoteJWKSet,
  errors,
  jwtVerify,
  type JSONWebKeySet,
  type JWTPayload,
  type JWTVerifyGetKey,
} from 'jose';

/** The request header that carries the identity token. */
export const IDENTITY_HEADER = 'x-brod-identity';

/** The only signature algorithm Brod uses, and the only one accepted. */
const ALGORITHMS = ['EdDSA'];

/** Claims of a Brod identity token. */
export interface BrodClaims extends JWTPayload {
  iss: string;
  aud: string;
  sub: string;
  email: string;
  name: string;
  workspace: { id: string; slug: string };
  role: string | null;
  groups: string[];
  iat: number;
  exp: number;
  jti: string;
}

/** The person signed in to this app. */
export interface BrodUser {
  /** Brod's user id (the token's sub). Stable: store this, or match on email first and then store it. */
  id: string;
  email: string;
  name: string;
  workspace: { id: string; slug: string };
  /** The person's role in this app, or null when the app gives them none (a public app). */
  role: string | null;
  groups: string[];
  /** The app id the token was made for (aud without its "brod:app:" prefix). */
  app: string;
  /** The verified claims as they came. */
  claims: BrodClaims;
}

export type BrodAuthErrorCode =
  | 'unauthenticated'
  | 'invalid_token'
  | 'bad_signature'
  | 'unknown_key'
  | 'alg_not_allowed'
  | 'expired'
  | 'not_yet_valid'
  | 'wrong_issuer'
  | 'wrong_audience'
  | 'invalid_claims'
  | 'jwks_unavailable'
  | 'misconfigured';

/**
 * A request that carried no usable identity. `status` is 401 for anything a caller sent (answer with it as it is),
 * 503 when the key set could not be fetched, and 500 when this app is not configured (no issuer or audience).
 */
export class BrodAuthError extends Error {
  readonly code: BrodAuthErrorCode;
  readonly status: number;
  constructor(code: BrodAuthErrorCode, message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = 'BrodAuthError';
    this.code = code;
    this.status = code === 'misconfigured' ? 500 : code === 'jwks_unavailable' ? 503 : 401;
  }
}

/** A JWK set, as an object, as its JSON text, or a jose key resolver. */
export type JwksInput = JSONWebKeySet | string | JWTVerifyGetKey;

export interface BrodAuthOptions {
  /** Expected iss. Default: env BROD_ISSUER. */
  issuer?: string;
  /** Expected aud. Default: "brod:app:" + appId. */
  audience?: string;
  /** The app id, for the default audience. Default: env BROD_APP_ID. */
  appId?: string;
  /**
   * The keys. Default: env BROD_IDENTITY_JWKS (inline JSON), else fetched from jwksUrl and cached
   * (refetched when a token names a key id it does not know).
   */
  jwks?: JwksInput;
  /** Where to fetch the keys when there is no inline set. Default: `${issuer}/.well-known/jwks.json`. */
  jwksUrl?: string | URL;
  /** Allowed clock skew, in seconds or as a jose time span ("30s"). Default: 30. */
  clockTolerance?: number | string;
  /**
   * Where to read BROD_ISSUER, BROD_APP_ID, BROD_IDENTITY_JWKS, BROD_DEV_USER and NODE_ENV. Default: process.env.
   * Pass the Worker's env on workerd, where there is no process.env.
   */
  env?: Record<string, unknown>;
}

/** Anything that carries request headers. */
export type HeadersLike =
  | Headers
  | { get(name: string): string | null | undefined }
  | Record<string, string | string[] | undefined>;

/**
 * The input to currentUser: a Request, a Headers, anything with a `headers` property (a Node IncomingMessage,
 * an Express or Fastify request, `{ headers }`), or the token itself as a string.
 */
export type IdentityInput = Request | HeadersLike | { headers: HeadersLike } | string | null | undefined;

function processEnv(): Record<string, unknown> {
  const p = (globalThis as { process?: { env?: Record<string, unknown> } }).process;
  return p?.env ?? {};
}

function envOf(opts: BrodAuthOptions): Record<string, unknown> {
  return opts.env ?? processEnv();
}

function str(v: unknown): string | undefined {
  return typeof v === 'string' && v !== '' ? v : undefined;
}

// Key resolvers, kept per key set so a remote set is fetched once and an inline one parsed once.
const localSets = new Map<string, JWTVerifyGetKey>();
const remoteSets = new Map<string, JWTVerifyGetKey>();

function keysFor(opts: BrodAuthOptions, issuer: string): JWTVerifyGetKey {
  const given = opts.jwks ?? str(envOf(opts).BROD_IDENTITY_JWKS);
  if (typeof given === 'function') return given;
  if (typeof given === 'string') {
    let found = localSets.get(given);
    if (!found) {
      let set: JSONWebKeySet;
      try {
        set = JSON.parse(given) as JSONWebKeySet;
      } catch (e) {
        throw new BrodAuthError('misconfigured', 'BROD_IDENTITY_JWKS is not valid JSON.', { cause: e });
      }
      found = localKeys(set);
      localSets.set(given, found);
    }
    return found;
  }
  if (given) return localKeys(given);
  const url = String(opts.jwksUrl ?? `${issuer.replace(/\/+$/, '')}/.well-known/jwks.json`);
  let found = remoteSets.get(url);
  if (!found) {
    let parsed: URL;
    try {
      parsed = new URL(url);
    } catch (e) {
      throw new BrodAuthError('misconfigured', `The key set address is not a URL: ${url}`, { cause: e });
    }
    found = createRemoteJWKSet(parsed);
    remoteSets.set(url, found);
  }
  return found;
}

function localKeys(set: JSONWebKeySet): JWTVerifyGetKey {
  if (!set || !Array.isArray(set.keys)) throw new BrodAuthError('misconfigured', 'The key set has no "keys" array.');
  return createLocalJWKSet(set);
}

/** Map jose's errors onto stable codes. */
function translate(e: unknown): BrodAuthError {
  if (e instanceof BrodAuthError) return e;
  const opts = { cause: e };
  if (e instanceof errors.JWTExpired) return new BrodAuthError('expired', 'The identity token has expired.', opts);
  if (e instanceof errors.JWTClaimValidationFailed) {
    if (e.claim === 'iss') return new BrodAuthError('wrong_issuer', 'The identity token was issued by another server.', opts);
    if (e.claim === 'aud') return new BrodAuthError('wrong_audience', 'The identity token was made for another app.', opts);
    if (e.claim === 'nbf' || e.claim === 'iat')
      return new BrodAuthError('not_yet_valid', 'The identity token is not valid yet.', opts);
    return new BrodAuthError('invalid_claims', `The identity token has a bad "${e.claim}" claim.`, opts);
  }
  if (e instanceof errors.JOSEAlgNotAllowed) return new BrodAuthError('alg_not_allowed', 'The identity token is not signed with EdDSA.', opts);
  if (e instanceof errors.JWSSignatureVerificationFailed)
    return new BrodAuthError('bad_signature', 'The identity token signature does not verify.', opts);
  if (e instanceof errors.JWKSNoMatchingKey || e instanceof errors.JWKSMultipleMatchingKeys)
    return new BrodAuthError('unknown_key', 'The identity token names a key this server does not publish.', opts);
  if (e instanceof errors.JWKSTimeout || e instanceof errors.JWKSInvalid || (e instanceof errors.JOSEError && /JSON Web Key Set/i.test(e.message)))
    return new BrodAuthError('jwks_unavailable', 'Could not load the identity key set.', opts);
  if (e instanceof errors.JOSEError) return new BrodAuthError('invalid_token', 'The identity token is malformed.', opts);
  // A failed fetch of the remote key set (network error, non-JSON answer).
  if (e instanceof TypeError || e instanceof SyntaxError) return new BrodAuthError('jwks_unavailable', 'Could not load the identity key set.', opts);
  return new BrodAuthError('invalid_token', 'The identity token could not be verified.', opts);
}

function isClaims(p: JWTPayload): p is BrodClaims {
  const w = p.workspace as { id?: unknown; slug?: unknown } | undefined;
  return (
    typeof p.sub === 'string' &&
    typeof p.aud === 'string' &&
    typeof p.email === 'string' &&
    typeof p.exp === 'number' &&
    !!w &&
    typeof w.id === 'string' &&
    typeof w.slug === 'string'
  );
}

function toUser(claims: BrodClaims): BrodUser {
  return {
    id: claims.sub,
    email: claims.email,
    name: typeof claims.name === 'string' ? claims.name : '',
    workspace: { id: claims.workspace.id, slug: claims.workspace.slug },
    role: typeof claims.role === 'string' ? claims.role : null,
    groups: Array.isArray(claims.groups) ? claims.groups.filter((g): g is string => typeof g === 'string') : [],
    app: claims.aud.startsWith('brod:app:') ? claims.aud.slice('brod:app:'.length) : claims.aud,
    claims,
  };
}

/**
 * Verify an identity token and return the person. Checks the EdDSA signature against the key named by kid, iss, aud
 * and exp (with 30 s of clock tolerance). Throws BrodAuthError when anything is wrong.
 */
export async function verifyIdentityToken(token: string, opts: BrodAuthOptions = {}): Promise<BrodUser> {
  const env = envOf(opts);
  const issuer = opts.issuer ?? str(env.BROD_ISSUER);
  const appId = opts.appId ?? str(env.BROD_APP_ID);
  const audience = opts.audience ?? (appId ? `brod:app:${appId}` : undefined);
  if (!issuer) throw new BrodAuthError('misconfigured', 'No issuer: set BROD_ISSUER or pass { issuer }.');
  if (!audience) throw new BrodAuthError('misconfigured', 'No audience: set BROD_APP_ID or pass { appId } or { audience }.');
  if (typeof token !== 'string' || token === '') throw new BrodAuthError('invalid_token', 'The identity token is empty.');
  const keys = keysFor(opts, issuer);
  let payload: JWTPayload;
  try {
    ({ payload } = await jwtVerify(token, keys, {
      issuer,
      audience,
      algorithms: ALGORITHMS,
      clockTolerance: opts.clockTolerance ?? 30,
      requiredClaims: ['exp', 'iat', 'sub'],
      // Brod's tokens live 5 minutes and exp enforces that. This only makes jose refuse an iat in the future.
      maxTokenAge: '1h',
    }));
  } catch (e) {
    throw translate(e);
  }
  if (!isClaims(payload)) throw new BrodAuthError('invalid_claims', 'The identity token lacks the Brod claims.');
  return toUser(payload);
}

function headerFrom(h: HeadersLike): string | null {
  if (typeof (h as { get?: unknown }).get === 'function') {
    const v = (h as { get(n: string): string | null | undefined }).get(IDENTITY_HEADER);
    return v ?? null;
  }
  const rec = h as Record<string, string | string[] | undefined>;
  let v = rec[IDENTITY_HEADER];
  if (v === undefined) {
    const key = Object.keys(rec).find((k) => k.toLowerCase() === IDENTITY_HEADER);
    v = key === undefined ? undefined : rec[key];
  }
  if (Array.isArray(v)) {
    if (v.length > 1) throw new BrodAuthError('invalid_token', 'The request carries more than one identity token.');
    v = v[0];
  }
  return v ?? null;
}

/** The raw x-brod-identity token of a request, or null when it has none. */
export function identityToken(input: IdentityInput): string | null {
  if (input === null || input === undefined) return null;
  if (typeof input === 'string') return input.trim() || null;
  const source =
    typeof (input as { get?: unknown }).get !== 'function' &&
    typeof (input as { headers?: unknown }).headers === 'object' &&
    (input as { headers?: unknown }).headers !== null
      ? (input as { headers: HeadersLike }).headers
      : (input as HeadersLike);
  const v = headerFrom(source);
  return v === null ? null : v.trim() || null;
}

let warnedDev = false;

/** BROD_DEV_USER as a person, outside production only. */
function devUser(opts: BrodAuthOptions): BrodUser | null {
  const env = envOf(opts);
  // Both places are checked: Next.js and bundlers inline process.env.NODE_ENV, and opts.env may be a Worker's env.
  if (env.NODE_ENV === 'production' || processEnv().NODE_ENV === 'production') return null;
  const raw = str(env.BROD_DEV_USER)?.trim();
  if (!raw) return null;
  let given: Partial<BrodUser> & { email?: string };
  if (raw.startsWith('{')) {
    try {
      given = JSON.parse(raw);
    } catch (e) {
      throw new BrodAuthError('misconfigured', 'BROD_DEV_USER is neither an email address nor valid JSON.', { cause: e });
    }
  } else {
    given = { email: raw };
  }
  if (typeof given.email !== 'string' || !given.email.includes('@'))
    throw new BrodAuthError('misconfigured', 'BROD_DEV_USER needs an email address.');
  const email = given.email;
  const workspace = given.workspace ?? { id: 'dev', slug: 'dev' };
  const app = given.app ?? str(env.BROD_APP_ID) ?? 'dev';
  const user: BrodUser = {
    id: given.id ?? `dev:${email}`,
    email,
    name: given.name ?? email.split('@')[0]!,
    workspace,
    role: given.role === undefined ? 'owner' : given.role,
    groups: given.groups ?? [],
    app,
    claims: {
      iss: 'brod:dev',
      aud: `brod:app:${app}`,
      sub: given.id ?? `dev:${email}`,
      email,
      name: given.name ?? email.split('@')[0]!,
      workspace,
      role: given.role === undefined ? 'owner' : given.role,
      groups: given.groups ?? [],
      iat: 0,
      exp: 0,
      jti: 'dev',
      brod_dev: true,
    },
  };
  if (!warnedDev) {
    warnedDev = true;
    console.warn(`@brod/auth: no x-brod-identity header, using BROD_DEV_USER (${email}). This never happens in production.`);
  }
  return user;
}

/**
 * The person signed in to this app, or null for an anonymous request (an open path, or a public app with nobody
 * signed in). Throws BrodAuthError when a token is present but does not verify: never treat that as anonymous.
 *
 * Outside production (NODE_ENV !== 'production') a request without a token returns BROD_DEV_USER when it is set:
 * an email address, or JSON such as {"email":"me@example.com","role":"admin"}.
 */
export async function currentUser(input: IdentityInput, opts: BrodAuthOptions = {}): Promise<BrodUser | null> {
  const token = identityToken(input);
  if (token === null) return devUser(opts);
  return verifyIdentityToken(token, opts);
}

/** Like currentUser, but throws BrodAuthError (status 401, code "unauthenticated") when nobody is signed in. */
export async function requireUser(input: IdentityInput, opts: BrodAuthOptions = {}): Promise<BrodUser> {
  const user = await currentUser(input, opts);
  if (!user) throw new BrodAuthError('unauthenticated', 'Sign in to Brod to use this.');
  return user;
}

/** Forget cached key sets (tests, or after rotating BROD_IDENTITY_JWKS in a long-running process). */
export function clearKeyCache(): void {
  localSets.clear();
  remoteSets.clear();
  warnedDev = false;
}
