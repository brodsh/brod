import { beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

const current = vi.hoisted(() => ({ headers: new Headers() }));
vi.mock('next/headers', () => ({ headers: async () => current.headers }));

import { BrodAuthError, clearKeyCache } from '../src/index';
import { currentUserFromHeaders, requireUserFromHeaders } from '../src/next';
import { APP_ID, ISSUER, brodKey, jwksOf, sign, type TestKey } from './helpers';

let key: TestKey;
beforeAll(async () => {
  key = await brodKey();
});
beforeEach(() => clearKeyCache());

const opts = () => ({ env: { BROD_ISSUER: ISSUER, BROD_APP_ID: APP_ID, BROD_IDENTITY_JWKS: JSON.stringify(jwksOf(key)) } });

describe('@brodsh/auth/next', () => {
  it('reads the person from next/headers', async () => {
    current.headers = new Headers({ 'x-brod-identity': await sign(key) });
    expect((await currentUserFromHeaders(opts()))?.email).toBe('ada@example.com');
    expect((await requireUserFromHeaders(opts())).id).toBe('usr_1');
  });

  it('is null, or a 401 from requireUserFromHeaders, without a token', async () => {
    current.headers = new Headers();
    expect(await currentUserFromHeaders(opts())).toBeNull();
    const e = await requireUserFromHeaders(opts()).catch((err: unknown) => err);
    expect(e).toBeInstanceOf(BrodAuthError);
    expect((e as BrodAuthError).status).toBe(401);
  });
});
