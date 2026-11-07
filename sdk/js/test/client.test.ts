import { afterEach, describe, expect, it, vi } from 'vitest';

import { filterValues } from '../src/index';
import { BrodSignInError, methods, returnTo, sendCode, verifyCode } from '../src/client';

const reply = (status: number, body: unknown) => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });

afterEach(() => vi.unstubAllGlobals());

describe('returnTo', () => {
  it('keeps a path on this app', () => expect(returnTo('?return=%2Freports%3Fy%3D1')).toBe('/reports?y=1'));
  it.each(['https://evil.test/', '//evil.test/', '/\\evil.test', ''])('refuses %s', r => {
    expect(returnTo(`?return=${encodeURIComponent(r)}`)).toBe('/');
  });
});

describe('sign-in calls', () => {
  it('posts JSON to the app\'s own address', async () => {
    const f = vi.fn(async () => reply(200, { sent: true, email: 'a@x.test' }));
    vi.stubGlobal('fetch', f);
    await sendCode('a@x.test');
    const [url, init] = f.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe('/_brod/auth/start');
    expect(init.method).toBe('POST');
    expect(init.credentials).toBe('same-origin');
    expect(JSON.parse(init.body as string)).toEqual({ email: 'a@x.test' });
  });

  it('turns a refusal into an error the page can show', async () => {
    vi.stubGlobal('fetch', async () => reply(400, { error: { code: 'bad_code', message: 'That code is wrong.' } }));
    const err = await verifyCode('a@x.test', '000000', '/').catch(e => e);
    expect(err).toBeInstanceOf(BrodSignInError);
    expect(err).toMatchObject({ code: 'bad_code', message: 'That code is wrong.', status: 400 });
  });

  it('survives an answer that is not JSON', async () => {
    vi.stubGlobal('fetch', async () => new Response('<html>', { status: 502 }));
    await expect(verifyCode('a@x.test', '1', '/')).rejects.toMatchObject({ code: 'failed', status: 502 });
  });

  it('says no methods when the app has no approved page', async () => {
    vi.stubGlobal('fetch', async () => reply(404, { error: { code: 'no_sign_in_page' } }));
    expect(await methods()).toEqual({ email: false, google: false });
  });
});

describe('filterValues', () => {
  it('gives a list whatever the shape', () => {
    expect(filterValues({ filters: { tenant: 'acme' } }, 'tenant')).toEqual(['acme']);
    expect(filterValues({ filters: { tenant: ['a', 'b'] } }, 'tenant')).toEqual(['a', 'b']);
    expect(filterValues({ filters: {} }, 'tenant')).toEqual([]);
  });
});
