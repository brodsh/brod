// The HTMLRewriter fallback, the Node request adapter, and how the host reads its configuration.
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { describe, expect, it } from 'vitest';
import { hostEnv } from '../src/node/env';
import { toNodeListener } from '../src/node/listener';
import { appendToBody } from '../src/platform/html';

const enc = new TextEncoder(), dec = new TextDecoder();
const add = (html: string) => dec.decode(appendToBody(enc.encode(html), '<a>Report</a>'));

describe('report link without HTMLRewriter', () => {
  it('goes just before the last </body>, whatever its case', () => {
    expect(add('<html><body><h1>x</h1></body></html>')).toBe('<html><body><h1>x</h1><a>Report</a></body></html>');
    expect(add('<BODY>x</BODY >')).toBe('<BODY>x<a>Report</a></BODY >');
    expect(add('<body><script>"</body>"</script>y</body>')).toBe('<body><script>"</body>"</script>y<a>Report</a></body>');
  });
  it('goes at the end when <body> is never closed, and nowhere when there is no <body>', () => {
    expect(add('<body>x')).toBe('<body>x<a>Report</a>');
    expect(add('<h1>v1</h1>')).toBe('<h1>v1</h1>');
  });
  it('leaves non-ASCII bytes untouched', () => {
    expect(add('<body>héllo ✓</body>')).toBe('<body>héllo ✓<a>Report</a></body>');
  });
});

async function serve(listener: http.RequestListener) {
  const server = http.createServer(listener);
  await new Promise<void>(r => server.listen(0, '127.0.0.1', r));
  return { url: `http://127.0.0.1:${(server.address() as AddressInfo).port}`, close: () => server.close() };
}

describe('Node adapter', () => {
  it('passes host, path, headers and a streamed body; returns status, every cookie and the body', async () => {
    let seen: Request | undefined, body = '';
    const s = await serve(toNodeListener(async r => {
      seen = r; body = await r.text();
      const h = new Headers({ 'content-type': 'text/plain' });
      h.append('set-cookie', 'a=1; Path=/'); h.append('set-cookie', 'b=2; Path=/');
      return new Response('done', { status: 201, headers: h });
    }));
    const res = await fetch(`${s.url}/v1/x?y=1`, { method: 'PUT', body: 'payload', headers: { 'x-test': 'yes' } });
    expect(res.status).toBe(201);
    expect(res.headers.getSetCookie()).toEqual(['a=1; Path=/', 'b=2; Path=/']);
    expect(await res.text()).toBe('done');
    expect(seen!.url).toBe(`${s.url}/v1/x?y=1`);
    expect(seen!.headers.get('x-test')).toBe('yes');
    expect(body).toBe('payload');
    s.close();
  });

  it('uses X-Forwarded-Host only when told to trust the proxy (on Vercel)', async () => {
    let url = '';
    const make = (trust: boolean) => serve(toNodeListener(async r => { url = r.url; return new Response(null, { status: 204 }); }, { trustForwarded: trust }));
    const a = await make(false);
    await fetch(`${a.url}/p`, { headers: { 'x-forwarded-host': 'evil.test', 'x-forwarded-proto': 'https' } });
    expect(url).toBe(`${a.url}/p`); a.close();
    const b = await make(true);
    await fetch(`${b.url}/p`, { headers: { 'x-forwarded-host': 'reading-list.brod.app', 'x-forwarded-proto': 'https' } });
    expect(url).toBe('https://reading-list.brod.app/p'); b.close();
  });

  it('answers 500 with a JSON error when the handler throws', async () => {
    const s = await serve(toNodeListener(async () => { throw new Error('boom'); }));
    const res = await fetch(s.url);
    expect(res.status).toBe(500);
    expect(((await res.json()) as any).error.code).toBe('internal');
    s.close();
  });
});

describe('configuration', () => {
  const base = { APPS_DOMAIN: 'brod.app', API_ORIGIN: 'https://brod.sh', ADMIN_SECRET: 'a', IDENTITY_SECRET: 'i', TURSO_DATABASE_URL: 'libsql://brod-x.turso.io', TURSO_AUTH_TOKEN: 't' };
  const s3 = { S3_ENDPOINT: 'https://acct.r2.cloudflarestorage.com', S3_BUCKET: 'brod-bundles', S3_ACCESS_KEY_ID: 'k', S3_SECRET_ACCESS_KEY: 's' };

  it('names every missing variable, and never a value', async () => {
    await expect(hostEnv({ TURSO_AUTH_TOKEN: 'secret-token' }, 'vercel')).rejects.toThrow(
      'Set these environment variables: APPS_DOMAIN, API_ORIGIN, ADMIN_SECRET, IDENTITY_SECRET, TURSO_DATABASE_URL, S3_ENDPOINT, S3_BUCKET, S3_ACCESS_KEY_ID, S3_SECRET_ACCESS_KEY');
    await expect(hostEnv({ ...base, S3_ENDPOINT: 'x' }, 'vercel')).rejects.toThrow('S3_BUCKET, S3_ACCESS_KEY_ID, S3_SECRET_ACCESS_KEY');
  });

  it('on Vercel: needs S3 and a remote database, refuses DEV_MODE in production, and presigns uploads', async () => {
    await expect(hostEnv({ ...base, FILES_DIR: '/tmp/x' }, 'vercel')).rejects.toThrow(/S3_ENDPOINT/);
    await expect(hostEnv({ ...base, ...s3, TURSO_DATABASE_URL: 'file:x.db' }, 'vercel')).rejects.toThrow(/remote/);
    await expect(hostEnv({ ...base, ...s3, DEV_MODE: '1', VERCEL_ENV: 'production' }, 'vercel')).rejects.toThrow(/DEV_MODE/);
    const env = await hostEnv({ ...base, ...s3, API_ORIGIN: 'https://brod.sh/' }, 'vercel');
    expect(env.API_ORIGIN).toBe('https://brod.sh');
    expect(env.HOST).toMatchObject({ name: 'vercel', serverApps: false });
    expect(await env.HOST!.presignPut!('_uploads/up_1.tar.gz', 900)).toMatch(/^https:\/\/acct\.r2\.cloudflarestorage\.com\/brod-bundles\/_uploads\/up_1\.tar\.gz\?.*X-Amz-Signature=/);
  });

  it('elsewhere: a folder for files and uploads through the API', async () => {
    const env = await hostEnv({ ...base, TURSO_DATABASE_URL: ':memory:', FILES_DIR: '/tmp/brod-files' }, 'node');
    expect(env.HOST).toMatchObject({ name: 'node', serverApps: false, presignPut: undefined });
  });
});
