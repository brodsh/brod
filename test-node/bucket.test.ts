// The R2 stand-ins: an S3-compatible store (against an in-memory fake S3 that checks every signature) and a folder.
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import { ACCESS_KEY, SECRET_KEY, fakeS3, verify } from '../scripts/fake-s3.mjs';
import { fsStore } from '../src/node/fs-bucket';
import { asR2 } from '../src/platform/bucket';
import { s3Store } from '../src/platform/s3';

const s3 = fakeS3();
const s3Config = { endpoint: 'http://s3.test', bucket: 'brod-bundles', accessKeyId: ACCESS_KEY, secretAccessKey: SECRET_KEY, fetch: s3.handle };
const dir = mkdtempSync(join(tmpdir(), 'brod-files-'));
afterAll(() => rmSync(dir, { recursive: true, force: true }));
const enc = new TextEncoder();

describe.each([
  ['S3', () => asR2(s3Store(s3Config))],
  ['folder', () => asR2(fsStore(dir))],
])('%s store through the R2 API', (_, make) => {
  const B = make();

  it('put then get: body, size, content type and a quoted httpEtag', async () => {
    await B.put('app_1/1/index.html', enc.encode('<h1>hi</h1>'), { httpMetadata: { contentType: 'text/html; charset=utf-8' } });
    const o = await B.get('app_1/1/index.html');
    expect(o).not.toBeNull();
    expect(await new Response(o!.body).text()).toBe('<h1>hi</h1>');
    expect(o!.size).toBe(11);
    expect(o!.httpMetadata?.contentType).toBe('text/html; charset=utf-8');
    expect(o!.httpEtag).toMatch(/^"[0-9a-f]{32}"$/);
    expect(o!.httpEtag).toBe(`"${o!.etag}"`);
  });

  it('a missing key is null', async () => {
    expect(await B.get('app_1/1/nope.png')).toBeNull();
    expect(await B.head('app_1/1/nope.png')).toBeNull();
  });

  it('keys with spaces, unicode and long names round-trip', async () => {
    const key = `app_1/1/a folder/ünïcode (1)+x/${'long-'.repeat(40)}.txt`;
    await B.put(key, enc.encode('ok'));
    expect(await (await B.get(key))!.text()).toBe('ok');
  });

  it('list pages with a cursor, then delete removes a list of keys', async () => {
    for (let i = 0; i < 5; i++) await B.put(`app_2/1/f${i}.txt`, enc.encode(String(i)));
    const seen: string[] = [];
    let cursor: string | undefined;
    do {
      const page = await B.list({ prefix: 'app_2/', cursor, limit: 2 });
      seen.push(...page.objects.map(o => o.key));
      cursor = page.truncated ? page.cursor : undefined;
    } while (cursor);
    expect(seen).toEqual(['app_2/1/f0.txt', 'app_2/1/f1.txt', 'app_2/1/f2.txt', 'app_2/1/f3.txt', 'app_2/1/f4.txt']);
    await B.delete(seen);
    expect((await B.list({ prefix: 'app_2/' })).objects).toEqual([]);
    expect(await B.get('app_1/1/index.html')).not.toBeNull();   // other prefixes untouched
  });
});

describe('S3 signing', () => {
  it('a wrong secret is refused by the server and reported clearly', async () => {
    const bad = asR2(s3Store({ ...s3Config, secretAccessKey: 'wrong' }));
    await expect(bad.put('k', enc.encode('x'))).rejects.toThrow(/403 SignatureDoesNotMatch/);
  });

  it('a presigned PUT lets anyone upload that one key until it expires', async () => {
    const store = s3Store(s3Config);
    const url = await store.presignPut('_uploads/up_1.tar.gz', 900);
    expect(new URL(url).searchParams.get('X-Amz-Expires')).toBe('900');
    expect((await s3.handle(new Request(url, { method: 'PUT', body: 'bundle' }))).status).toBe(200);
    expect(await (await asR2(store).get('_uploads/up_1.tar.gz'))!.text()).toBe('bundle');
    const other = url.replace('up_1', 'up_2');
    expect((await s3.handle(new Request(other, { method: 'PUT', body: 'x' }))).status).toBe(403);
  });

  it('virtual-hosted addressing puts the bucket in the host name', async () => {
    const url = await s3Store({ ...s3Config, endpoint: 'https://s3.eu-west-1.amazonaws.com', virtualHosted: true, region: 'eu-west-1' }).presignPut('a b.txt', 60);
    expect(new URL(url).host).toBe('brod-bundles.s3.eu-west-1.amazonaws.com');
    expect(new URL(url).pathname).toBe('/a%20b.txt');
  });

  // The fake's verifier is our own SigV4 implementation; check it against AWS's published examples
  // (https://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-header-based-auth.html and sigv4-query-string-auth.html).
  const aws = { now: Date.UTC(2013, 4, 24), keys: { AKIAIOSFODNN7EXAMPLE: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY' } };
  it('the fake S3 verifier agrees with AWS\'s header-signing example', () => {
    const r = new Request('https://examplebucket.s3.amazonaws.com/test.txt', {
      headers: {
        host: 'examplebucket.s3.amazonaws.com', range: 'bytes=0-9', 'x-amz-date': '20130524T000000Z',
        'x-amz-content-sha256': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
        authorization: 'AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, SignedHeaders=host;range;x-amz-content-sha256;x-amz-date, Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41',
      },
    });
    expect(verify(r, '/test.txt', '', aws)).toBeNull();
  });
  it('the fake S3 verifier agrees with AWS\'s presigned URL example', () => {
    const q = 'X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAIOSFODNN7EXAMPLE%2F20130524%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20130524T000000Z&X-Amz-Expires=86400&X-Amz-SignedHeaders=host&X-Amz-Signature=aeeed9bbccd4d02ee5c0109b86d86835f995330da4c265957d157751f604d404';
    expect(verify(new Request(`https://examplebucket.s3.amazonaws.com/test.txt?${q}`), '/test.txt', q, aws)).toBeNull();
    expect(verify(new Request(`https://examplebucket.s3.amazonaws.com/test.txt?${q}`, { method: 'PUT', body: 'x' }), '/test.txt', q, aws)).toBe('SignatureDoesNotMatch');
  });
});
