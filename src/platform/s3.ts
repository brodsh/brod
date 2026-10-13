// A Store over any S3-compatible API: Cloudflare R2's S3 endpoint, AWS S3, MinIO, Backblaze B2 and others.
// Requests are signed with SigV4 by aws4fetch (a few KB, fetch-based), not the AWS SDK.
import { AwsClient } from 'aws4fetch';
import type { Store, StoredObject } from './bucket';

export interface S3Config {
  endpoint: string;            // https://<account>.r2.cloudflarestorage.com, https://s3.<region>.amazonaws.com, http://localhost:9000
  bucket: string;
  accessKeyId: string;
  secretAccessKey: string;
  region?: string;             // "auto" for R2
  virtualHosted?: boolean;     // <bucket>.<endpoint host>/<key> instead of <endpoint>/<bucket>/<key>
  fetch?: (r: Request) => Promise<Response>;
}

const unxml = (s: string) => s.replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&apos;/g, "'").replace(/&#(\d+);/g, (_, n) => String.fromCodePoint(Number(n))).replace(/&amp;/g, '&');
const tag = (xml: string, name: string) => { const m = new RegExp(`<${name}>([\\s\\S]*?)</${name}>`).exec(xml); return m ? unxml(m[1]) : undefined; };

export function s3Store(c: S3Config): Store & { presignPut(key: string, expiresSec: number): Promise<string> } {
  const aws = new AwsClient({ accessKeyId: c.accessKeyId, secretAccessKey: c.secretAccessKey, service: 's3', region: c.region || 'auto' });
  const send = c.fetch ?? ((r: Request) => fetch(r));
  const ep = new URL(c.endpoint.replace(/\/+$/, ''));
  const base = c.virtualHosted ? `${ep.protocol}//${c.bucket}.${ep.host}${ep.pathname.replace(/\/$/, '')}` : `${ep.origin}${ep.pathname.replace(/\/$/, '')}/${encodeURIComponent(c.bucket)}`;
  const url = (key = '') => `${base}/${key.split('/').map(encodeURIComponent).join('/')}`;

  async function call(method: string, u: string, init: { body?: Uint8Array; headers?: Record<string, string> } = {}, ok: number[] = []) {
    const res = await send(await aws.sign(u, { method, headers: init.headers, body: init.body }));
    if (res.ok || ok.includes(res.status)) return res;
    const text = await res.text().catch(() => '');
    throw new Error(`S3 ${method} ${new URL(u).pathname} failed: ${res.status} ${tag(text, 'Code') ?? ''} ${tag(text, 'Message') ?? text.slice(0, 200)}`.trim());
  }
  const meta = (key: string, res: Response): StoredObject => ({
    key, size: Number(res.headers.get('content-length') ?? 0), etag: res.headers.get('etag') ?? '',
    contentType: res.headers.get('content-type') ?? undefined,
    uploaded: res.headers.get('last-modified') ? new Date(res.headers.get('last-modified')!) : undefined,
  });

  return {
    async put(key, bytes, contentType) {
      const res = await call('PUT', url(key), { body: bytes, headers: contentType ? { 'content-type': contentType } : {} });
      await res.body?.cancel();
      return { key, size: bytes.byteLength, etag: res.headers.get('etag') ?? '', contentType, uploaded: new Date() };
    },
    async get(key) {
      const res = await call('GET', url(key), {}, [404]);
      if (res.status === 404) { await res.body?.cancel(); return null; }
      return { meta: meta(key, res), body: res.body ?? new Response('').body! };
    },
    async head(key) {
      const res = await call('HEAD', url(key), {}, [404]);
      return res.status === 404 ? null : meta(key, res);
    },
    async list(prefix, cursor, limit = 1000) {
      const q = new URLSearchParams({ 'list-type': '2', prefix, 'max-keys': String(limit) });
      if (cursor) q.set('continuation-token', cursor);
      const xml = await (await call('GET', `${base}/?${q}`)).text();
      const objects = [...xml.matchAll(/<Contents>([\s\S]*?)<\/Contents>/g)].map(m => ({
        key: tag(m[1], 'Key') ?? '', size: Number(tag(m[1], 'Size') ?? 0), etag: tag(m[1], 'ETag') ?? '',
        uploaded: tag(m[1], 'LastModified') ? new Date(tag(m[1], 'LastModified')!) : undefined,
      }));
      return { objects, cursor: tag(xml, 'IsTruncated') === 'true' ? tag(xml, 'NextContinuationToken') : undefined };
    },
    async delete(key) { await (await call('DELETE', url(key), {}, [404])).body?.cancel(); },
    /** A URL anyone can PUT one object to until it expires: used for uploads larger than the host lets a request carry. */
    async presignPut(key, expiresSec) {
      const u = new URL(url(key)); u.searchParams.set('X-Amz-Expires', String(expiresSec));
      return (await aws.sign(u.href, { method: 'PUT', aws: { signQuery: true } })).url;
    },
  };
}
