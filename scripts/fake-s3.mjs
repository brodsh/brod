// A small in-memory S3-compatible server for tests: path-style buckets, PUT/GET/HEAD/DELETE objects and ListObjectsV2.
// It checks every request's SigV4 signature (header or presigned query) with its own implementation from the AWS spec,
// so a signing mistake in src/platform/s3.ts fails the tests instead of passing silently.
// Usage: node scripts/fake-s3.mjs [port]   (credentials: test-key / test-secret, any bucket name)
import { createHash, createHmac } from 'node:crypto';
import http from 'node:http';
import { fileURLToPath } from 'node:url';

export const ACCESS_KEY = 'test-key', SECRET_KEY = 'test-secret';
/** @type {Record<string, string>} */
const KEYS = { [ACCESS_KEY]: SECRET_KEY };

const enc = s => encodeURIComponent(s).replace(/[!'()*]/g, c => '%' + c.charCodeAt(0).toString(16).toUpperCase());
const hmac = (k, s) => createHmac('sha256', k).update(s).digest();
const xml = s => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
const error = (status, code) => new Response(`<?xml version="1.0"?><Error><Code>${code}</Code><Message>${code}</Message></Error>`, { status, headers: { 'content-type': 'application/xml' } });

/**
 * Check a request's SigV4 signature. Returns an error code, or null when it is valid.
 * @param {Request} request @param {string} rawPath @param {string} rawQuery @param {{ now: number, keys: Record<string, string> }} [o]
 */
export function verify(request, rawPath, rawQuery, o = { now: Date.now(), keys: KEYS }) {
  const query = rawQuery ? rawQuery.split('&').map(p => p.split('=').map(x => decodeURIComponent(x))) : [];
  const q = Object.fromEntries(query);
  let credential, signedHeaders, signature, datetime, payload;
  if (q['X-Amz-Signature']) {
    ({ 'X-Amz-Credential': credential, 'X-Amz-SignedHeaders': signedHeaders, 'X-Amz-Signature': signature, 'X-Amz-Date': datetime } = q);
    const t = Date.UTC(+datetime.slice(0, 4), +datetime.slice(4, 6) - 1, +datetime.slice(6, 8), +datetime.slice(9, 11), +datetime.slice(11, 13), +datetime.slice(13, 15));
    if (o.now > t + Number(q['X-Amz-Expires']) * 1000) return 'ExpiredToken';
    payload = 'UNSIGNED-PAYLOAD';
  } else {
    const m = /^AWS4-HMAC-SHA256 Credential=([^,]+), SignedHeaders=([^,]+), Signature=([0-9a-f]+)$/.exec(request.headers.get('authorization') ?? '');
    if (!m) return 'AccessDenied';
    [, credential, signedHeaders, signature] = m;
    datetime = request.headers.get('x-amz-date');
    payload = request.headers.get('x-amz-content-sha256');
  }
  const [key, date, region, service] = credential.split('/');
  const secret = o.keys[key];
  if (!secret) return 'InvalidAccessKeyId';
  const canonical = [
    request.method,
    rawPath.split('/').map(s => enc(decodeURIComponent(s))).join('/'),
    query.filter(([k]) => k !== 'X-Amz-Signature').map(([k, v]) => [enc(k), enc(v ?? '')]).sort(([a, x], [b, y]) => (a < b ? -1 : a > b ? 1 : x < y ? -1 : 1)).map(p => p.join('=')).join('&'),
    signedHeaders.split(';').map(h => `${h}:${(request.headers.get(h) ?? (h === 'host' ? new URL(request.url).host : '')).trim().replace(/\s+/g, ' ')}\n`).join(''),
    signedHeaders,
    payload,
  ].join('\n');
  const toSign = ['AWS4-HMAC-SHA256', datetime, `${date}/${region}/${service}/aws4_request`, createHash('sha256').update(canonical).digest('hex')].join('\n');
  const k = hmac(hmac(hmac(hmac('AWS4' + secret, date), region), service), 'aws4_request');
  return hmac(k, toSign).toString('hex') === signature ? null : 'SignatureDoesNotMatch';
}

/** A fetch-style handler holding objects in memory. `objects` is exposed for assertions. */
export function fakeS3() {
  const objects = new Map();   // "bucket/key" -> { bytes, type, etag, at }
  const stats = { presignedPuts: 0 };
  async function handle(request) {
    const u = new URL(request.url);
    const [rawPath, rawQuery = ''] = request.url.slice(u.origin.length).split('?');
    const bad = verify(request, rawPath, rawQuery);
    if (bad) return error(403, bad);
    if (request.method === 'PUT' && u.searchParams.has('X-Amz-Signature')) stats.presignedPuts++;
    const [, bucket, ...rest] = rawPath.split('/');
    const key = rest.map(decodeURIComponent).join('/'), id = `${bucket}/${key}`;
    if (request.method === 'GET' && !key && u.searchParams.get('list-type') === '2') {
      const prefix = u.searchParams.get('prefix') ?? '', after = u.searchParams.get('continuation-token') ?? '', max = Number(u.searchParams.get('max-keys') ?? 1000);
      const keys = [...objects.keys()].filter(k => k.startsWith(`${bucket}/${prefix}`) && k > `${bucket}/${after}`).sort();
      const page = keys.slice(0, max), more = keys.length > max;
      const body = page.map(k => { const o = objects.get(k); return `<Contents><Key>${xml(k.slice(bucket.length + 1))}</Key><Size>${o.bytes.length}</Size><ETag>${xml(o.etag)}</ETag><LastModified>${o.at.toISOString()}</LastModified></Contents>`; }).join('');
      return new Response(`<?xml version="1.0"?><ListBucketResult><Name>${xml(bucket)}</Name><KeyCount>${page.length}</KeyCount><IsTruncated>${more}</IsTruncated>${more ? `<NextContinuationToken>${xml(page[page.length - 1].slice(bucket.length + 1))}</NextContinuationToken>` : ''}${body}</ListBucketResult>`, { headers: { 'content-type': 'application/xml' } });
    }
    if (!key) return error(400, 'InvalidRequest');
    if (request.method === 'PUT') {
      const bytes = new Uint8Array(await request.arrayBuffer());
      const etag = `"${createHash('md5').update(bytes).digest('hex')}"`;
      objects.set(id, { bytes, type: request.headers.get('content-type') ?? 'application/octet-stream', etag, at: new Date() });
      return new Response(null, { headers: { etag } });
    }
    if (request.method === 'DELETE') { objects.delete(id); return new Response(null, { status: 204 }); }
    const o = objects.get(id);
    if (request.method === 'GET' || request.method === 'HEAD') {
      if (!o) return error(404, 'NoSuchKey');
      const headers = { etag: o.etag, 'content-type': o.type, 'content-length': String(o.bytes.length), 'last-modified': o.at.toUTCString() };
      return new Response(request.method === 'HEAD' ? null : o.bytes, { headers });
    }
    return error(405, 'MethodNotAllowed');
  }
  return { handle, objects, stats };
}

/** Serve the fake on a port, for the end-to-end suite. */
export function serveFakeS3(port = 0) {
  const s3 = fakeS3();
  const server = http.createServer(async (req, res) => {
    const chunks = []; for await (const c of req) chunks.push(c);
    const body = ['GET', 'HEAD'].includes(req.method) ? undefined : Buffer.concat(chunks);
    const r = await s3.handle(new Request(`http://${req.headers.host}${req.url}`, { method: req.method, headers: req.headers, body }));
    res.writeHead(r.status, Object.fromEntries(r.headers));
    res.end(Buffer.from(await r.arrayBuffer()));
  });
  return new Promise(resolve => server.listen(port, '127.0.0.1', () => resolve({ server, port: server.address().port, s3 })));
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const { port } = await serveFakeS3(Number(process.argv[2] ?? 9000));
  console.log(`fake S3 on http://127.0.0.1:${port} (${ACCESS_KEY} / ${SECRET_KEY})`);
}
