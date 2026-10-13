// The part of the R2 API Brod calls (put, get, head, list, delete), so file stores other than R2 can stand in for env.BUNDLES.

export interface StoredObject { key: string; size: number; etag: string; contentType?: string; uploaded?: Date }

/** A file store reduced to five calls. s3.ts and node/fs-bucket.ts implement it; asR2() makes it look like an R2 bucket. */
export interface Store {
  put(key: string, bytes: Uint8Array, contentType?: string): Promise<StoredObject>;
  get(key: string): Promise<{ meta: StoredObject; body: ReadableStream<Uint8Array> } | null>;
  head(key: string): Promise<StoredObject | null>;
  list(prefix: string, cursor?: string, limit?: number): Promise<{ objects: StoredObject[]; cursor?: string }>;
  delete(key: string): Promise<void>;
}

async function bytesOf(v: unknown): Promise<Uint8Array> {
  if (v === null || v === undefined) return new Uint8Array();
  if (typeof v === 'string') return new TextEncoder().encode(v);
  if (v instanceof Uint8Array) return v;
  if (v instanceof ArrayBuffer) return new Uint8Array(v);
  if (ArrayBuffer.isView(v)) return new Uint8Array(v.buffer, v.byteOffset, v.byteLength);
  return new Uint8Array(await new Response(v as BodyInit).arrayBuffer());   // Blob or ReadableStream
}

function r2Object(m: StoredObject) {
  const etag = m.etag.replace(/^(W\/)?"|"$/g, '');
  return {
    key: m.key, size: m.size, etag, httpEtag: `"${etag}"`, version: etag, uploaded: m.uploaded ?? new Date(0),
    httpMetadata: m.contentType ? { contentType: m.contentType } : {}, customMetadata: {}, storageClass: 'Standard', checksums: {},
    writeHttpMetadata(h: Headers) { if (m.contentType) h.set('content-type', m.contentType); },
  };
}

/** Present a Store as env.BUNDLES. Only the R2 calls Brod makes are implemented. */
export function asR2(store: Store): R2Bucket {
  const bucket = {
    async put(key: string, value: unknown, o?: { httpMetadata?: { contentType?: string } | Headers }) {
      const ct = o?.httpMetadata instanceof Headers ? o.httpMetadata.get('content-type') ?? undefined : o?.httpMetadata?.contentType;
      return r2Object(await store.put(key, await bytesOf(value), ct));
    },
    async get(key: string) {
      const hit = await store.get(key);
      if (!hit) return null;
      const body = hit.body;
      return {
        ...r2Object(hit.meta), body, bodyUsed: false,
        arrayBuffer: () => new Response(body).arrayBuffer(),
        text: () => new Response(body).text(),
        json: () => new Response(body).json(),
        blob: () => new Response(body).blob(),
      };
    },
    async head(key: string) { const m = await store.head(key); return m ? r2Object(m) : null; },
    async list(o: { prefix?: string; cursor?: string; limit?: number } = {}) {
      const page = await store.list(o.prefix ?? '', o.cursor, Math.min(o.limit ?? 1000, 1000));
      return { objects: page.objects.map(r2Object), truncated: !!page.cursor, ...(page.cursor ? { cursor: page.cursor } : {}), delimitedPrefixes: [] };
    },
    async delete(keys: string | string[]) {
      const all = Array.isArray(keys) ? keys : [keys];
      for (let i = 0; i < all.length; i += 20) await Promise.all(all.slice(i, i + 20).map(k => store.delete(k)));
    },
  };
  // Structurally a subset of R2Bucket: multipart uploads and conditional requests are not used by Brod.
  return bucket as unknown as R2Bucket;
}
