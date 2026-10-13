// A Store on the local disk, for running Brod on one machine and for the end-to-end suite. Not for Vercel:
// a function's disk is temporary and not shared between instances.
import { createHash } from 'node:crypto';
import { createReadStream } from 'node:fs';
import { mkdir, readFile, readdir, rm, stat, writeFile } from 'node:fs/promises';
import { dirname, join, relative, sep } from 'node:path';
import { Readable } from 'node:stream';
import type { Store, StoredObject } from '../platform/bucket';

export function fsStore(root: string): Store {
  const parts = (key: string) => {
    const p = key.split('/');
    if (p.some(x => x === '..' || x === '.' || x === '')) throw new Error(`Bad object key: ${key}`);
    return p;
  };
  const data = (key: string) => join(root, 'objects', ...parts(key));
  const metaFile = (key: string) => join(root, 'meta', ...parts(key)) + '.json';
  const head = async (key: string): Promise<StoredObject | null> => {
    try {
      const m = JSON.parse(await readFile(metaFile(key), 'utf8'));
      return { key, etag: m.etag, contentType: m.contentType, uploaded: new Date(m.uploaded), size: (await stat(data(key))).size };
    } catch { return null; }
  };
  async function walk(dir: string): Promise<string[]> {
    const out: string[] = [];
    for (const e of await readdir(dir, { withFileTypes: true }).catch(() => [])) {
      const p = join(dir, e.name);
      if (e.isDirectory()) out.push(...(await walk(p))); else out.push(relative(join(root, 'objects'), p).split(sep).join('/'));
    }
    return out;
  }
  return {
    async put(key, bytes, contentType) {
      const etag = createHash('md5').update(bytes).digest('hex'), uploaded = new Date();
      await mkdir(dirname(data(key)), { recursive: true });
      await mkdir(dirname(metaFile(key)), { recursive: true });
      await writeFile(data(key), bytes);
      await writeFile(metaFile(key), JSON.stringify({ etag, contentType, uploaded }));
      return { key, size: bytes.byteLength, etag, contentType, uploaded };
    },
    async get(key) {
      const m = await head(key);
      return m ? { meta: m, body: Readable.toWeb(createReadStream(data(key))) as unknown as ReadableStream<Uint8Array> } : null;
    },
    head,
    async list(prefix, cursor, limit = 1000) {
      const keys = (await walk(join(root, 'objects'))).filter(k => k.startsWith(prefix) && (!cursor || k > cursor)).sort();
      const page = keys.slice(0, limit);
      const objects = (await Promise.all(page.map(head))).filter((m): m is StoredObject => !!m);
      return { objects, cursor: keys.length > limit ? page[page.length - 1] : undefined };
    },
    async delete(key) {
      await rm(data(key), { force: true });
      await rm(metaFile(key), { force: true });
    },
  };
}
