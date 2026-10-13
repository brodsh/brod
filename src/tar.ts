// Pack and unpack .tar and .tar.gz bundles in memory. Unpacking handles ustar prefixes, GNU long names and pax path
// records; packing writes ustar, with a pax path record for a path longer than a ustar header holds.
import { BundleFile, LIMITS, Problem, readCapped } from './lib';

const dec = new TextDecoder();
const str = (b: Uint8Array, from: number, len: number) => {
  let end = from;
  while (end < from + len && b[end] !== 0) end++;
  return dec.decode(b.subarray(from, end));
};

export async function unpack(body: Uint8Array): Promise<BundleFile[]> {
  let tar = body;
  if (body[0] === 0x1f && body[1] === 0x8b) {
    const stream = new Blob([body]).stream().pipeThrough(new DecompressionStream('gzip')) as ReadableStream<Uint8Array>;
    try { tar = await readCapped(stream, LIMITS.unpackedBytes, 'The unpacked bundle'); }
    catch (e) { if (e instanceof Problem) throw e; throw new Problem(400, 'bad_bundle', 'The upload is not a valid gzip file.'); }
  }
  if (tar.byteLength < 512 || str(tar, 257, 5) !== 'ustar')
    throw new Problem(400, 'bad_bundle', 'The upload must be a tar or tar.gz archive. Create it with: tar -czf - -C <build folder> .');

  const files: BundleFile[] = [];
  let pos = 0, longName = '';
  while (pos + 512 <= tar.byteLength) {
    const h = tar.subarray(pos, pos + 512);
    if (h.every(x => x === 0)) break;
    const size = parseInt(str(h, 124, 12).trim() || '0', 8);
    const type = String.fromCharCode(h[156] || 48);
    const data = tar.subarray(pos + 512, pos + 512 + size);
    pos += 512 + Math.ceil(size / 512) * 512;
    if (type === 'L') { longName = str(data, 0, data.byteLength); continue; }
    if (type === 'x') { const m = /(?:^|\n)\d+ path=([^\n]*)\n/.exec(dec.decode(data)); if (m) longName = m[1]; continue; }
    if (type !== '0') { longName = ''; continue; }   // directories, links and global headers are skipped
    const prefix = str(h, 345, 155);
    const name = longName || (prefix ? `${prefix}/${str(h, 0, 100)}` : str(h, 0, 100));
    longName = '';
    files.push({ path: name, bytes: data.slice() });
    if (files.length > LIMITS.files) throw new Problem(413, 'too_many_files', `A bundle can hold at most ${LIMITS.files} files.`);
  }
  return files;
}

const enc = new TextEncoder();

/** One ustar header block. */
function header(name: Uint8Array, size: number, type: string, mtime: number): Uint8Array {
  const h = new Uint8Array(512);
  const put = (s: string | Uint8Array, at: number) => h.set(typeof s === 'string' ? enc.encode(s) : s, at);
  put(name.subarray(0, 100), 0);
  put('0000644\0', 100); put('0000000\0', 108); put('0000000\0', 116);
  put(size.toString(8).padStart(11, '0') + '\0', 124);
  put(Math.floor(mtime / 1000).toString(8).padStart(11, '0') + '\0', 136);
  put(type, 156); put('ustar\0', 257); put('00', 263);
  put('        ', 148);
  put(h.reduce((a, b) => a + b, 0).toString(8).padStart(6, '0') + '\0 ', 148);
  return h;
}

/** A tar.gz of the files, the way `tar -czf` would write them, every file dated `mtime` (milliseconds). */
export async function pack(files: BundleFile[], mtime: number): Promise<Uint8Array> {
  const parts: Uint8Array[] = [];
  const add = (data: Uint8Array) => { parts.push(data); const pad = (512 - (data.byteLength % 512)) % 512; if (pad) parts.push(new Uint8Array(pad)); };
  for (const f of files) {
    const name = enc.encode(f.path);
    if (name.byteLength > 100) {
      // A pax record is "<length> path=<path>\n", where the length counts itself.
      const body = ` path=${f.path}\n`;
      let len = enc.encode(body).byteLength + 1;
      while (String(len).length + enc.encode(body).byteLength !== len) len++;
      const record = enc.encode(len + body);
      parts.push(header(enc.encode('PaxHeader'), record.byteLength, 'x', mtime)); add(record);
    }
    parts.push(header(name, f.bytes.byteLength, '0', mtime)); add(f.bytes);
  }
  parts.push(new Uint8Array(1024));
  const tar = new Uint8Array(parts.reduce((n, p) => n + p.byteLength, 0));
  let at = 0;
  for (const p of parts) { tar.set(p, at); at += p.byteLength; }
  return new Uint8Array(await new Response(new Blob([tar]).stream().pipeThrough(new CompressionStream('gzip'))).arrayBuffer());
}
