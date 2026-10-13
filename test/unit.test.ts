// Unit tests for the pure pieces: slugs, escaping, signing, bundle clean-up and tar unpacking.
import { describe, expect, it } from 'vitest';
import { normalise } from '../src/control';
import { Problem, RESERVED_WORKSPACES, contentType, cookie, cookieName, esc, hmac, safeEqual, setCookie, signToken, slugify } from '../src/lib';
import { unpack } from '../src/tar';

const enc = new TextEncoder();
const file = (path: string, content = 'x') => ({ path, bytes: enc.encode(content) });
const code = (fn: () => unknown) => { try { fn(); } catch (e) { return (e as Problem).code; } return null; };

/** Build a ustar archive in memory, the way `tar -c` would. */
function tar(files: { name: string; content: string; prefix?: string; type?: string }[]): Uint8Array {
  const blocks: Uint8Array[] = [];
  for (const f of files) {
    const h = new Uint8Array(512), data = enc.encode(f.content);
    const put = (s: string, at: number) => h.set(enc.encode(s), at);
    put(f.name, 0); put('0000644\0', 100); put('0000000\0', 108); put('0000000\0', 116);
    put(data.length.toString(8).padStart(11, '0') + '\0', 124); put('00000000000\0', 136);
    put(f.type ?? '0', 156); put('ustar\0', 257); put('00', 263);
    if (f.prefix) put(f.prefix, 345);
    put('        ', 148);
    const sum = h.reduce((a, b) => a + b, 0);
    put(sum.toString(8).padStart(6, '0') + '\0 ', 148);
    blocks.push(h, new Uint8Array(Math.ceil(data.length / 512) * 512));
    blocks[blocks.length - 1].set(data);
  }
  blocks.push(new Uint8Array(1024));
  const out = new Uint8Array(blocks.reduce((n, b) => n + b.length, 0));
  let o = 0; for (const b of blocks) { out.set(b, o); o += b.length; }
  return out;
}
const gzip = async (b: Uint8Array) => new Uint8Array(await new Response(new Blob([b]).stream().pipeThrough(new CompressionStream('gzip'))).arrayBuffer());

describe('slugify', () => {
  it('makes a readable address from a name', () => {
    expect(slugify('Reading List!')).toBe('reading-list');
    expect(slugify('www', RESERVED_WORKSPACES, 'team')).toBe('team-www');
    expect(slugify('  Café   Menu  ')).toBe('cafe-menu');
  });
  it('never hands out a reserved or empty name', () => {
    expect(slugify('API')).toBe('app-api');
    expect(slugify('!!!')).toBe('app-x');
  });
  it('caps the length without a trailing dash', () => {
    const s = slugify('a'.repeat(39) + ' b c');
    expect(s.length).toBeLessThanOrEqual(40);
    expect(s.endsWith('-')).toBe(false);
  });
});

describe('small helpers', () => {
  it('compares secrets', () => {
    expect(safeEqual('abc', 'abc')).toBe(true);
    expect(safeEqual('abc', 'abd')).toBe(false);
    expect(safeEqual('abc', 'abcd')).toBe(false);
  });
  it('escapes HTML', () => {
    expect(esc('<a href="x">\'&')).toBe('&lt;a href=&quot;x&quot;&gt;&#39;&amp;');
  });
  it('knows common content types', () => {
    expect(contentType('a/b/app.JS')).toMatch(/^text\/javascript/);
    expect(contentType('x.unknown')).toBe('application/octet-stream');
  });
  it('signs identity tokens that a holder of the key can check', async () => {
    const token = await signToken('k', { sub: 'usr_1', role: 'editor' });
    const [body, sig] = token.split('.');
    expect(sig).toBe(await hmac('k', body));
    expect(sig).not.toBe(await hmac('other', body));
    const payload = JSON.parse(atob(body.replace(/-/g, '+').replace(/_/g, '/')));
    expect(payload).toEqual({ sub: 'usr_1', role: 'editor' });
  });
});

describe('cookies', () => {
  it('use the __Host- prefix on HTTPS, so a sibling subdomain such as an app cannot set them', () => {
    expect(cookieName('https://brod.sh', 'brod_platform')).toBe('__Host-brod_platform');
    expect(cookieName('http://localhost:8787', 'brod_platform')).toBe('brod_platform');
    const set = setCookie('https://notes.apps.brod.sh', 'brod_session', 'abc', 60);
    expect(set).toBe('__Host-brod_session=abc; Path=/; HttpOnly; SameSite=Lax; Max-Age=60; Secure');
    expect(set).not.toMatch(/domain=/i);
  });
  it('ignore an unprefixed cookie that an app planted on HTTPS', () => {
    const req = (c: string) => new Request('https://brod.sh/', { headers: { cookie: c } });
    expect(cookie(req('brod_platform=planted'), 'https://brod.sh', 'brod_platform')).toBe('');
    expect(cookie(req('brod_platform=planted; __Host-brod_platform=real'), 'https://brod.sh', 'brod_platform')).toBe('real');
  });
});

describe('normalise', () => {
  it('strips one wrapping folder such as dist/', () => {
    const out = normalise([file('dist/index.html'), file('dist/assets/app.js')]);
    expect(out.map(f => f.path)).toEqual(['index.html', 'assets/app.js']);
  });
  it('drops junk files and cleans leading ./ and slashes', () => {
    const out = normalise([file('./index.html'), file('/a.css'), file('.DS_Store'), file('x/._y'), file('.git/config')]);
    expect(out.map(f => f.path)).toEqual(['index.html', 'a.css']);
  });
  it('refuses paths that climb out, platform paths, and bundles without index.html', () => {
    expect(code(() => normalise([file('index.html'), file('../etc/passwd')]))).toBe('bad_path');
    expect(code(() => normalise([file('index.html'), file('_brod/me')]))).toBe('bad_path');
    expect(code(() => normalise([file('main.py')]))).toBe('no_index');
    expect(code(() => normalise([]))).toBe('empty_bundle');
  });
});

describe('unpack', () => {
  it('reads a tar.gz with a ustar prefix and skips directories', async () => {
    const files = await unpack(await gzip(tar([
      { name: 'dist/', content: '', type: '5' },
      { name: 'index.html', content: '<h1>hi</h1>', prefix: 'dist' },
      { name: 'dist/app.js', content: 'console.log(1)' },
    ])));
    expect(files.map(f => f.path)).toEqual(['dist/index.html', 'dist/app.js']);
    expect(new TextDecoder().decode(files[0].bytes)).toBe('<h1>hi</h1>');
  });
  it('reads GNU long names', async () => {
    const long = 'd/' + 'n'.repeat(150) + '.txt';
    const files = await unpack(tar([{ name: '././@LongLink', content: long, type: 'L' }, { name: 'ignored', content: 'long' }]));
    expect(files[0].path).toBe(long);
  });
  it('refuses something that is not an archive', async () => {
    await expect(unpack(enc.encode('not a tar'))).rejects.toMatchObject({ code: 'bad_bundle' });
    await expect(unpack(new Uint8Array([0x1f, 0x8b, 1, 2, 3]))).rejects.toMatchObject({ code: 'bad_bundle' });
  });
});
