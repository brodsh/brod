// Build Brod for Vercel with the Build Output API: one Node.js function that answers every path on every host.
// Usage: npm run build:vercel   (Vercel runs it as the build command; see vercel.json)
// Output: .vercel/output/{config.json, functions/index.func/{index.mjs, .vc-config.json}}
import { build } from 'esbuild';
import { mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

const out = '.vercel/output', fn = join(out, 'functions', 'index.func');
rmSync(out, { recursive: true, force: true });
mkdirSync(fn, { recursive: true });

await build({
  entryPoints: ['src/node/handler.ts'],
  outfile: join(fn, 'index.mjs'),
  bundle: true, platform: 'node', format: 'esm', target: 'node22', minify: false, sourcemap: 'inline', legalComments: 'none',
  // Some bundled CommonJS code calls require(); give the ES module one.
  banner: { js: "import { createRequire as __brodRequire } from 'node:module'; const require = __brodRequire(import.meta.url);" },
  // Server-app classes import Cloudflare's runtime module; give Node a stand-in (server apps are refused off Cloudflare).
  alias: { 'cloudflare:workers': './src/node/cloudflare-workers.ts' },
  logLevel: 'warning',
});

// One function for everything: the API host, the wildcard apps host, and every path. It sees the original URL.
writeFileSync(join(out, 'config.json'), JSON.stringify({ version: 3, routes: [{ src: '/(.*)', dest: '/index' }] }, null, 2));
writeFileSync(join(fn, '.vc-config.json'), JSON.stringify({
  runtime: 'nodejs22.x', handler: 'index.mjs', launcherType: 'Nodejs', shouldAddHelpers: false, supportsResponseStreaming: true,
  // An upload deploy reads up to 25 MB from the bucket and writes up to 2,000 files back; give it time and memory.
  maxDuration: 60, memory: 1024,
}, null, 2));
console.log(`Built ${fn}/index.mjs`);
