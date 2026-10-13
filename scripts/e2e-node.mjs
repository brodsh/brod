// Run the end-to-end suite against the Vercel build served by Node.js: the same bundle Vercel runs, with a fresh
// libSQL file database migrated by scripts/migrate-libsql.mjs, and app files either in a local folder or in a
// fake S3 server (which also takes uploads by presigned PUT, the way they work on Vercel).
// Usage: npm run e2e:node            (files in a folder, uploads through the API)
//        npm run e2e:node -- s3      (files in S3, uploads by presigned PUT + finish)
import { execFileSync, spawn } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { serveFakeS3, ACCESS_KEY, SECRET_KEY } from './fake-s3.mjs';
import { migrate } from './migrate-libsql.mjs';
import { serveFakeDns } from './fake-dns.mjs';

const mode = process.argv[2] === 's3' ? 's3' : 'fs';
const PORT = process.env.E2E_PORT ?? '8788';
const API = `http://localhost:${PORT}`;
const state = mkdtempSync(join(tmpdir(), 'brod-e2e-node-'));

execFileSync(process.execPath, ['scripts/build-vercel.mjs'], { stdio: 'inherit' });
const dbUrl = `file:${join(state, 'brod.db')}`;
await migrate(dbUrl);

let fake;
// Custom domains are proven against a fake DNS-over-HTTPS resolver.
const dns = await serveFakeDns();
const env = {
  ...process.env, VERCEL: '', APPS_DOMAIN: `localhost:${PORT}`, API_ORIGIN: API, ADMIN_SECRET: 'dev-admin-secret', IDENTITY_SECRET: 'dev-identity-secret',
  DEV_MODE: '1', TURSO_DATABASE_URL: dbUrl, SECRETS_KEY: 'dev-secrets-key-0123456789', DNS_RESOLVER_URL: `http://127.0.0.1:${dns.port}/dns-query`,
};
if (mode === 's3') {
  fake = await serveFakeS3();
  Object.assign(env, { S3_ENDPOINT: `http://127.0.0.1:${fake.port}`, S3_BUCKET: 'brod-bundles', S3_ACCESS_KEY_ID: ACCESS_KEY, S3_SECRET_ACCESS_KEY: SECRET_KEY, DIRECT_UPLOADS: '1' });
} else env.FILES_DIR = join(state, 'files');

const server = spawn(process.execPath, ['scripts/serve-node.mjs', PORT], { stdio: ['ignore', 'pipe', 'pipe'], env });
let log = '';
server.stdout.on('data', d => (log += d)); server.stderr.on('data', d => (log += d));

let code = 1;
try {
  const deadline = Date.now() + 30_000;
  for (;;) {
    try { if ((await fetch(`${API}/healthz`)).ok) break; } catch { /* not up yet */ }
    if (Date.now() > deadline || server.exitCode !== null) throw new Error(`The Node server did not start:\n${log}`);
    await new Promise(r => setTimeout(r, 300));
  }
  console.log(`Brod on Node (${mode === 's3' ? 'S3 files, presigned uploads' : 'local files'}) at ${API}\n`);
  code = await new Promise(resolve => spawn(process.execPath, ['scripts/e2e.mjs', API], { stdio: 'inherit', env: { ...process.env, E2E_SKIP_SERVER_APPS: '1', E2E_DNS: `http://127.0.0.1:${dns.port}` } }).on('exit', resolve));
  if (code !== 0) console.error(`\n--- server log ---\n${log.slice(-5000)}`);
  if (mode === 's3') {
    const staged = [...fake.s3.objects.keys()].filter(k => k.includes('/_uploads/'));
    const files = [...fake.s3.objects.keys()].filter(k => !k.includes('/_uploads/'));
    const ok = staged.length === 0 && files.length > 0 && fake.s3.stats.presignedPuts === 4;
    console.log(`${ok ? 'PASS' : 'FAIL'}  uploads went to S3 by presigned PUT (${fake.s3.stats.presignedPuts} of 4), app files are in S3 (${files.length}), no staged upload is left (${staged.length})`);
    if (!ok) code = 1;
  }
} catch (e) {
  console.error(e.message);
} finally {
  server.kill('SIGTERM');
  fake?.server.close();
  dns.close();
  rmSync(state, { recursive: true, force: true });
}
process.exit(code ?? 1);
