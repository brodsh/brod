// SPDX-License-Identifier: AGPL-3.0-only
// Run the end-to-end suite against the Rust server (server/): build the release binary, start it on a fresh data
// directory with DEV_MODE=1, run scripts/e2e.mjs, stop it.
// Usage: npm run e2e:rust              (app files in a folder; server apps on a workerd sidecar, deploy/runtime/, run by
//                                       its supervisor, deploy/runtime/supervisor/, as in the Docker image)
//        npm run e2e:rust -- s3        (app files in a fake S3 server that checks every SigV4 signature)
//        npm run e2e:rust -- static    (no runtime: server apps must be refused, so E2E_SKIP_SERVER_APPS=1)
//        npm run e2e:rust -- pg        (the database in Postgres: a fresh database is made with psql on the server at
//                                       E2E_DATABASE_URL, default postgres://postgres:pg@127.0.0.1:55432/postgres, and dropped after)
// Modes combine: npm run e2e:rust -- s3 static pg
// Marketplace previews are taken by the headless-browser service in deploy/preview/ (Playwright's Chromium); set
// E2E_SKIP_PREVIEWS=1 to run without it.
import { execFileSync, spawn } from 'node:child_process';
import { mkdirSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { serveFakeS3, ACCESS_KEY, SECRET_KEY } from './fake-s3.mjs';
import { serveFakeDns } from './fake-dns.mjs';
import { serveFakeStripe, SECRET_KEY as STRIPE_KEY, WEBHOOK_SECRET } from './fake-stripe.mjs';

const args = process.argv.slice(2);
const mode = args.includes('s3') ? 's3' : 'fs';
const withRuntime = !args.includes('static');
const pg = args.includes('pg');
const RT_PORT = process.env.E2E_RUNTIME_PORT ?? '8789';
const RT_SECRET = 'e2e-runtime-secret-0123456789';
const PORT = process.env.E2E_PORT ?? '8787';
const API = `http://localhost:${PORT}`;
const state = mkdtempSync(join(tmpdir(), 'brod-e2e-rust-'));

if (process.env.BROD_BIN === undefined) execFileSync('cargo', ['build', '--release', '--manifest-path', 'server/Cargo.toml'], { stdio: 'inherit' });
const bin = process.env.BROD_BIN ?? join('server', 'target', 'release', 'brod');

let fake;
// Billing runs against a stand-in for Stripe that sends its webhooks back to this server.
const stripe = await serveFakeStripe(`${API}/stripe/webhook`);
// Custom domains are proven against a fake DNS-over-HTTPS resolver.
const dns = await serveFakeDns();
const env = {
  ...process.env, APPS_DOMAIN: `localhost:${PORT}`, API_ORIGIN: API, ADMIN_SECRET: 'dev-admin-secret', IDENTITY_SECRET: 'dev-identity-secret',
  SECRETS_KEY: 'dev-secrets-key-0123456789', DEV_MODE: '1', BROD_LISTEN: `127.0.0.1:${PORT}`, BROD_DATA_DIR: state,
  STRIPE_SECRET_KEY: STRIPE_KEY, STRIPE_WEBHOOK_SECRET: WEBHOOK_SECRET, STRIPE_PRICE_SOLO: 'price_solo', STRIPE_PRICE_TEAM: 'price_team',
  STRIPE_API_BASE: `http://127.0.0.1:${stripe.port}`, DNS_RESOLVER_URL: `http://127.0.0.1:${dns.port}/dns-query`,
  // A small free plan, so the storage checks can fill it (honoured only with DEV_MODE=1).
  DEV_FREE_STORAGE_MB: '3',
};
if (mode === 's3') {
  fake = await serveFakeS3();
  Object.assign(env, { S3_ENDPOINT: `http://127.0.0.1:${fake.port}`, S3_BUCKET: 'brod-bundles', S3_ACCESS_KEY_ID: ACCESS_KEY, S3_SECRET_ACCESS_KEY: SECRET_KEY });
}

// The preview service, which screenshots and records marketplace releases in a sandbox on Brod's internal listener.
const PV_PORT = process.env.E2E_PREVIEW_PORT ?? '8791';
const PV_SECRET = 'e2e-preview-secret-0123456789';
const withPreviews = process.env.E2E_SKIP_PREVIEWS !== '1';
if (withPreviews) Object.assign(env, { BROD_PREVIEW_URL: `http://127.0.0.1:${PV_PORT}`, BROD_PREVIEW_SECRET: PV_SECRET });

let pgDb, pgAdmin;
if (pg) {
  pgAdmin = process.env.E2E_DATABASE_URL ?? 'postgres://postgres:pg@127.0.0.1:55432/postgres';
  pgDb = `brod_e2e_${process.pid}`;
  const psql = (sql) => execFileSync('psql', [pgAdmin, '-v', 'ON_ERROR_STOP=1', '-qc', sql], { stdio: 'inherit' });
  psql(`DROP DATABASE IF EXISTS ${pgDb} WITH (FORCE)`);
  psql(`CREATE DATABASE ${pgDb}`);
  const url = new URL(pgAdmin);
  url.pathname = `/${pgDb}`;
  env.BROD_DATABASE_URL = url.toString();
}

let runtime, rtLog = '';
if (withRuntime) {
  Object.assign(env, { BROD_RUNTIME_URL: `http://127.0.0.1:${RT_PORT}`, BROD_RUNTIME_SECRET: RT_SECRET });
  const workerd = join('node_modules', 'workerd', 'bin', 'workerd');
  mkdirSync(join(state, 'runtime'));
  if (process.env.BROD_RUNTIME_BIN === undefined) execFileSync('cargo', ['build', '--release', '--manifest-path', 'deploy/runtime/supervisor/Cargo.toml'], { stdio: 'inherit' });
  const supervisor = process.env.BROD_RUNTIME_BIN ?? join('deploy', 'runtime', 'supervisor', 'target', 'release', 'brod-runtime');
  // The supervisor restarts workerd when an app stalls it or makes it run out of memory (scripts/e2e-server-apps.mjs
  // checks both); a short stall limit and a small memory limit keep those checks quick.
  runtime = spawn(supervisor, [workerd, 'serve', 'deploy/runtime/config.capnp', '--experimental', '-s', `http=127.0.0.1:${RT_PORT}`, '-e', `brod=127.0.0.1:${PORT}`, '-d', `data=${join(state, 'runtime')}`],
    { stdio: ['ignore', 'pipe', 'pipe'], env: { ...process.env, BROD_RUNTIME_SECRET: RT_SECRET, BROD_INTERNAL_URL: `http://127.0.0.1:${PORT}`, RUNTIME_PORT: RT_PORT, RUNTIME_STALL_MS: '2000', RUNTIME_MEMORY_MB: '768' } });
  runtime.stdout.on('data', d => (rtLog += d)); runtime.stderr.on('data', d => (rtLog += d));
}

let preview, pvLog = '';
if (withPreviews) {
  preview = spawn(process.execPath, ['deploy/preview/server.mjs'], { stdio: ['ignore', 'pipe', 'pipe'],
    env: { ...process.env, BROD_PREVIEW_SECRET: PV_SECRET, BROD_INTERNAL_URL: `http://127.0.0.1:${PORT}`, PREVIEW_LISTEN: `127.0.0.1:${PV_PORT}` } });
  preview.stdout.on('data', d => (pvLog += d)); preview.stderr.on('data', d => (pvLog += d));
}

// Run from the temp folder so a developer's own .env is not picked up.
const server = spawn(join(process.cwd(), bin), [], { stdio: ['ignore', 'pipe', 'pipe'], env, cwd: state });
let log = '';
server.stdout.on('data', d => (log += d)); server.stderr.on('data', d => (log += d));

let code = 1;
try {
  const deadline = Date.now() + 30_000;
  for (;;) {
    try { if ((await fetch(`${API}/healthz`)).ok) break; } catch { /* not up yet */ }
    if (Date.now() > deadline || server.exitCode !== null) throw new Error(`The Rust server did not start:\n${log}`);
    await new Promise(r => setTimeout(r, 100));
  }
  if (runtime) {
    const rtDeadline = Date.now() + 30_000;
    for (;;) {
      try { if ((await fetch(`http://127.0.0.1:${RT_PORT}/_runtime/health`, { headers: { 'x-brod-runtime-secret': RT_SECRET } })).ok) break; } catch { /* not up yet */ }
      if (Date.now() > rtDeadline || runtime.exitCode !== null) throw new Error(`The workerd runtime did not start:\n${rtLog}`);
      await new Promise(r => setTimeout(r, 100));
    }
  }
  if (preview) {
    const pvDeadline = Date.now() + 30_000;
    for (;;) {
      try { if ((await fetch(`http://127.0.0.1:${PV_PORT}/health`)).ok) break; } catch { /* not up yet */ }
      if (Date.now() > pvDeadline || preview.exitCode !== null) throw new Error(`The preview service did not start:\n${pvLog}`);
      await new Promise(r => setTimeout(r, 100));
    }
  }
  console.log(`Brod (Rust, ${pg ? 'Postgres' : 'SQLite'}, ${mode === 's3' ? 'files in S3' : 'files in a folder'}, ${runtime ? 'server apps on workerd' : 'static apps only'}${preview ? ', previews' : ''}) at ${API}\n`);
  const skip = runtime ? '' : '1';
  const node = (script, ...more) => new Promise(resolve => spawn(process.execPath, [script, API, ...more], { stdio: 'inherit', env: { ...process.env, E2E_SKIP_SERVER_APPS: skip, E2E_PREVIEWS: withPreviews ? '1' : '', E2E_DNS: `http://127.0.0.1:${dns.port}` } }).on('exit', resolve));
  code = await node('scripts/e2e.mjs');
  if (code === 0) { console.log('\nBilling, visits, analytics, storage and spaces\n'); code = await node('scripts/e2e-billing.mjs', `http://127.0.0.1:${stripe.port}`); }
  if (code === 0) { console.log('\nMarketplace\n'); code = await node('scripts/e2e-market.mjs'); }
  if (code === 0) { console.log('\nAgent connections: scopes, expiry and refresh\n'); code = await node('scripts/e2e-tokens.mjs'); }
  // The cases of test/server.test.ts, which only the Workers runtime runs otherwise.
  if (runtime && code === 0) { console.log('\nServer apps on the workerd runtime\n'); code = await node('scripts/e2e-server-apps.mjs'); }
  if (code !== 0) console.error(`\n--- server log ---\n${log.slice(-5000)}${runtime ? `\n--- runtime log ---\n${rtLog.slice(-5000)}` : ''}${preview ? `\n--- preview log ---\n${pvLog.slice(-3000)}` : ''}`);
  if (mode === 's3') {
    const files = [...fake.s3.objects.keys()];
    const ok = files.length > 0 && files.every(k => /^brod-bundles\/(app|lst)_/.test(k));
    console.log(`${ok ? 'PASS' : 'FAIL'}  app files are in S3 (${files.length} objects)`);
    if (!ok) code = 1;
  }
} catch (e) {
  console.error(e.message);
} finally {
  server.kill('SIGTERM');
  runtime?.kill('SIGTERM');
  preview?.kill('SIGTERM');
  fake?.server.close();
  stripe.server.close();
  dns.close();
  rmSync(state, { recursive: true, force: true });
  if (pgDb) {
    await new Promise(r => server.exitCode !== null ? r() : server.on('exit', r));
    try { execFileSync('psql', [pgAdmin, '-qc', `DROP DATABASE IF EXISTS ${pgDb} WITH (FORCE)`], { stdio: 'inherit' }); } catch { /* best effort */ }
  }
}
process.exit(code ?? 1);
