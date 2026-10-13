// Compare the Rust server with the Node build of the TypeScript server (scripts/serve-node.mjs) under load.
// Both get a fresh database, the same public app and an agent token; then `oha` (https://github.com/hatoo/oha,
// `cargo install oha`) measures a static file, an HTML page (with the report link added), and an API call.
// Usage: npm run build:vercel && cargo build --release --manifest-path server/Cargo.toml && node scripts/bench.mjs [seconds] [connections]
import { execFileSync, spawn } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { migrate } from './migrate-libsql.mjs';

const SECONDS = process.argv[2] ?? '10', CONNECTIONS = process.argv[3] ?? '50';
const state = mkdtempSync(join(tmpdir(), 'brod-bench-'));
const common = { ADMIN_SECRET: 'bench-admin', IDENTITY_SECRET: 'bench-identity', SECRETS_KEY: 'bench-secrets-key-0123456789', DEV_MODE: '1' };

async function start(name, port) {
  const API = `http://localhost:${port}`;
  const env = { ...process.env, ...common, APPS_DOMAIN: `localhost:${port}`, API_ORIGIN: API };
  let child;
  if (name === 'rust') {
    child = spawn(join(process.cwd(), 'server/target/release/brod'), [], { env: { ...env, BROD_LISTEN: `127.0.0.1:${port}`, BROD_DATA_DIR: join(state, name) }, cwd: state, stdio: 'ignore' });
  } else {
    const db = `file:${join(state, 'node.db')}`;
    await migrate(db, undefined, () => {});
    child = spawn(process.execPath, ['scripts/serve-node.mjs', String(port)], { env: { ...env, VERCEL: '', TURSO_DATABASE_URL: db, FILES_DIR: join(state, 'node-files') }, stdio: 'ignore' });
  }
  for (let i = 0; i < 100; i++) {
    try { if ((await fetch(`${API}/healthz`)).ok) break; } catch { /* starting */ }
    await new Promise(r => setTimeout(r, 100));
  }
  // A person, a workspace, an agent token and one public app with an HTML page and a 40 KB script.
  const email = `bench@${name}.test`;
  const start = await (await fetch(`${API}/auth/start`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ email }) })).json();
  const verify = await fetch(`${API}/auth/verify`, { method: 'POST', redirect: 'manual', headers: { origin: API, 'content-type': 'application/x-www-form-urlencoded' }, body: `token=${new URL(start.dev_link).searchParams.get('token')}` });
  const cookie = verify.headers.get('set-cookie').split(';')[0];
  const post = (path, body) => fetch(`${API}${path}`, { method: 'POST', headers: { cookie, origin: API, 'content-type': 'application/json' }, body: JSON.stringify(body) }).then(r => r.json());
  await post('/v1/workspaces', { name: 'Bench', accept_terms: true });
  const { token } = await post('/v1/tokens', { name: 'bench' });
  const html = `<!doctype html><html><head><title>Bench</title></head><body>${'<p>Hello from a small app.</p>'.repeat(60)}</body></html>`;
  const app = await (await fetch(`${API}/v1/deploys`, { method: 'POST', headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' }, body: JSON.stringify({ name: 'Bench app', files: [{ path: 'index.html', content: html }, { path: 'assets/app.js', content: 'console.log(1);\n'.repeat(2500) }] }) })).json();
  await post(`/v1/apps/${app.app}/access`, { access: 'public' });
  return { child, port, token, host: `${app.app}.localhost:${port}` };
}

function oha(url, headers) {
  const args = ['-z', `${SECONDS}s`, '-c', CONNECTIONS, '--no-tui', '--output-format', 'json', ...headers.flatMap(h => ['-H', h]), url];
  const r = JSON.parse(execFileSync('oha', args, { maxBuffer: 1 << 26 }).toString());
  const ok = Object.entries(r.statusCodeDistribution ?? {}).filter(([s]) => s === '200').reduce((n, [, c]) => n + c, 0);
  return { rps: Math.round(r.summary.requestsPerSec), p50: (r.latencyPercentiles.p50 * 1000).toFixed(2), p99: (r.latencyPercentiles.p99 * 1000).toFixed(2), ok: `${((ok / Object.values(r.statusCodeDistribution).reduce((a, b) => a + b, 0)) * 100).toFixed(1)}%` };
}

const servers = [await start('node', 8790), await start('rust', 8791)];
const rows = [];
try {
  for (const [label, path, auth] of [['static file (40 KB JS)', '/assets/app.js', false], ['HTML page + report link', '/', false], ['API: GET /v1/apps', '/v1/apps', true]]) {
    for (const [i, s] of servers.entries()) {
      const headers = auth ? [`authorization: Bearer ${s.token}`] : [`host: ${s.host}`];
      rows.push({ test: label, server: i ? 'Rust' : 'Node (TS)', ...oha(`http://127.0.0.1:${s.port}${path}`, headers) });
    }
  }
} finally {
  for (const s of servers) s.child.kill('SIGTERM');
  rmSync(state, { recursive: true, force: true });
}
console.log(`${SECONDS}s per test, ${CONNECTIONS} connections\n`);
console.log('| Test | Server | Requests/s | p50 ms | p99 ms | 200 OK |\n| --- | --- | --- | --- | --- | --- |');
for (const r of rows) console.log(`| ${r.test} | ${r.server} | ${r.rps} | ${r.p50} | ${r.p99} | ${r.ok} |`);
