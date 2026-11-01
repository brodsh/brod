// SPDX-License-Identifier: AGPL-3.0-only
// End-to-end check of managed Postgres for container apps (server/src/databases.rs, backups.rs, node/src/db.rs) with
// real Docker: Brod, a brod-node on this machine, a registry:2 and a postgres:17 as apps-postgres (published on
// 127.0.0.1 only because Brod runs on this machine here; in Compose it has no network at all). The app is
// examples/container-pg-app. Checks: request_database, the app reaching its database at brod-db.internal through the
// node and the tunnel, the role's limits, one app never reaching another's database (through the proxy or in Postgres
// itself), the migrate step (passing and failing), DATABASE_URL being Brod's, backup, restore behind a person's
// confirmation, the restore drill, and deleting the app (final backup kept, database and role dropped).
// pg_dump and pg_restore run inside the Postgres container (wrappers in BROD_PG_BIN_DIR), so their version matches it.
// Usage: npm run e2e:postgres   (builds both release binaries unless BROD_BIN and BROD_NODE_BIN are set)
// Needs Docker with buildx and network access for npm in the image build. Everything it creates is named brod-e2e*
// and removed at the end.
import { execFileSync, spawn } from 'node:child_process';
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import http from 'node:http';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

const PORT = process.env.E2E_PORT ?? '8840';
const REGISTRY_PORT = process.env.E2E_REGISTRY_PORT ?? String(Number(PORT) + 8);
const PG_PORT = process.env.E2E_PG_PORT ?? String(Number(PORT) + 9);
const API = `http://localhost:${PORT}`;
const ADMIN = 'dev-admin-secret';
const PREFIX = 'brod-e2e';
const BUILDER = `${PREFIX}-builder`;
const REGISTRY = `${PREFIX}-registry`;
const PG = `${PREFIX}-apps-postgres`;
const PG_PASSWORD = 'e2e-apps-admin-' + Math.random().toString(36).slice(2);
const REGISTRY_IMAGE = 'registry:2@sha256:a3d8aaa63ed8681a604f1dea0aa03f100d5895b6a58ace528858a7b332415373';
const PG_IMAGE = 'postgres:17@sha256:2d2b8998d31037bf721cfdf764d76ba74171b4fab3431b7f72c27c56ddbdf9e3';
const FIXTURE = resolve('examples', 'container-pg-app');
const state = mkdtempSync(join(tmpdir(), 'brod-e2e-postgres-'));
if (process.env.BROD_BIN === undefined) execFileSync('cargo', ['build', '--release', '--manifest-path', 'server/Cargo.toml'], { stdio: 'inherit' });
if (process.env.BROD_NODE_BIN === undefined) execFileSync('cargo', ['build', '--release', '--manifest-path', 'node/Cargo.toml'], { stdio: 'inherit' });
const bin = resolve(process.env.BROD_BIN ?? join('server', 'target', 'release', 'brod'));
const nodeBin = resolve(process.env.BROD_NODE_BIN ?? join('node', 'target', 'release', 'brod-node'));
const tokenFile = join(state, 'node-join', 'token');
const certFile = join(state, 'registry', 'token.crt');
const pgBin = join(state, 'pgbin');

let passed = 0, failed = 0, skipped = 0;
const check = (name, ok, detail = '') => { ok ? passed++ : failed++; console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${ok || !detail ? '' : `\n      ${detail}`}`); };
const skip = (name, why) => { skipped++; console.log(`SKIP  ${name}\n      ${why}`); };
const sleep = ms => new Promise(r => setTimeout(r, ms));
async function until(fn, ms, every = 500) {
  const deadline = Date.now() + ms;
  for (;;) {
    const v = await fn().catch(() => undefined);
    if (v) return v;
    if (Date.now() > deadline) return undefined;
    await sleep(every);
  }
}
const docker = (...args) => execFileSync('docker', args, { stdio: ['ignore', 'pipe', 'pipe'] }).toString().trim();
const dockerQuiet = (...args) => { try { return docker(...args); } catch { return ''; } };

// ---------- HTTP with cookies, for apps on <slug>.<workspace>.localhost ----------

const api = new URL(API);
function send(url, { method = 'GET', headers = {}, body } = {}) {
  const u = new URL(url);
  return new Promise((resolve, reject) => {
    const req = http.request({ host: api.hostname, port: api.port, path: u.pathname + u.search, method, headers: { host: u.host, ...headers } }, res => {
      const chunks = []; res.on('data', c => chunks.push(c)); res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks).toString() }));
    });
    req.on('error', reject); if (body) req.write(body); req.end();
  });
}
class Browser {
  constructor(email) { this.email = email; this.jars = {}; }
  async go(url, o = {}) {
    const u = new URL(url, API), headers = { ...(o.headers ?? {}) };
    const c = Object.entries(this.jars[u.host] ?? {}).map(([k, v]) => `${k}=${v}`).join('; ');
    if (c) headers.cookie = [headers.cookie, c].filter(Boolean).join('; ');
    let body = o.body;
    if (o.form) { body = new URLSearchParams(o.form).toString(); headers['content-type'] = 'application/x-www-form-urlencoded'; headers.origin ??= API; }
    if (o.json) { body = JSON.stringify(o.json); headers['content-type'] = 'application/json'; headers.origin ??= API; }
    const r = await send(u.href, { method: o.method ?? (body ? 'POST' : 'GET'), headers, body });
    for (const sc of [].concat(r.headers['set-cookie'] ?? [])) {
      const [k, v] = sc.split(';')[0].split('='); (this.jars[u.host] ??= {});
      if (/max-age=0/i.test(sc)) delete this.jars[u.host][k]; else this.jars[u.host][k] = v;
    }
    return { ...r, url: u.href };
  }
  async open(url) {
    let r = await this.go(url), hops = 0;
    while (r.status >= 300 && r.status < 400 && hops++ < 10) r = await this.go(new URL(r.headers.location, r.url).href);
    return r;
  }
  async api(path, o = {}) {
    const r = await this.go(path, { ...o, headers: { ...(o.headers ?? {}), origin: API } });
    let body = null; try { body = r.body ? JSON.parse(r.body) : null; } catch { body = r.body; }
    return { status: r.status, body };
  }
}
const parse = r => { try { return JSON.parse(r.body); } catch { return {}; } };

// pg_dump and pg_restore for Brod: run inside apps-postgres, connecting over its socket; only the user and password
// pass through (Brod's PGHOST and PGPORT are this machine's view of it).
mkdirSync(pgBin, { recursive: true });
for (const tool of ['pg_dump', 'pg_restore']) {
  const f = join(pgBin, tool);
  writeFileSync(f, `#!/bin/sh\nexec docker exec -i -e PGUSER -e PGPASSWORD ${PG} ${tool} "$@"\n`);
  chmodSync(f, 0o755);
}

const server = spawn(bin, [], {
  cwd: state, stdio: ['ignore', 'pipe', 'pipe'],
  env: { PATH: process.env.PATH, HOME: process.env.HOME, DOCKER_HOST: process.env.DOCKER_HOST ?? '', APPS_DOMAIN: `localhost:${PORT}`, API_ORIGIN: API,
    ADMIN_SECRET: ADMIN, IDENTITY_SECRET: 'dev-identity-secret', SECRETS_KEY: 'dev-secrets-key-0123456789', DEV_MODE: '1',
    BROD_LISTEN: `127.0.0.1:${PORT}`, BROD_DATA_DIR: join(state, 'data'), BROD_NODE_JOIN_TOKEN_FILE: tokenFile, BROD_CONTAINERS: 'on',
    BROD_REGISTRY_URL: `http://127.0.0.1:${REGISTRY_PORT}`, BROD_REGISTRY_CERT_FILE: certFile, BROD_CONTAINER_PREFIX: PREFIX,
    BROD_APPS_DATABASE_URL: `postgres://brod_admin@127.0.0.1:${PG_PORT}/postgres`, APPS_DATABASE_PASSWORD: PG_PASSWORD, BROD_PG_BIN_DIR: pgBin },
});
let log = '';
server.stdout.on('data', d => (log += d)); server.stderr.on('data', d => (log += d));

function startNode() {
  const p = spawn(nodeBin, ['run'], { stdio: ['ignore', 'pipe', 'pipe'],
    env: { PATH: process.env.PATH, HOME: process.env.HOME, DOCKER_HOST: process.env.DOCKER_HOST ?? '', BROD_NODE_DIR: join(state, 'node'), BROD_URL: API,
      BROD_NODE_JOIN_TOKEN_FILE: tokenFile, BROD_NODE_NAME: 'e2e-docker', BROD_NODE_BUILDER: BUILDER,
      ...(process.env.BROD_NODE_DOCKER_SOCKET ? { BROD_NODE_DOCKER_SOCKET: process.env.BROD_NODE_DOCKER_SOCKET } : {}) } });
  p.log = '';
  p.stdout.on('data', d => (p.log += d)); p.stderr.on('data', d => (p.log += d));
  return p;
}
const stopNode = p => new Promise(r => { if (!p || p.exitCode !== null) return r(); p.once('exit', r); p.kill('SIGTERM'); });

function cleanup() {
  const containers = dockerQuiet('ps', '-aq', '--filter', `name=^${PREFIX}`).split('\n').filter(Boolean);
  if (containers.length) dockerQuiet('rm', '-f', '-v', ...containers);
  const networks = dockerQuiet('network', 'ls', '-q', '--filter', `name=^${PREFIX}`).split('\n').filter(Boolean);
  if (networks.length) dockerQuiet('network', 'rm', ...networks);
  const images = dockerQuiet('images', '--format', '{{.Repository}}:{{.Tag}}').split('\n').filter(i => i.startsWith(`${PREFIX}-`));
  if (images.length) dockerQuiet('rmi', '-f', ...images);
  dockerQuiet('buildx', 'rm', '-f', BUILDER);
  dockerQuiet('volume', 'rm', `${REGISTRY}-data`);
}

/** One SQL statement as the admin, inside apps-postgres: its output, trimmed. */
const psql = (sql, db = 'postgres') => dockerQuiet('exec', PG, 'psql', '-U', 'brod_admin', '-d', db, '-tAc', sql);
/** psql over TCP inside apps-postgres with a URL (so the password is checked): {ok, out}. */
function psqlAs(url, sql) {
  try { return { ok: true, out: execFileSync('docker', ['exec', PG, 'psql', url, '-tAc', sql], { stdio: ['ignore', 'pipe', 'pipe'] }).toString().trim() }; }
  catch (e) { return { ok: false, out: (e.stderr?.toString() ?? '') + (e.stdout?.toString() ?? '') }; }
}
const cname = id => `${PREFIX}-${id.replaceAll('_', '-')}`;
function fixture(changes = {}) {
  const files = readdirSync(FIXTURE).filter(p => p !== 'node_modules').map(path => ({ path, content: readFileSync(join(FIXTURE, path), 'utf8') }));
  for (const [path, content] of Object.entries(changes)) {
    const f = files.find(x => x.path === path);
    if (f) f.content = content; else files.push({ path, content });
  }
  return files;
}
const backupFiles = dbId => { const dir = join(state, 'data', 'files', 'objects', 'backups', dbId); return existsSync(dir) ? readdirSync(dir) : []; };

let node, code = 1;
try {
  cleanup();
  docker('run', '-d', '--name', PG, '-p', `127.0.0.1:${PG_PORT}:5432`, '-e', 'POSTGRES_USER=brod_admin', '-e', `POSTGRES_PASSWORD=${PG_PASSWORD}`,
    '-e', 'POSTGRES_INITDB_ARGS=--auth-host=scram-sha-256', PG_IMAGE);
  const pgUp = await until(async () => psql('SELECT 1') === '1' && dockerQuiet('exec', PG, 'pg_isready', '-h', '127.0.0.1').includes('accepting'), 60_000, 500);
  check('apps-postgres (postgres:17) is up', !!pgUp);
  const deadline = Date.now() + 30_000;
  for (;;) {
    try { if ((await fetch(`${API}/healthz`)).ok) break; } catch { /* not up yet */ }
    if (Date.now() > deadline || server.exitCode !== null) throw new Error(`Brod did not start:\n${log}`);
    await sleep(100);
  }
  docker('run', '-d', '--name', REGISTRY, '-p', `127.0.0.1:${REGISTRY_PORT}:5000`, '-v', `${REGISTRY}-data:/var/lib/registry`,
    '-v', `${certFile}:/certs/registry-token.crt:ro`,
    '-e', 'REGISTRY_AUTH=token', '-e', `REGISTRY_AUTH_TOKEN_REALM=${API}/v1/registry/token`, '-e', 'REGISTRY_AUTH_TOKEN_SERVICE=brod-registry',
    '-e', 'REGISTRY_AUTH_TOKEN_ISSUER=brod', '-e', 'REGISTRY_AUTH_TOKEN_ROOTCERTBUNDLE=/certs/registry-token.crt',
    '-e', 'REGISTRY_STORAGE_DELETE_ENABLED=true', REGISTRY_IMAGE);
  await until(async () => (await fetch(`http://127.0.0.1:${REGISTRY_PORT}/v2/`)).status === 401, 30_000);
  const compose = readFileSync('docker-compose.yml', 'utf8');
  const pgService = compose.match(/\n  apps-postgres:\n[\s\S]*?(?=\n\n|\n\S)/)?.[0] ?? '';
  check('docker-compose.yml: apps-postgres is pinned by digest, publishes no port and has no network',
    /image: postgres:17[\w.-]*@sha256:[0-9a-f]{64}/.test(pgService) && !/\n\s+ports:/.test(pgService) && /network_mode: none/.test(pgService), pgService.slice(0, 400));

  node = startNode();
  const joined = await until(async () => {
    const r = await (await fetch(`${API}/v1/admin/nodes`, { headers: { authorization: `Bearer ${ADMIN}` } })).json();
    const n = r.nodes?.[0];
    return n?.status === 'online' && n.connected && n.capabilities?.engine === 'docker' && n;
  }, 30_000);
  check('the node joins', !!joined, node.log.slice(-800));
  if (!joined) throw new Error('no node');

  const alice = new Browser(`alice-${Date.now()}@acme.test`);
  const started = await alice.go('/auth/start', { json: { email: alice.email } });
  await alice.go('/auth/verify', { form: { token: new URL(JSON.parse(started.body).dev_link).searchParams.get('token') } });
  const W = (await alice.api('/v1/workspaces', { json: { name: `Postgres ${Date.now()}`, accept_terms: true } })).body.workspace;
  await send(`${API}/v1/admin/workspaces/${W}/trust`, { method: 'POST', headers: { authorization: `Bearer ${ADMIN}`, 'content-type': 'application/json' }, body: '{}' });
  const agentToken = (await alice.api('/v1/tokens', { json: { name: 'pg-agent' } })).body.token;
  const mcp = async (name, args) => {
    const r = await send(`${API}/mcp`, { method: 'POST', headers: { authorization: `Bearer ${agentToken}`, 'content-type': 'application/json', accept: 'application/json, text/event-stream' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name, arguments: args } }) });
    const msg = JSON.parse(r.body.startsWith('{') ? r.body : r.body.split('\n').find(l => l.startsWith('data:')).slice(5));
    const text = msg.result?.content?.[0]?.text ?? '{}';
    return { error: msg.result?.isError ? JSON.parse(text) : null, value: msg.result?.isError ? null : JSON.parse(text), raw: msg };
  };
  const deployment = (slug, id) => alice.api(`/v1/apps/${slug}/deployments/${id}`);
  async function settle(slug, id, ms = 600_000) {
    let last;
    await until(async () => {
      last = await deployment(slug, id);
      const s = last.body?.state ?? last.body?.error?.deployment?.state;
      return last.status === 422 || ['serving', 'stopped', 'failed'].includes(s);
    }, ms, 1000);
    return last;
  }
  const admin = (path) => send(`${API}${path}`, { method: 'POST', headers: { authorization: `Bearer ${ADMIN}`, 'content-type': 'application/json' }, body: '{}' }).then(parse);

  /** A new app from the fixture, first deployed without a migration (it has no database yet). */
  async function newApp(name) {
    const first = await mcp('deploy_app', { name, migrate: '' });
    const tarball = execFileSync('tar', ['-czf', '-', '--exclude', 'node_modules', '-C', FIXTURE, '.'], { env: { ...process.env, COPYFILE_DISABLE: '1' }, maxBuffer: 64 << 20 });
    const v = await (await fetch(first.value.upload_url, { method: 'PUT', body: tarball })).json();
    const d = await settle(v.app, v.deployment.id);
    await alice.open(v.url + '/healthz'); // signs alice in to the app's address
    return { slug: v.app, url: v.url, serving: d.body?.state === 'serving', d };
  }
  /** Deploy the fixture again (production), with a migrate command; the settled deployment. */
  async function redeploy(slug, migrate) {
    const r = await alice.api('/v1/deploys', { json: { app: slug, files: fixture(), environment: 'production', ...(migrate === undefined ? {} : { migrate }) } });
    if (r.status !== 201) return { body: r.body, status: r.status };
    return settle(slug, r.body.deployment.id);
  }

  // ---------- request_database, migrate, the app reaching its database ----------

  const A = await newApp('Notes A');
  check('app A builds and serves without a database', A.serving, JSON.stringify(A.d.body).slice(0, 2000));
  const reqA = await mcp('request_database', { app: A.slug });
  const dbA = reqA.value?.database;
  check('request_database (an agent, no confirmation) creates the app\'s database', reqA.value?.created === true && /^app_[0-9a-f]+$/.test(dbA?.name ?? '')
    && dbA?.host === 'brod-db.internal', JSON.stringify(reqA.raw).slice(0, 600));
  const again = await mcp('request_database', { app: A.slug });
  check('and calling it again changes nothing (idempotent)', again.value?.created === false && again.value?.database?.name === dbA?.name, JSON.stringify(again.raw).slice(0, 400));
  const roleA = psql(`SELECT rolsuper, rolcreatedb, rolcreaterole, rolinherit, rolreplication, rolconnlimit FROM pg_roles WHERE rolname = '${dbA?.name}'`);
  check('its role is a plain login: no superuser, createdb, createrole, inherit or replication; 20 connections', roleA === 'f|f|f|f|f|20', roleA);
  check('its database is owned by that role, and PUBLIC cannot connect', psql(`SELECT pg_get_userbyid(datdba) FROM pg_database WHERE datname = '${dbA?.name}'`) === dbA?.name
    && psql(`SELECT has_database_privilege('public', '${dbA?.name}', 'CONNECT')`) === 'f');

  const dA = await redeploy(A.slug);
  const logA = dA.body?.log ?? dA.body?.error?.log ?? [];
  check('a deploy with brod.json\'s migrate runs it before switching, and serves', dA.body?.state === 'serving'
    && logA.some(l => /migrating: node migrate\.js/.test(l)) && logA.some(l => /migrate: migrated: notes and migrations are there/.test(l))
    && logA.findIndex(l => /migrated \(exit code 0\)/.test(l)) < logA.findIndex(l => /created the container/.test(l)), logA.join('\n').slice(-3000));
  const wrote = await alice.go(A.url + '/notes?text=first', { method: 'POST' });
  const notes = parse(await alice.go(A.url + '/notes'));
  check('the app writes and reads its database at brod-db.internal, through the node and the tunnel', wrote.status === 201 && JSON.stringify(notes.notes) === '["first"]',
    `${wrote.status} ${wrote.body} ${JSON.stringify(notes)}`);
  const envUrl = dockerQuiet('exec', cname(dA.body.id), 'printenv', 'DATABASE_URL');
  check('DATABASE_URL names brod-db.internal and the app\'s role and database', new URL(envUrl || 'x:').hostname === 'brod-db.internal'
    && new URL(envUrl || 'x:').username === dbA?.name && new URL(envUrl || 'x:').pathname === `/${dbA?.name}`, envUrl.replace(/:[^:@/]+@/, ':***@'));
  const pwA = envUrl ? decodeURIComponent(new URL(envUrl).password) : '';
  const st1 = await mcp('get_status', { app: A.slug });
  check('get_status shows the database (name, size) and never its password', st1.value?.database?.name === dbA?.name && 'size_bytes' in (st1.value?.database ?? {})
    && pwA.length > 10 && !JSON.stringify(st1.raw).includes(pwA), JSON.stringify(st1.value?.database).slice(0, 500));
  const setUrl = await mcp('set_secret', { app: A.slug, name: 'DATABASE_URL', value: 'postgres://evil@example.com/x' });
  const rmUrl = await mcp('set_secret', { app: A.slug, name: 'DATABASE_URL', remove: true });
  check('set_secret refuses DATABASE_URL while the database is managed', setUrl.error?.error === 'database_managed' && rmUrl.error?.error === 'database_managed',
    JSON.stringify([setUrl.raw, rmUrl.raw]).slice(0, 600));

  // ---------- what the app's role may not do ----------

  const sql = async q => parse(await alice.go(A.url + '/sql?q=' + encodeURIComponent(q)));
  const createRole = await sql('CREATE ROLE evil LOGIN');
  const createDb = await sql('CREATE DATABASE evil');
  check('the app\'s role cannot CREATE ROLE or CREATE DATABASE', createRole.code === '42501' && createDb.code === '42501', JSON.stringify([createRole, createDb]));
  const toPostgres = parse(await alice.go(A.url + '/connect?database=postgres'));
  check('nor reach any other database through brod-db.internal (postgres)', toPostgres.ok === false && /This app's database is/.test(toPostgres.message ?? ''), JSON.stringify(toPostgres));

  // ---------- a second app ----------

  const B = await newApp('Notes B');
  const reqB = await mcp('request_database', { app: B.slug });
  const dbB = reqB.value?.database;
  const dB = await redeploy(B.slug);
  await alice.go(B.url + '/notes?text=b-secret', { method: 'POST' });
  check('app B gets a database of its own', dB.body?.state === 'serving' && dbB?.name && dbB.name !== dbA?.name
    && JSON.stringify(parse(await alice.go(B.url + '/notes')).notes) === '["b-secret"]', JSON.stringify(dB.body).slice(0, 1500));
  const urlB = dockerQuiet('exec', cname(dB.body.id), 'printenv', 'DATABASE_URL');
  const pwB = urlB ? decodeURIComponent(new URL(urlB).password) : '';
  const aToB = parse(await alice.go(A.url + '/connect?database=' + dbB.name));
  check('A, with its own credentials, cannot connect to B\'s database through brod-db.internal', aToB.ok === false && /This app's database is/.test(aToB.message ?? ''), JSON.stringify(aToB));
  const aAsB = parse(await alice.go(A.url + `/connect?database=${dbB.name}&user=${dbB.name}&password=${encodeURIComponent(pwB)}`));
  check('A\'s listener never forwards to B\'s database, even with B\'s own password', aAsB.ok === false && /This app's database is/.test(aAsB.message ?? '')
    && pwB.length > 10, JSON.stringify(aAsB));
  const direct = psqlAs(`postgresql://${dbA.name}:${encodeURIComponent(pwA)}@127.0.0.1:5432/${dbB.name}`, 'SELECT 1');
  const directOwn = psqlAs(`postgresql://${dbA.name}:${encodeURIComponent(pwA)}@127.0.0.1:5432/${dbA.name}`, 'SELECT count(*) FROM notes');
  check('in Postgres itself, A\'s role is refused CONNECT on B\'s database (and reaches its own)', !direct.ok && /permission denied for database/.test(direct.out)
    && directOwn.ok && directOwn.out === '1', JSON.stringify([direct, directOwn]));
  const listeners = parse(await alice.go(B.url + '/connect?database=' + dbA.name + `&user=${dbA.name}&password=${encodeURIComponent(pwA)}`));
  check('and B\'s listener never forwards to A\'s', listeners.ok === false, JSON.stringify(listeners));

  // ---------- a failing migration ----------

  const bad = await redeploy(A.slug, 'echo boom-migration; exit 7');
  check('a failing migrate fails the deployment as migration_failed with its output', bad.status === 422 && bad.body?.error?.code === 'migration_failed'
    && bad.body.error.log?.some(l => /boom-migration/.test(l)) && /exited with code 7/.test(bad.body.error.message ?? ''), JSON.stringify(bad.body).slice(0, 2000));
  check('and the old version keeps serving its data', JSON.stringify(parse(await alice.go(A.url + '/notes')).notes) === '["first"]');

  // ---------- backup, restore with a person, the drill ----------

  await alice.go(A.url + '/notes?text=before-backup', { method: 'POST' });
  const bk = await mcp('backup_database', { app: A.slug });
  check('backup_database (an agent, no confirmation) backs up now', bk.value?.backup?.state === 'done' && bk.value.backup.bytes > 0, JSON.stringify(bk.raw).slice(0, 600));
  check('and warns that folder storage keeps backups on the same machine', /same machine/.test(bk.value?.warning ?? ''), bk.value?.warning);
  await alice.go(A.url + '/notes?text=after-backup', { method: 'POST' });
  const asked = await mcp('restore_database', { app: A.slug });
  check('restore_database from an agent returns a confirm_url and changes nothing', asked.value?.needs_confirmation === true && /\/confirm\/cf_/.test(asked.value?.confirm_url ?? '')
    && JSON.stringify(parse(await alice.go(A.url + '/notes')).notes) === '["first","before-backup","after-backup"]', JSON.stringify(asked.raw).slice(0, 600));
  const confirmed = await alice.go(new URL(asked.value.confirm_url).pathname, { form: { decision: 'confirm' } });
  const restored = await until(async () => {
    const n = parse(await alice.go(A.url + '/notes'));
    return JSON.stringify(n.notes) === '["first","before-backup"]' && n;
  }, 60_000, 1000);
  check('once a person confirms, the data is the backup\'s (the row written after it is gone)', confirmed.status === 200 && !!restored,
    `${confirmed.status} ${confirmed.body.slice(0, 300)} ${JSON.stringify(parse(await alice.go(A.url + '/notes')))}`);
  const before = psql(`SELECT datname FROM pg_database WHERE datname LIKE '${dbA.name}\\_before\\_%'`);
  check('the replaced database is kept (as <name>_before_<ms>) for 24 hours', before.startsWith(`${dbA.name}_before_`), before);
  check('the app can still write after the restore', (await alice.go(A.url + '/notes?text=after-restore', { method: 'POST' })).status === 201);

  const drill = await admin('/v1/admin/backups/drill');
  const mine = (drill.drills ?? []).find(x => x.database === dbA.name);
  const st2 = await mcp('get_status', { app: A.slug });
  check('the restore drill restores the latest backup into a scratch database and the counts match', mine?.result?.ok === true
    && !!st2.value?.database?.backups?.[0]?.restore_tested && !!st2.value?.database?.last_restore_drill, JSON.stringify([drill, st2.value?.database]).slice(0, 1200));
  check('and drops its scratch database', psql(`SELECT count(*) FROM pg_database WHERE datname LIKE '%\\_drill\\_%'`) === '0');
  const run = await admin('/v1/admin/backups/run');
  check('POST /v1/admin/backups/run backs up every managed database', (run.backups ?? []).length === 2 && run.backups.every(b => b.result?.state === 'done'), JSON.stringify(run).slice(0, 800));

  // ---------- deleting the app ----------

  const dbIdA = st1.value?.database?.id ?? 'none';
  const kept = backupFiles(dbIdA).length;
  const del = await alice.api(`/v1/apps/${A.slug}`, { method: 'DELETE' });
  check('deleting app A drops its database and role', del.status === 200 && psql(`SELECT count(*) FROM pg_database WHERE datname LIKE '${dbA.name}%'`) === '0'
    && psql(`SELECT count(*) FROM pg_roles WHERE rolname = '${dbA.name}'`) === '0', JSON.stringify(del.body));
  check('and keeps a final backup', backupFiles(dbIdA).length === kept + 1, JSON.stringify([kept, backupFiles(dbIdA)]));
  check('app B and its data are untouched', JSON.stringify(parse(await alice.go(B.url + '/notes')).notes) === '["b-secret"]');

  code = failed === 0 ? 0 : 1;
} catch (e) {
  console.error(e.stack ?? e.message);
} finally {
  await stopNode(node);
  server.kill('SIGTERM');
  console.log(`\n${passed} passed, ${failed} failed, ${skipped} skipped`);
  if (code !== 0) console.error(`\n--- server log ---\n${log.slice(-6000)}\n--- node log ---\n${node?.log.slice(-4000) ?? ''}`);
  cleanup();
  rmSync(state, { recursive: true, force: true });
}
process.exit(code);
