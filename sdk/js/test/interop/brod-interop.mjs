// Interop with a real Brod: start the server and its workerd runtime, sign in, deploy a server app that runs
// @brodsh/auth itself (bundled with esbuild) and echoes x-brod-identity, then verify the real tokens with the built SDK
// from Node, against the inline key set from env and against the live /.well-known/jwks.json.
//
// Usage (from sdk/js, after npm run build):
//   BROD_BIN=../../server/target/release/brod \
//   BROD_RUNTIME_BIN=../../deploy/runtime/supervisor/target/release/brod-runtime \
//   WORKERD_BIN=../../node_modules/workerd/bin/workerd \
//   npm run test:interop
// Ports: INTEROP_PORT (default 8847) for Brod, INTEROP_RUNTIME_PORT (default 8849) for workerd.
import { spawn } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { existsSync, mkdirSync, mkdtempSync, rmSync } from 'node:fs';
import http from 'node:http';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { build } from 'esbuild';
import { BrodAuthError, clearKeyCache, currentUser, verifyIdentityToken } from '@brodsh/auth';

const here = dirname(fileURLToPath(import.meta.url));
const sdk = resolve(here, '..', '..');
const repo = resolve(sdk, '..', '..');
const PORT = process.env.INTEROP_PORT ?? '8847';
const RT_PORT = process.env.INTEROP_RUNTIME_PORT ?? '8849';
const API = `http://localhost:${PORT}`;
const RT_SECRET = randomBytes(16).toString('hex');
const bin = resolve(process.env.BROD_BIN ?? join(repo, 'server/target/release/brod'));
const supervisor = resolve(process.env.BROD_RUNTIME_BIN ?? join(repo, 'deploy/runtime/supervisor/target/release/brod-runtime'));
const workerd = resolve(process.env.WORKERD_BIN ?? join(repo, 'node_modules/workerd/bin/workerd'));
for (const [name, path] of [['BROD_BIN', bin], ['BROD_RUNTIME_BIN', supervisor], ['WORKERD_BIN', workerd]]) {
  if (!existsSync(path)) {
    console.error(`${name}: ${path} does not exist. Build it (or set ${name}) first.`);
    process.exit(2);
  }
}

let passed = 0, failed = 0;
const check = (name, ok, detail = '') => {
  ok ? passed++ : failed++;
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${ok || !detail ? '' : `\n      ${detail}`}`);
};

/** A request with any Host header, so <app>.localhost need not resolve. Never follows redirects. */
function send(url, { method = 'GET', headers = {}, body } = {}) {
  const u = new URL(url);
  return new Promise((ok, fail) => {
    const req = http.request({ host: '127.0.0.1', port: PORT, path: u.pathname + u.search, method, headers: { host: u.host, ...headers } }, (res) => {
      let data = '';
      res.on('data', (c) => (data += c));
      res.on('end', () => ok({ status: res.statusCode, headers: res.headers, body: data }));
    });
    req.on('error', fail);
    if (body) req.write(body);
    req.end();
  });
}
class Browser {
  constructor(email) { this.email = email; this.jars = {}; }
  async go(url, o = {}) {
    const u = new URL(url, API), headers = { ...(o.headers ?? {}) };
    const c = Object.entries(this.jars[u.host] ?? {}).map(([k, v]) => `${k}=${v}`).join('; ');
    if (c) headers.cookie = c;
    let body;
    if (o.form) { body = new URLSearchParams(o.form).toString(); headers['content-type'] = 'application/x-www-form-urlencoded'; headers.origin ??= API; }
    if (o.json) { body = JSON.stringify(o.json); headers['content-type'] = 'application/json'; headers.origin ??= API; }
    const r = await send(u.href, { method: o.method ?? (body ? 'POST' : 'GET'), headers, body });
    for (const sc of [].concat(r.headers['set-cookie'] ?? [])) {
      const [k, v] = sc.split(';')[0].split('=');
      (this.jars[u.host] ??= {});
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
    return { status: r.status, body: r.body ? JSON.parse(r.body) : null };
  }
}

async function waitFor(url, headers, proc, out, what) {
  const deadline = Date.now() + 30_000;
  for (;;) {
    try { if ((await fetch(url, { headers })).ok) return; } catch { /* not up yet */ }
    if (Date.now() > deadline || proc.exitCode !== null) throw new Error(`${what} did not start:\n${out.log}`);
    await new Promise((r) => setTimeout(r, 100));
  }
}

// The server app: @brodsh/auth running inside workerd, bundled into one _worker.js.
const WORKER_SOURCE = `
import { currentUser } from '@brodsh/auth';
export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname === '/api/echo') return Response.json({ token: request.headers.get('x-brod-identity'),
      issuer: env.BROD_ISSUER, app: env.BROD_APP_ID, jwks: env.BROD_IDENTITY_JWKS });
    if (url.pathname === '/api/me') {
      try { return Response.json({ user: await currentUser(request, { env }) }); }
      catch (e) { return Response.json({ error: e.code ?? String(e) }, { status: e.status ?? 500 }); }
    }
    return new Response('interop');
  },
};`;
const bundled = await build({
  stdin: { contents: WORKER_SOURCE, resolveDir: sdk, loader: 'js' },
  bundle: true, write: false, format: 'esm', platform: 'browser', target: 'es2022', minify: true,
  conditions: ['worker', 'browser'],
});
const worker = bundled.outputFiles[0].text;

const state = mkdtempSync(join(tmpdir(), 'brod-auth-interop-'));
mkdirSync(join(state, 'runtime'));
const env = {
  PATH: process.env.PATH, HOME: process.env.HOME,
  APPS_DOMAIN: `localhost:${PORT}`, API_ORIGIN: API, ADMIN_SECRET: randomBytes(16).toString('hex'), IDENTITY_SECRET: randomBytes(16).toString('hex'),
  IDENTITY_SIGNING_KEY: randomBytes(32).toString('hex'), SECRETS_KEY: randomBytes(16).toString('hex'), DEV_MODE: '1',
  BROD_LISTEN: `127.0.0.1:${PORT}`, BROD_DATA_DIR: state, BROD_MODE: 'hosted',
  BROD_RUNTIME_URL: `http://127.0.0.1:${RT_PORT}`, BROD_RUNTIME_SECRET: RT_SECRET,
};
const rtOut = { log: '' }, out = { log: '' };
const runtime = spawn(supervisor, [workerd, 'serve', join(repo, 'deploy/runtime/config.capnp'), '--experimental', '-s', `http=127.0.0.1:${RT_PORT}`,
  '-e', `brod=127.0.0.1:${PORT}`, '-d', `data=${join(state, 'runtime')}`], {
  // Its own process group, so stopping it stops the workerd it supervises too.
  stdio: ['ignore', 'pipe', 'pipe'], cwd: repo, detached: true,
  env: { PATH: process.env.PATH, BROD_RUNTIME_SECRET: RT_SECRET, BROD_INTERNAL_URL: `http://127.0.0.1:${PORT}`, RUNTIME_PORT: RT_PORT },
});
runtime.stdout.on('data', (d) => (rtOut.log += d)); runtime.stderr.on('data', (d) => (rtOut.log += d));
const server = spawn(bin, [], { stdio: ['ignore', 'pipe', 'pipe'], env, cwd: state });
server.stdout.on('data', (d) => (out.log += d)); server.stderr.on('data', (d) => (out.log += d));

const exited = (p) => new Promise((r) => (p.exitCode !== null || p.signalCode !== null ? r() : p.once('exit', r)));
let code = 1;
try {
  await waitFor(`${API}/healthz`, {}, server, out, 'Brod');
  await waitFor(`http://127.0.0.1:${RT_PORT}/_runtime/health`, { 'x-brod-runtime-secret': RT_SECRET }, runtime, rtOut, 'The workerd runtime');

  const admin = new Browser(`interop-${Date.now()}@acme.test`);
  const started = await admin.go('/auth/start', { json: { email: admin.email } });
  await admin.go('/auth/verify', { form: { token: new URL(JSON.parse(started.body).dev_link).searchParams.get('token') } });
  const ws = await admin.api('/v1/workspaces', { json: { name: `Interop ${Date.now()}`, accept_terms: true } });
  check('signs in and makes a workspace', ws.status === 201 || ws.status === 200, JSON.stringify(ws.body));
  const deploy = async (name) => (await admin.api('/v1/deploys', { json: { name, files: [{ path: '_worker.js', content: worker }] } })).body;
  const app = await deploy('Auth echo');
  const other = await deploy('Other app');
  check('a server app bundling @brodsh/auth deploys', app.kind === 'server' && !!app.url, JSON.stringify(app));
  await admin.open(app.url + '/');
  await admin.open(other.url + '/');

  const echo = JSON.parse((await admin.go(app.url + '/api/echo')).body);
  const otherEcho = JSON.parse((await admin.go(other.url + '/api/echo')).body);
  check('the gateway hands the app a token and the env', !!echo.token && echo.issuer === API && /^app_/.test(echo.app) && !!echo.jwks, JSON.stringify(echo).slice(0, 300));

  // Node, inline keys: exactly what a container app does with its env.
  const appEnv = { BROD_ISSUER: echo.issuer, BROD_APP_ID: echo.app, BROD_IDENTITY_JWKS: echo.jwks };
  const user = await currentUser({ headers: { 'x-brod-identity': echo.token } }, { env: appEnv }).catch((e) => e);
  check('Node: currentUser verifies the real x-brod-identity header with the inline key set',
    user?.email === admin.email && user.app === echo.app && user.role === 'owner' && typeof user.workspace?.slug === 'string', JSON.stringify(user));

  // Node, remote keys: no inline set, so the SDK fetches <issuer>/.well-known/jwks.json.
  clearKeyCache();
  const remote = await verifyIdentityToken(echo.token, { env: { BROD_ISSUER: API, BROD_APP_ID: echo.app } }).catch((e) => e);
  check('Node: verifyIdentityToken verifies it against the live /.well-known/jwks.json', remote?.id === user?.id, JSON.stringify(remote));

  const meToken = JSON.parse((await admin.go(app.url + '/_brod/me')).body).token;
  const fromMe = await verifyIdentityToken(meToken, { env: appEnv }).catch((e) => e);
  check('Node: the /_brod/me token verifies too', fromMe?.id === user?.id, JSON.stringify(fromMe));

  const wrongAud = await verifyIdentityToken(echo.token, { env: { ...appEnv, BROD_APP_ID: otherEcho.app } }).catch((e) => e);
  check('Node: another app refuses it (wrong_audience)', wrongAud instanceof BrodAuthError && wrongAud.code === 'wrong_audience', String(wrongAud));
  const wrongIss = await verifyIdentityToken(echo.token, { env: { ...appEnv, BROD_ISSUER: 'https://elsewhere.test' } }).catch((e) => e);
  check('Node: another issuer refuses it (wrong_issuer)', wrongIss instanceof BrodAuthError && wrongIss.code === 'wrong_issuer', String(wrongIss));

  // workerd: the SDK itself runs in the app.
  const inside = await admin.go(app.url + '/api/me');
  const insideBody = JSON.parse(inside.body);
  check('workerd: currentUser(request, { env }) inside the server app returns the person', inside.status === 200 && insideBody.user?.email === admin.email
    && insideBody.user.id === user?.id, inside.body.slice(0, 300));
  const forged = await admin.go(app.url + '/api/me', { headers: { 'x-brod-identity': 'forged' } });
  check('workerd: a visitor\'s own x-brod-identity header is replaced by the gateway', JSON.parse(forged.body).user?.email === admin.email, forged.body.slice(0, 200));

  code = failed === 0 ? 0 : 1;
  console.log(`\n${passed} passed, ${failed} failed`);
} catch (e) {
  console.error(e?.stack ?? e);
} finally {
  if (code !== 0) console.error(`\n--- server log ---\n${out.log.slice(-3000)}\n--- runtime log ---\n${rtOut.log.slice(-3000)}`);
  const killGroup = (sig) => { try { process.kill(-runtime.pid, sig); } catch { /* already gone */ } };
  server.kill('SIGTERM');
  killGroup('SIGTERM');
  await Promise.race([Promise.all([exited(server), exited(runtime)]), new Promise((r) => setTimeout(r, 5000))]);
  if (server.exitCode === null && server.signalCode === null) server.kill('SIGKILL');
  killGroup('SIGKILL');
  rmSync(state, { recursive: true, force: true });
}
process.exit(code);
