// SPDX-License-Identifier: AGPL-3.0-only
// End-to-end check of a self-hosted Brod started the way the quickstart starts it: no secrets, no email provider, no
// DEV_MODE, only BROD_ADMIN_EMAIL. It follows the first-start link from the log, makes an agent token, deploys over
// MCP, and checks what self-hosted mode changes: no plans or billing, no marketplace, no landing page, and
// workspaces made only by admins. Then it restarts the server on the same data and asks for a fresh link.
// Usage: node scripts/e2e-self-hosted.mjs   (BROD_BIN defaults to server/target/release/brod; build it first)
import { execFileSync, spawn } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import http from 'node:http';

const PORT = process.env.E2E_PORT ?? '8797';
const API = `http://localhost:${PORT}`;
const ADMIN = 'ada@acme.test';
const bin = join(process.cwd(), process.env.BROD_BIN ?? join('server', 'target', 'release', 'brod'));
const state = mkdtempSync(join(tmpdir(), 'brod-e2e-self-hosted-'));
// Only what the quickstart sets. The parent's environment is left out so no stray Brod variable leaks in.
const env = { PATH: process.env.PATH, BROD_ADMIN_EMAIL: ADMIN, BROD_DATA_DIR: join(state, 'data'), BROD_LISTEN: `127.0.0.1:${PORT}` };

let passed = 0, failed = 0;
const check = (name, ok, detail = '') => { ok ? passed++ : failed++; console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${ok || !detail ? '' : `\n      ${detail}`}`); };

/** A request with any Host header, so *.localhost need not resolve here. Never follows redirects. */
function send(url, { method = 'GET', headers = {}, body } = {}) {
  const u = new URL(url);
  return new Promise((resolve, reject) => {
    const req = http.request({ host: '127.0.0.1', port: PORT, method, path: u.pathname + u.search, headers: { host: u.host, ...headers } }, res => {
      let data = '';
      res.on('data', d => (data += d));
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: data }));
    });
    req.on('error', reject);
    if (body !== undefined) req.write(body);
    req.end();
  });
}
const json = (url, { method = 'POST', headers = {}, body } = {}) =>
  send(url, { method, headers: { 'content-type': 'application/json', origin: API, ...headers }, body: body === undefined ? undefined : JSON.stringify(body) })
    .then(r => ({ ...r, json: (() => { try { return JSON.parse(r.body); } catch { return null; } })() }));
const form = (url, fields, headers = {}) =>
  send(url, { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded', origin: API, ...headers }, body: new URLSearchParams(fields).toString() });
const cookieOf = r => (r.headers['set-cookie'] ?? []).map(c => c.split(';')[0]).find(c => c.startsWith('brod_platform=')) ?? '';

async function start() {
  const server = spawn(bin, [], { env, cwd: state, stdio: ['ignore', 'pipe', 'pipe'] });
  const out = { log: '' };
  server.stdout.on('data', d => (out.log += d)); server.stderr.on('data', d => (out.log += d));
  const deadline = Date.now() + 30_000;
  for (;;) {
    try { if ((await fetch(`${API}/healthz`)).ok) break; } catch { /* not up yet */ }
    if (Date.now() > deadline || server.exitCode !== null) throw new Error(`Brod did not start:\n${out.log}`);
    await new Promise(r => setTimeout(r, 100));
  }
  // The first-start banner is printed just after the listener opens.
  await new Promise(r => setTimeout(r, 300));
  return { server, out };
}
const stop = s => new Promise(r => { s.server.once('exit', r); s.server.kill('SIGTERM'); });

let code = 1, run;
try {
  run = await start();
  const log = () => run.out.log;
  check('the log names the mode', log().includes('(self-hosted)'), log());
  check('secrets are generated and kept in the data folder', /config: ADMIN_SECRET, IDENTITY_SECRET, SECRETS_KEY, BROD_RUNTIME_SECRET generated/.test(log()));
  const mode = statSync(join(state, 'data', 'secrets.env')).mode & 0o777;
  check('the secrets file is readable by its owner only', mode === 0o600, mode.toString(8));
  check('migrations are applied with one clear line', /database: applied \d+ new migrations \(0001_init\.sql to \S+\); schema up to date/.test(log()));
  check('email is printed to the log when no provider is set', log().includes('email: printed to this log'));
  const link = log().match(/http:\/\/localhost:\d+\/auth\/verify\?token=([0-9a-f]+)/);
  check('the first start prints a sign-in link for the admin', !!link && log().includes(`Sign in as ${ADMIN}`));
  check('and the command that connects Claude Code', log().includes(`claude mcp add --transport http brod ${API}/mcp --header "Authorization: Bearer <token>"`));

  // The front page is the sign-in form; the hosted service's pages are not here.
  const home = await send(`${API}/`);
  check('/ is the sign-in form, not the hosted landing page', home.status === 200 && home.body.includes('action="/auth/start"') && !home.body.includes('googletagmanager'));
  check('the sign-in form does not offer to create a workspace', !home.body.includes('/auth/signup'));
  check('/terms does not exist', (await send(`${API}/terms`)).status === 404);
  check('/auth/signup goes back to /', (await send(`${API}/auth/signup`)).status === 302);

  // The admin follows the link: it opens the connections page, signed in.
  const verified = await form(`${API}/auth/verify`, { token: link?.[1] ?? '' });
  const ada = cookieOf(verified);
  check('the link signs the admin in and opens the connections page', verified.status === 302 && verified.headers.location === '/w/default/connections' && !!ada,
    `${verified.status} ${verified.headers.location}`);
  const ws = await json(`${API}/v1/workspace`, { method: 'GET', headers: { cookie: ada } });
  check('the admin is the admin of a workspace called Default', ws.json?.workspace === 'default' && ws.json?.your_role === 'admin', ws.body);
  check('a self-hosted workspace has no plan limits', ws.json?.plan === 'self-hosted' && ws.json?.app_limit === null && ws.json?.member_limit === null && ws.json?.storage_limit === null, ws.body);
  check('billing does not exist', (await json(`${API}/v1/billing`, { method: 'GET', headers: { cookie: ada } })).status === 404);
  check('the marketplace is off', (await json(`${API}/v1/marketplace`, { method: 'GET', headers: { cookie: ada } })).status === 404);

  // An agent token, shown once, then MCP with it.
  const tok = await json(`${API}/v1/tokens`, { headers: { cookie: ada }, body: { name: 'claude' } });
  const token = tok.json?.token ?? '';
  check('the admin makes an agent token', tok.status === 201 && token.startsWith('brod_'), tok.body);
  const listed = await json(`${API}/v1/tokens`, { method: 'GET', headers: { cookie: ada } });
  check('the token is shown once: the list never includes it', listed.status === 200 && !listed.body.includes(token));
  const mcp = (id, method, params) => json(`${API}/mcp`, { headers: { authorization: `Bearer ${token}`, accept: 'application/json, text/event-stream' }, body: { jsonrpc: '2.0', id, method, params } });
  const deployed = await mcp(1, 'tools/call', { name: 'deploy_app', arguments: { name: 'On-call rota', files: [{ path: 'index.html', content: '<h1>On-call rota</h1>' }] } });
  const app = deployed.json?.result?.structuredContent;
  check('an agent deploys an app over MCP', app?.status === 'live' && app?.url === `http://on-call-rota.default.localhost:${PORT}`, deployed.body.slice(0, 400));
  // A private app never answers a visitor who is not signed in: it sends them to the platform, which asks them to sign in.
  const anon = await send(`${app?.url ?? API}/`);
  const hop = anon.status === 302 ? await send(anon.headers.location) : { status: 0, headers: {} };
  check('the app sends a visitor who is not signed in to sign in', anon.status === 302 && hop.status === 302 && (hop.headers.location ?? '').startsWith('/auth/signin'),
    `${anon.status} ${anon.headers.location} -> ${hop.status} ${hop.headers.location}`);
  const apps = await mcp(2, 'tools/call', { name: 'list_apps', arguments: {} });
  check('list_apps shows no app limit', apps.json?.result?.structuredContent?.app_limit === null, apps.body.slice(0, 300));

  // Someone else signs in: their link goes to the log, and they cannot make a workspace of their own.
  const asked = await json(`${API}/auth/start`, { body: { email: 'bo@acme.test' } });
  check('anyone can ask for a sign-in link', asked.status === 200 && asked.json?.sent === true && asked.json?.dev_link === undefined, asked.body);
  await new Promise(r => setTimeout(r, 100));
  const boLink = [...log().matchAll(/email to bo@acme\.test: Your Brod sign-in link\n[^\n]*\n(http\S+token=([0-9a-f]+))/g)].pop();
  check('their link is printed to the log, not returned by the API', !!boLink);
  const bo = cookieOf(await form(`${API}/auth/verify`, { token: boLink?.[2] ?? '' }));
  const made = await json(`${API}/v1/workspaces`, { headers: { cookie: bo }, body: { name: 'Shadow IT' } });
  check('someone who is not an admin cannot make a workspace', made.status === 403 && made.json?.error?.code === 'workspaces_closed', made.body);
  const boHome = await send(`${API}/`, { headers: { cookie: bo } });
  check('they are told to ask for an invitation', boHome.status === 403 && boHome.body.includes('Ask a workspace admin to invite you'));
  const second = await json(`${API}/v1/workspaces`, { headers: { cookie: ada }, body: { name: 'Platform' } });
  check('an admin can make another workspace, with no terms to accept', second.status === 201 && second.json?.workspace === 'platform', second.body);

  // A restart on the same data: the secrets are reused, nothing is migrated, and no link is printed once used.
  await stop(run);
  run = await start();
  check('a restart finds the schema up to date', /database: schema up to date \(\d+ migrations\)/.test(log()));
  check('a restart prints no link once the admin has signed in', !log().includes('/auth/verify?token='));
  const still = await json(`${API}/v1/workspace`, { method: 'GET', headers: { authorization: `Bearer ${token}` } });
  check('the token still works, so the generated secrets were reused', still.status === 200, still.body);
  const fresh = execFileSync(bin, ['setup-link'], { env, cwd: state }).toString();
  check('brod setup-link prints a fresh sign-in link', /\/auth\/verify\?token=[0-9a-f]+/.test(fresh), fresh);
  code = failed ? 1 : 0;
} catch (e) {
  console.error(e);
} finally {
  if (run) await stop(run);
  rmSync(state, { recursive: true, force: true });
}
console.log(`\n${passed} passed, ${failed} failed`);
process.exit(code);
