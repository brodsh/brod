// SPDX-License-Identifier: AGPL-3.0-only
// End-to-end check of app MCP (server/src/app_mcp.rs): an app declares "mcp": "/api/mcp" in brod.json, and an MCP
// client reaches it with only the address and a Brod sign-in. Brod (release build) and the workerd runtime start here on
// a fresh data directory. Covered: the 401 with WWW-Authenticate, the protected-resource metadata, dynamic client
// registration, authorize with resource and the consent page, the token exchange with PKCE, the app getting a valid
// x-brod-identity for the right person and never the Authorization header, tokens refused where they do not belong
// (Brod's own token at the app, an app token at Brod's /mcp, app A's token at app B, live vs staging), refresh keeping
// the binding, an app-scoped personal token, and access revoked -> refused.
// Usage: npm run e2e:app-mcp   (builds the release binaries unless BROD_BIN and BROD_RUNTIME_BIN are set)
//        E2E_PORT / E2E_RUNTIME_PORT choose the ports (default 8813 and 8814).
import { execFileSync, spawn } from 'node:child_process';
import http from 'node:http';
import { mkdirSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { createRemoteJWKSet, decodeJwt, jwtVerify } from 'jose';

const PORT = process.env.E2E_PORT ?? '8813';
const RT_PORT = process.env.E2E_RUNTIME_PORT ?? '8814';
const RT_SECRET = 'e2e-runtime-secret-0123456789';
const API = `http://localhost:${PORT}`;
const state = mkdtempSync(join(tmpdir(), 'brod-e2e-app-mcp-'));
if (process.env.BROD_BIN === undefined) execFileSync('cargo', ['build', '--release', '--manifest-path', 'server/Cargo.toml'], { stdio: 'inherit' });
if (process.env.BROD_RUNTIME_BIN === undefined) execFileSync('cargo', ['build', '--release', '--manifest-path', 'deploy/runtime/supervisor/Cargo.toml'], { stdio: 'inherit' });
const bin = resolve(process.env.BROD_BIN ?? join('server', 'target', 'release', 'brod'));
const supervisor = resolve(process.env.BROD_RUNTIME_BIN ?? join('deploy', 'runtime', 'supervisor', 'target', 'release', 'brod-runtime'));

let passed = 0, failed = 0;
const check = (name, ok, detail = '') => { ok ? passed++ : failed++; console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${ok || !detail ? '' : `\n      ${detail}`}`); };
const run = Date.now();

// ---------- Brod and the runtime ----------

const groups = [];
const signalGroup = (p, signal) => { try { process.kill(-p.pid, signal); } catch { /* already gone */ } };
process.on('exit', () => { for (const p of groups) signalGroup(p, 'SIGKILL'); });
for (const signal of ['SIGINT', 'SIGTERM']) process.on(signal, () => process.exit(130));

mkdirSync(join(state, 'runtime'));
const workerd = resolve('node_modules', 'workerd', 'bin', 'workerd');
const runtime = spawn(supervisor, [workerd, 'serve', resolve('deploy/runtime/config.capnp'), '--experimental', '-s', `http=127.0.0.1:${RT_PORT}`, '-e', `brod=127.0.0.1:${PORT}`, '-d', `data=${join(state, 'runtime')}`],
  { detached: true, stdio: ['ignore', 'pipe', 'pipe'], env: { ...process.env, BROD_RUNTIME_SECRET: RT_SECRET, BROD_INTERNAL_URL: `http://127.0.0.1:${PORT}`, RUNTIME_PORT: RT_PORT } });
groups.push(runtime);
let rtLog = '';
runtime.stdout.on('data', d => (rtLog += d)); runtime.stderr.on('data', d => (rtLog += d));

const server = spawn(bin, [], {
  cwd: state, detached: true, stdio: ['ignore', 'pipe', 'pipe'],
  env: { PATH: process.env.PATH, APPS_DOMAIN: `localhost:${PORT}`, API_ORIGIN: API, ADMIN_SECRET: 'dev-admin-secret', IDENTITY_SECRET: 'dev-identity-secret',
    IDENTITY_SIGNING_KEY: '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60', SECRETS_KEY: 'dev-secrets-key-0123456789', DEV_MODE: '1',
    BROD_LISTEN: `127.0.0.1:${PORT}`, BROD_DATA_DIR: join(state, 'data'), BROD_RUNTIME_URL: `http://127.0.0.1:${RT_PORT}`, BROD_RUNTIME_SECRET: RT_SECRET },
});
groups.push(server);
let log = '';
server.stdout.on('data', d => (log += d)); server.stderr.on('data', d => (log += d));

async function until(what, fn, ms = 30_000) {
  const deadline = Date.now() + ms;
  for (;;) {
    try { if (await fn()) return; } catch { /* not up yet */ }
    if (Date.now() > deadline) throw new Error(`${what} did not start:\n${log}\n${rtLog}`);
    await new Promise(r => setTimeout(r, 100));
  }
}

// ---------- HTTP helpers: every host is served on 127.0.0.1, named by the Host header ----------

function send(url, { method = 'GET', headers = {}, body } = {}) {
  const u = new URL(url);
  return new Promise((ok, fail) => {
    const req = http.request({ host: '127.0.0.1', port: PORT, path: u.pathname + u.search, method, headers: { host: u.host, ...headers } }, res => {
      let data = ''; res.on('data', c => (data += c)); res.on('end', () => ok({ status: res.statusCode, headers: res.headers, body: data }));
    });
    req.on('error', fail); if (body) req.write(body); req.end();
  });
}
const parse = r => { try { return JSON.parse(r.body); } catch { return null; } };

class Browser {
  constructor(email) { this.email = email; this.jars = {}; }
  async go(url, o = {}) {
    const u = new URL(url, API), headers = { ...(o.headers ?? {}) };
    const c = Object.entries(this.jars[u.host] ?? {}).map(([k, v]) => `${k}=${v}`).join('; '); if (c) headers.cookie = c;
    let body;
    if (o.form) { body = new URLSearchParams(o.form).toString(); headers['content-type'] = 'application/x-www-form-urlencoded'; headers.origin ??= API; }
    if (o.json) { body = JSON.stringify(o.json); headers['content-type'] = 'application/json'; headers.origin ??= API; }
    const r = await send(u.href, { method: o.method ?? (body ? 'POST' : 'GET'), headers, body });
    for (const sc of [].concat(r.headers['set-cookie'] ?? [])) {
      const [k, v] = sc.split(';')[0].split('='); (this.jars[u.host] ??= {});
      if (/max-age=0/i.test(sc)) delete this.jars[u.host][k]; else this.jars[u.host][k] = v;
    }
    return { ...r, url: u.href };
  }
  async open(url, o = {}) {
    let r = await this.go(url, o), hops = 0;
    while (r.status >= 300 && r.status < 400 && hops++ < 10) r = await this.go(new URL(r.headers.location, r.url).href);
    return r;
  }
  async signIn() {
    const start = await this.go('/auth/start', { json: { email: this.email, return: '/' } });
    await this.go('/auth/verify', { form: { token: new URL(JSON.parse(start.body).dev_link).searchParams.get('token') } });
  }
  async api(path, o = {}) {
    const r = await this.go(path, { ...o, headers: { ...(o.headers ?? {}), origin: API, 'x-brod-workspace': this.workspace ?? '' } });
    return { status: r.status, body: parse(r) };
  }
}

const b64u = b => Buffer.from(b).toString('base64url');
async function pkce() {
  const verifier = b64u(crypto.getRandomValues(new Uint8Array(32)));
  const challenge = b64u(new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier))));
  return { verifier, challenge };
}
const CB = 'http://127.0.0.1:40123/callback';
const tokenAt = form => send(`${API}/oauth/token`, { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams(form).toString() });
/** Drive the consent page as `who`: returns the consent page, and the code the client got back (or the redirect). */
async function authorize(who, client, extra = {}, decide = {}) {
  const { verifier, challenge } = await pkce();
  const q = { response_type: 'code', client_id: client, redirect_uri: CB, state: 'st', code_challenge: challenge, code_challenge_method: 'S256', ...extra };
  const consent = await who.go(`/oauth/authorize?${new URLSearchParams(q)}`);
  if (consent.status !== 200) return { consent, verifier };
  const allowed = await who.go('/oauth/authorize', { form: { ...q, decision: 'allow', ...decide } });
  const loc = allowed.headers.location ? new URL(allowed.headers.location) : null;
  return { consent, allowed, code: loc?.searchParams.get('code'), iss: loc?.searchParams.get('iss'), verifier };
}
async function signInFor(who, client, resource, brod = !resource) {
  const a = await authorize(who, client, resource ? { resource } : {}, brod ? { workspace: who.workspace } : {});
  const r = await tokenAt({ grant_type: 'authorization_code', code: a.code, client_id: client, redirect_uri: CB, code_verifier: a.verifier, ...(resource ? { resource } : {}) });
  return { ...a, status: r.status, token: parse(r) };
}
const call = (url, token, body = { jsonrpc: '2.0', id: 1, method: 'tools/list' }) =>
  send(url, { method: 'POST', headers: { 'content-type': 'application/json', accept: 'application/json, text/event-stream', ...(token ? { authorization: `Bearer ${token}` } : {}) }, body: JSON.stringify(body) });

// The app: echoes what the gateway handed it.
const ECHO = `
export default {
  async fetch(request) {
    const url = new URL(request.url);
    return Response.json({
      path: url.pathname, method: request.method, authorization: request.headers.get('authorization'),
      identity: request.headers.get('x-brod-identity'), email: request.headers.get('x-brod-user-email'), role: request.headers.get('x-brod-role'),
      body: request.method === 'POST' ? await request.text() : null,
    });
  },
};`;
const bundle = (version) => [{ path: '_worker.js', content: ECHO.replace('Response.json({', `Response.json({ version: ${version},`) }, { path: 'brod.json', content: JSON.stringify({ mcp: '/api/mcp' }) }];

let code = 1;
try {
  await until('Brod', async () => (await fetch(`${API}/healthz`)).ok);
  await until('The runtime', async () => (await fetch(`http://127.0.0.1:${RT_PORT}/_runtime/health`, { headers: { 'x-brod-runtime-secret': RT_SECRET } })).ok);
  console.log(`Brod at ${API}, server apps on workerd\n`);

  const ana = new Browser(`ana-${run}@acme.test`), bob = new Browser(`bob@bob-${run}.test`), cyd = new Browser(`cyd-${run}@outside.test`);
  for (const b of [ana, bob, cyd]) await b.signIn();
  const wsName = `Acme MCP ${run}`;
  ana.workspace = (await ana.api('/v1/workspaces', { json: { name: wsName, accept_terms: true } })).body.workspace;
  const W = ana.workspace;

  // ---------- declaring it ----------

  const staticMcp = await ana.api('/v1/deploys', { json: { name: 'Static', files: [{ path: 'index.html', content: 'x' }, { path: 'brod.json', content: '{"mcp":"/api/mcp"}' }] } });
  check('a static bundle cannot declare an MCP endpoint', staticMcp.status === 400 && staticMcp.body?.error?.code === 'bad_mcp', JSON.stringify(staticMcp.body));
  const badPath = await ana.api('/v1/deploys', { json: { name: 'Bad', files: [{ path: '_worker.js', content: ECHO }, { path: 'brod.json', content: '{"mcp":"/api/*"}' }] } });
  check('an MCP path is checked like an open path', badPath.status === 400 && badPath.body?.error?.code === 'bad_mcp', JSON.stringify(badPath.body));

  const echo = await ana.api('/v1/deploys', { json: { name: 'Echo', files: bundle(1) } });
  const other = await ana.api('/v1/deploys', { json: { name: 'Other', files: bundle(1) } });
  check('two server apps declare "mcp": "/api/mcp"', echo.status === 201 && other.status === 201, JSON.stringify(echo.body));
  const ECHO_URL = echo.body.url, OTHER_URL = other.body.url;
  const R = `${ECHO_URL}/api/mcp`, R_OTHER = `${OTHER_URL}/api/mcp`;
  check('get_status shows the MCP address', echo.body.mcp?.url === R && echo.body.mcp?.path === '/api/mcp', JSON.stringify(echo.body.mcp));

  // ---------- discovery ----------

  const anon = await call(R);
  const www = anon.headers['www-authenticate'] ?? '';
  check('an MCP call without credentials gets 401 with WWW-Authenticate', anon.status === 401
    && www === `Bearer resource_metadata="${ECHO_URL}/.well-known/oauth-protected-resource/api/mcp"`, `${anon.status} ${www}`);
  check('a sub-path of the endpoint is part of it', (await call(`${R}/messages`)).status === 401);
  const page = await send(`${ECHO_URL}/`);
  check('the rest of the app still sends people to sign in', page.status === 302 && page.headers.location?.startsWith(`${API}/auth/app`), String(page.status));
  const prm = await send(`${ECHO_URL}/.well-known/oauth-protected-resource/api/mcp`);
  const meta = parse(prm);
  check('the protected-resource metadata names the address and Brod, without sign-in', prm.status === 200 && meta?.resource === R
    && JSON.stringify(meta.authorization_servers) === JSON.stringify([API]) && JSON.stringify(meta.bearer_methods_supported) === '["header"]', prm.body);
  check('the bare metadata address answers the same', parse(await send(`${ECHO_URL}/.well-known/oauth-protected-resource`))?.resource === R);
  const asm = await (await fetch(`${API}/.well-known/oauth-authorization-server`)).json();
  check('Brod\'s authorization-server metadata is where the client goes next', asm.issuer === API && !!asm.registration_endpoint);
  const reg = await (await fetch(asm.registration_endpoint, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ redirect_uris: [CB.replace(':40123', '')], client_name: 'Claude' }) })).json();
  check('the client registers itself', !!reg.client_id, JSON.stringify(reg));
  const C = reg.client_id;

  // ---------- sharing and authorizing ----------

  const shared = await ana.api(`/v1/apps/${echo.body.app}/access`, { json: { access: 'people', add: [{ domain: `bob-${run}.test` }] } });
  check('the owner shares Echo with Bob (by his domain: he is not in the workspace)', shared.status === 200, JSON.stringify(shared.body));
  const unknown = await authorize(bob, C, { resource: `${API.replace('localhost', 'nope.' + W + '.localhost')}/api/mcp` });
  check('a resource that is no app MCP endpoint goes back as invalid_target', unknown.consent.status === 302
    && new URL(unknown.consent.headers.location).searchParams.get('error') === 'invalid_target', JSON.stringify(unknown.consent.headers));
  const wrongPath = await authorize(bob, C, { resource: `${ECHO_URL}/api/other` });
  check('a path the app did not declare is no resource', new URL(wrongPath.consent.headers.location ?? 'x:/').searchParams.get('error') === 'invalid_target');
  const outsider = await authorize(cyd, C, { resource: R });
  check('someone who cannot open the app cannot connect a client to it', outsider.consent.status === 403, String(outsider.consent.status));

  const bobIn = await signInFor(bob, C, R);
  check('the consent page names the client, the app and the workspace', bobIn.consent.body.includes('<b>Claude</b> wants to use <b>Echo</b>')
    && bobIn.consent.body.includes(`in <b>${wsName}</b> as you (<b>${bob.email}</b>)`) && !bobIn.consent.body.includes('name="workspace"'), bobIn.consent.body.slice(0, 600));
  check('the code comes back with the issuer', !!bobIn.code && bobIn.iss === API);
  const T = bobIn.token;
  check('the code swaps for a token bound to the app (PKCE)', bobIn.status === 200 && T.access_token?.startsWith('brodapp_') && T.refresh_token?.startsWith('brodappr_') && T.expires_in === 3600, JSON.stringify(T));
  const noPkce = await authorize(bob, C, { resource: R });
  const badVerifier = await tokenAt({ grant_type: 'authorization_code', code: noPkce.code, client_id: C, redirect_uri: CB, code_verifier: 'x'.repeat(43), resource: R });
  check('a wrong code_verifier is refused', badVerifier.status === 400 && parse(badVerifier)?.error === 'invalid_grant');
  const wrongTarget = await authorize(bob, C, { resource: R });
  const mismatch = await tokenAt({ grant_type: 'authorization_code', code: wrongTarget.code, client_id: C, redirect_uri: CB, code_verifier: wrongTarget.verifier, resource: R_OTHER });
  check('a token request for another resource than the code\'s is invalid_target', mismatch.status === 400 && parse(mismatch)?.error === 'invalid_target', mismatch.body);

  // ---------- calling the app ----------

  const ok = await call(R, T.access_token);
  const seen = parse(ok);
  check('the client calls the app\'s MCP endpoint with the token', ok.status === 200 && seen?.path === '/api/mcp' && seen.method === 'POST' && seen.body?.includes('tools/list'), ok.body);
  check('the app never sees the Authorization header', seen?.authorization === null, String(seen?.authorization));
  const jwks = createRemoteJWKSet(new URL(`${API}/.well-known/jwks.json`));
  // The audience is Echo's own: the same one a browser visit to Echo gets (checked at the end).
  let aud = '';
  try { aud = decodeJwt(seen?.identity ?? '').aud; } catch { /* checked below */ }
  const claims = await jwtVerify(seen?.identity ?? '', jwks, { issuer: API, audience: aud, algorithms: ['EdDSA'] }).then(v => v.payload, e => ({ error: e.message }));
  check('the app gets a valid x-brod-identity for the person who signed in', claims.email === bob.email && seen.email === bob.email && seen.role === 'viewer', JSON.stringify(claims));
  check('sub-paths work with the token too', parse(await call(`${R}/messages`, T.access_token))?.path === '/api/mcp/messages');
  check('a forged x-brod-identity from the client is replaced', parse(await send(R, { method: 'POST', headers: { authorization: `Bearer ${T.access_token}`, 'x-brod-identity': 'forged' }, body: '{}' }))?.identity !== 'forged');

  // ---------- tokens where they do not belong ----------

  const anaBrod = await signInFor(ana, C, null);
  check('Ana signs in to Brod\'s own MCP as before (no resource)', anaBrod.status === 200 && anaBrod.token.access_token?.startsWith('brod_'), JSON.stringify(anaBrod.token));
  const brodAtApp = await call(R, anaBrod.token.access_token);
  check('Brod\'s own token is refused at the app with invalid_token', brodAtApp.status === 401 && (brodAtApp.headers['www-authenticate'] ?? '').startsWith('Bearer error="invalid_token"'), `${brodAtApp.status} ${brodAtApp.headers['www-authenticate']}`);
  const withBrodResource = await signInFor(ana, C, `${API}/mcp`, true);
  check('a sign-in with resource=Brod\'s /mcp is Brod\'s own, as before', withBrodResource.status === 200 && withBrodResource.token.access_token?.startsWith('brod_'), JSON.stringify(withBrodResource.token));
  const appAtBrod = await send(`${API}/mcp`, { method: 'POST', headers: { authorization: `Bearer ${T.access_token}`, 'content-type': 'application/json' }, body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list' }) });
  check('an app token is refused at Brod\'s own /mcp', appAtBrod.status === 401, `${appAtBrod.status} ${appAtBrod.body.slice(0, 200)}`);
  check('an app token is refused at Brod\'s API', (await send(`${API}/v1/apps`, { headers: { authorization: `Bearer ${T.access_token}` } })).status === 401);
  await ana.api(`/v1/apps/${other.body.app}/access`, { json: { access: 'people', add: [{ domain: `bob-${run}.test` }] } });
  const atOther = await call(R_OTHER, T.access_token);
  check('a token for app A is refused at app B, even for a person B is shared with', atOther.status === 401 && (atOther.headers['www-authenticate'] ?? '').includes('invalid_token'), String(atOther.status));
  check('garbage tokens get invalid_token', (await call(R, 'brodapp_nope')).status === 401);

  // ---------- staging is its own resource ----------

  const staged = await ana.api('/v1/deploys', { json: { app: echo.body.app, files: bundle(2), environment: 'staging' } });
  const STAGING = staged.body?.staging_url;
  const RS = `${STAGING}/api/mcp`;
  check('a staging version is deployed', staged.status === 201 && !!STAGING && staged.body.mcp?.staging_url === RS, JSON.stringify(staged.body).slice(0, 400));
  const sMeta = parse(await send(`${STAGING}/.well-known/oauth-protected-resource/api/mcp`));
  check('the staging host names its own resource', sMeta?.resource === RS && RS !== R, JSON.stringify(sMeta));
  const liveAtStaging = await call(RS, T.access_token);
  check('a live token is refused on the staging host', liveAtStaging.status === 401 && (liveAtStaging.headers['www-authenticate'] ?? '').includes('invalid_token'));
  const bobStaging = await authorize(bob, C, { resource: RS });
  check('Bob, who may not open staging, cannot sign in to its endpoint', bobStaging.consent.status === 403, String(bobStaging.consent.status));
  const anaStaging = await signInFor(ana, C, RS);
  check('the staging consent page says so', anaStaging.consent.body.includes('(its staging version)'));
  const stagingCall = parse(await call(RS, anaStaging.token.access_token));
  check('a staging token reaches the staging version', stagingCall?.version === 2 && stagingCall.email === ana.email, JSON.stringify(stagingCall));
  check('a staging token is refused on the live host', (await call(R, anaStaging.token.access_token)).status === 401);

  // ---------- refresh keeps the binding ----------

  const renewed = await tokenAt({ grant_type: 'refresh_token', refresh_token: T.refresh_token, client_id: C, resource: R });
  const T2 = parse(renewed);
  check('the refresh token swaps for a new pair', renewed.status === 200 && T2.access_token?.startsWith('brodapp_') && T2.refresh_token !== T.refresh_token, renewed.body);
  check('the old access token stops working', (await call(R, T.access_token)).status === 401);
  check('the new one works at the same address, as the same person', parse(await call(R, T2.access_token))?.email === bob.email);
  check('the new one still does not work at app B', (await call(R_OTHER, T2.access_token)).status === 401);
  const retarget = await tokenAt({ grant_type: 'refresh_token', refresh_token: T2.refresh_token, client_id: C, resource: R_OTHER });
  check('a refresh cannot move the token to another resource', retarget.status === 400 && parse(retarget)?.error === 'invalid_target', retarget.body);
  const brodRefreshForApp = await tokenAt({ grant_type: 'refresh_token', refresh_token: anaBrod.token.refresh_token, client_id: C, resource: R });
  check('a Brod refresh token cannot be turned into an app token', brodRefreshForApp.status === 400 && parse(brodRefreshForApp)?.error === 'invalid_target', brodRefreshForApp.body);

  // ---------- a personal token for automation ----------

  const pat = await ana.api('/v1/tokens', { json: { name: 'nightly sync', app: echo.body.app, expires_in_days: 30 } });
  check('a person makes a token for one app\'s MCP endpoint', pat.status === 201 && pat.body.token?.startsWith('brodapp_') && pat.body.resource === R, JSON.stringify(pat.body));
  check('it works at that endpoint as the person', parse(await call(R, pat.body.token))?.email === ana.email);
  check('it does not work at Brod\'s API', (await send(`${API}/v1/apps`, { headers: { authorization: `Bearer ${pat.body.token}` } })).status === 401);
  const listed = await ana.api('/v1/tokens');
  check('app connections are listed with the workspace\'s connections', listed.body?.connections?.some(t => t.id === pat.body.id && t.kind === 'app' && t.app === echo.body.app)
    && listed.body.connections.some(t => t.kind === 'app' && t.made_by === bob.email), JSON.stringify(listed.body).slice(0, 400));
  check('a token for an app without an MCP endpoint is refused', (await ana.api('/v1/tokens', { json: { app: 'static' } })).status >= 400);
  check('the connections page shows it', (await ana.go(`/w/${W}/connections`)).body.includes('MCP of the app echo'));
  await ana.api(`/v1/tokens/${pat.body.id}`, { method: 'DELETE' });
  check('a revoked app token stops working', (await call(R, pat.body.token)).status === 401);

  // ---------- the browser still works ----------

  // The endpoint never sends anyone to sign in; a browser signs in to the app on any other page first.
  const home = await ana.open(`${ECHO_URL}/`);
  const browserCall = home.status === 200 ? await ana.go(`${ECHO_URL}/api/mcp`) : home;
  check('a browser signed in to the app reaches the path as before, with its identity', browserCall.status === 200 && parse(browserCall)?.email === ana.email, `${browserCall.status} ${browserCall.body.slice(0, 200)}`);
  let browserAud = '';
  try { browserAud = decodeJwt(parse(browserCall)?.identity ?? '').aud; } catch { /* checked below */ }
  check('the token-borne identity has the app\'s own audience, as a browser visit does', /^brod:app:app_/.test(aud) && aud === browserAud, `${aud} ${browserAud}`);

  // ---------- losing access ----------

  const unshared = await ana.api(`/v1/apps/${echo.body.app}/access`, { json: { remove: [{ domain: `bob-${run}.test` }] } });
  check('the owner stops sharing Echo with Bob', unshared.status === 200, JSON.stringify(unshared.body));
  const lost = await call(R, T2.access_token);
  check('Bob\'s token is refused at the next request: 403 insufficient_scope', lost.status === 403 && (lost.headers['www-authenticate'] ?? '').startsWith('Bearer error="insufficient_scope"'), `${lost.status} ${lost.headers['www-authenticate']}`);
  const lostRefresh = await tokenAt({ grant_type: 'refresh_token', refresh_token: T2.refresh_token, client_id: C });
  check('and its refresh token no longer renews it', lostRefresh.status === 400 && parse(lostRefresh)?.error === 'invalid_grant', lostRefresh.body);
  const events = await ana.api(`/v1/events?app=${echo.body.app}&action=refused`);
  check('the refusal is in the activity log', events.body?.events?.some(e => e.detail.includes(bob.email)), JSON.stringify(events.body).slice(0, 300));

  code = failed === 0 ? 0 : 1;
} catch (e) {
  console.error(e.stack ?? e.message);
  failed++;
} finally {
  console.log(`\n${passed} passed, ${failed} failed`);
  if (failed) console.error(`\n--- server log ---\n${log.slice(-4000)}\n--- runtime log ---\n${rtLog.slice(-2000)}`);
  for (const p of groups) signalGroup(p, 'SIGTERM');
  await new Promise(r => setTimeout(r, 500));
  for (const p of groups) signalGroup(p, 'SIGKILL');
  rmSync(state, { recursive: true, force: true });
}
process.exit(failed === 0 ? code : 1);
