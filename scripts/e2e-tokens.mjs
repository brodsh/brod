// Agent connections that expire, renew and can be read-only, on the Rust server: read-only tokens are refused when they
// try to change anything, OAuth access tokens come with a refresh token that rotates, and a reused refresh token
// disconnects the agent. Run by scripts/e2e-rust.mjs.
// Usage: node scripts/e2e-tokens.mjs <api origin>
import http from 'node:http';

const API = process.argv[2] ?? 'http://localhost:8787';
let passed = 0, failed = 0;
const check = (name, ok, detail = '') => { ok ? passed++ : failed++; console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${ok || !detail ? '' : `\n      ${detail}`}`); };
const run = Date.now();

class Browser {
  constructor(email) { this.email = email; this.jar = {}; }
  async go(path, o = {}) {
    const headers = { ...(o.headers ?? {}) };
    const jar = Object.entries(this.jar).map(([k, v]) => `${k}=${v}`).join('; ');
    if (jar) headers.cookie = jar;
    let body;
    if (o.json) { body = JSON.stringify(o.json); headers['content-type'] = 'application/json'; }
    if (o.form) { body = new URLSearchParams(o.form).toString(); headers['content-type'] = 'application/x-www-form-urlencoded'; }
    if (body || (o.method && o.method !== 'GET')) headers.origin ??= API;
    const r = await fetch(new URL(path, API), { method: o.method ?? (body ? 'POST' : 'GET'), headers, body, redirect: 'manual' });
    for (const sc of r.headers.getSetCookie()) { const [kv] = sc.split(';'); const [k, v] = kv.split('='); this.jar[k.trim()] = v; }
    return { status: r.status, headers: Object.fromEntries(r.headers), body: await r.text() };
  }
  async signIn() {
    const start = await this.go('/auth/start', { json: { email: this.email, return: '/' } });
    const token = new URL(JSON.parse(start.body).dev_link).searchParams.get('token');
    await this.go('/auth/verify', { form: { token } });
  }
  async api(path, o = {}) {
    const r = await this.go(path, { ...o, headers: { ...(o.headers ?? {}), 'x-brod-workspace': this.workspace ?? '' } });
    return { status: r.status, body: r.body ? JSON.parse(r.body) : null };
  }
}
const bearer = (token, path = '/v1/apps', o = {}) =>
  fetch(`${API}${path}`, { ...o, headers: { ...(o.headers ?? {}), authorization: `Bearer ${token}`, 'content-type': 'application/json' } });
const mcp = async (token, method, params = {}) => {
  const r = await bearer(token, '/mcp', { method: 'POST', body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }) });
  return { status: r.status, body: await r.json() };
};

const ana = new Browser(`ana-${run}@tokens.test`);
await ana.signIn();
ana.workspace = (await ana.api('/v1/workspaces', { json: { name: `Tokens ${run}`, accept_terms: true } })).body.workspace;
const W = ana.workspace;

// ---------- tokens made by a person: scope and expiry ----------

check('a token cannot ask for an unknown scope', (await ana.api('/v1/tokens', { json: { name: 'x', scope: 'admin' } })).status === 400);
check('a token cannot live longer than a year', (await ana.api('/v1/tokens', { json: { name: 'x', expires_in_days: 400 } })).status === 400);
check('a token cannot expire in part of a day', (await ana.api('/v1/tokens', { json: { name: 'x', expires_in_days: 1.5 } })).status === 400);
const manage = await ana.api('/v1/tokens', { json: { name: 'builder' } });
check('a token made without options can deploy and never expires', manage.status === 201 && manage.body.scope === 'manage' && manage.body.expires_at === null, JSON.stringify(manage.body));
const reader = await ana.api('/v1/tokens', { json: { name: 'watcher', scope: 'read', expires_in_days: 7 } });
const week = Date.now() + 7 * 86400_000;
check('a read-only token expires when asked', reader.status === 201 && reader.body.scope === 'read' && Math.abs(reader.body.expires_at - week) < 60_000, JSON.stringify(reader.body));
const R = reader.body.token;
check('a read-only token can list apps', (await bearer(R)).status === 200);
const refused = await bearer(R, '/v1/apps/anything/paused', { method: 'POST', body: '{"paused":true}' });
check('a read-only token is refused when it tries to change something', refused.status === 403 && (await refused.json()).error?.code === 'read_only');
const deploy = await bearer(manage.body.token, '/v1/deploys', { method: 'POST', body: JSON.stringify({ name: 'Reading list', files: [{ path: 'index.html', content: '<h1>Hi</h1>' }] }) });
check('a manage token can still deploy', deploy.status === 201, String(deploy.status));
const listed = await mcp(R, 'tools/list');
const names = listed.body.result?.tools?.map(t => t.name) ?? [];
check('a read-only agent is offered only the reading tools', names.join() === 'list_apps,get_files,get_status,get_logs,get_workspace', names.join());
const tried = await mcp(R, 'tools/call', { name: 'set_paused', arguments: { app: 'reading-list', paused: true } });
check('a read-only agent cannot call a changing tool', tried.body.result?.isError === true && tried.body.result.content[0].text.includes('read_only'), JSON.stringify(tried.body));
const status = await mcp(R, 'tools/call', { name: 'get_status', arguments: { app: 'reading-list' } });
check('a read-only agent can read an app\'s status', status.body.result?.isError === false, JSON.stringify(status.body).slice(0, 200));
check('a read-only agent cannot make connections either', (await bearer(R, '/v1/tokens', { method: 'POST', body: '{}' })).status === 403);

const page = await ana.go(`/w/${W}/connections`, { form: { name: 'laptop', scope: 'read', expires_in_days: '30' } });
const pageToken = /value="(brod_[0-9a-f]+)"/.exec(page.body)?.[1];
check('the connections page makes a read-only token that expires', !!pageToken && (await bearer(pageToken, '/v1/apps/reading-list/paused', { method: 'POST', body: '{}' })).status === 403);
check('the connections page shows each connection\'s rights, expiry and last use',
  /watcher<br><small>[^<]*read-only · made [0-9-]+ · last used [0-9-]+ · expires [0-9-]+/.test(page.body) && /builder<br><small>[^<]*deploy and manage[^<]*never expires/.test(page.body),
  page.body.slice(page.body.indexOf('<h2>Connections'), page.body.indexOf('<h2>Connections') + 900));
check('the connections page refuses a bad expiry', (await ana.go(`/w/${W}/connections`, { form: { name: 'x', expires_in_days: '9999' } })).status === 400);

// ---------- OAuth: short-lived access tokens, rotating refresh tokens, scopes ----------

const asm = await (await fetch(`${API}/.well-known/oauth-authorization-server`)).json();
check('the metadata offers refresh tokens and the read scope', asm.grant_types_supported.includes('refresh_token') && asm.scopes_supported.includes('brod:read'));
// scripts/e2e.mjs used up this hour's client registrations from 127.0.0.1, so register from another loopback address.
const register = name => new Promise((resolve, reject) => {
  const u = new URL(asm.registration_endpoint);
  const req = http.request({ host: '127.0.0.1', port: u.port, path: u.pathname, method: 'POST', localAddress: '127.0.0.2', headers: { host: u.host, 'content-type': 'application/json' } }, res => {
    let data = ''; res.on('data', c => (data += c)); res.on('end', () => resolve(JSON.parse(data)));
  });
  req.on('error', reject); req.end(JSON.stringify({ redirect_uris: ['http://127.0.0.1/callback'], client_name: name }));
});
const reg = await register('Token agent');
const other = await register('Other agent');
check('two clients registered', !!reg.client_id && !!other.client_id, JSON.stringify(reg));
const b64u = b => Buffer.from(b).toString('base64url');
async function signInAgent(scope) {
  const verifier = b64u(crypto.getRandomValues(new Uint8Array(32)));
  const challenge = b64u(new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier))));
  const cb = 'http://127.0.0.1:40123/callback';
  const authz = { response_type: 'code', client_id: reg.client_id, redirect_uri: cb, state: 's', code_challenge: challenge, code_challenge_method: 'S256', ...(scope ? { scope } : {}) };
  const consent = await ana.go(`/oauth/authorize?${new URLSearchParams(authz)}`);
  const allowed = await ana.go('/oauth/authorize', { form: { ...authz, workspace: W, decision: 'allow' } });
  const code = new URL(allowed.headers.location).searchParams.get('code');
  const r = await swap({ grant_type: 'authorization_code', code, client_id: reg.client_id, redirect_uri: cb, code_verifier: verifier });
  return { consent, status: r.status, body: await r.json() };
}
const swap = form => fetch(asm.token_endpoint, { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams(form) });

const fuzzy = await ana.go(`/oauth/authorize?${new URLSearchParams({ response_type: 'code', client_id: reg.client_id, redirect_uri: 'http://127.0.0.1/callback', state: 's', code_challenge: 'a'.repeat(43), code_challenge_method: 'S256', scope: 'offline_access brod:read' })}`);
check('scope words Brod does not know are ignored', fuzzy.status === 200 && fuzzy.body.includes('value="brod:read"'), String(fuzzy.status));

const ro = await signInAgent('brod:read');
check('the consent page says a read-only agent changes nothing', ro.consent.body.includes('change nothing') && ro.consent.body.includes('value="brod:read"'));
check('a read-only sign-in gets an hour-long token and a refresh token', ro.status === 200 && ro.body.expires_in === 3600 && ro.body.refresh_token?.startsWith('brodr_') && ro.body.scope === 'brod:read', JSON.stringify(ro.body));
check('the signed-in read-only agent is refused when it deploys', (await bearer(ro.body.access_token, '/v1/deploys', { method: 'POST', body: '{}' })).status === 403);
const widen = await swap({ grant_type: 'refresh_token', refresh_token: ro.body.refresh_token, client_id: reg.client_id, scope: 'brod' });
check('a refresh cannot widen a read-only connection', widen.status === 400 && (await widen.json()).error === 'invalid_grant');

const full = await signInAgent();
check('a sign-in without a scope can deploy and manage', full.status === 200 && full.body.scope === 'brod' && (await bearer(full.body.access_token)).status === 200, JSON.stringify(full.body));
check('a refresh token works only for the client it was issued to',
  (await swap({ grant_type: 'refresh_token', refresh_token: full.body.refresh_token, client_id: other.client_id })).status === 400);
const renewed = await swap({ grant_type: 'refresh_token', refresh_token: full.body.refresh_token, client_id: reg.client_id });
const next = await renewed.json();
check('a refresh token swaps for a new pair', renewed.status === 200 && next.access_token !== full.body.access_token && next.refresh_token !== full.body.refresh_token && next.expires_in === 3600, JSON.stringify(next));
check('the old access token stops working after a refresh', (await bearer(full.body.access_token)).status === 401);
check('the new access token works', (await bearer(next.access_token)).status === 200);
const narrowed = await swap({ grant_type: 'refresh_token', refresh_token: next.refresh_token, client_id: reg.client_id, scope: 'brod:read' });
const third = await narrowed.json();
check('a refresh may narrow the connection to read-only', narrowed.status === 200 && third.scope === 'brod:read' && (await bearer(third.access_token, '/v1/apps', { method: 'POST', body: '{}' })).status === 403, JSON.stringify(third));
const reused = await swap({ grant_type: 'refresh_token', refresh_token: next.refresh_token, client_id: reg.client_id });
check('a refresh token used twice is refused', reused.status === 400 && (await reused.json()).error_description.includes('disconnected'));
check('reusing a refresh token disconnects the agent', (await bearer(third.access_token)).status === 401
  && (await swap({ grant_type: 'refresh_token', refresh_token: third.refresh_token, client_id: reg.client_id })).status === 400);

const events = await ana.api('/v1/events?action=token_revoked');
check('the disconnection is in the activity log', events.body.events?.some(e => e.detail.includes('refresh token was used again')), JSON.stringify(events.body).slice(0, 300));
const conns = await ana.api('/v1/tokens');
const ros = conns.body.connections.find(t => t.kind === 'oauth' && t.scope === 'read' && t.revoked_at === null);
check('the API lists signed-in connections with their scope and renewal date', !!ros && ros.refresh_expires_at > Date.now() + 29 * 86400_000, JSON.stringify(conns.body.connections));

console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed ? 1 : 0);
