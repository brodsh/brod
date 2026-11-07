// SPDX-License-Identifier: AGPL-3.0-only
// End-to-end check against a running Brod server with DEV_MODE=1 (started by scripts/e2e-rust.mjs), using the official MCP client
// the way an agent would, and a small cookie-keeping browser for people signing in across the API and app hosts.
// Usage: node scripts/e2e.mjs [api origin]   (default http://localhost:8787)
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { execSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import http from 'node:http';

const API = process.argv[2] ?? 'http://localhost:8787';
const ADMIN = process.env.ADMIN_SECRET ?? 'dev-admin-secret';
const api = new URL(API);
let passed = 0, failed = 0;
const check = (name, ok, detail = '') => { ok ? passed++ : failed++; console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${ok || !detail ? '' : `\n      ${detail}`}`); };
const run = Date.now();

/** Send a request to the local server with any Host header, so *.localhost need not resolve on this machine. */
function send(url, { method = 'GET', headers = {}, body } = {}) {
  const u = new URL(url);
  return new Promise((resolve, reject) => {
    const req = http.request({ host: api.hostname, port: api.port, path: u.pathname + u.search, method, headers: { host: u.host, ...headers } }, res => {
      let data = ''; res.on('data', c => (data += c)); res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: data, url: u.href }));
    });
    req.on('error', reject); if (body) req.write(body); req.end();
  });
}

/** A person with a browser: one cookie jar per host, like a real browser keeps host-only cookies. */
class Browser {
  constructor(email) { this.email = email; this.jars = {}; }
  cookieFor(host) { return Object.entries(this.jars[host] ?? {}).map(([k, v]) => `${k}=${v}`).join('; '); }
  async go(url, o = {}) {
    const u = new URL(url, API);
    const headers = { ...(o.headers ?? {}) };
    const c = this.cookieFor(u.host); if (c) headers.cookie = c;
    let body = o.body;
    if (o.form) { body = new URLSearchParams(o.form).toString(); headers['content-type'] = 'application/x-www-form-urlencoded'; headers.origin ??= API; }
    if (o.json) { body = JSON.stringify(o.json); headers['content-type'] = 'application/json'; headers.origin ??= API; }
    const r = await send(u.href, { method: o.method ?? (body ? 'POST' : 'GET'), headers, body });
    for (const sc of [].concat(r.headers['set-cookie'] ?? [])) {
      const [kv, ...attrs] = sc.split(';'); const [k, v] = kv.split('=');
      if (attrs.some(a => /^\s*domain=/i.test(a))) throw new Error('cookies must be host-only');
      (this.jars[u.host] ??= {});
      if (/max-age=0/i.test(sc)) delete this.jars[u.host][k.trim()]; else this.jars[u.host][k.trim()] = v;
    }
    return r;
  }
  /** Follow redirects across hosts, the way a browser would. */
  async open(url, o = {}) {
    let r = await this.go(url, o), hops = 0;
    while (r.status >= 300 && r.status < 400 && hops++ < 10) r = await this.go(new URL(r.headers.location, r.url).href);
    return r;
  }
  async signIn() {
    const start = await this.go('/auth/start', { json: { email: this.email, return: '/' } });
    const token = new URL(start.body && JSON.parse(start.body).dev_link).searchParams.get('token');
    return this.go('/auth/verify', { form: { token } });
  }
  async api(path, o = {}) {
    const r = await this.go(path, { ...o, headers: { ...(o.headers ?? {}), origin: API } });
    return { status: r.status, body: r.body ? JSON.parse(r.body) : null };
  }
}
const appHost = url => new URL(url).host;
/** The platform operator's API, with the admin secret. */
async function admin(path, body = {}, method = 'POST') {
  const r = await send(`${API}/v1/admin/${path}`, { method, headers: { authorization: `Bearer ${ADMIN}`, 'content-type': 'application/json' }, body: method === 'GET' ? undefined : JSON.stringify(body) });
  return { status: r.status, body: r.body ? JSON.parse(r.body) : null };
}
const tokenOf = link => new URL(link).searchParams.get('token');

// ---------- 1. sign-up by emailed link, workspace, agent connection ----------

const alice = new Browser(`alice-${run}@acme.test`);
const verifyGet = await alice.go('/auth/verify?token=x');
check('emailed link opens a confirm page, not an instant sign-in (mail scanners)', verifyGet.status === 200 && verifyGet.body.includes('method="post"'));
const signed = await alice.signIn();
check('magic link signs in and sets a host-only platform cookie', signed.status === 302 && !!alice.jars[api.host]?.brod_platform);
const reused = await alice.go('/auth/verify', { form: { token: 'not-a-real-token' } });
check('an unknown or used sign-in link is refused', reused.status === 410);
check('a cross-site form post is refused', (await alice.go('/auth/verify', { form: { token: 'x' }, headers: { origin: 'https://evil.test' } })).status === 403);

const noTerms = await alice.api('/v1/workspaces', { json: { name: 'Acme' } });
check('a workspace needs the terms accepted', noTerms.status === 400 && noTerms.body.error.code === 'terms');
const ws = await alice.api('/v1/workspaces', { json: { name: `Acme ${run}`, accept_terms: true } });
check('create a workspace; creator is admin', ws.status === 201 && ws.body.role === 'admin', JSON.stringify(ws.body));
const W = ws.body.workspace;

// The landing page at / for visitors; people who are signed in go on to their workspace.
const visitor = new Browser('visitor');
const landing = await visitor.go('/');
check('a signed-out visitor at / gets the landing page', landing.status === 200 && landing.body.includes('<title>Brod: a cloud for the small software your team builds with AI</title>')
  && landing.headers['content-type'] === 'text/html; charset=utf-8', `${landing.status} ${landing.body.slice(0, 120)}`);
check('the landing page may be indexed and is cached only with revalidation', !landing.headers['x-robots-tag'] && /no-cache/.test(landing.headers['cache-control'] ?? '')
  && /cookie/i.test(landing.headers.vary ?? '') && !!landing.headers.etag, JSON.stringify(landing.headers));
check('the landing page revalidates with its ETag', (await visitor.go('/', { headers: { 'if-none-match': landing.headers.etag } })).status === 304);
// HEAD is GET without the body, for uptime monitors and link previews.
const headHome = await send(`${API}/`, { method: 'HEAD' });
check('HEAD / answers like GET, without the body', headHome.status === 200 && headHome.body === '' && headHome.headers['content-type'] === landing.headers['content-type']
  && headHome.headers.etag === landing.headers.etag && Number(headHome.headers['content-length']) > 0
  && headHome.headers['content-length'] === (landing.headers['content-length'] ?? headHome.headers['content-length']), `${headHome.status} ${JSON.stringify(headHome.headers)}`);
const headHealth = await send(`${API}/healthz`, { method: 'HEAD' });
check('HEAD /healthz answers 200, without the body', headHealth.status === 200 && headHealth.body === '' && /^application\/json/.test(headHealth.headers['content-type'] ?? ''), `${headHealth.status} ${JSON.stringify(headHealth.headers)}`);
const headSignIn = await send(`${API}/auth/signin`, { method: 'HEAD' }), headShort = await send(`${API}/signin`, { method: 'HEAD' });
check('HEAD on the sign-in page answers 200, and HEAD on /signin redirects like GET', headSignIn.status === 200 && headSignIn.body === '' && headShort.status === 302
  && headShort.headers.location === '/auth/signin', `${headSignIn.status} ${headShort.status} ${headShort.headers.location}`);
// Without BROD_GA_ID there is no Google tag anywhere; the landing page names this server, never brod.sh.
check('the landing page has no Google tag unless BROD_GA_ID is set', !landing.body.includes('googletagmanager') && !landing.body.includes('gtag('));
check('the landing page tells visitors to connect to this server', landing.body.includes(`${API}/mcp`) && !landing.body.includes('brod.sh'));
const signInLinks = [...new Set([...landing.body.matchAll(/href="(\/[^"#]*)"/g)].map(m => m[1]))];
check('the landing page links to the sign-in page, not a missing /signin', signInLinks.includes('/auth/signin') && !signInLinks.includes('/signin'), signInLinks.join(' '));
const fromLanding = await visitor.open('/auth/signin');
check('its sign-in link opens the sign-in form', fromLanding.status === 200 && fromLanding.body.includes('action="/auth/start"'));
check('the sign-in page has no Google tag', !fromLanding.body.includes('googletagmanager'));
const withReturn = await visitor.go('/?return=/x');
check('/?return=... still shows the sign-in form', withReturn.status === 200 && withReturn.body.includes('action="/auth/start"') && withReturn.body.includes('value="/x"'));
const short = await visitor.go('/signin?return=/x');
check('/signin redirects to /auth/signin with its query', short.status === 302 && short.headers.location === '/auth/signin?return=/x', JSON.stringify(short.headers.location));
check('/signin reaches the sign-in form', (await visitor.open('/signin')).body.includes('action="/auth/start"'));
const signUp = await visitor.open('/auth/signup');
check('"Start free" opens a sign-up page that speaks to a new visitor', landing.body.includes('href="/auth/signup"') && signUp.status === 200
  && signUp.body.includes('Create your workspace') && signUp.body.includes('action="/auth/start"') && signUp.body.includes('href="/auth/signin"'));
const og = await send(`${API}/og.png`);
check('/og.png is the link preview picture the landing page names', og.status === 200 && og.headers['content-type'] === 'image/png' && landing.body.includes('og:image'), `${og.status} ${og.headers['content-type']}`);
const robotsTxt = await send(`${API}/robots.txt`), sitemapXml = await send(`${API}/sitemap.xml`);
check('robots.txt and sitemap.xml answer 200 and name this origin', robotsTxt.status === 200 && robotsTxt.body.includes(`Sitemap: ${API}/sitemap.xml`)
  && sitemapXml.status === 200 && sitemapXml.body.includes(`<loc>${API}/</loc>`), `${robotsTxt.status} ${sitemapXml.status}`);
const atRoot = await alice.go('/');
check('a signed-in person at / still goes to their workspace', atRoot.status === 302 && atRoot.headers.location === `/w/${W}`, JSON.stringify(atRoot.headers.location));
const noOrigin = await alice.go('/v1/tokens', { method: 'POST', body: '{}', headers: { 'content-type': 'application/json' } });
check('a cookie-signed request without the dashboard origin is refused', noOrigin.status === 403);
const agent = await alice.api('/v1/tokens', { json: { name: 'claude-code' } });
check('create a named agent connection', agent.status === 201 && agent.body.name === 'claude-code');

const client = new Client({ name: 'e2e', version: '1.0.0' });
await client.connect(new StreamableHTTPClientTransport(new URL(API + '/mcp'), { requestInit: { headers: { authorization: `Bearer ${agent.body.token}` } } }));
const tools = await client.listTools();
check('MCP lists 24 tools', tools.tools.length === 24, tools.tools.map(t => t.name).join(','));
const tool = async (name, args = {}) => { const r = await client.callTool({ name, arguments: args }); return { isError: r.isError, data: r.structuredContent ?? JSON.parse(r.content[0].text) }; };
const gw = await tool('get_workspace');
check('get_workspace explains groups, roles and the identity contract', gw.data.workspace === W && gw.data.identity?.how.includes('/_brod/me') && gw.data.default_app_roles.length === 3);
const ai = await tool('get_auth_integration', { framework: 'python' });
check('get_auth_integration gives the JWT contract and a snippet for one framework', !ai.isError && ai.data.identity?.jwks_url === `${API}/.well-known/jwks.json`
  && ai.data.identity.issuer === API && Object.keys(ai.data.snippets).join() === 'python' && ai.data.snippets.python.code.includes(API), JSON.stringify(ai.data).slice(0, 300));
check('get_auth_integration refuses an unknown framework', (await tool('get_auth_integration', { framework: 'cobol' })).isError);

// ---------- 2. deploy, private by default, one sign-in handed to the app's host ----------

const d1 = await tool('deploy_app', { name: `Reading List ${run}`, note: 'First version', files: [{ path: 'index.html', content: '<html><body><h1>v1</h1></body></html>' }, { path: 'assets/app.js', content: 'console.log(1)' }] });
check('deploy_app inline returns an address and version 1, private', !d1.isError && d1.data.version === 1 && d1.data.access === 'private', JSON.stringify(d1.data));
const APP = d1.data.app, url = d1.data.url;
const anon = new Browser('nobody');
const bounce = await anon.go(url + '/');
check('a private app sends a visitor to sign in on the API host', bounce.status === 302 && bounce.headers.location.startsWith(`${API}/auth/app?app=${APP}.${W}`));
const aliceApp = await alice.open(url + '/');
check('owner signs in once and lands on version 1', aliceApp.status === 200 && aliceApp.body.includes('v1') && aliceApp.headers['x-brod-version'] === '1');
check('the app host gets its own session cookie, never the platform one', !!alice.jars[appHost(url)]?.brod_session && !alice.jars[appHost(url)]?.brod_platform);
const me = await alice.go(url + '/_brod/me');
const meBody = JSON.parse(me.body);
check('/_brod/me gives the person, their app role and a signed JWT', me.status === 200 && meBody.user.email === alice.email && meBody.role === 'owner' && /^[\w-]+\.[\w-]+\.[\w-]+$/.test(meBody.token));
check('the client library is served on the app host', (await alice.go(url + '/_brod/client.js')).body.includes('Brod'));
const js = await alice.go(url + '/assets/app.js');
check('asset served with the right type', js.status === 200 && js.headers['content-type'].startsWith('text/javascript'));
const code = await alice.go(`${API}/auth/app?app=${APP}.${W}&return=/`);
const codeUrl = new URL(code.headers.location);
const other = new Browser('throwaway');
await other.go(codeUrl.href);
check('a sign-in code works once', (await other.go(codeUrl.href)).status === 400);

// ---------- 2b. custom domains, proven against a fake DNS-over-HTTPS resolver (E2E_DNS, see scripts/fake-dns.mjs) ----------

if (process.env.E2E_DNS) {
  const txt = (name, value) => fetch(`${process.env.E2E_DNS}/_test/records`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ name, value }) });
  const port = api.port ? `:${api.port}` : '';
  const SHOP = `shop-${run}.example.test`, WILD = `apps-${run}.example.test`;
  const dom = await tool('set_domain', { domain: SHOP, app: APP });
  check('set_domain claims a domain and names the TXT and CNAME records to add', !dom.isError && dom.data.status === 'pending' && dom.data.dns?.[0].name === `_brod.${SHOP}` && dom.data.dns?.[1].type === 'CNAME', JSON.stringify(dom.data));
  check('a domain is not served before it is proven', !(await alice.go(`http://${SHOP}${port}/`)).headers['x-brod-app']);
  await txt(dom.data.dns[0].name, dom.data.dns[0].value);
  const proven = await tool('set_domain', { domain: SHOP });
  check('set_domain again finds the TXT record and verifies the domain', proven.data.status === 'verified', JSON.stringify(proven.data));
  const onDomain = await alice.open(`http://${SHOP}${port}/`);
  check('a private app opens at its custom domain after the sign-in hand-off', onDomain.status === 200 && onDomain.headers['x-brod-app'] === APP && !!alice.jars[`${SHOP}${port}`]?.brod_session);
  check('the hand-off refuses an address that is not a domain of the app', (await alice.go(`${API}/auth/app?app=${APP}.${W}&host=evil.test${port}&return=/`)).status === 400);
  const wild = await alice.api('/v1/domains', { json: { domain: `*.${WILD}` } });
  await txt(wild.body.dns[0].name, wild.body.dns[0].value);
  const wv = await alice.api(`/v1/domains/${WILD}/verify`, { method: 'POST' });
  const wApp = await alice.open(`http://${APP}.${WILD}${port}/`);
  check('a wildcard domain serves every app in the workspace', wild.status === 201 && wv.body.status === 'verified' && wApp.status === 200 && wApp.headers['x-brod-app'] === APP, JSON.stringify(wv.body));
  check('get_status lists the app\'s domains', (await tool('get_status', { app: APP })).data.domains?.filter(d => d.status === 'verified').length === 2);
  const rm = await tool('set_domain', { domain: SHOP, remove: true });
  check('removing a domain stops serving it at once', rm.data.removed === SHOP && !(await alice.go(`http://${SHOP}${port}/`)).headers['x-brod-app']);
} else console.log('SKIP  custom domains: E2E_DNS is not set');

// ---------- 3. people, invites, confirmations, groups, roles ----------

const bob = new Browser(`bob-${run}@acme.test`);
const inv = await alice.api('/v1/invites', { json: { email: bob.email, role: 'member' } });
check('admin invites a member by email', inv.status === 201 && inv.body.role === 'member' && inv.body.dev_link);
const invPage = await bob.go(`/auth/invite?token=${tokenOf(inv.body.dev_link)}`);
check('the invitation page names the workspace', invPage.status === 200 && invPage.body.includes('Acme'));
const accepted = await bob.go('/auth/invite', { form: { token: tokenOf(inv.body.dev_link) } });
check('accepting the invite signs the person in and opens the home page', accepted.status === 302 && accepted.headers.location === `/w/${W}` && !!bob.jars[api.host]?.brod_platform);
check('an invite works once', (await bob.go('/auth/invite', { form: { token: tokenOf(inv.body.dev_link) } })).status === 410);
const bobDenied = await bob.open(url + '/');
const noApp = await bob.go(url.replace(`//${APP}.`, `//no-such-app-${run}.`) + '/');
check('a member cannot open a private app: they see "App not found", the very page an empty address shows',
  bobDenied.status === 404 && bobDenied.body.includes('App not found') && !bobDenied.body.includes(bob.email) && noApp.status === 404 && noApp.body === bobDenied.body);

const widen = await tool('set_access', { app: APP, access: 'workspace' });
check('widening access from an agent waits for confirmation', !widen.isError && widen.data.needs_confirmation === true && widen.data.confirm_url.includes('/confirm/'), JSON.stringify(widen.data));
check('nothing changes before the owner confirms', (await bob.open(url + '/')).status === 404);
const cpath = new URL(widen.data.confirm_url).pathname;
check('the confirmation page shows what the agent asked for', (await alice.go(cpath)).body.includes('workspace'));
check('only a signed-in person can confirm', (await anon.go(cpath)).status === 302);
const confirmed = await alice.go(cpath, { form: { decision: 'confirm' } });
check('owner confirms; the change applies', confirmed.status === 200 && confirmed.body.includes('done'));
const bobIn = await bob.open(url + '/');
check('everyone in the workspace can now open it', bobIn.status === 200 && bobIn.body.includes('v1'));
check('a member gets the lowest app role by default', JSON.parse((await bob.go(url + '/_brod/me')).body).role === 'viewer');
check('a confirmation cannot be used twice', (await alice.go(cpath, { form: { decision: 'confirm' } })).status === 410);

const grp = await alice.api('/v1/groups', { json: { name: 'Finance' } });
const addBob = await alice.api('/v1/groups/finance/members', { json: { email: bob.email } });
check('groups are defined once and people added to them', grp.status === 201 && grp.body.name === 'finance' && addBob.body.people.includes(bob.email));
const share = await tool('set_access', { app: APP, access: 'people', add: [{ group: 'finance', role: 'editor' }] });
check('granting a group a role from an agent also waits for confirmation', share.data.needs_confirmation === true);
await alice.go(new URL(share.data.confirm_url).pathname, { form: { decision: 'confirm' } });
const bobMe = JSON.parse((await bob.go(url + '/_brod/me')).body);
check('the group mapping gives the role in the app', bobMe.role === 'editor' && bobMe.groups.includes('finance'), JSON.stringify(bobMe));
const st0 = await tool('get_status', { app: APP });
check('the share sentence says who can open it', st0.data.who_can_open.includes('finance') && st0.data.shared_with.some(g => g.group === 'finance' && g.role === 'editor'));
const narrow = await tool('set_access', { app: APP, access: 'private' });
check('narrowing access from an agent applies at once', !narrow.isError && narrow.data.access === 'private' && !narrow.data.needs_confirmation);
check('the change takes effect on the next request', (await bob.go(url + '/')).status === 404);
// A workspace less than a day old keeps its apps inside it, until the platform operator trusts it.
const young = await tool('set_access', { app: APP, access: 'public' });
check('a new workspace cannot open an app to everyone, and is told what it can do', young.isError && young.data.error === 'workspace_too_new' && young.data.message.includes('"workspace"'), JSON.stringify(young.data));
const trusted = await admin(`workspaces/${W}/trust`);
check('the operator trusts the workspace with the admin secret', trusted.status === 200 && trusted.body.trusted === true, JSON.stringify(trusted.body));
const declineReq = await tool('set_access', { app: APP, access: 'public' });
await alice.go(new URL(declineReq.data.confirm_url).pathname, { form: { decision: 'decline' } });
check('a declined request changes nothing', (await anon.go(url + '/')).status === 302);

// sharing with a password: anyone with the address and the password gets in, without an account
const pwNone = await tool('set_access', { app: APP, access: 'password' });
check('the password mode needs a password', pwNone.isError && pwNone.data.error === 'password_needed', JSON.stringify(pwNone.data));
const pwReq = await tool('set_access', { app: APP, password: `open sesame ${run}` });
check('sharing with a password from an agent waits for confirmation', pwReq.data.needs_confirmation === true && pwReq.data.summary.includes('to password'), JSON.stringify(pwReq.data));
check('the request keeps no copy of the password', !JSON.stringify(pwReq.data).includes('sesame'));
const pwVisitor = new Browser('');
check('nothing changes before the owner confirms it', (await pwVisitor.go(url + '/')).status === 302);
await alice.go(new URL(pwReq.data.confirm_url).pathname, { form: { decision: 'confirm' } });
const gate = await pwVisitor.go(url + '/notes?x=1');
check('a visitor is asked for the password instead of a sign-in', gate.status === 401 && gate.body.includes('needs a password') && gate.body.includes('name="password"') && gate.body.includes('value="/notes?x=1"'));
const wrongPw = await pwVisitor.go(url + '/_brod/password', { form: { password: 'not the one', return: '/' } });
check('a wrong password is refused', wrongPw.status === 401 && wrongPw.body.includes('not right'));
const rightPw = await pwVisitor.go(url + '/_brod/password', { form: { password: `open sesame ${run}`, return: '/' } });
check('the right password lets the visitor in', rightPw.status === 302 && rightPw.headers.location === '/');
const pwIn = await pwVisitor.go(url + '/');
check('the visitor opens the app without an account, and the app sees nobody signed in', pwIn.status === 200 && pwIn.body.includes('v1') && (await pwVisitor.go(url + '/_brod/me')).status === 401);
check('the owner still opens it signed in, with their role', JSON.parse((await alice.open(url + '/_brod/me')).body).role === 'owner');
const pwStatus = await tool('get_status', { app: APP });
check('the share sentence names the password and never shows it', pwStatus.data.access === 'password' && pwStatus.data.who_can_open.includes('password') && !/sesame|pbkdf2/.test(JSON.stringify(pwStatus.data)));
check('the owner can set a new password at once', (await alice.api(`/v1/apps/${APP}/access`, { json: { password: `new one ${run}` } })).status === 200);
check('a new password signs out everyone who used the old one', (await pwVisitor.go(url + '/')).status === 401);
check('a password needs another mode to go with it', (await alice.api(`/v1/apps/${APP}/access`, { json: { access: 'people', password: 'whatever1' } })).body.error?.code === 'bad_password');
await alice.api(`/v1/apps/${APP}/access`, { json: { access: 'workspace' } });

const home = await bob.go(`/w/${W}`);
check('the home page lists the apps a member can open, with search', home.status === 200 && home.body.includes(`Reading List ${run}`) && home.body.includes('type="search"'));
// The Rust server has an admin console at /w/<workspace>/admin and sends builders and admins there from the home
// page; the TS Worker has no admin page and keeps showing everyone the launcher.
if ((await alice.go(`/w/${W}/admin`)).status === 200) {
  const adminHome = await alice.go(`/w/${W}`);
  check('the home page sends an admin to the admin console', adminHome.status === 302 && adminHome.headers.location === `/w/${W}/admin`, `${adminHome.status} ${adminHome.headers.location}`);
  const launcher = await alice.go(`/w/${W}?view=apps`);
  check('an admin can still open the plain app launcher', launcher.status === 200 && launcher.body.includes(`Reading List ${run}`) && launcher.body.includes(`/w/${W}/admin`));
  check('a member is kept out of the admin console', (await bob.go(`/w/${W}/admin`)).status === 403);
  check('a member asking for the launcher view still gets the app list', (await bob.go(`/w/${W}?view=apps`)).status === 200);
}
const memberToken = await bob.api('/v1/tokens', { json: { name: 'bobs-agent' } });
check('a member cannot connect an agent or deploy', memberToken.status === 403);

// guests: one named app only
const carol = new Browser(`carol-${run}@partner.test`);
const ginv = await alice.api('/v1/invites', { json: { email: carol.email, app: APP, app_role: 'viewer' } });
check('invite a guest to one app', ginv.status === 201 && ginv.body.role === 'guest' && ginv.body.app === APP);
const gacc = await carol.go('/auth/invite', { form: { token: tokenOf(ginv.body.dev_link) } });
check('a guest lands straight in the app after accepting', gacc.status === 302 && gacc.headers.location.startsWith(`/auth/app?app=${APP}.${W}`));
const carolApp = await carol.open(gacc.headers.location);
check('the guest opens the app they were given', carolApp.status === 200 && carolApp.body.includes('v1'));
const d2 = await tool('deploy_app', { name: `Second ${run}`, files: [{ path: 'index.html', content: 'second' }] });
await alice.api(`/v1/apps/${d2.data.app}/access`, { json: { access: 'workspace' } });
check('a guest cannot open other workspace apps', (await carol.open(d2.data.url + '/')).status === 404);
check('a member can open workspace apps', (await bob.open(d2.data.url + '/')).status === 200);

// MCP invite needs confirmation; then it shows as pending
const dave = `dave-${run}@acme.test`;
const ainv = await tool('invite', { email: dave });
check('invite from an agent waits for confirmation', ainv.data.needs_confirmation === true);
await alice.go(new URL(ainv.data.confirm_url).pathname, { form: { decision: 'confirm' } });
const pending = await alice.api('/v1/invites');
check('after confirmation the invite is pending and visible', pending.body.pending.some(i => i.email === dave));
// Invite people until the free plan's allowance runs out.
let more;
for (let i = 0; i < 20; i++) {
  more = await alice.api('/v1/invites', { json: { email: `erin${i}-${run}@acme.test` } });
  if (more.status !== 201 && more.status !== 200) break;
}
check('the free plan member allowance is enforced', more.status === 402 && more.body.error.code === 'member_limit', JSON.stringify(more.body));
const pid = pending.body.pending.find(i => i.email === dave).id;
check('a pending invite can be revoked', (await alice.api(`/v1/invites/${pid}`, { method: 'DELETE' })).status === 200);

// removing a person ends their access at once
const rm = await alice.api(`/v1/people/${encodeURIComponent(bob.email)}`, { method: 'DELETE' });
check('admin removes a person', rm.status === 200);
check('their access to every app ends on the next request', (await bob.go(url + '/')).status === 404 && (await bob.go(d2.data.url + '/')).status === 404);

// one sign-in, one sign-out
await carol.go(url + '/_brod/signout');
check('signing out of one app signs out of the platform too', (await carol.go(url + '/')).status === 302 && (await carol.api('/v1/me')).status === 401);

// ---------- 4. public, report, versions, rollback ----------

const pub = await tool('set_access', { app: APP, access: 'public' });
await alice.go(new URL(pub.data.confirm_url).pathname, { form: { decision: 'confirm' } });
const pubPage = await anon.go(url + '/');
check('a public app opens with no sign-in and carries a report link', pubPage.status === 200 && pubPage.body.includes('v1') && pubPage.body.includes('/_brod/report'));
const headApp = await send(url + '/', { method: 'HEAD' });
check('HEAD on an app host answers like GET, without the body', headApp.status === 200 && headApp.body === '' && headApp.headers['content-type'] === pubPage.headers['content-type']
  && headApp.headers.etag === pubPage.headers.etag, `${headApp.status} ${JSON.stringify(headApp.headers)}`);
check('a public app carries no Google tag', !pubPage.body.includes('googletagmanager'));
check('a visitor is anonymous to /_brod/me on a public app', (await anon.go(url + '/_brod/me')).status === 401);
const rep = await anon.go(url + '/_brod/report', { form: { reason: 'Looks like phishing' }, headers: { origin: url } });
const queue = await send(`${API}/v1/admin/reports`, { headers: { authorization: `Bearer ${ADMIN}` } });
check('a report reaches the review queue', rep.status === 200 && JSON.parse(queue.body).reports.some(r => r.app === APP && r.reason === 'Looks like phishing'));

const up = await tool('deploy_app', { app: APP, note: 'Second version by upload' });
check('deploy_app without files returns an upload address', !up.isError && up.data.upload_url?.includes('/v1/uploads/'), JSON.stringify(up.data));
// Follow next_step: one PUT of the tar.gz to the upload address.
const curl = (args, input) => { const r = execSync(`${input ? `${input} | ` : ''}curl -sS -w "\\n%{http_code}" ${args}`).toString(); const i = r.lastIndexOf('\n'); return { body: r.slice(0, i), status: Number(r.slice(i + 1)) }; };
const sendBundle = (u, source) => curl(`-X PUT --data-binary @- "${u.upload_url}"`, source);
const upload = source => sendBundle(up.data, source);
const dir = mkdtempSync(join(tmpdir(), 'sc-')); mkdirSync(join(dir, 'dist', 'about'), { recursive: true });
writeFileSync(join(dir, 'dist', 'index.html'), '<h1>v2</h1>'); writeFileSync(join(dir, 'dist', 'about', 'index.html'), '<h1>about</h1>');
writeFileSync(join(dir, 'dist', 'a-very-long-file-name-'.repeat(6) + '.txt'), 'long');
const bad = upload('echo x');
check('a bad archive is refused without using up the address', bad.status === 400, JSON.stringify(bad));
const outRes = upload(`tar -czf - -C ${dir} dist`), out = JSON.parse(outRes.body);
check('tar.gz upload deploys version 2 and strips the wrapping folder', out.version === 2 && out.files === 3, JSON.stringify(out));
const again = upload(`tar -czf - -C ${dir} dist`);
check('an upload address works once', again.status === 410, JSON.stringify(again));
// An agent's update to a live app goes to staging: builders try it at <app>--staging.<workspace> before visitors see it.
const stagingUrl = url.replace(`//${APP}.`, `//${APP}--staging.`);
check('an agent\'s update to a live app lands on staging, not live', out.environment === 'staging' && out.live_version === 1 && out.staging?.version === 2
  && out.staging_url === stagingUrl && out.staging.url === stagingUrl, JSON.stringify(out));
check('visitors still get version 1 while version 2 is on staging', (await anon.go(url + '/')).body.includes('v1'));
// The TLS front (Caddy's on-demand ask, or Brod's own TLS) must agree to a certificate for the staging address.
// Asked on the internal listener: 127.0.0.1 is neither the API host nor under APPS_DOMAIN.
const askCert = async host => (await fetch(`${API.replace('//localhost', '//127.0.0.1')}/_caddy/ask?domain=${host}`)).status;
const appsHost = new URL(API).hostname;
check('a staging address may get a TLS certificate', await askCert(`${APP}--staging.${W}.${appsHost}`) === 200);
check('a staging address of an app that does not exist may not', await askCert(`no-such-app--staging.${W}.${appsHost}`) === 404);
const anonStaging = await anon.go(stagingUrl + '/');
check('a visitor is sent to sign in on staging, even for a public app', anonStaging.status === 302 && anonStaging.headers.location.includes(`app=${APP}--staging.${W}`), JSON.stringify(anonStaging.headers.location));
const ownStaging = await alice.open(stagingUrl + '/');
check('the owner signs in at the staging address and sees version 2', ownStaging.status === 200 && ownStaging.body.includes('v2') && ownStaging.headers['x-brod-version'] === '2'
  && !!alice.jars[appHost(stagingUrl)]?.brod_session && !ownStaging.body.includes('/_brod/report'), `${ownStaging.status} ${ownStaging.body.slice(0, 100)}`);
check('get_status shows what is on staging', (await tool('get_status', { app: APP })).data.versions.find(v => v.version === 2)?.staging === true);
const published = await tool('publish_staging', { app: APP });
check('publish_staging makes the staging version live and empties staging', !published.isError && published.data.published === 2 && published.data.live_version === 2 && published.data.staging === null, JSON.stringify(published.data));
check('nothing is left on staging after publishing', (await alice.go(stagingUrl + '/')).status === 404 && (await tool('publish_staging', { app: APP })).data.error === 'nothing_on_staging');
check('visitors now get version 2', (await anon.go(url + '/')).body.includes('v2'));
check('folder index and clean URLs work', (await anon.go(url + '/about')).body.includes('about') && (await anon.go(url + '/about/')).body.includes('about'));
check('unknown route falls back to index.html (single-page apps)', (await anon.go(url + '/some/route')).body.includes('v2'));
check('missing asset is a 404', (await anon.go(url + '/nope.png')).status === 404);
const rb = await tool('rollback', { app: APP, version: 1 });
check('rollback to version 1', !rb.isError && rb.data.live_version === 1 && rb.data.changed === true);
check('visitors get version 1 again on the next request', (await anon.go(url + '/')).body.includes('v1'));
// Several people on one app: a deploy says which version its files started from, and one that would undo someone else's is refused.
check('get_status gives the current version to build on', (await tool('get_status', { app: APP })).data.current_version === 1);
const based = await tool('deploy_app', { app: APP, base_version: 1, note: 'New menu', files: [{ path: 'index.html', content: '<h1>v3</h1>' }] });
check('a deploy with base_version records what it was built on', !based.isError && based.data.version === 3 && based.data.based_on === 1 && based.data.current_version === 3, JSON.stringify(based.data));
const staleRes = await alice.api('/v1/deploys', { json: { app: APP, base_version: 1, files: [{ path: 'index.html', content: 'mine' }] } });
const staleErr = staleRes.body.error ?? {};
check('a deploy from an older version is refused and says who changed what', staleRes.status === 409 && staleErr.code === 'stale_base' && staleErr.current_version === 3
  && staleErr.current_environment === 'staging' && staleErr.since?.[0]?.version === 3 && staleErr.since[0].note === 'New menu' && staleErr.message.includes('"base_version": 3'), JSON.stringify(staleRes.body));
check('a bad base_version is refused', (await tool('deploy_app', { app: APP, base_version: 'two', files: [{ path: 'index.html', content: 'x' }] })).data.error === 'bad_base_version');
// Getting the files back: a small version inline, ready to change and deploy on top of.
const pulled = await tool('get_files', { app: APP });
check('get_files returns the current version inline', !pulled.isError && pulled.data.version === 3 && pulled.data.environment === 'staging'
  && pulled.data.files.length === 1 && pulled.data.files[0].path === 'index.html' && pulled.data.files[0].content === '<h1>v3</h1>' && /^[0-9a-f]{64}$/.test(pulled.data.files[0].sha256) && pulled.data.next_step.includes('"base_version": 3')
  && JSON.stringify(pulled.data.others_editing) === '[]' && !pulled.data.warning, JSON.stringify(pulled.data));
check('get_files gives an older version by number', (await tool('get_files', { app: APP, version: 1 })).data.files?.some(f => f.path === 'index.html' && f.content.includes('v1')));
// ---------- patch deploys: send only what changed; a stale base is merged per file ----------
const LINES = Array.from({ length: 12 }, (_, i) => `line ${i + 1}`).join('\n') + '\n';
const pf = await tool('deploy_app', { name: 'Patchy', files: [{ path: 'index.html', content: '<h1>patchy v1</h1>' }, { path: 'notes.txt', content: LINES }, { path: 'old.txt', content: 'to delete' }] });
const PA = pf.data.app;
check('a full deploy makes version 1 of a new app', !pf.isError && pf.data.version === 1, JSON.stringify(pf.data));
const pfiles = await tool('get_files', { app: PA });
const shaOf = path => pfiles.data.files.find(f => f.path === path)?.sha256;
check('get_files lists a sha256 and size for every file', pfiles.data.files.length === 3 && pfiles.data.files.every(f => /^[0-9a-f]{64}$/.test(f.sha256) && f.size > 0), JSON.stringify(pfiles.data.files));
const p2 = await tool('deploy_app', { app: PA, base_version: 1, changes: { 'index.html': { content: '<h1>patchy v2</h1>' } } });
check('a one-file patch deploy makes version 2', !p2.isError && p2.data.version === 2 && p2.data.based_on === 1 && p2.data.patch?.stale_base === false, JSON.stringify(p2.data));
const p2files = await tool('get_files', { app: PA });
check('the patch kept every other file and changed the one', p2files.data.files.length === 3 && p2files.data.files.find(f => f.path === 'index.html').content === '<h1>patchy v2</h1>'
  && p2files.data.files.find(f => f.path === 'notes.txt').content === LINES, JSON.stringify(p2files.data.files));
const unknown = await alice.api('/v1/deploys', { json: { app: PA, base_version: 2, changes: { 'x.txt': { sha256: 'a'.repeat(64) } } } });
check('a patch naming an unknown sha256 is refused with the missing hashes', unknown.status === 422 && unknown.body.error?.code === 'unknown_blobs' && unknown.body.error.missing?.includes('a'.repeat(64)), JSON.stringify(unknown.body));
const noBase = await alice.api('/v1/deploys', { json: { app: PA, changes: { 'x.txt': { content: 'x' } } } });
check('a patch without base_version is refused', noBase.status === 400, JSON.stringify(noBase.body));
const bySha = await tool('deploy_app', { app: PA, base_version: 2, changes: { 'copy.txt': { sha256: shaOf('notes.txt') }, 'logo.bin': { content_base64: Buffer.from([0, 1, 2, 3]).toString('base64') } }, deletes: ['old.txt'] });
check('a patch can reuse a known sha256, add a binary file and delete a path', !bySha.isError && bySha.data.version === 3, JSON.stringify(bySha.data));
const p3 = await tool('get_files', { app: PA });
check('the new version has copy.txt and logo.bin and no old.txt', p3.data.files.map(f => f.path).sort().join() === 'copy.txt,index.html,logo.bin,notes.txt'
  && p3.data.files.find(f => f.path === 'copy.txt').content === LINES, JSON.stringify(p3.data.files.map(f => f.path)));
// Stale base: two people start from version 3.
const mineText = LINES.replace('line 2\n', 'line 2 mine\n');
const theirText = LINES.replace('line 11\n', 'line 11 theirs\n');
const theirs = await tool('deploy_app', { app: PA, base_version: 3, changes: { 'notes.txt': { content: theirText } } });
const merged = await tool('deploy_app', { app: PA, base_version: 3, changes: { 'notes.txt': { content: mineText }, 'extra.txt': { content: 'mine' } } });
check('a stale-base patch touching other lines is merged onto the newer version', !theirs.isError && !merged.isError && merged.data.version === 5 && merged.data.patch?.stale_base === true && merged.data.patch.merged?.includes('notes.txt'), JSON.stringify([theirs.data, merged.data]));
const mergedNotes = (await tool('get_files', { app: PA })).data.files.find(f => f.path === 'notes.txt').content;
check('the merged file has both edits', mergedNotes.includes('line 2 mine') && mergedNotes.includes('line 11 theirs'), mergedNotes);
const before = (await tool('get_status', { app: PA })).data.current_version;
const clash = await alice.api('/v1/deploys', { json: { app: PA, base_version: 3, changes: { 'notes.txt': { content: LINES.replace('line 2\n', 'line 2 other\n') } } } });
const conflict = clash.body.error?.conflicts?.[0];
check('a stale-base patch that clashes is refused with 409 and the conflicting hunks', clash.status === 409 && clash.body.error?.code === 'merge_conflict' && conflict?.path === 'notes.txt'
  && conflict.hunks?.length === 1 && conflict.hunks[0].incoming.includes('line 2 other') && conflict.hunks[0].current.includes('line 2 mine'), JSON.stringify(clash.body));
check('and nothing was deployed', (await tool('get_status', { app: PA })).data.current_version === before);
const since = await tool('get_files', { app: PA, since: 1 });
check('get_files since=<version> returns only what changed', !since.isError && since.data.files.some(f => f.path === 'index.html') && JSON.stringify(since.data).includes('old.txt'), JSON.stringify(since.data).slice(0, 600));
const dv = await tool('diff_versions', { app: PA, from: 1, to: 2 });
check('diff_versions returns a unified diff', !dv.isError && dv.data.diff.includes('-<h1>patchy v1</h1>') && dv.data.diff.includes('+<h1>patchy v2</h1>'), JSON.stringify(dv.data).slice(0, 400));
const rbp = await tool('rollback', { app: PA, version: 1 });
check('rollback still works on a patched app', !rbp.isError && rbp.data.live_version === 1, JSON.stringify(rbp.data));
const rbFiles = await tool('get_files', { app: PA, version: 1 });
check('and version 1 still reads back from the manifest', rbFiles.data.files?.length === 3 && rbFiles.data.files.some(f => f.path === 'index.html' && f.content.includes('patchy v1')), JSON.stringify(rbFiles.data).slice(0, 300));


// ---------- git: export as a repository, clone over smart HTTP, import work back ----------
{
  const SECRET = `s3cret-${run}`;
  const gd = await tool('deploy_app', { name: 'Gitty', files: [{ path: 'index.html', content: '<h1>gitty v1</h1>\n' }, { path: 'css/app.css', content: 'body{color:red}\n' }, { path: 'notes.txt', content: LINES }] });
  const GA = gd.data.app;
  await tool('set_secret', { app: GA, name: 'API_KEY', value: SECRET });
  const g2 = await tool('deploy_app', { app: GA, environment: 'production', base_version: 1, changes: { 'index.html': { content: '<h1>gitty v2</h1>\n' } }, note: 'Second look' });
  const g3 = await tool('deploy_app', { app: GA, base_version: 2, changes: { 'notes.txt': { content: LINES.replace('line 11\n', 'line 11 staged\n') } } });
  check('git section: two live versions and one on staging', gd.data.version === 1 && g2.data.version === 2 && g3.data.version === 3 && g3.data.environment === 'staging', JSON.stringify([g2.data, g3.data]).slice(0, 400));
  const gdir = mkdtempSync(join(tmpdir(), 'gitty-'));
  const env = { ...process.env, GIT_TERMINAL_PROMPT: '0', GIT_CONFIG_GLOBAL: '/dev/null', GIT_CONFIG_SYSTEM: '/dev/null', GIT_AUTHOR_NAME: 'Local Dev', GIT_AUTHOR_EMAIL: 'dev@example.test', GIT_COMMITTER_NAME: 'Local Dev', GIT_COMMITTER_EMAIL: 'dev@example.test' };
  const git = (cwd, args) => execSync(`git ${args}`, { cwd, env, stdio: ['ignore', 'pipe', 'pipe'] }).toString();
  const gitTry = (cwd, args) => { try { return { ok: true, out: git(cwd, args) }; } catch (e) { return { ok: false, out: String(e.stderr ?? e) }; } };
  const cloneUrl = `${api.protocol}//agent:${agent.body.token}@${api.host}/v1/apps/${GA}.git`;

  const unauth = await fetch(`${API}/v1/apps/${GA}.git/info/refs?service=git-upload-pack`);
  check('git: a clone without a token is challenged for Basic credentials', unauth.status === 401 && /basic/i.test(unauth.headers.get('www-authenticate') ?? ''), String(unauth.status));
  const push = await fetch(`${API}/v1/apps/${GA}.git/info/refs?service=git-receive-pack`, { headers: { authorization: `Bearer ${agent.body.token}` } });
  check('git: pushing is refused with 403', push.status === 403, String(push.status));
  const adv = await fetch(`${API}/v1/apps/${GA}.git/info/refs?service=git-upload-pack`, { headers: { authorization: `Bearer ${agent.body.token}` } });
  check('git: a Bearer token reads the advertisement', adv.status === 200 && /git-upload-pack-advertisement/.test(adv.headers.get('content-type') ?? ''), String(adv.status));

  const cloned = join(gdir, 'smart');
  const cl = gitTry(gdir, `clone ${cloneUrl} smart`);
  check('git: git clone over smart HTTP with a token works', cl.ok, cl.out);
  if (cl.ok) {
    check('git: the clone checks out main, the live version', readFileSync(join(cloned, 'index.html'), 'utf8') === '<h1>gitty v2</h1>\n' && git(cloned, 'rev-parse --abbrev-ref HEAD').trim() === 'main');
    check('git: every version is a tag and staging is a branch', git(cloned, 'tag').trim().split('\n').join() === 'v1,v2,v3' && git(cloned, 'rev-parse --verify origin/staging').trim().length === 40);
    check('git: staging holds the staged file', git(cloned, 'show origin/staging:notes.txt').includes('line 11 staged'));
    check('git: a version is a commit with its note, a trailer and a noreply author', git(cloned, 'log -1 --format=%B%n%ae v2').includes('Second look') && git(cloned, 'log -1 --format=%B v2').includes('Brod-Version: 2') && /@users\.noreply\./.test(git(cloned, 'log -1 --format=%ae v2')), git(cloned, 'log -1 --format=%B%n%ae v2'));
    check('git: v1 is the root and v2 its child', git(cloned, 'rev-list --count v2').trim() === '2' && git(cloned, 'rev-list --count v1').trim() === '1');
    const everything = git(cloned, 'log --all -p') + git(cloned, 'ls-files');
    check('git: no secret appears anywhere in the exported history', !everything.includes(SECRET) && !everything.includes('API_KEY'));
  }

  // The bundle, from an address and from the API.
  const ex = await tool('export_app', { app: GA, format: 'git-bundle' });
  check('export_app returns a download address and a clone address', !ex.isError && /\/v1\/downloads\//.test(ex.data.download_url) && ex.data.clone_url?.endsWith(`${GA}.git`), JSON.stringify(ex.data));
  const dl = await fetch(ex.data.download_url.replace(/^https?:\/\/[^/]+/, API));
  const bundleBytes = Buffer.from(await dl.arrayBuffer());
  const direct = await fetch(`${API}/v1/apps/${GA}/export.bundle`, { headers: { authorization: `Bearer ${agent.body.token}` } });
  const directBytes = Buffer.from(await direct.arrayBuffer());
  check('the export is a git bundle v2, the same twice', dl.status === 200 && bundleBytes.subarray(0, 16).toString() === '# v2 git bundle\n' && direct.status === 200 && directBytes.equals(bundleBytes), `${dl.status} ${direct.status}`);
  const bfile = join(gdir, 'gitty.bundle'); writeFileSync(bfile, bundleBytes);
    const fromBundle = join(gdir, 'work');
  const bc = gitTry(gdir, `clone ${bfile} work`);
  check('git clone of the bundle works and has the same history as the smart HTTP clone', bc.ok && (!cl.ok || git(fromBundle, 'rev-parse v2').trim() === git(cloned, 'rev-parse v2').trim()), bc.out);

  if (bc.ok) {
    const bv = gitTry(fromBundle, `bundle verify ${bfile}`);
    check('git bundle verify accepts it', bv.ok, bv.out);
    // Work locally and import it back: it lands on staging, merged with what is there.
    git(fromBundle, 'checkout -q -b mine');
    writeFileSync(join(fromBundle, 'css', 'app.css'), 'body{color:blue}\n');
    git(fromBundle, 'commit -q -am "Blue please"');
    const mine = join(gdir, 'mine.bundle');
    git(fromBundle, `bundle create ${mine} mine main v1 v2 v3`);
    const imp = await fetch(`${API}/v1/apps/${GA}/import?ref=mine`, { method: 'POST', headers: { authorization: `Bearer ${agent.body.token}`, 'content-type': 'application/x-git-bundle' }, body: readFileSync(mine) });
    const impBody = await imp.json();
    check('importing a bundle makes a new staging version based on the commit it came from', imp.status === 201 && impBody.version === 4 && impBody.environment === 'staging' && impBody.merge_base?.version === 2 && !impBody.warning, JSON.stringify(impBody).slice(0, 500));
    const after = await tool('get_files', { app: GA, version: 4 });
    const af = Object.fromEntries((after.data.files ?? []).map(f => [f.path, f.content]));
    check('the import is merged with what was on staging', af['css/app.css'] === 'body{color:blue}\n' && af['notes.txt']?.includes('line 11 staged') && af['index.html'] === '<h1>gitty v2</h1>\n', JSON.stringify(af).slice(0, 300));
    const again = await fetch(`${API}/v1/apps/${GA}/import?ref=mine`, { method: 'POST', headers: { authorization: `Bearer ${agent.body.token}`, 'content-type': 'application/x-git-bundle' }, body: readFileSync(mine) });
    const againBody = await again.json();
    check('importing the same commit again changes nothing', again.status === 201 && againBody.unchanged === true && againBody.version === 4, JSON.stringify(againBody).slice(0, 300));

    // The same through import_app's upload address.
    git(fromBundle, 'checkout -q -b more');
    writeFileSync(join(fromBundle, 'index.html'), '<h1>gitty from upload</h1>\n');
    git(fromBundle, 'commit -q -am "Upload route"');
    const more = join(gdir, 'more.bundle');
    git(fromBundle, `bundle create ${more} more main v1 v2 v3`);
    const ticket = await tool('import_app', { app: GA, ref: 'more' });
    check('import_app without a url gives an upload address', !ticket.isError && /\/v1\/uploads\//.test(ticket.data.upload_url ?? ''), JSON.stringify(ticket.data));
    const up = await fetch(ticket.data.upload_url.replace(/^https?:\/\/[^/]+/, API), { method: 'PUT', body: readFileSync(more) });
    const upBody = await up.json();
    check('uploading the bundle imports it into staging', up.status === 201 && upBody.environment === 'staging' && upBody.version === 5 && upBody.imported_commit?.length === 40, JSON.stringify(upBody).slice(0, 400));

    // A bundle with a symlink is refused, naming the path.
    git(fromBundle, 'checkout -q -b linky main');
    execSync('ln -s index.html link', { cwd: fromBundle });
    git(fromBundle, 'add link'); git(fromBundle, 'commit -q -m "A link"');
    const linky = join(gdir, 'linky.bundle');
    git(fromBundle, `bundle create ${linky} linky main v1 v2 v3`);
    const sl = await fetch(`${API}/v1/apps/${GA}/import?ref=linky`, { method: 'POST', headers: { authorization: `Bearer ${agent.body.token}`, 'content-type': 'application/x-git-bundle' }, body: readFileSync(linky) });
    const slBody = await sl.json();
    check('importing a bundle with a symlink is refused and names the path', sl.status === 422 && slBody.error?.code === 'git_symlink' && slBody.error.message.includes('"link"'), JSON.stringify(slBody));
  }

  // A repository on this machine is not reachable by address.
  const local = await fetch(`${API}/v1/apps/${GA}/import`, { method: 'POST', headers: { authorization: `Bearer ${agent.body.token}`, 'content-type': 'application/json' }, body: JSON.stringify({ url: 'http://10.0.0.1/repo.git' }) });
  const localBody = await local.json();
  check('importing from a private address is refused by the outbound guard', local.status === 400 && localBody.error?.code === 'blocked_url', JSON.stringify(localBody));
  const meta = await tool('import_app', { app: GA, url: 'http://169.254.169.254/latest' });
  check('import_app refuses a metadata address', meta.isError === true, JSON.stringify(meta.data));
}

// ---------- git mirror and inbound sync: a local bare repository behind git http-backend ----------
{
  const { createHmac } = await import('node:crypto');
  const { spawn } = await import('node:child_process');
  const mdir = mkdtempSync(join(tmpdir(), 'mirror-'));
  const genv = { ...process.env, GIT_TERMINAL_PROMPT: '0', GIT_CONFIG_GLOBAL: '/dev/null', GIT_CONFIG_SYSTEM: '/dev/null', GIT_AUTHOR_NAME: 'Remote Dev', GIT_AUTHOR_EMAIL: 'remote@example.test', GIT_COMMITTER_NAME: 'Remote Dev', GIT_COMMITTER_EMAIL: 'remote@example.test' };
  const git = (cwd, args) => execSync(`git ${args}`, { cwd, env: genv, stdio: ['ignore', 'pipe', 'pipe'] }).toString();
  const bare = name => { const p = join(mdir, name); mkdirSync(p); git(p, 'init -q --bare -b main'); git(p, 'config http.receivepack true'); return p; };
  const seen = [];
  const srv = http.createServer((req, res) => {
    seen.push(`${req.method} ${req.url} ${req.headers.authorization ? 'auth' : 'anon'}`);
    const u = new URL(req.url, 'http://x');
    const cgi = spawn('git', ['http-backend'], { env: { ...genv, GIT_PROJECT_ROOT: mdir, GIT_HTTP_EXPORT_ALL: '1', REQUEST_METHOD: req.method, PATH_INFO: u.pathname, QUERY_STRING: u.search.slice(1), CONTENT_TYPE: req.headers['content-type'] ?? '', CONTENT_LENGTH: req.headers['content-length'] ?? '', REMOTE_USER: 'brod', REMOTE_ADDR: '127.0.0.1', HTTP_CONTENT_ENCODING: req.headers['content-encoding'] ?? '' } });
    req.pipe(cgi.stdin);
    const chunks = [];
    cgi.stdout.on('data', c => chunks.push(c));
    cgi.stdout.on('end', () => {
      const out = Buffer.concat(chunks);
      const cut = out.indexOf('\r\n\r\n');
      const head = out.subarray(0, cut).toString().split('\r\n');
      let status = 200; const headers = {};
      for (const l of head) { const i = l.indexOf(':'); const k = l.slice(0, i).toLowerCase(), v = l.slice(i + 1).trim(); if (k === 'status') status = parseInt(v, 10); else headers[k] = v; }
      res.writeHead(status, headers); res.end(out.subarray(cut + 4));
    });
  });
  await new Promise(r => srv.listen(0, '127.0.0.1', r));
  const base = `http://127.0.0.1:${srv.address().port}`;
  const until = async (fn, ms = 40000) => { const t0 = Date.now(); for (;;) { try { const v = await fn(); if (v) return v; } catch {} if (Date.now() - t0 > ms) return null; await new Promise(r => setTimeout(r, 300)); } };
  const tryGit = (cwd, args) => { try { return git(cwd, args).trim(); } catch { return ''; } };

  const remote = bare('one.git');
  const md = await tool('deploy_app', { name: 'Mirrored', files: [{ path: 'index.html', content: '<h1>m1</h1>\n' }, { path: 'notes.txt', content: LINES }] });
  const MA = md.data.app;
  const bad = await tool('set_git_mirror', { app: MA, url: 'ftp://example.com/x.git', token: 'tok' });
  check('set_git_mirror refuses a non-https address', bad.isError === true, JSON.stringify(bad.data));
  const cfg = await tool('set_git_mirror', { app: MA, url: `${base}/one.git`, token: 'mirror-token-xyz', sync_inbound: true });
  check('set_git_mirror enables the mirror and shows the webhook secret once', !cfg.isError && /^whsec_/.test(cfg.data.webhook_secret ?? '') && !!cfg.data.webhook_url, JSON.stringify(cfg.data));
  const SECRET_WH = cfg.data.webhook_secret;
  const whUrl = cfg.data.webhook_url.replace(/^https?:\/\/[^/]+/, API);
  const shown = await tool('get_git_mirror', { app: MA });
  const shownText = JSON.stringify(shown.data);
  check('get_git_mirror never shows the token or the webhook secret', !shown.isError && !shownText.includes('mirror-token-xyz') && !shownText.includes(SECRET_WH) && shown.data.token === 'set', shownText.slice(0, 400));

  const tagged = await until(() => tryGit(remote, 'tag').split('\n').includes('v1') && tryGit(remote, 'rev-parse --verify main'));
  check('the mirror pushes main and the tag v1 to the remote after setup', !!tagged, seen.slice(-5).join(' | '));
  check('the push carries the token as Basic auth', seen.some(s => s.startsWith('POST') && s.includes('git-receive-pack') && s.endsWith('auth')), seen.join(' | '));
  const d2m = await tool('deploy_app', { app: MA, environment: 'production', base_version: 1, changes: { 'index.html': { content: '<h1>m2</h1>\n' } }, note: 'Second' });
  const gotV2 = await until(() => tryGit(remote, 'tag').split('\n').includes('v2') && tryGit(remote, 'show main:index.html') === '<h1>m2</h1>');
  check('a new live version is pushed: main moves, tag v2 appears', d2m.data.version === 2 && !!gotV2, tryGit(remote, 'tag'));
  const st1 = await until(async () => { const s = await tool('get_status', { app: MA }); return s.data.git_mirror?.status === 'ok' && s.data; });
  check('get_status shows git_mirror status ok with a push time', !!st1 && !!st1.git_mirror.last_push_at, JSON.stringify(st1?.git_mirror));
  const v1tag = tryGit(remote, 'rev-parse v1');

  // Inbound: a commit pushed to the remote's main and a signed webhook land on staging.
  const work = join(mdir, 'work'); git(mdir, `clone -q -b main ${remote} work`);
  writeFileSync(join(work, 'css.css'), 'body{margin:0}\n'); git(work, 'add .'); git(work, 'commit -q -m "Add css"'); git(work, 'push -q origin HEAD:main');
  const push1 = JSON.stringify({ ref: 'refs/heads/main', after: git(work, 'rev-parse HEAD').trim(), commits: [] });
  const sign = (body, key = SECRET_WH) => 'sha256=' + createHmac('sha256', key).update(body).digest('hex');
  const post = (body, headers) => fetch(whUrl, { method: 'POST', headers: { 'content-type': 'application/json', 'x-github-event': 'push', ...headers }, body });
  const noSig = await post(push1, {});
  const wrongSig = await post(push1, { 'x-hub-signature-256': sign(push1, 'whsec_wrong') });
  check('a webhook with no or a wrong signature is refused with 401', noSig.status === 401 && wrongSig.status === 401, `${noSig.status} ${wrongSig.status}`);
  const before = (await tool('get_status', { app: MA })).data.versions.length;
  const okSig = await post(push1, { 'x-hub-signature-256': sign(push1) });
  check('a signed push webhook is accepted with 202', okSig.status === 202, String(okSig.status));
  const imported = await until(async () => { const s = await tool('get_status', { app: MA }); return s.data.versions.length === before + 1 && s.data; });
  check('the pushed commit becomes a new staging version', !!imported, JSON.stringify((await tool('get_status', { app: MA })).data.versions));
  const stagedV = imported ? imported.versions.find(v => v.staging) : null;
  const sf = stagedV ? await tool('get_files', { app: MA, version: stagedV.version }) : null;
  check('the staging version has the remote change and the live files', !!sf && (sf.data.files ?? []).some(f => f.path === 'css.css') && (sf.data.files ?? []).some(f => f.content === '<h1>m2</h1>\n'), JSON.stringify(sf?.data).slice(0, 300));
  const other = JSON.stringify({ ref: 'refs/heads/feature', after: 'a'.repeat(40) });
  const ign = await post(other, { 'x-hub-signature-256': sign(other) });
  const ping = await post('{}', { 'x-hub-signature-256': sign('{}'), 'x-github-event': 'ping' });
  check('a push to another branch, and a ping, are accepted and ignored', ign.status === 202 && ping.status === 202, `${ign.status} ${ping.status}`);
  const gl = await fetch(whUrl, { method: 'POST', headers: { 'content-type': 'application/json', 'x-gitlab-event': 'Push Hook', 'x-gitlab-token': 'nope' }, body: push1 });
  check('a wrong GitLab token is refused with 401', gl.status === 401, String(gl.status));

  // Loop prevention: Brod's own pushes (staging branch, tags) bring no new version. Repeat the webhook for the same commit too.
  await new Promise(r => setTimeout(r, 4000));
  await post(push1, { 'x-hub-signature-256': sign(push1) });
  await new Promise(r => setTimeout(r, 3000));
  const afterAll = (await tool('get_status', { app: MA })).data.versions.length;
  check('Brod\'s own pushes and a repeated webhook are not re-imported', afterAll === before + 1, `${before} -> ${afterAll}`);
  check('the staging version was mirrored to the remote staging branch', !!(await until(() => tryGit(remote, 'rev-parse --verify staging'))));
  check('an existing tag is never moved', tryGit(remote, 'rev-parse v1') === v1tag);

  // Conflict: staging and the remote change the same line from the same base.
  const base2 = git(remote, 'rev-parse main').trim();
  const work2 = join(mdir, 'work2'); git(mdir, `clone -q -b main ${remote} work2`);
  const cur = (await tool('get_status', { app: MA })).data.versions.find(v => v.staging)?.version;
  const sc = await tool('deploy_app', { app: MA, base_version: cur, changes: { 'notes.txt': { content: LINES.replace('line 5\n', 'line 5 from brod\n') } } });
  check('staging takes an edit of line 5', !sc.isError, JSON.stringify(sc.data));
  await until(async () => (await tool('get_git_mirror', { app: MA })).data.status === 'ok');
  writeFileSync(join(work2, 'notes.txt'), LINES.replace('line 5\n', 'line 5 from remote\n')); git(work2, 'commit -q -am "Remote edit"');
  git(work2, 'push -q origin HEAD:main');
  const push2 = JSON.stringify({ ref: 'refs/heads/main', after: git(work2, 'rev-parse HEAD').trim() });
  const vCount = (await tool('get_status', { app: MA })).data.versions.length;
  await post(push2, { 'x-hub-signature-256': sign(push2) });
  const conflict = await until(async () => { const g = await tool('get_git_mirror', { app: MA }); return g.data.inbound?.status === 'conflict' && g.data; });
  check('a conflicting edit sets the inbound status to conflict and names the path', !!conflict && JSON.stringify(conflict.inbound.conflicts).includes('notes.txt'), JSON.stringify(conflict?.inbound));
  check('a conflict creates no version', (await tool('get_status', { app: MA })).data.versions.length === vCount);
  check('a conflict is in the sync history', !!conflict && (conflict.recent_sync ?? []).some(e => e.result === 'conflict'), JSON.stringify(conflict?.recent_sync));
  void base2;

  // Diverged remote: Brod will not force. The remote's own commit stays.
  const rem2 = bare('two.git');
  const w3 = join(mdir, 'w3'); mkdirSync(w3); git(w3, 'init -q -b main'); writeFileSync(join(w3, 'theirs.txt'), 'theirs\n'); git(w3, 'add .'); git(w3, 'commit -q -m "Theirs"'); git(w3, `push -q ${rem2} main`);
  const theirs = git(rem2, 'rev-parse main').trim();
  const mb = await tool('deploy_app', { name: 'Diverging', files: [{ path: 'index.html', content: 'd1' }] });
  const MB = mb.data.app;
  const cfg2 = await tool('set_git_mirror', { app: MB, url: `${base}/two.git`, token: 'other-token' });
  check('a second mirror is configured', !cfg2.isError, JSON.stringify(cfg2.data));
  const div = await until(async () => { const g = await tool('get_git_mirror', { app: MB }); return g.data.status === 'diverged' && g.data; });
  check('a remote branch with unknown history gives status diverged with a message', !!div && /diverg|force|history/i.test(div.error ?? ''), JSON.stringify(div));
  check('the diverged remote branch is untouched', git(rem2, 'rev-parse main').trim() === theirs);
  check('get_status shows the diverged mirror', (await tool('get_status', { app: MB })).data.git_mirror?.status === 'diverged');

  // Who may configure it, and removal.
  const gm = await alice.api(`/v1/apps/${MA}/git-mirror`, { method: 'GET' });
  check('GET /git-mirror returns the settings without secrets', gm.status === 200 && !JSON.stringify(gm.body).includes('mirror-token-xyz'), JSON.stringify(gm.body).slice(0, 300));
  const del = await tool('set_git_mirror', { app: MB, enabled: false });
  check('a mirror can be switched off', !del.isError && (await tool('get_git_mirror', { app: MB })).data.status === 'disabled', JSON.stringify(del.data));
  srv.close();
}

await tool('publish_staging', { app: APP, discard: true });
const etag = (await anon.go(url + '/assets/app.js')).headers.etag;
check('unchanged file answers 304', (await anon.go(url + '/assets/app.js', { headers: { 'if-none-match': etag } })).status === 304);

// ---------- 4b. takedown by the platform operator ----------

const down = await admin(`apps/${W}/${d2.data.app}/takedown`, { reason: 'Reported as phishing' });
check('the operator takes an app down', down.status === 200 && down.body.taken_down === true, JSON.stringify(down.body));
const downPage = await alice.go(d2.data.url + '/');
check('a taken-down app answers 410 with a neutral page, even for its owner', downPage.status === 410 && downPage.body.includes('This app has been taken down') && !downPage.body.includes('phishing'));
const downResume = await tool('set_paused', { app: d2.data.app, paused: false });
const downDeploy = await tool('deploy_app', { app: d2.data.app, files: [{ path: 'index.html', content: 'again' }] });
const downWiden = await tool('set_access', { app: d2.data.app, access: 'public' });
check('resume, deploy and widening access are refused while it is down', [downResume, downDeploy, downWiden].every(r => r.isError && r.data.error === 'taken_down'),
  JSON.stringify([downResume.data, downDeploy.data, downWiden.data]));
const downStatus = await tool('get_status', { app: d2.data.app });
check('get_status shows the takedown and its reason', downStatus.data.taken_down?.reason === 'Reported as phishing', JSON.stringify(downStatus.data.taken_down));
await admin(`apps/${W}/${d2.data.app}/restore`);
const upAgain = await alice.open(d2.data.url + '/');
check('restoring brings it back', upAgain.status === 200 && upAgain.body.includes('second') && !(await tool('get_status', { app: d2.data.app })).data.taken_down);
const reports = await admin('reports?status=open', undefined, 'GET');
check('the operator lists open reports by status', reports.status === 200 && reports.body.reports.every(r => r.status === 'open'), JSON.stringify(reports.body).slice(0, 300));

// ---------- 5. status, audit log, plan limit, errors an agent can act on ----------

const st = await tool('get_status', { app: APP });
check('get_status lists the three versions and marks v1 live', st.data.versions?.length === 3 && st.data.versions.find(v => v.version === 1).live === true
  && st.data.versions.find(v => v.version === 3).based_on === 1);
// A larger version comes as a download address that `curl | tar` unpacks.
const many = [{ path: 'index.html', content: '<h1>many</h1>' }, { path: `deep/${'a'.repeat(120)}.txt`, content: 'long path' }, ...Array.from({ length: 205 }, (_, i) => ({ path: `p/${i}.txt`, content: `page ${i}` }))];
const big = await tool('deploy_app', { app: APP, base_version: 1, files: many });
const bigFiles = (await tool('get_files', { app: APP, version: big.data.version })).data;
const into = mkdtempSync(join(tmpdir(), 'pull-'));
let unpacked = '';
try { execSync(`curl -sS --fail "${bigFiles.download_url}" | tar -xzf - -C ${into}`); unpacked = readFileSync(join(into, 'deep', `${'a'.repeat(120)}.txt`), 'utf8') + '|' + readFileSync(join(into, 'p', '204.txt'), 'utf8'); } catch (e) { unpacked = String(e); }
check('get_files gives a larger version as a download that curl | tar unpacks', !big.isError && bigFiles.file_count === 207 && !bigFiles.files && unpacked === 'long path|page 204', `${unpacked} ${JSON.stringify(bigFiles).slice(0, 300)}`);
await tool('publish_staging', { app: APP, discard: true });
const lg = await tool('get_logs', { app: APP });
check('get_logs attributes actions to the agent connection and the confirming person', lg.data.events.some(e => e.action === 'rollback' && e.by === 'claude-code') && lg.data.events.some(e => e.action === 'access' && e.by === alice.email));
const audit = await alice.api('/v1/events?action=refused');
check('one audit log across the workspace records refused sign-ins', audit.status === 200 && audit.body.events.some(e => e.detail.includes(bob.email)));
const noIndex = await tool('deploy_app', { name: 'Broken', files: [{ path: 'main.py', content: 'print(1)' }] });
check('bundle without index.html is refused with a clear reason', noIndex.isError && noIndex.data.error === 'no_index', JSON.stringify(noIndex.data));
// Deploy apps until the free plan's allowance runs out.
let fourth;
for (let i = 3; i <= 20; i++) {
  fourth = await tool('deploy_app', { name: `Filler ${i} ${run}`, files: [{ path: 'index.html', content: String(i) }] });
  if (fourth.isError) break;
}
check('an app over the free plan is refused with the count and a way out', fourth.isError && fourth.data.error === 'plan_limit' && fourth.data.app_limit === 10 && fourth.data.upgrade_url, JSON.stringify(fourth.data));
const paused = await tool('set_paused', { app: APP, paused: true });
check('pause frees a slot and visitors see the paused page', !paused.isError && (await anon.go(url + '/')).status === 503);
const fourth2 = await tool('deploy_app', { name: 'Fourth', files: [{ path: 'index.html', content: '4' }] });
check('a new app deploys once a slot is free', !fourth2.isError && fourth2.data.version === 1, JSON.stringify(fourth2.data));
const resume = await tool('set_paused', { app: APP, paused: false });
check('resume is refused while the plan is full', resume.isError && resume.data.error === 'plan_limit');

// ---------- 6. isolation and revoking ----------

const mallory = new Browser(`mallory-${run}@other.test`);
await mallory.signIn();
await mallory.api('/v1/workspaces', { json: { name: `Other ${run}`, accept_terms: true } });
check('another workspace cannot see or touch the app', (await mallory.api(`/v1/apps/${APP}`)).status === 404);
const conns = await alice.api('/v1/tokens');
const id = conns.body.connections.find(t => t.name === 'claude-code').id;
await alice.api(`/v1/tokens/${id}`, { method: 'DELETE' });
const after = await fetch(`${API}/mcp`, { method: 'POST', headers: { authorization: `Bearer ${agent.body.token}`, 'content-type': 'application/json' }, body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list' }) });
check('a revoked agent connection is locked out', after.status === 401);
check('no token at all is refused', (await fetch(`${API}/v1/apps`)).status === 401);

// ---------- 6b. agents sign in with OAuth; the connections page ----------

const unauth = await fetch(`${API}/mcp`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'ping' }) });
const metaUrl = /resource_metadata="([^"]+)"/.exec(unauth.headers.get('www-authenticate') ?? '')?.[1];
check('an MCP client without a token is pointed at the sign-in metadata', unauth.status === 401 && metaUrl === `${API}/.well-known/oauth-protected-resource/mcp`, unauth.headers.get('www-authenticate'));
const prm = await (await fetch(metaUrl)).json();
const asm = await (await fetch(`${prm.authorization_servers[0]}/.well-known/oauth-authorization-server`)).json();
check('the metadata names this server, PKCE S256 and client registration', prm.resource === `${API}/mcp` && asm.issuer === API && asm.code_challenge_methods_supported.includes('S256') && !!asm.registration_endpoint);
const regBad = await fetch(asm.registration_endpoint, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ redirect_uris: ['http://evil.test/cb'] }) });
check('a client cannot register a plain-http address off this machine', regBad.status === 400);
const reg = await (await fetch(asm.registration_endpoint, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ redirect_uris: ['http://127.0.0.1/callback'], client_name: 'E2E agent' }) })).json();
const b64u = b => Buffer.from(b).toString('base64url');
const verifier = b64u(crypto.getRandomValues(new Uint8Array(32)));
const challenge = b64u(new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier))));
const cb = 'http://127.0.0.1:40123/callback';
const authz = { response_type: 'code', client_id: reg.client_id, redirect_uri: cb, state: 's1', code_challenge: challenge, code_challenge_method: 'S256' };
const authzPath = `/oauth/authorize?${new URLSearchParams(authz)}`;
const toSignIn = await new Browser('nobody').go(authzPath);
check('authorizing without a session goes to sign-in and back', toSignIn.status === 302 && toSignIn.headers.location === `/auth/signin?return=${encodeURIComponent(authzPath)}`, toSignIn.headers.location);
const strangerB = new Browser(`stranger-${run}@else.test`); await strangerB.signIn();
check('a person who builds in no workspace cannot connect an agent', (await strangerB.go(authzPath)).status === 403);
// Someone with no account starts from their agent, signs up, makes a workspace, and lands back on the consent page.
const htmlAttr = t => t.replaceAll('&', '&amp;');
const authzBack = encodeURIComponent(authzPath);
const newcomerB = new Browser(`newcomer-${run}@else.test`);
check('the sign-in page offers sign-up without losing the agent', (await newcomerB.go(`/auth/signin?return=${authzBack}`)).body.includes(`href="/auth/signup?return=${authzBack}"`));
const signUpBack = await newcomerB.go(`/auth/signup?return=${authzBack}`);
check('the sign-up page keeps where the agent was going', signUpBack.status === 200 && signUpBack.body.includes(`name="return" value="${htmlAttr(authzPath)}"`) && signUpBack.body.includes(`href="/auth/signin?return=${authzBack}"`));
await newcomerB.signIn();
const noWorkspace = await newcomerB.go(authzPath);
check('with no workspace, consent links to making one and coming back', noWorkspace.status === 403 && noWorkspace.body.includes(`href="/new?return=${htmlAttr(authzBack)}"`));
const newForm = await newcomerB.go(`/new?return=${authzBack}`);
check('the new-workspace form keeps where the agent was going', newForm.status === 200 && newForm.body.includes(`name="return" value="${htmlAttr(authzPath)}"`));
const madeBack = await newcomerB.go('/new', { form: { name: `Newcomer ${run}`, accept_terms: '1', return: authzPath } });
check('making the workspace returns to the agent\'s consent page', madeBack.status === 302 && madeBack.headers.location === authzPath, madeBack.headers.location);
check('the consent page now offers the new workspace', (await newcomerB.go(authzPath)).body.includes('Connect E2E agent'));
for (const [i, [why, bad]] of [['another site', 'https://evil.test/'], ['a protocol-relative address', '//evil.test/'], ['a line break', '/x\r\nset-cookie: a=b']].entries()) {
  const b = new Browser(`return-${i}-${run}@else.test`); await b.signIn();
  const made = await b.go('/new', { form: { name: `Return ${i} ${run}`, accept_terms: '1', return: bad } });
  check(`making a workspace does not follow a return to ${why}`, made.status === 302 && made.headers.location?.startsWith('/w/'), made.headers.location);
}
const consent = await mallory.go(authzPath);
const OW = (await mallory.api('/v1/me')).body.workspaces[0].slug;
check('the consent page names the client and the workspace', consent.status === 200 && consent.body.includes('Connect E2E agent') && consent.body.includes(`value="${OW}"`));
check('the consent form refuses a cross-site post', (await mallory.go('/oauth/authorize', { form: { ...authz, workspace: OW, decision: 'allow' }, headers: { origin: 'https://evil.test' } })).status === 403);
const allowed = await mallory.go('/oauth/authorize', { form: { ...authz, workspace: OW, decision: 'allow' } });
const backTo = new URL(allowed.headers.location ?? 'http://x/');
check('allowing returns a code and the state to the client on this machine, any port', `${backTo.origin}${backTo.pathname}` === cb && backTo.searchParams.get('state') === 's1' && !!backTo.searchParams.get('code'), allowed.headers.location);
const swap = form => fetch(asm.token_endpoint, { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams(form) });
const grant = { grant_type: 'authorization_code', code: backTo.searchParams.get('code'), client_id: reg.client_id, redirect_uri: cb };
const issued = await swap({ ...grant, code_verifier: verifier });
const issuedBody = await issued.json();
check('the code and verifier swap for a connection token', issued.status === 200 && issuedBody.token_type === 'Bearer' && issuedBody.access_token?.startsWith('brod_'), JSON.stringify(issuedBody));
check('a code works once', (await swap({ ...grant, code_verifier: verifier })).status === 400);
// 10 client registrations an hour from one address; the e2e has made one so far.
const regs = [];
for (let i = 0; i < 11 && regs.at(-1)?.status !== 429; i++)
  regs.push(await fetch(asm.registration_endpoint, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ redirect_uris: ['http://127.0.0.1/callback'], client_name: `Flood ${i}` }) }));
const limited = regs.at(-1);
check('too many client registrations from one address get a 429', regs.length === 10 && limited.status === 429 && (await limited.json()).error === 'temporarily_unavailable',
  regs.map(r => r.status).join(','));
const oclient = new Client({ name: 'e2e-oauth', version: '1.0.0' });
await oclient.connect(new StreamableHTTPClientTransport(new URL(API + '/mcp'), { requestInit: { headers: { authorization: `Bearer ${issuedBody.access_token}` } } }));
const ogw = JSON.parse((await oclient.callTool({ name: 'get_workspace', arguments: {} })).content[0].text);
check('the signed-in agent works in the workspace that was picked', ogw.workspace === OW, JSON.stringify(ogw).slice(0, 200));
await oclient.close().catch(() => {});
const connPage = await mallory.go(`/w/${OW}/connections`);
check('the connections page lists the signed-in agent and the sign-in command', connPage.status === 200 && connPage.body.includes('E2E agent') && connPage.body.includes(`claude mcp add --transport http brod ${API}/mcp`));
const madeTok = await mallory.go(`/w/${OW}/connections`, { form: { name: 'laptop' } });
const pageToken = /value="(brod_[0-9a-f]+)"/.exec(madeTok.body)?.[1];
check('the connections page makes a token, shown once', !!pageToken && (await fetch(`${API}/v1/apps`, { headers: { authorization: `Bearer ${pageToken}` } })).status === 200);
const laptopId = /name="revoke" value="(tok_[0-9a-f]+)"/.exec(madeTok.body.slice(madeTok.body.indexOf('laptop<br>')))?.[1];
await mallory.go(`/w/${OW}/connections`, { form: { revoke: laptopId ?? '' } });
check('disconnecting from the page locks the token out', (await fetch(`${API}/v1/apps`, { headers: { authorization: `Bearer ${pageToken}` } })).status === 401);
check('someone no longer in the workspace cannot open its connections page', (await bob.go(`/w/${W}/connections`)).status === 404);

// ---------- 6c. a suspended workspace ----------

await strangerB.api('/v1/workspaces', { json: { name: `Spam ${run}`, accept_terms: true } });
const SW = (await strangerB.api('/v1/me')).body.workspaces[0].slug;
const spam = await strangerB.api('/v1/deploys', { json: { name: 'Offer', files: [{ path: 'index.html', content: '<h1>offer</h1>' }] } });
check('a workspace deploys before it is suspended', spam.status === 201 && (await strangerB.open(spam.body.url + '/')).status === 200, JSON.stringify(spam.body));
check('the operator suspends a workspace', (await admin(`workspaces/${SW}/suspend`, { reason: 'Spam' })).status === 200);
check('its apps stop serving', (await strangerB.go(spam.body.url + '/')).status === 410);
const spamDeploy = await strangerB.api('/v1/deploys', { json: { name: 'Offer 2', files: [{ path: 'index.html', content: 'x' }] } });
check('and its deploys are refused', spamDeploy.status === 403 && spamDeploy.body.error.code === 'workspace_suspended', JSON.stringify(spamDeploy.body));

// ---------- 6d. the deploy-time phishing check ----------

// An abstract snippet, not an imitation of any real page: a password field in a form that posts to another site, plus a "verify" phrase.
const suspicious = '<title>Example</title><form action="https://collector.example.net/x"><input type="password"></form><p>Verify your account</p>';
const fl = await mallory.api('/v1/deploys', { json: { name: 'Check', files: [{ path: 'index.html', content: suspicious }] } });
check('a flagged version still deploys, private, and says why', fl.status === 201 && fl.body.access === 'private' && fl.body.flagged?.reasons.includes('a password field'), JSON.stringify(fl.body));
const autoRep = (await admin('reports?status=open', undefined, 'GET')).body.reports.find(r => r.app === fl.body.app && r.kind === 'automatic');
check('the phishing check files a report for the operator', autoRep?.reporter === 'brod' && autoRep.workspace === OW, JSON.stringify(autoRep));
const flWide = await mallory.api(`/v1/apps/${fl.body.app}/access`, { json: { access: 'workspace' } });
check('a flagged app cannot be opened wider than named people', flWide.status === 403 && flWide.body.error.code === 'flagged', JSON.stringify(flWide.body));
const cleared = await admin(`apps/${OW}/${fl.body.app}/clear`);
check('the operator clears the flag', cleared.body.cleared_versions === 1 && (await mallory.api(`/v1/apps/${fl.body.app}/access`, { json: { access: 'workspace' } })).status === 200, JSON.stringify(cleared.body));
await mallory.api(`/v1/apps/${fl.body.app}`, { method: 'DELETE' });

// ---------- 7. server apps (in the second workspace, whose plan has free slots) ----------

const mtok = await mallory.api('/v1/tokens', { json: { name: 'server-agent' } });
const sclient = new Client({ name: 'e2e-server', version: '1.0.0' });
await sclient.connect(new StreamableHTTPClientTransport(new URL(API + '/mcp'), { requestInit: { headers: { authorization: `Bearer ${mtok.body.token}` } } }));
const stool = async (name, args = {}) => { const r = await sclient.callTool({ name, arguments: args }); return { isError: r.isError, data: r.structuredContent ?? JSON.parse(r.content[0].text) }; };
const sup = await stool('deploy_app', { name: `Notes ${run}`, note: 'Server app by upload' });
const sdir = mkdtempSync(join(tmpdir(), 'brod-server-')); mkdirSync(join(sdir, 'build', '_worker'), { recursive: true });
writeFileSync(join(sdir, 'build', 'style.css'), 'body{}');
writeFileSync(join(sdir, 'build', '_worker', 'db.js'), `export const add = async (env, text) => {
  await env.DB.run('CREATE TABLE IF NOT EXISTS notes (text TEXT)');
  await env.DB.run('INSERT INTO notes VALUES (?)', [text]);
  return env.DB.query('SELECT text FROM notes');
};`);
writeFileSync(join(sdir, 'build', '_worker', 'index.js'), `import { add } from './db.js';
export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (request.method === 'POST') {
      const rows = await add(env, await request.text());
      console.log('note saved by', request.headers.get('x-brod-user-email'), 'total', rows.length);
      return Response.json({ notes: rows.map(r => r.text), key: env.NOTES_KEY ?? null });
    }
    return new Response('<html><body><h1>notes</h1></body></html>', { headers: { 'content-type': 'text/html' } });
  },
};`);
const sres = sendBundle(sup.data, `tar -czf - -C ${sdir} build`);
if (process.env.E2E_SKIP_SERVER_APPS === '1') {
  // A server without the server-app runtime serves static apps only; the rest of this section needs one.
  check('a server app is refused with a clear reason on a static-only host', sres.status === 400 && JSON.parse(sres.body).error.code === 'server_apps_unavailable', sres.body);
  console.log('SKIP  the rest of section 7 (server apps): E2E_SKIP_SERVER_APPS=1');
  await sclient.close().catch(() => {});
  await client.close().catch(() => {});
  console.log(`\n${passed} passed, ${failed} failed`);
  process.exit(failed ? 1 : 0);
}
const sout = JSON.parse(sres.body);
check('a server app deploys by upload, with a _worker/ folder of modules', sout.kind === 'server' && sout.version === 1, JSON.stringify(sout));
await stool('set_secret', { app: sout.app, name: 'NOTES_KEY', value: 'k-789' });
const sapp = await mallory.open(sout.url + '/');
check('the server code answers pages for the signed-in owner', sapp.status === 200 && sapp.body.includes('<h1>notes</h1>'));
check('files in the bundle are still served directly', (await mallory.go(sout.url + '/style.css')).body === 'body{}');
const posted = JSON.parse((await mallory.go(sout.url + '/notes', { method: 'POST', body: 'first' })).body);
const posted2 = JSON.parse((await mallory.go(sout.url + '/notes', { method: 'POST', body: 'second' })).body);
check('the app keeps data in its own database and reads its secret', posted.key === 'k-789' && posted2.notes.join(',') === 'first,second', JSON.stringify(posted2));
let slogs = [];
for (let i = 0; i < 40 && !slogs.length; i++) {
  slogs = (await stool('get_logs', { app: sout.app, search: 'note saved' })).data.requests;
  if (!slogs.length) await new Promise(r => setTimeout(r, 250));
}
check('console output from each request shows in get_logs', slogs.some(l => l.logs.some(m => m.includes(`note saved by ${mallory.email}`))), JSON.stringify(slogs[0]));
const sstat = await stool('get_status', { app: sout.app });
check('secret names are listed, values never', sstat.data.secrets.some(x => x.name === 'NOTES_KEY') && !JSON.stringify(sstat.data).includes('k-789'));
await sclient.close().catch(() => {});

await client.close().catch(() => {});
console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed ? 1 : 0);
