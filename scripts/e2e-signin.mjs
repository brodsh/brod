// SPDX-License-Identifier: AGPL-3.0-only
// An app's own login page: the app designs it, Brod sends the code, checks it and sets a session for that app alone.
// Run by scripts/e2e-rust.mjs. Usage: node scripts/e2e-signin.mjs <api origin>
import http from 'node:http';

const API = process.argv[2] ?? 'http://localhost:8787';
const api = new URL(API);
const ADMIN = process.env.ADMIN_SECRET ?? 'dev-admin-secret';
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
class Browser {
  constructor(email = '') { this.email = email; this.jars = {}; }
  async go(url, o = {}) {
    const u = new URL(url, API), headers = { ...(o.headers ?? {}) };
    const c = Object.entries(this.jars[u.host] ?? {}).map(([k, v]) => `${k}=${v}`).join('; '); if (c) headers.cookie = c;
    let body = o.body;
    if (o.form) { body = new URLSearchParams(o.form).toString(); headers['content-type'] = 'application/x-www-form-urlencoded'; headers.origin ??= API; }
    if (o.json) { body = JSON.stringify(o.json); headers['content-type'] = 'application/json'; headers.origin ??= u.origin; }
    const r = await send(u.href, { method: o.method ?? (body ? 'POST' : 'GET'), headers, body });
    for (const sc of [].concat(r.headers['set-cookie'] ?? [])) {
      const [k, v] = sc.split(';')[0].split('='); (this.jars[u.host] ??= {});
      if (/max-age=0/i.test(sc)) delete this.jars[u.host][k]; else this.jars[u.host][k] = v;
    }
    return { ...r, url: u.href, json() { try { return JSON.parse(this.body); } catch { throw new Error(`${o.method ?? (body ? 'POST' : 'GET')} ${u.href} answered ${this.status}: ${this.body.slice(0, 200)}`); } } };
  }
  async signIn() {
    const start = await this.go('/auth/start', { json: { email: this.email, return: '/' }, headers: { origin: API } });
    await this.go('/auth/verify', { form: { token: new URL(start.json().dev_link).searchParams.get('token') } });
  }
}
const operator = path => send(`${API}/v1/admin/${path}`, { method: 'POST', headers: { authorization: `Bearer ${ADMIN}`, 'content-type': 'application/json' }, body: '{}' });

const owner = new Browser(`owner-${run}@signin.test`);
await owner.signIn();
const W = (await owner.go('/v1/workspaces', { json: { name: `Signin ${run}`, accept_terms: true }, headers: { origin: API } })).json().workspace;
await operator(`workspaces/${W}/trust`);
const AGENT = (await owner.go(`/w/${W}/connections`, { form: { name: 'agent' } })).body.match(/brod_[A-Za-z0-9_-]+/)?.[0];
check('the test has an agent token', !!AGENT);
const asAgent = async (path, o = {}) => {
  const r = await send(`${API}${path}`, { method: o.method ?? 'POST', headers: { authorization: `Bearer ${AGENT}`, 'content-type': 'application/json' }, body: o.json ? JSON.stringify(o.json) : undefined });
  return { status: r.status, body: r.body ? JSON.parse(r.body) : null };
};

const LOGIN = '<!doctype html><title>Acme login</title><script src="/_brod/client.js"></script><form id="own-login"><input type="email"></form>';
const MANIFEST = JSON.stringify({ open_paths: [{ path: '/login', sign_in_page: true }, '/login.css'] });
const files = [
  { path: 'index.html', content: '<h1>The private page</h1>' },
  { path: 'login/index.html', content: LOGIN },
  { path: 'login.css', content: 'body{color:teal}' },
  { path: 'brod.json', content: MANIFEST },
];
const app = (await asAgent('/v1/deploys', { json: { name: `Acme ${run}`, files } })).body;
const U = app.url;
check('declaring a sign-in page waits for a person, like any open path', !!app.confirm_url && app.open_paths?.pending?.length === 2, JSON.stringify(app));

// ---------- before anyone approved it: nothing changes ----------
const before = new Browser();
const beforeHome = await before.go(`${U}/`);
check('until a person approves it, visitors still go to Brod\'s sign-in', beforeHome.status === 302 && beforeHome.headers.location.startsWith(`${API}/auth/app`), beforeHome.headers.location);
const beforeStart = await before.go(`${U}/_brod/auth/start`, { json: { email: 'x@signin.test' } });
check('and the app cannot send email through Brod', beforeStart.status === 404 && beforeStart.json().error.code === 'no_sign_in_page', beforeStart.body);

const confirmed = await owner.go(new URL(app.confirm_url).pathname, { form: { decision: 'confirm' } });
check('a person approves it', confirmed.status === 200, confirmed.body.slice(0, 200));

// ---------- signed out: the app's own page ----------
const pat = new Browser();
const home = await pat.go(`${U}/reports?year=2026`);
check('a signed-out visitor goes to the app\'s own login page, keeping where they were going', home.status === 302 && home.headers.location === `/login?return=${encodeURIComponent('/reports?year=2026')}`, `${home.status} ${home.headers.location}`);
const page = await pat.go(`${U}/login?return=%2Freports`);
check('the login page is the app\'s own design', page.status === 200 && page.body.includes('id="own-login"'), page.body.slice(0, 200));
check('its other open files load too', (await pat.go(`${U}/login.css`)).body.includes('teal'));
const viaClient = await pat.go(`${U}/_brod/signin?return=/x`);
check('Brod.signIn() goes to the app\'s page as well', viaClient.status === 302 && viaClient.headers.location.startsWith('/login?return='), viaClient.headers.location);
const methods = (await pat.go(`${U}/_brod/auth/methods?return=/x`)).json();
const GOOGLE = !!process.env.GOOGLE_CLIENT_ID;
check('the page can ask how people sign in', methods.email === true && methods.google === GOOGLE && methods.return === '/x' && methods.app.name.startsWith('Acme'), JSON.stringify(methods));
const toGoogle = await pat.go(`${U}/_brod/auth/google?return=/x`);
if (GOOGLE) {
  const inner = toGoogle.status === 302 ? new URL(toGoogle.headers.location).searchParams.get('return') : '';
  check('Google sign-in goes through the API host and hands back to this app', toGoogle.headers.location?.startsWith(`${API}/auth/google?`) && inner.startsWith('/auth/app?app=') && inner.endsWith('return=%2Fx'), toGoogle.headers.location);
  const atGoogle = await pat.go(toGoogle.headers.location);
  check('and on to Google', atGoogle.status === 302 && atGoogle.headers.location.startsWith('https://accounts.google.com/'), atGoogle.headers.location);
} else check('with no Google set up, its route answers 404', toGoogle.status === 404, `${toGoogle.status}`);
const clientJs = (await pat.go(`${U}/_brod/client.js`)).body;
check('the browser client offers sign-in', clientJs.includes('verifyCode') && clientJs.includes('sendCode'));

// ---------- who may ask ----------
const email = `pat-${run}@else.test`;
const foreign = await pat.go(`${U}/_brod/auth/start`, { json: { email }, headers: { origin: 'https://evil.test' } });
check('another site cannot ask for a code', foreign.status === 403 && foreign.json().error.code === 'bad_origin', foreign.body);
const asForm = await pat.go(`${U}/_brod/auth/start`, { form: { email }, headers: { origin: U } });
check('a form post cannot ask for a code', asForm.status === 415, `${asForm.status}`);
const bad = await pat.go(`${U}/_brod/auth/start`, { json: { email: 'nope' } });
check('a bad address is refused', bad.status === 400 && bad.json().error.code === 'bad_email', bad.body);

// ---------- the code ----------
const sent = (await pat.go(`${U}/_brod/auth/start`, { json: { email } })).json();
check('asking for a code sends one', sent.sent === true && /^\d{6}$/.test(sent.dev_code), JSON.stringify(sent));
const wrong = sent.dev_code === '000000' ? '000001' : '000000';
const wrongTry = await pat.go(`${U}/_brod/auth/verify`, { json: { email, code: wrong } });
check('a wrong code is refused, with no session', wrongTry.status === 400 && wrongTry.json().error.code === 'bad_code' && !pat.jars[new URL(U).host]?.brod_session, wrongTry.body);
const otherAddress = await pat.go(`${U}/_brod/auth/verify`, { json: { email: `other-${run}@else.test`, code: sent.dev_code } });
check('a code works only for the address it was sent to', otherAddress.status === 400, otherAddress.body);
const otherApp = (await asAgent('/v1/deploys', { json: { name: `Other ${run}`, files } })).body;
await owner.go(new URL(otherApp.confirm_url).pathname, { form: { decision: 'confirm' } });
const elsewhere = await new Browser().go(`${otherApp.url}/_brod/auth/verify`, { json: { email, code: sent.dev_code } });
check('a code works only on the app it was asked from', elsewhere.status === 400, elsewhere.body);

const signed = await pat.go(`${U}/_brod/auth/verify`, { json: { email, code: sent.dev_code, return: '/reports' } });
const answer = signed.json();
check('the right code signs in; the app is private, so the page is told this person has no access', signed.status === 200 && answer.ok === true && answer.allowed === false && answer.return === '/reports', signed.body);
check('the session cookie is the app\'s, on its own host', !!pat.jars[new URL(U).host]?.brod_session && !/domain=/i.test([].concat(signed.headers['set-cookie']).join(';')));
check('and it is not handed to the page as data', !signed.body.includes(pat.jars[new URL(U).host].brod_session));
check('a person not shared with still sees nothing', (await pat.go(`${U}/`)).status === 404);
const reused = await new Browser().go(`${U}/_brod/auth/verify`, { json: { email, code: sent.dev_code } });
check('a code works once', reused.status === 400, reused.body);

// ---------- limits and returns ----------
const guess = `guess-${run}@else.test`;
const guessing = new Browser();
const guessed = (await guessing.go(`${U}/_brod/auth/start`, { json: { email: guess } })).json().dev_code;
const miss = guessed === '000000' ? '000001' : '000000';
for (let i = 0; i < 5; i++) await guessing.go(`${U}/_brod/auth/verify`, { json: { email: guess, code: miss } });
const tooLate = await guessing.go(`${U}/_brod/auth/verify`, { json: { email: guess, code: guessed } });
check('five wrong tries end the code, even for the right one after', tooLate.status === 400, tooLate.body);
const flood = new Browser();
let floodStatus = 0;
for (let i = 0; i < 6; i++) floodStatus = (await flood.go(`${otherApp.url}/_brod/auth/start`, { json: { email: guess } })).status;
check('one inbox is limited across apps', floodStatus === 429, `${floodStatus}`);

const rets = [];
for (const [i, ret] of ['https://evil.test/', '//evil.test/', '/\\evil.test', '/x\r\nset-cookie: a=b'].entries()) {
  const who = `ret-${i}-${run}@else.test`, b = new Browser();
  const code = (await b.go(`${otherApp.url}/_brod/auth/start`, { json: { email: who } })).json().dev_code;
  rets.push((await b.go(`${otherApp.url}/_brod/auth/verify`, { json: { email: who, code, return: ret } })).json().return);
}
check('a return to another site or with a line break falls back to /', rets.every(r => r === '/'), JSON.stringify(rets));

// ---------- a person the app is shared with; the session reaches nothing else ----------
for (const a of [app, otherApp]) {
  const widened = await asAgent(`/v1/apps/${a.app}/access`, { json: { access: 'signed_in' } });
  await owner.go(new URL(widened.body.confirm_url).pathname, { form: { decision: 'confirm' } });
}
const sam = new Browser();
const samEmail = `sam-${run}@customer.test`;
const samCode = (await sam.go(`${U}/_brod/auth/start`, { json: { email: samEmail } })).json().dev_code;
const samIn = (await sam.go(`${U}/_brod/auth/verify`, { json: { email: samEmail, code: samCode } })).json();
check('someone the app is open to is told they are in', samIn.allowed === true, JSON.stringify(samIn));
check('and opens it', (await sam.go(`${U}/`)).body.includes('The private page'));
const me = await sam.go(`${U}/_brod/me`);
check('the app reads them the usual way', me.status === 200 && me.json().user.email === samEmail, me.body.slice(0, 200));
const cookieValue = sam.jars[new URL(U).host].brod_session;
const onOther = await send(`${otherApp.url}/_brod/me`, { headers: { cookie: `brod_session=${cookieValue}` } });
check('the session does not work on another app, even one open to anyone who signs in', onOther.status === 401, `${onOther.status} ${onOther.body.slice(0, 120)}`);
const onPlatform = await send(`${API}/v1/workspaces`, { headers: { cookie: `brod_session=${cookieValue}; brod_platform=${cookieValue}` } });
check('nor on the platform', onPlatform.status === 401 || onPlatform.status === 403, `${onPlatform.status} ${onPlatform.body.slice(0, 120)}`);
const noPlatform = Object.keys(sam.jars).filter(h => h === api.host);
check('signing in here sets nothing on the API host', noPlatform.length === 0, noPlatform.join());

const foreignOut = await send(`${U}/_brod/auth/signout`, { method: 'POST', headers: { cookie: `brod_session=${cookieValue}`, origin: 'https://evil.test', 'content-type': 'application/json' }, body: '{}' });
check('another site cannot sign someone out', foreignOut.status === 403, `${foreignOut.status}`);
const out = await sam.go(`${U}/_brod/auth/signout`, { json: {} });
check('signing out answers on the app\'s own address', out.status === 200 && out.json().ok === true, out.body);
const after = await send(`${U}/_brod/me`, { headers: { cookie: `brod_session=${cookieValue}` } });
check('and the old session no longer works', after.status === 401, `${after.status}`);

// ---------- app users: one app only, with filters besides a role ----------
const tenantApp = (await asAgent('/v1/deploys', { json: { name: `Tenants ${run}`, files } })).body;
await owner.go(new URL(tenantApp.confirm_url).pathname, { form: { decision: 'confirm' } });
const T = tenantApp.url, S = tenantApp.app;
const access = o => asAgent(`/v1/apps/${S}/access`, { json: o });
const confirm = r => owner.go(new URL(r.body.confirm_url).pathname, { form: { decision: 'confirm' } });
const codeIn = async (b, who) => {
  const started = await b.go(`${T}/_brod/auth/start`, { json: { email: who } });
  if (started.status !== 200) throw new Error(`asking for a code for ${who} answered ${started.status}: ${started.body}`);
  const code = started.json().dev_code;
  return (await b.go(`${T}/_brod/auth/verify`, { json: { email: who, code } })).json();
};
const meOf = async b => (await b.go(`${T}/_brod/me`)).json();
const stranger = `stranger-${run}@acme.test`, ann = `ann-${run}@acme.test`;
check('someone not named is told they have no access', (await codeIn(new Browser(), stranger)).allowed === false);

const named = await access({ add: [{ app_user: ann, role: 'viewer', filters: { tenant: 'acme' } }] });
check('naming an app user waits for a person, who is shown the filter', !!named.body.confirm_url && JSON.stringify(named.body).includes('tenant') , JSON.stringify(named.body));
const annB = new Browser();
check('until then they have no access', (await codeIn(annB, ann)).allowed === false);
await confirm(named);
check('afterwards their next request is let in', (await annB.go(`${T}/`)).body.includes('The private page'));
const annMe = await meOf(annB);
check('the app sees their role and tenant', annMe.role === 'viewer' && annMe.filters?.tenant === 'acme', JSON.stringify(annMe));
const claims = JSON.parse(Buffer.from(annMe.token.split('.')[1], 'base64url'));
check('the signed token carries the filters', claims.filters?.tenant === 'acme', JSON.stringify(claims));
const onLogin = await annB.go(`${otherApp.url}/_brod/me`);
check('an app user reaches no other app', onLogin.status === 401, `${onLogin.status}`);
const annPlatform = new Browser(ann);
await annPlatform.signIn();
const ws = (await annPlatform.go('/v1/workspaces', { headers: { origin: API } })).json();
check('and has no place in the workspace', JSON.stringify(ws).includes(W) === false, JSON.stringify(ws).slice(0, 200));
check('its pages stay closed to them', (await annPlatform.go(`/w/${W}`)).status !== 200);
const list = (await asAgent(`/v1/apps/${S}/access`, { method: 'GET' })).body;
const listed = list.shared_with?.find(g => g.app_user === ann);
check('the app lists them as an app user, with their filters', listed?.role === 'viewer' && listed?.filters?.tenant === 'acme', JSON.stringify(list.shared_with));

await confirm(await access({ add: [{ app_user: ann, role: 'editor' }] }));
const annEditor = await meOf(annB);
check('changing a role keeps the filters', annEditor.role === 'editor' && annEditor.filters?.tenant === 'acme', JSON.stringify(annEditor));
const moving = await access({ add: [{ app_user: ann, role: 'editor', filters: { tenant: 'beta' } }] });
check('moving someone to another tenant waits for a person', !!moving.body.confirm_url && (await meOf(annB)).filters?.tenant === 'acme', JSON.stringify(moving.body));
await confirm(moving);
check('and applies on their next request', (await meOf(annB)).filters?.tenant === 'beta');

await confirm(await access({ add: [{ domain: 'acme.test', role: 'viewer', filters: { tenant: 'whole-domain', region: ['np', 'in'] } }] }));
const dom = new Browser();
check('a domain grant lets a colleague in', (await codeIn(dom, stranger)).allowed === true);
const domMe = await meOf(dom);
check('with the domain\'s filters', domMe.filters?.tenant === 'whole-domain' && domMe.filters?.region?.length === 2, JSON.stringify(domMe));
check('the grant naming a person beats their domain, with nothing added from it', JSON.stringify((await meOf(annB)).filters) === '{"tenant":"beta"}', JSON.stringify((await meOf(annB)).filters));
await confirm(await access({ add: [{ app_user: ann, role: 'editor', filters: {} }] }));
check('clearing a person\'s filters leaves the domain\'s', (await meOf(annB)).filters?.tenant === 'whole-domain');
const removal = await access({ remove: [{ app_user: ann }, { domain: 'acme.test' }] });
check('removing them applies at once', removal.status === 200 && (await annB.go(`${T}/_brod/me`)).status === 401, JSON.stringify(removal.body).slice(0, 200));

for (const [why, f] of [['a list', ['acme']], ['a bad name', { 'Ten ant': 'x' }], ['too many', Object.fromEntries(Array.from({ length: 9 }, (_, i) => [`f${i}`, 'x']))], ['an empty value', { tenant: '' }], ['a number', { tenant: 1 }]]) {
  const r = await access({ add: [{ app_user: ann, role: 'viewer', filters: f }] });
  check(`filters refuse ${why}`, r.status === 400 && r.body.error.code === 'bad_filters', JSON.stringify(r.body));
}
const onEveryone = await access({ add: [{ everyone: 'signed_in', role: 'viewer', filters: { tenant: 'x' } }] });
check('filters do not go on everyone', onEveryone.status === 400 && onEveryone.body.error.code === 'bad_filters', JSON.stringify(onEveryone.body));
const badUser = await access({ add: [{ app_user: 'nope', role: 'viewer' }] });
check('an app user is an email address', badUser.status === 400 && badUser.body.error.code === 'bad_email', JSON.stringify(badUser.body));

// ---------- a later version that stops naming the page ----------
await asAgent('/v1/deploys', { json: { app: app.app, files: files.filter(f => f.path !== 'brod.json') } });
const staged = await asAgent(`/v1/apps/${app.app}/publish`, { json: {} });
const later = await new Browser().go(`${U}/_brod/auth/start`, { json: { email: `later-${run}@else.test` } });
check('a live version that stops naming the page turns its sign-in off', staged.status === 200 && later.status === 404, `${staged.status} ${JSON.stringify(staged.body).slice(0, 120)} ${later.status}`);
const laterHome = await new Browser().go(`${U}/`);
check('and visitors go back to Brod\'s sign-in', laterHome.status === 302 && laterHome.headers.location.startsWith(`${API}/auth/app`), laterHome.headers.location);

console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed ? 1 : 0);
