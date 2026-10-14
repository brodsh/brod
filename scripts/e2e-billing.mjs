// SPDX-License-Identifier: AGPL-3.0-only
// Billing, visit counts, analytics, storage and spaces on the Rust server, against the fake Stripe in scripts/fake-stripe.mjs.
// Run by scripts/e2e-rust.mjs after scripts/e2e.mjs, with Brod started on STRIPE_API_BASE=<fake>.
// Usage: node scripts/e2e-billing.mjs <api origin> <fake stripe origin>
import http from 'node:http';
import { sign } from './fake-stripe.mjs';

const API = process.argv[2] ?? 'http://localhost:8787';
const STRIPE = process.argv[3] ?? 'http://127.0.0.1:8790';
const api = new URL(API);
let passed = 0, failed = 0;
const check = (name, ok, detail = '') => { ok ? passed++ : failed++; console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${ok || !detail ? '' : `\n      ${detail}`}`); };
const run = Date.now();

/** Send a request to Brod with any Host header, so app hosts need not resolve on this machine. */
function send(url, { method = 'GET', headers = {}, body } = {}) {
  const u = new URL(url);
  return new Promise((resolve, reject) => {
    const req = http.request({ host: api.hostname, port: api.port, path: u.pathname + u.search, method, headers: { host: u.host, ...headers } }, res => {
      let data = ''; res.on('data', c => (data += c)); res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: data }));
    });
    req.on('error', reject); if (body) req.write(body); req.end();
  });
}

class Browser {
  constructor(email) { this.email = email; this.jars = {}; }
  async go(url, o = {}) {
    const u = new URL(url, API);
    const headers = { ...(o.headers ?? {}) };
    const jar = Object.entries(this.jars[u.host] ?? {}).map(([k, v]) => `${k}=${v}`).join('; ');
    if (jar) headers.cookie = jar;
    let body;
    if (o.json) { body = JSON.stringify(o.json); headers['content-type'] = 'application/json'; }
    if (o.form) { body = new URLSearchParams(o.form).toString(); headers['content-type'] = 'application/x-www-form-urlencoded'; }
    if (body || (o.method && o.method !== 'GET')) headers.origin ??= API;
    const r = await send(u.href, { method: o.method ?? (body ? 'POST' : 'GET'), headers, body });
    for (const sc of [].concat(r.headers['set-cookie'] ?? [])) {
      const [kv] = sc.split(';'); const [k, v] = kv.split('=');
      (this.jars[u.host] ??= {})[k.trim()] = v;
    }
    return r;
  }
  async signIn() {
    const start = await this.go('/auth/start', { json: { email: this.email, return: '/' } });
    const token = new URL(JSON.parse(start.body).dev_link).searchParams.get('token');
    return this.go('/auth/verify', { form: { token } });
  }
  async api(path, o = {}) {
    const r = await this.go(path, { ...o, headers: { ...(o.headers ?? {}), 'x-brod-workspace': this.workspace ?? '' } });
    return { status: r.status, body: r.body ? JSON.parse(r.body) : null };
  }
}
const stripe = (path, o = {}) => fetch(STRIPE + path, o).then(async r => ({ status: r.status, headers: r.headers, body: await r.text() }));
const webhook = (payload, signature) => send(`${API}/stripe/webhook`, { method: 'POST', headers: { 'content-type': 'application/json', 'stripe-signature': signature }, body: payload });

// ---------- billing ----------

const ada = new Browser(`ada-${run}@bill.test`);
await ada.signIn();
const ws = await ada.api('/v1/workspaces', { json: { name: `Bill ${run}`, accept_terms: true } });
ada.workspace = ws.body.workspace;

let b = await ada.api('/v1/billing');
const team = b.body?.plans?.find(p => p.id === 'team');
check('billing shows the free plan, the paid plans and their Stripe prices', b.status === 200 && b.body.enabled && b.body.plan === 'free' && team?.price?.amount === 2900 && team.available, JSON.stringify(b.body));

const co = await ada.api('/v1/billing/checkout', { json: { plan: 'team' } });
check('upgrading starts a Stripe Checkout session', co.status === 200 && co.body.url?.startsWith(STRIPE + '/pay/'), JSON.stringify(co.body));
const paid = await fetch(co.body.url, { redirect: 'manual' });
check('paying returns to the billing page', paid.status === 303 && paid.headers.get('location') === `${API}/w/${ada.workspace}/admin#billing/done`);
b = await ada.api('/v1/billing');
check('the webhook moves the workspace to the paid plan', b.body.plan === 'team' && b.body.status === 'active' && b.body.renews_at > Date.now() && b.body.has_customer, JSON.stringify(b.body));
check('invoices come from Stripe', b.body.invoices.length === 1 && b.body.invoices[0].amount === 2900 && b.body.invoices[0].status === 'paid');
check('the new allowance applies at once', (await ada.api('/v1/workspace')).body.app_limit === 50);

const sw = await ada.api('/v1/billing/checkout', { json: { plan: 'solo' } });
b = await ada.api('/v1/billing');
check('switching paid plans updates the subscription in place, no Checkout', sw.body.changed === true && !sw.body.url && b.body.plan === 'solo', JSON.stringify(sw.body));

const portal = await ada.api('/v1/billing/portal', { method: 'POST' });
check('the customer portal opens for the card and receipts', portal.status === 200 && portal.body.url.startsWith(STRIPE + '/portal'));

const down = await ada.api('/v1/billing/checkout', { json: { plan: 'free' } });
b = await ada.api('/v1/billing');
check('moving to free cancels at the end of the period, keeping the plan until then', down.body.cancel_at_period_end && b.body.plan === 'solo' && b.body.cancel_at > Date.now(), JSON.stringify(b.body));

const delivered = JSON.parse((await stripe('/_test/delivered')).body);
check('every webhook was accepted', delivered.length >= 4 && delivered.every(d => d.status === 200), JSON.stringify(delivered));

const payload = JSON.stringify({ id: `evt_dup_${run}`, type: 'invoice.paid', data: { object: {} } });
check('a webhook with a bad signature is refused', (await webhook(payload, sign(payload, 'whsec_wrong'))).status === 400);
check('an old signature is refused (replay)', (await webhook(payload, sign(payload, undefined, Math.floor(Date.now() / 1000) - 3600))).status === 400);
const first = await webhook(payload, sign(payload));
const again = await webhook(payload, sign(payload));
check('a redelivered event is applied once', first.status === 200 && JSON.parse(again.body).duplicate === true);

// A failed renewal keeps the plan but says so; the subscription ending in Stripe (period over, or cancelled in the
// portal) drops the workspace to free.
const [live] = JSON.parse((await stripe('/_test/subscriptions')).body);
await stripe(`/_test/subscriptions/${live.id}`, { method: 'POST', body: new URLSearchParams({ status: 'past_due' }) });
b = await ada.api('/v1/billing');
check('a failed payment keeps the plan and shows past due', b.body.plan === 'solo' && b.body.status === 'past_due', JSON.stringify(b.body));
await stripe(`/_test/subscriptions/${live.id}`, { method: 'DELETE' });
b = await ada.api('/v1/billing');
check('a subscription that ends drops the workspace to free', b.body.plan === 'free' && b.body.status === 'canceled' && (await ada.api('/v1/workspace')).body.app_limit === 10, JSON.stringify(b.body));
const log = (await ada.api('/v1/events?action=plan')).body.events.map(e => e.detail);
check('plan changes are in the activity log', log.length === 3 && log[0].startsWith('solo to free'), JSON.stringify(log));

// ---------- a member cannot see billing ----------

const bo = new Browser(`bo-${run}@bill.test`);
const inv = await ada.api('/v1/invites', { json: { email: bo.email, role: 'member' } });
await bo.go('/auth/invite', { form: { token: new URL(inv.body.dev_link).searchParams.get('token') } });
bo.workspace = ada.workspace;
check('only admins see billing', (await bo.api('/v1/billing')).status === 403);

// ---------- visits ----------

const d1 = await ada.api('/v1/deploys', { json: { name: `Counter ${run}`, files: [{ path: 'index.html', content: '<h1>hi</h1>' }, { path: 'style.css', content: 'h1{}' }] } });
const APP = d1.body.app, url = d1.body.url;
// A new free workspace keeps its apps inside it for a day unless the operator trusts it (server/src/abuse.rs).
await send(`${API}/v1/admin/workspaces/${ada.workspace}/trust`, { method: 'POST', headers: { authorization: `Bearer ${process.env.ADMIN_SECRET ?? 'dev-admin-secret'}` } });
await ada.api(`/v1/apps/${APP}/access`, { json: { access: 'public' } });
const page = (ua, dest, path = '/') => send(url + path, { headers: { 'user-agent': ua, ...(dest ? { 'sec-fetch-dest': dest } : {}) } });
for (const ua of ['one', 'one', 'one']) await page(ua, 'document');
await page('two'); // no Sec-Fetch-Dest (an older browser): a path without an extension is a page
await page('one', 'style', '/style.css');
await page('three', null, '/style.css');
const u = await ada.api(`/v1/apps/${APP}/usage?days=7`);
check('page views and distinct visitors are counted per day, assets are not', u.body.total_views === 4 && u.body.total_visitors === 2 && u.body.views.length === 7, JSON.stringify(u.body));
const wu = await ada.api('/v1/usage?days=14');
check('the workspace usage lists every app with its views', wu.body.apps.find(a => a.app === APP)?.total_views === 4 && wu.body.days.length === 14);

// ---------- analytics ----------

const chrome = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36';
const iphone = 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1';
const landing = await send(url + '/?utm_source=newsletter&utm_campaign=launch&secret=1', { headers: { 'user-agent': chrome, 'sec-fetch-dest': 'document',
  referer: 'https://news.ycombinator.com/item?id=1', 'accept-language': 'de-DE,de;q=0.9' } });
check('pages carry the insights script', landing.body.includes('<script src="/_brod/insights.js" defer></script>') && !landing.headers['content-length']?.startsWith('0'));
await send(url + '/missing.html', { headers: { 'user-agent': iphone, 'sec-fetch-dest': 'document' } });
await send(url + '/', { headers: { 'user-agent': 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)', 'sec-fetch-dest': 'document' } });
const script = await send(url + '/_brod/insights.js');
check('the insights script is served on the app host', script.status === 200 && script.body.includes('brod.track'));
const beacon = await send(url + '/_brod/insights', { method: 'POST', headers: { 'user-agent': chrome, 'content-type': 'text/plain' },
  body: JSON.stringify([{ k: 'nav', p: '/settings' }, { k: 'vital', n: 'LCP', v: 1800 }, { k: 'event', n: 'signup', v: 1 }, { k: 'error', n: 'boom', l: '/app.js:1' }]) });
check('what the browser reports is taken in', beacon.status === 204);
const an = await ada.api(`/v1/analytics?days=7&app=${APP}`);
const A = an.body, has = (list, key) => (list ?? []).some(x => x.key === key);
check('analytics count page views, but not crawlers', an.status === 200 && A.totals.views === 7 && A.requests.bots >= 1, JSON.stringify(A.totals));
check('analytics break visits down by referrer, campaign, country, browser and device',
  has(A.referrers, 'news.ycombinator.com') && has(A.utm_sources, 'newsletter') && has(A.utm_campaigns, 'launch') && has(A.countries, 'DE')
  && has(A.languages, 'de') && has(A.browsers, 'Chrome') && has(A.devices, 'Mobile'), JSON.stringify([A.referrers, A.countries, A.devices]));
check('analytics list pages, missing pages and single-page-app navigations, never the query string',
  has(A.pages, '/') && has(A.pages, '/settings') && has(A.not_found, '/missing.html') && !JSON.stringify(A).includes('secret=1'));
check('analytics include web vitals, custom events and JavaScript errors',
  A.vitals.find(v => v.name === 'LCP')?.samples === 1 && has(A.events, 'signup') && A.errors[0]?.message === 'boom', JSON.stringify([A.vitals[0], A.events, A.errors]));
check('analytics cover sessions, requests and the period before', A.totals.sessions > 0 && A.requests.total >= 8 && A.series.length === 7 && A.previous.views === 0);
const long = await ada.api('/v1/analytics?days=365');
check('the free plan keeps 30 days of analytics', long.status === 200 && long.body.days === 30 && long.body.retention_days === 30 && has(long.body.by_app, APP));
check('members cannot see analytics', (await bo.api('/v1/analytics')).status === 403);

// ---------- storage ----------

const v1bytes = d1.body.bytes;
check('storage counts each kept version', wu.body.storage.total === v1bytes && wu.body.storage.limit > 0, JSON.stringify(wu.body.storage));
const d2 = await ada.api('/v1/deploys', { json: { app: APP, files: [{ path: 'index.html', content: '<h1>hello again</h1>' }] } });
check('a live version cannot be deleted', (await ada.api(`/v1/apps/${APP}/versions/2`, { method: 'DELETE' })).status === 409);
const del = await ada.api(`/v1/apps/${APP}/versions/1`, { method: 'DELETE' });
const after = await ada.api(`/v1/apps/${APP}/usage`);
check('deleting an old version frees its storage', del.status === 200 && del.body.freed_bytes === v1bytes && after.body.storage.total === d2.body.bytes, JSON.stringify(del.body));
check('the deleted version is gone from the list', !(await ada.api(`/v1/apps/${APP}`)).body.versions.some(v => v.version === 1));
const wsInfo = await ada.api('/v1/workspace');
check('get_workspace reports storage against the plan', wsInfo.body.storage_bytes === d2.body.bytes && wsInfo.body.storage_limit > wsInfo.body.storage_bytes);

// ---------- spaces ----------

const sp = await ada.api('/v1/spaces', { json: { name: 'Front desk', note: 'Tools for the desk' } });
check('admins create spaces', sp.status === 201 && sp.body.name === 'Front desk');
check('members cannot', (await bo.api('/v1/spaces', { json: { name: 'Mine' } })).status === 403);
await ada.api(`/v1/apps/${APP}/access`, { json: { access: 'people' } });
const moved = await ada.api(`/v1/apps/${APP}/space`, { json: { space: 'front desk' } });
const added = await ada.api('/v1/spaces/Front%20desk/members', { json: { email: bo.email, role: 'editor' } });
const list = await ada.api('/v1/spaces');
const desk = list.body.spaces[0];
check('a space lists its apps and people', moved.body.space === 'Front desk' && added.status === 200 && desk.apps[0]?.app === APP && desk.people[0]?.email === bo.email && desk.people[0].role === 'editor', JSON.stringify(list.body));
const described = (await ada.api(`/v1/apps/${APP}`)).body;
check('the app says it is in the space and who that lets in', described.space === 'Front desk' && /Front desk space/.test(described.who_can_open), described.who_can_open);

// Bo opens the app: the space lets him in with his space role.
const signin = await bo.go(`${url}/`);
let r = signin, hops = 0;
while (r.status >= 300 && r.status < 400 && hops++ < 10) r = await bo.go(new URL(r.headers.location, url).href);
const me = await bo.go(`${url}/_brod/me`);
check('someone in the space can open its apps, with their space role', r.status === 200 && JSON.parse(me.body).role === 'editor', `${r.status} ${me.body}`);
await ada.api(`/v1/spaces/Front%20desk/members/${encodeURIComponent(bo.email)}`, { method: 'DELETE' });
check('taking them out of the space takes the access away', (await bo.go(`${url}/`)).status === 404);
check('deleting a space keeps its apps', (await ada.api('/v1/spaces/Front%20desk', { method: 'DELETE' })).status === 200 && !(await ada.api(`/v1/apps/${APP}`)).body.space);

console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed ? 1 : 0);
