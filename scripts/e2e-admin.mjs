// SPDX-License-Identifier: AGPL-3.0-only
// Admin mode on the Rust server (docs/plans/admin-mode.md): the operator API behind ADMIN_SECRET, instance settings
// that take effect without a restart, per-workspace limit overrides that beat the plan, operators and the audit log,
// and the /admin console page. Run by scripts/e2e-rust.mjs.
// Usage: node scripts/e2e-admin.mjs <api origin>
const API = process.argv[2] ?? 'http://localhost:8787';
const SECRET = process.env.ADMIN_SECRET ?? 'dev-admin-secret';
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
    let body = null;
    try { body = r.body ? JSON.parse(r.body) : null; } catch { body = r.body; }
    return { status: r.status, body };
  }
}

const admin = async (path, { method = 'GET', json, token = SECRET } = {}) => {
  const headers = token ? { authorization: `Bearer ${token}` } : {};
  if (json !== undefined) headers['content-type'] = 'application/json';
  const r = await fetch(`${API}/v1/admin${path}`, { method, headers, body: json === undefined ? undefined : JSON.stringify(json) });
  const text = await r.text();
  let body = null;
  try { body = text ? JSON.parse(text) : null; } catch { body = text; }
  return { status: r.status, body };
};

// ---------- the operator API needs the secret ----------

check('the console API refuses a request without the admin secret', (await admin('/overview', { token: null })).status === 401);
check('the console API refuses a wrong admin secret', (await admin('/overview', { token: 'not-the-secret' })).status === 401);
const ov = await admin('/overview');
check('the overview counts workspaces, users and apps', ov.status === 200 && typeof ov.body.workspaces === 'number' && typeof ov.body.apps?.live === 'number' && ['hosted', 'self-hosted'].includes(ov.body.mode), JSON.stringify(ov.body));

// ---------- instance settings ----------

const settings = await admin('/settings');
const setting = (list, key) => list.find(s => s.key === key);
check('the settings list every knob with its source', settings.status === 200 && !!setting(settings.body.settings, 'limits.max_running_apps') && !!setting(settings.body.settings, 'server.max_workspaces'), JSON.stringify(settings.body).slice(0, 300));
check('an unknown setting is refused', (await admin('/settings', { method: 'PATCH', json: { 'nope.nothing': 1 } })).status === 404);
check('a setting of the wrong kind is refused', (await admin('/settings', { method: 'PATCH', json: { 'limits.max_members': 'lots' } })).status === 400);

// ---------- a workspace and its limits ----------

const ana = new Browser(`ana-${run}@admin.test`);
await ana.signIn();
ana.workspace = (await ana.api('/v1/workspaces', { json: { name: `Admin ${run}`, accept_terms: true } })).body.workspace;
const W = ana.workspace;
check('a person can make a workspace', typeof W === 'string' && W.length > 0);

const found = await admin(`/workspaces?q=${encodeURIComponent(W)}`);
check('the console finds a workspace by slug', found.status === 200 && found.body.workspaces.some(w => w.slug === W), JSON.stringify(found.body).slice(0, 300));
const before = await admin(`/workspaces/${W}/limits`);
check('a workspace shows its base, override and effective limits', before.status === 200 && before.body.override === null && !!before.body.effective, JSON.stringify(before.body));

check('a negative limit is refused', (await admin(`/workspaces/${W}/limits`, { method: 'PATCH', json: { max_members: -3 } })).status === 400);
check('an unknown limit field is refused', (await admin(`/workspaces/${W}/limits`, { method: 'PATCH', json: { apps: 1 } })).status === 400);
check('limits of a missing workspace are a 404', (await admin(`/workspaces/no-such-${run}/limits`, { method: 'PATCH', json: { max_members: 1 } })).status === 404);

const capped = await admin(`/workspaces/${W}/limits`, { method: 'PATCH', json: { max_members: 1, note: 'e2e' } });
check('an override sets one limit and keeps the rest', capped.status === 200 && capped.body.effective.max_members === 1 && capped.body.override.note === 'e2e', JSON.stringify(capped.body));

const inv = await ana.api('/v1/invites', { json: { email: `bo-${run}@admin.test`, role: 'member' } });
check('the override is enforced: inviting past the member limit is refused', inv.status === 402 && inv.body?.error?.code === 'member_limit', JSON.stringify(inv));

const lifted = await admin(`/workspaces/${W}/limits`, { method: 'PATCH', json: { max_members: 'unlimited' } });
check('an override can lift a limit to unlimited', lifted.status === 200 && lifted.body.effective.max_members === null && lifted.body.override.max_members === 'unlimited', JSON.stringify(lifted.body));
const inv2 = await ana.api('/v1/invites', { json: { email: `bo-${run}@admin.test`, role: 'member' } });
check('the lifted limit applies right away', inv2.status === 201 || inv2.status === 200, JSON.stringify(inv2));

const cleared = await admin(`/workspaces/${W}/limits`, { method: 'PATCH', json: { max_members: null, note: null } });
check('clearing every field removes the override', cleared.status === 200 && cleared.body.override === null, JSON.stringify(cleared.body));

// ---------- operators ----------

const ops = await admin('/operators');
check('the operators list is readable', ops.status === 200 && Array.isArray(ops.body.operators));
check('making an operator needs an existing account', (await admin('/operators', { method: 'POST', json: { email: `nobody-${run}@admin.test` } })).status === 404);
const added = await admin('/operators', { method: 'POST', json: { email: ana.email } });
const anaOp = (added.body?.operators ?? []).find(o => o.email === ana.email);
check('an existing person can be made an operator', added.status === 200 && !!anaOp, JSON.stringify(added.body));

const page = await ana.go('/admin');
check('an operator gets the console page', page.status === 200 && page.body.includes('admin'), `status ${page.status}`);
const viaCookie = await ana.go('/v1/admin/overview');
check('an operator signed in on the dashboard may use the console API', viaCookie.status === 200, `status ${viaCookie.status}`);

const cy = new Browser(`cy-${run}@admin.test`);
await cy.signIn();
check('someone who is not an operator gets a 403 on /admin', (await cy.go('/admin')).status === 403);
check('someone who is not an operator gets a 403 on the console API', (await cy.go('/v1/admin/overview')).status === 403);
const anon = await new Browser('x@admin.test').go('/admin');
check('/admin sends a signed-out visitor to sign in', anon.status >= 300 && anon.status < 400 && (anon.headers.location ?? '').includes('/auth/signin'), `status ${anon.status}`);

if (anaOp) {
  // The last operator cannot be removed, so make cy one first.
  await admin('/operators', { method: 'POST', json: { email: cy.email } });
  const removed = await admin(`/operators/${encodeURIComponent(anaOp.id)}`, { method: 'DELETE' });
  check('an operator can be removed', removed.status === 200 && !(removed.body.operators ?? []).some(o => o.email === ana.email), JSON.stringify(removed.body));
  check('a removed operator loses the console', (await ana.go('/v1/admin/overview')).status === 403);
}

// ---------- audit ----------

const audit = await admin('/audit');
const actions = (audit.body?.events ?? []).map(e => e.action);
check('the audit log records limit and operator changes', audit.status === 200 && actions.includes('limits_changed') && actions.includes('operator_added'), JSON.stringify(actions.slice(0, 10)));

console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed ? 1 : 0);
