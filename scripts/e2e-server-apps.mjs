// SPDX-License-Identifier: AGPL-3.0-only
// Server apps on the self-hosted runtime (Rust server + workerd sidecar): the cases of test/server.test.ts, over HTTP.
// Run by scripts/e2e-rust.mjs after scripts/e2e.mjs when the runtime is on. Usage: node scripts/e2e-server-apps.mjs [api origin]
import http from 'node:http';

const API = process.argv[2] ?? 'http://localhost:8787';
const api = new URL(API);
let passed = 0, failed = 0;
const check = (name, ok, detail = '') => { ok ? passed++ : failed++; console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${ok || !detail ? '' : `\n      ${detail}`}`); };
const run = Date.now();

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
    const u = new URL(url, API), headers = { ...(o.headers ?? {}) };
    const c = Object.entries(this.jars[u.host] ?? {}).map(([k, v]) => `${k}=${v}`).join('; '); if (c) headers.cookie = c;
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
  async api(path, o = {}) { const r = await this.go(path, { ...o, headers: { ...(o.headers ?? {}), origin: API } }); return { status: r.status, body: r.body ? JSON.parse(r.body) : null }; }
}

const WORKER = `
export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname === '/api/count') {
      await env.DB.run('CREATE TABLE IF NOT EXISTS hits (n INTEGER)');
      await env.DB.run('INSERT INTO hits VALUES (?)', [1]);
      const [row] = await env.DB.query('SELECT COUNT(*) AS n FROM hits');
      console.log('counted', row.n);
      return Response.json({ count: row.n });
    }
    if (url.pathname === '/api/kv') { await env.KV.put('greeting', 'hej'); return new Response(await env.KV.get('greeting')); }
    if (url.pathname === '/api/file') {
      await env.FILES.put('notes/a.txt', 'file body', 'text/plain');
      const res = await env.FILES.get('notes/a.txt');
      return new Response(await res.text() + ' ' + (await env.FILES.list('notes/')).length);
    }
    if (url.pathname === '/api/me') return Response.json({ email: request.headers.get('x-brod-user-email'), role: request.headers.get('x-brod-role'), cookie: request.headers.get('cookie') });
    if (url.pathname === '/api/secret') return new Response(env.API_TOKEN ?? 'none');
    if (url.pathname === '/api/boom') throw new Error('kaboom');
    if (request.method === 'POST') return new Response('posted ' + await request.text());
    return new Response('<html><body>server home</body></html>', { headers: { 'content-type': 'text/html' } });
  },
};`;

const admin = new Browser(`server-${run}@acme.test`);
const start = await admin.go('/auth/start', { json: { email: admin.email } });
await admin.go('/auth/verify', { form: { token: new URL(JSON.parse(start.body).dev_link).searchParams.get('token') } });
await admin.api('/v1/workspaces', { json: { name: `Servers ${run}`, accept_terms: true } });
const deploy = async (o) => (await admin.api('/v1/deploys', { json: o }));

const d = await deploy({ name: 'Counter', files: [{ path: '_worker.js', content: WORKER }, { path: 'logo.txt', content: 'static file' }] });
check('a server app deploys with inline files', d.status === 201 && d.body.kind === 'server', JSON.stringify(d.body));
const url = d.body.url;
check('the server code answers pages', (await admin.open(url + '/')).body.includes('server home'));
const c1 = JSON.parse((await admin.go(url + '/api/count')).body), c2 = JSON.parse((await admin.go(url + '/api/count')).body);
check('its own database keeps data between requests', c1.count === 1 && c2.count === 2, JSON.stringify([c1, c2]));
check('its key-value store works', (await admin.go(url + '/api/kv')).body === 'hej');
check('its file storage works', (await admin.go(url + '/api/file')).body === 'file body 1');
check('files in the bundle are served directly', (await admin.go(url + '/logo.txt')).body === 'static file');
check('the server source is never served', !(await admin.go(url + '/_worker.js')).body.includes('export default'));
check('other methods reach the server code', (await admin.go(url + '/x', { method: 'POST', body: 'hi' })).body === 'posted hi');
const me = JSON.parse((await admin.go(url + '/api/me', { headers: { 'x-brod-role': 'owner-forged' } })).body);
check('the person arrives as headers; forged ones and the session cookie are stripped', me.email === admin.email && me.role === 'owner' && !(me.cookie ?? '').includes('brod_session'), JSON.stringify(me));

const other = await deploy({ name: 'Other', files: [{ path: '_worker.js', content: WORKER }] });
await admin.open(other.body.url + '/');
check('each app has its own database', JSON.parse((await admin.go(other.body.url + '/api/count')).body).count === 1);

const boom = await admin.go(url + '/api/boom');
check('a request that throws gets a plain error page, not the exception', boom.status === 502 && !boom.body.includes('kaboom'));
let found = [];
for (let i = 0; i < 40 && !found.length; i++) {
  found = (await admin.api(`/v1/apps/${d.body.app}/logs?search=kaboom`)).body.requests;
  if (!found.length) await new Promise(r => setTimeout(r, 250));
}
check('the exception shows in the logs', found[0]?.request === 'GET /api/boom' && found[0]?.outcome === 'exception', JSON.stringify(found[0]));
check('a search with no match finds nothing', (await admin.api(`/v1/apps/${d.body.app}/logs?search=nothing-like-this`)).body.requests.length === 0);

check('no secret yet', (await admin.go(url + '/api/secret')).body === 'none');
await admin.api(`/v1/apps/${d.body.app}/secrets/API_TOKEN`, { method: 'PUT', json: { value: 'tok-123' } });
check('a secret reaches the app on its next request', (await admin.go(url + '/api/secret')).body === 'tok-123');
await admin.api(`/v1/apps/${d.body.app}/secrets/API_TOKEN`, { method: 'PUT', json: { value: 'tok-456' } });
check('a changed secret too', (await admin.go(url + '/api/secret')).body === 'tok-456');
await admin.api(`/v1/apps/${d.body.app}/secrets/API_TOKEN`, { method: 'DELETE' });
check('a removed secret is gone', (await admin.go(url + '/api/secret')).body === 'none');

const syntax = await deploy({ app: d.body.app, files: [{ path: '_worker.js', content: 'export default {' }] });
const throws = await deploy({ app: d.body.app, files: [{ path: '_worker.js', content: 'throw new Error("no config"); export default {}' }] });
const nofetch = await deploy({ app: d.body.app, files: [{ path: '_worker.js', content: 'export default { hello: 1 }' }] });
check('server code that cannot start is refused', syntax.body.error?.code === 'server_failed' && throws.body.error?.message.includes('no config') && nofetch.body.error?.code === 'server_failed',
  JSON.stringify([syntax.body, throws.body, nofetch.body]));
check('and the live version keeps serving', (await admin.go(url + '/')).body.includes('server home'));

const folder = await deploy({ name: 'Folder', files: [
  { path: 'dist/_worker/index.js', content: "import { greet } from './greet.js'; import cfg from './cfg.json'; export default { fetch: () => new Response(greet(cfg.name)) };" },
  { path: 'dist/_worker/greet.js', content: 'export const greet = n => `hi ${n}`;' },
  { path: 'dist/_worker/cfg.json', content: '{"name":"brod"}' },
] });
check('a _worker/ folder with several modules loads', (await admin.open(folder.body.url + '/anything')).body === 'hi brod', JSON.stringify(folder.body));
await deploy({ app: folder.body.app, files: [{ path: 'index.html', content: '<html><body>static now</body></html>' }] });
check('a static version replaces it', (await admin.go(folder.body.url + '/')).body.includes('static now') && (await admin.go(folder.body.url + '/', { method: 'POST', body: 'x' })).status === 405);
await admin.api(`/v1/apps/${folder.body.app}/rollback`, { json: { version: 1 } });
check('and a rollback brings the server version back', (await admin.go(folder.body.url + '/anything')).body === 'hi brod');

const del = await admin.api(`/v1/apps/${other.body.app}`, { method: 'DELETE' });
const again = await deploy({ name: 'Other', files: [{ path: '_worker.js', content: WORKER }] });
await admin.open(again.body.url + '/');
check('deleting an app wipes it; a new app starts empty', del.status === 200 && JSON.parse((await admin.go(again.body.url + '/api/count')).body).count === 1);

// ---------- storage: an app's database and key-value data count toward the plan ----------
// e2e-rust.mjs runs Brod with DEV_FREE_STORAGE_MB=3, so a free workspace runs out after about 3 MB.

const FILLER = `
const chunk = 'x'.repeat(100 * 1024);
export default {
  async fetch(request, env) {
    const p = new URL(request.url).pathname;
    try {
      if (p === '/fill') { await env.DB.run('CREATE TABLE IF NOT EXISTS t (v TEXT)'); await env.DB.run('INSERT INTO t VALUES (?)', [chunk]); return new Response('ok'); }
      if (p === '/kv') { await env.KV.put('k' + Math.random(), chunk); return new Response('ok'); }
      if (p === '/read') { const [r] = await env.DB.query('SELECT COUNT(*) AS n FROM t'); return new Response(String(r.n)); }
      if (p === '/clear') { await env.DB.run('DELETE FROM t'); for (const k of await env.KV.list('k')) await env.KV.delete(k); return new Response('cleared'); }
    } catch (e) { return new Response(e.message, { status: 507 }); }
    return new Response('filler');
  },
};`;
const pause = ms => new Promise(r => setTimeout(r, ms));
const owner = new Browser(`filler-${run}@acme.test`);
const fs = await owner.go('/auth/start', { json: { email: owner.email } });
await owner.go('/auth/verify', { form: { token: new URL(JSON.parse(fs.body).dev_link).searchParams.get('token') } });
await owner.api('/v1/workspaces', { json: { name: `Filler ${run}`, accept_terms: true } });
const filler = await owner.api('/v1/deploys', { json: { name: 'Filler', files: [{ path: '_worker.js', content: FILLER }] } });
const furl = filler.body.url;
await owner.open(furl + '/');
await owner.go(furl + '/fill');
await pause(500);
const used = await owner.api(`/v1/apps/${filler.body.app}/usage`);
// Sizes are reported at most every 5 seconds unless they grew by 256 KB, so this one lags the second write a little.
check("an app's database size is reported and counts toward storage", used.body.storage.data > 0 && used.body.storage.total === used.body.storage.bundles + used.body.storage.data, JSON.stringify(used.body.storage));
let refused = null, rows = 1;
for (; rows < 60; rows++) { const r = await owner.go(furl + '/fill'); if (r.status !== 200) { refused = r; break; } }
check('when the workspace is out of storage, database writes are refused', refused?.status === 507 && /out of storage/.test(refused.body) && rows >= 20 && rows < 45, `${rows} rows, ${refused?.status} ${refused?.body}`);
const kv = await owner.go(furl + '/kv');
check('and key-value writes too', kv.status === 507 && /out of storage/.test(kv.body), `${kv.status} ${kv.body}`);
check('reads still work', (await owner.go(furl + '/read')).body === String(rows));
const ws = (await owner.api('/v1/workspace')).body;
check('get_workspace shows the workspace at its storage limit', ws.storage_bytes >= ws.storage_limit, JSON.stringify([ws.storage_bytes, ws.storage_limit]));
check('deleting data is allowed while full', (await owner.go(furl + '/clear')).body === 'cleared');
await pause(500);
const after = await owner.go(furl + '/fill');
check('and frees the space, so writes work again', after.status === 200 && after.body === 'ok', `${after.status} ${after.body}`);
await pause(500);
check('the reported size shrinks with it', (await owner.api(`/v1/apps/${filler.body.app}/usage`)).body.storage.data < 1024 * 1024);

// ---------- limits: an app that holds the runtime is cut off, and the others keep serving ----------
// workerd runs every app on one thread and does not enforce the CPU limit; its supervisor (deploy/runtime/supervisor/)
// restarts it, and Brod stops the app that made it (server/src/watchdog.rs). e2e-rust.mjs runs the supervisor with
// RUNTIME_STALL_MS=2000 and RUNTIME_MEMORY_MB=768.

const RUNAWAY = `
export default {
  async fetch(request) {
    const p = new URL(request.url).pathname;
    if (p === '/spin') for (;;) {}
    if (p === '/grow') { const kept = []; for (;;) { kept.push(new Array(1e6).fill(1)); await new Promise(r => setTimeout(r, 0)); } }
    return new Response('running');
  },
};`;
const STEADY = `export default { fetch: () => new Response('steady') };`;
const lim = new Browser(`limits-${run}@acme.test`);
const ls = await lim.go('/auth/start', { json: { email: lim.email } });
await lim.go('/auth/verify', { form: { token: new URL(JSON.parse(ls.body).dev_link).searchParams.get('token') } });
await lim.api('/v1/workspaces', { json: { name: `Limits ${run}`, accept_terms: true } });
const limDeploy = async (name, code) => (await lim.api('/v1/deploys', { json: { name, files: [{ path: '_worker.js', content: code }, { path: 'about.txt', content: 'static' }] } })).body;
const steady = await limDeploy('Steady', STEADY);
const spinner = await limDeploy('Spinner', RUNAWAY);
const hog = await limDeploy('Hog', RUNAWAY);
await lim.open(steady.url + '/');
await lim.open(spinner.url + '/');
await lim.open(hog.url + '/');
const timed = async (p) => { const t = Date.now(); const r = await p; return { ...r, ms: Date.now() - t }; };
const logsOf = async (app, outcome) => {
  for (let i = 0; i < 20; i++) {
    const found = (await lim.api(`/v1/apps/${app}/logs`)).body.requests.filter(r => !outcome || r.outcome === outcome);
    if (found.length || !outcome) return found;
    await pause(250);
  }
  return [];
};

const spin = timed(lim.go(spinner.url + '/spin'));
await pause(300);
const during = await timed(lim.go(steady.url + '/'));
const spun = await spin;
check('an app stuck in a loop is cut off', spun.status === 503 && spun.body.includes('was stopped') && spun.ms < 15_000, `${spun.status} after ${spun.ms} ms`);
check('a request to another app that queued behind it is answered once the runtime is back', during.status === 200 && during.body === 'steady' && during.ms < 15_000, `${during.status} ${during.body.slice(0, 80)} after ${during.ms} ms`);
const steadyNow = await timed(lim.go(steady.url + '/'));
check('and other apps keep serving', steadyNow.status === 200 && steadyNow.body === 'steady' && steadyNow.ms < 1000, `${steadyNow.status} after ${steadyNow.ms} ms`);
const paused = await lim.go(spinner.url + '/');
check('the app that stalled it is paused for a while', paused.status === 503 && paused.body.includes('paused') && Number(paused.headers['retry-after']) > 0, `${paused.status} retry-after ${paused.headers['retry-after']}`);
check('while its static files still serve', (await lim.go(spinner.url + '/about.txt')).body === 'static');
const spinLog = (await logsOf(spinner.app, 'exceededCpu'))[0];
check('its logs say why, for the agent to fix it', spinLog?.request === 'GET /spin' && /without pausing/.test(spinLog?.exceptions?.[0]?.message ?? '') && /stopped for/.test(spinLog?.exceptions?.[0]?.message ?? ''), JSON.stringify(spinLog));
check('the other app is not blamed', (await logsOf(steady.app)).every(r => r.outcome !== 'exceededCpu'));

const grow = timed(lim.go(hog.url + '/grow'));
await pause(300);
const whileGrowing = await timed(lim.go(steady.url + '/'));
const grown = await grow;
check('an app that uses too much memory is cut off', grown.status === 503 && grown.body.includes('too much memory') && grown.ms < 15_000, `${grown.status} after ${grown.ms} ms`);
check('other apps keep serving meanwhile', whileGrowing.status === 200 && whileGrowing.body === 'steady', `${whileGrowing.status} after ${whileGrowing.ms} ms`);
const hogLog = (await logsOf(hog.app, 'exceededMemory'))[0];
check('and it is paused too, with the reason in its logs', (await lim.go(hog.url + '/')).status === 503 && hogLog?.request === 'GET /grow', JSON.stringify(hogLog));
check('the runtime is back for everyone else', (await lim.go(steady.url + '/')).body === 'steady');

const stuck = await lim.api('/v1/deploys', { json: { app: steady.app, files: [{ path: '_worker.js', content: 'for (;;) {} export default { fetch: () => new Response("never") };' }] } });
check('server code whose start-up never finishes is refused', stuck.status === 400 && stuck.body.error?.code === 'server_failed' && /did not start/.test(stuck.body.error?.message), JSON.stringify(stuck.body));
check('and the live version keeps serving', (await lim.go(steady.url + '/')).body === 'steady');

console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed ? 1 : 0);
