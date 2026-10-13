// The server-app runtime for the self-hosted Brod: a host Worker that runs in workerd next to the Rust server.
// It is src/runtime.ts adapted to a sidecar. The Rust gateway decides access and forwards an app's request here with
// the app id, version and secrets revision; this Worker loads the app's code into its own isolate with the Worker
// Loader (keyed by app:version:secrets-revision), so a rollback or a secret change takes effect on the next request.
// The app sees only what it is handed in `env`: its secrets and capabilities scoped to itself by `props`:
//   env.SETTINGS  the settings its workspace chose for it (brod.json), defaults filled in
// Its own fetch() goes through AppOutbound, which lets through only the hosts its brod.json declares (or logs them).
//   env.DB     its own SQLite database (a Durable Object per app, on disk)
//   env.KV     a small key-value store in the same object
// Its size counts toward the workspace's storage: it reports to Brod after writes and refuses growth when it is full.
//   env.FILES  file storage, kept by the Rust server under <app id>/files/
// Its console output and exceptions reach AppLogs through the loader's tail hook and are posted back to Rust.
//
// Every request between the two carries the shared BROD_RUNTIME_SECRET. Brod is reached through the BROD service
// binding; apps' own outgoing fetches go to the public internet only (see config.capnp).
import { DurableObject, WorkerEntrypoint } from 'cloudflare:workers';

const COMPAT_DATE = '2025-09-01';
const LOG_BYTES = 8 * 1024;
const SERVER_CPU_MS = 50;
const SERVER_SUBREQUESTS = 50;
// Storage: the database (and the key-value store in it) reports its size to Brod after writes, at most this often unless
// it changed by more than this much. While the workspace is out of storage, writes that can grow it are refused; reads
// and deletes still work, and deleting frees space at once (the file shrinks), which lifts the block on the next write.
const REPORT_MS = 5000;
const REPORT_BYTES = 256 * 1024;
const FULL_RECHECK_MS = 30000;
const READS = /^\s*(select|explain)\b/i;
const SHRINKS = /^\s*(delete|drop)\b/i;
const OUT_OF_STORAGE = "This app's workspace is out of storage. Delete data you no longer need, or ask a workspace admin to upgrade the plan.";

const fail = message => { throw new Error(message); };   // errors cross RPC to the app as plain Errors
const sqlValue = v => {
  if (v === undefined || v === null) return null;
  if (typeof v === 'boolean') return v ? 1 : 0;
  if (typeof v === 'number' || typeof v === 'string' || v instanceof ArrayBuffer) return v;
  if (ArrayBuffer.isView(v)) return v.buffer.slice(v.byteOffset, v.byteOffset + v.byteLength);
  return JSON.stringify(v);
};

/** A call to the Rust server's internal runtime endpoints. */
function brod(env, path, init = {}) {
  const headers = new Headers(init.headers);
  headers.set('x-brod-runtime-secret', env.BROD_RUNTIME_SECRET);
  return env.BROD.fetch(`http://brod${path}`, { ...init, headers });
}

// ---------- the per-app database ----------

/** One SQLite database and key-value store per app. Created on first use; costs nothing while idle. */
export class AppData extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
    this.full = false;      // what Brod last said about the workspace's storage
    this.checked = 0;
    this.reported = { at: 0, size: -1 };
  }
  size() { return this.ctx.storage.sql.databaseSize; }
  /** Tell Brod how big this database is now; it answers whether the workspace is out of storage. */
  async report(appId, force = false) {
    const size = this.size();
    if (!force && Date.now() - this.reported.at < REPORT_MS && Math.abs(size - this.reported.size) < REPORT_BYTES) return;
    this.reported = { at: Date.now(), size };
    try {
      const res = await brod(this.env, '/_runtime/usage', { method: 'POST', body: JSON.stringify({ app: appId, data_bytes: size }), headers: { 'content-type': 'application/json' } });
      if (!res.ok) { await res.body?.cancel(); return; }
      this.full = Boolean((await res.json()).full);
      this.checked = Date.now();
    } catch { /* Brod is unreachable for a moment: the next write tries again */ }
  }
  /** Refuse a write that can grow the database while the workspace is out of storage. */
  async guard(appId, grows) {
    if (!grows || !this.full) return;
    if (Date.now() - this.checked > FULL_RECHECK_MS) await this.report(appId, true);
    if (this.full) fail(OUT_OF_STORAGE);
  }
  after(appId, wrote) {
    if (wrote) this.ctx.waitUntil(this.report(appId, this.full));
  }
  exec(sql, params) {
    const c = this.ctx.storage.sql.exec(sql, ...params);
    const rows = c.toArray();
    return { rows, rowsWritten: c.rowsWritten };
  }
  async query(appId, sql, params = []) {
    await this.guard(appId, !READS.test(sql) && !SHRINKS.test(sql));
    const r = this.exec(sql, params);
    this.after(appId, r.rowsWritten > 0 || !READS.test(sql));
    return r;
  }
  async batch(appId, statements) {
    await this.guard(appId, statements.some(s => !READS.test(s.sql) && !SHRINKS.test(s.sql)));
    const r = this.ctx.storage.transactionSync(() => statements.map(s => this.exec(s.sql, s.params ?? [])));
    this.after(appId, statements.some(s => !READS.test(s.sql)));
    return r;
  }
  kvGet(key) { return this.ctx.storage.kv.get(key) ?? null; }
  async kvPut(appId, key, value) {
    await this.guard(appId, true);
    this.ctx.storage.kv.put(key, value);
    this.after(appId, true);
  }
  kvDelete(appId, key) {
    const r = this.ctx.storage.kv.delete(key);
    this.after(appId, true);
    return r;
  }
  kvList(prefix, limit) { return [...this.ctx.storage.kv.list({ prefix, limit })].map(([k]) => k); }
  async wipe() { await this.ctx.storage.deleteAll(); }
}
const data = (env, appId) => env.APP_DATA.get(env.APP_DATA.idFromName(appId));

/** env.DB inside an app: `await env.DB.query(sql, params)` returns rows; `run` returns how many rows changed. */
export class AppDatabase extends WorkerEntrypoint {
  async query(sql, params = []) {
    const appId = this.ctx.props.appId;
    return (await data(this.env, appId).query(appId, String(sql), (params ?? []).map(sqlValue))).rows;
  }
  async run(sql, params = []) {
    const appId = this.ctx.props.appId;
    return { changes: (await data(this.env, appId).query(appId, String(sql), (params ?? []).map(sqlValue))).rowsWritten };
  }
  /** Several statements in one transaction: all apply or none do. */
  async batch(statements) {
    const appId = this.ctx.props.appId;
    const r = await data(this.env, appId).batch(appId, statements.map(s => ({ sql: String(s.sql), params: (s.params ?? []).map(sqlValue) })));
    return r.map(x => x.rows);
  }
}

const kvKey = k => {
  const key = String(k ?? '');
  if (!key || key.length > 512) fail('A key is 1 to 512 characters.');
  return key;
};
/** env.KV inside an app: string values, up to 128 KB each. */
export class AppKV extends WorkerEntrypoint {
  async get(key) { return data(this.env, this.ctx.props.appId).kvGet(kvKey(key)); }
  async put(key, value) {
    const v = String(value);
    if (v.length > 128 * 1024) fail('A value can be at most 128 KB.');
    await data(this.env, this.ctx.props.appId).kvPut(this.ctx.props.appId, kvKey(key), v);
  }
  async delete(key) { return data(this.env, this.ctx.props.appId).kvDelete(this.ctx.props.appId, kvKey(key)); }
  async list(prefix = '', limit = 1000) { return data(this.env, this.ctx.props.appId).kvList(String(prefix), Math.min(Math.max(Number(limit) || 1000, 1), 1000)); }
}

/** env.FILES inside an app: files under the app's own prefix, stored by the Rust server. */
export class AppFiles extends WorkerEntrypoint {
  key(k) {
    const key = String(k ?? '').replace(/^\/+/, '');
    if (!key || key.length > 512 || key.split('/').includes('..')) fail('A file key is 1 to 512 characters, without "..".');
    return key;
  }
  path(key) { return `/_runtime/files/${this.ctx.props.appId}/${key.split('/').map(encodeURIComponent).join('/')}`; }
  async put(key, body, contentType = 'application/octet-stream') {
    const k = this.key(key);
    const res = await brod(this.env, this.path(k), { method: 'PUT', body: await new Response(body).arrayBuffer(), headers: { 'content-type': String(contentType) } });
    if (!res.ok) fail(`Could not store ${k}: ${await res.text()}`);
    return { key, size: (await res.json()).size };
  }
  /** A Response with the file's body and content type, or null when there is no such file. */
  async get(key) {
    const res = await brod(this.env, this.path(this.key(key)));
    if (res.status === 404) { await res.body?.cancel(); return null; }
    if (!res.ok) fail(`Could not read ${key}: ${await res.text()}`);
    return new Response(res.body, { headers: { 'content-type': res.headers.get('content-type') ?? 'application/octet-stream', etag: res.headers.get('etag') ?? '' } });
  }
  async delete(key) { await (await brod(this.env, this.path(this.key(key)), { method: 'DELETE' })).body?.cancel(); }
  async list(prefix = '') {
    const res = await brod(this.env, `/_runtime/files/${this.ctx.props.appId}?prefix=${encodeURIComponent(String(prefix))}`);
    if (!res.ok) fail(`Could not list files: ${await res.text()}`);
    return res.json();
  }
}

// ---------- logs ----------

const clip = (s, n) => (s.length > n ? s.slice(0, n) + '…' : s);
/** Receives the trace of every request a server app handled, and hands it to the Rust server for get_logs. */
export class AppLogs extends WorkerEntrypoint {
  async tail(events) {
    const { appId, version } = this.ctx.props;
    const rows = events.map(e => {
      const ev = e.event;
      let path = '';
      try { const u = new URL(ev?.request?.url ?? ''); path = u.pathname + u.search; } catch { /* not a fetch event */ }
      const logs = e.logs.map(l => ({ level: l.level, at: l.timestamp, message: (Array.isArray(l.message) ? l.message : [l.message]).map(m => (typeof m === 'string' ? m : JSON.stringify(m))).join(' ') }));
      const exceptions = e.exceptions.map(x => ({ name: x.name, message: x.message, at: x.timestamp }));
      return {
        app_id: appId, at: e.eventTimestamp ?? Date.now(), version: version ?? null, method: ev?.request?.method ?? '', path: clip(path, 500),
        status: ev?.response?.status ?? null, outcome: e.outcome, logs: clip(JSON.stringify(logs), LOG_BYTES), exceptions: clip(JSON.stringify(exceptions), LOG_BYTES),
      };
    });
    if (!rows.length) return;
    const res = await brod(this.env, '/_runtime/logs', { method: 'POST', body: JSON.stringify(rows), headers: { 'content-type': 'application/json' } });
    await res.body?.cancel();
  }
}

// ---------- outside requests ----------

/** Whether a host is covered by an app's declared hosts. "*.example.com" covers subdomains only, as in network.rs. */
function declares(allow, host) {
  host = host.toLowerCase();
  return allow.some(d => d.startsWith('*.') ? host.endsWith(d.slice(1)) && host.length > d.length - 1 : d === host);
}
// Undeclared requests are reported to Brod at most once per app and host every REPORT_EVERY_MS, with how many there were.
const REPORT_EVERY_MS = 10000;
const undeclared = new Map();
function reportUndeclared(env, ctx, appId, version, host, blocked) {
  const key = `${appId} ${host}`;
  const r = undeclared.get(key) ?? { at: 0, count: 0 };
  r.count++;
  undeclared.set(key, r);
  if (Date.now() - r.at < REPORT_EVERY_MS) return;
  const count = r.count;
  Object.assign(r, { at: Date.now(), count: 0 });
  ctx.waitUntil(brod(env, '/_runtime/network', { method: 'POST', body: JSON.stringify({ app: appId, version, host, count, blocked }), headers: { 'content-type': 'application/json' } })
    .then(res => res.body?.cancel()).catch(() => { /* Brod is unreachable for a moment: the next one reports it */ }));
}

/**
 * The only way out for an app's own fetch(): every outgoing request passes here. A host the app declares in its
 * brod.json goes through; any other is reported to Brod, and refused when Brod enforces declarations.
 */
export class AppOutbound extends WorkerEntrypoint {
  async fetch(request) {
    const { appId, version, network } = this.ctx.props;
    const host = new URL(request.url).hostname;
    if (network.policy === 'off' || declares(network.allow, host)) return fetch(request);
    const blocked = network.policy === 'enforce';
    reportUndeclared(this.env, this.ctx, appId, version, host, blocked);
    if (!blocked) return fetch(request);
    return new Response(`Brod refused this request: ${host} is not one of the hosts this app declares in the "network" list of its brod.json.`, { status: 403, headers: { 'x-brod-network': 'refused' } });
  }
}

// ---------- loading an app ----------

const unb64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
export function moduleFor(path, bytes) {
  const ext = path.split('.').pop().toLowerCase();
  const text = () => new TextDecoder().decode(bytes);
  if (ext === 'js' || ext === 'mjs') return { js: text() };
  if (ext === 'cjs') return { cjs: text() };
  if (ext === 'json') { try { return { json: JSON.parse(text()) }; } catch { throw new Error(`${path} is not valid JSON.`); } }
  if (ext === 'wasm') return { wasm: bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) };
  if (['txt', 'html', 'md', 'css', 'sql', 'svg', 'csv'].includes(ext)) return { text: text() };
  return { data: bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) };
}
const modulesOf = files => Object.fromEntries(Object.entries(files).map(([p, b64]) => [p, moduleFor(p, unb64(b64))]));

function serverFor(env, ctx, appId, version, rev) {
  const props = { appId, version };
  const stub = env.LOADER.get(`${appId}:${version}:${rev}`, async () => {
    const res = await brod(env, `/_runtime/code?app=${encodeURIComponent(appId)}&version=${version}`);
    if (!res.ok) throw new Error(`Brod did not hand over the code: ${res.status} ${await res.text()}`);
    const code = await res.json();
    return {
      compatibilityDate: COMPAT_DATE,
      compatibilityFlags: ['nodejs_compat'],
      mainModule: code.main,
      modules: modulesOf(code.modules),
      env: {
        ...code.secrets,
        SETTINGS: code.settings ?? {},
        DB: ctx.exports.AppDatabase({ props }), KV: ctx.exports.AppKV({ props }), FILES: ctx.exports.AppFiles({ props }),
      },
      // Outgoing fetches pass the app's declared hosts (network.rs); without a declaration, nothing gets out under "enforce".
      globalOutbound: ctx.exports.AppOutbound({ props: { ...props, network: code.network ?? { policy: 'log', allow: [] } } }),
      tails: [ctx.exports.AppLogs({ props })],
      limits: { cpuMs: SERVER_CPU_MS, subRequests: SERVER_SUBREQUESTS },
    };
  });
  return stub.getEntrypoint();
}

/** Refuse server code that cannot start: import the main module (running its top-level code) and check it exports fetch. */
async function check(env, body) {
  const modules = modulesOf(body.modules);
  modules['__brod_check.js'] = { js: `import * as m from './${body.main}';
export default { fetch() { const h = m.default; return new Response(h && typeof h.fetch === 'function' ? 'ok' : 'no_fetch'); } };` };
  try {
    const stub = env.LOADER.load({ compatibilityDate: COMPAT_DATE, compatibilityFlags: ['nodejs_compat'], mainModule: '__brod_check.js', modules, env: {}, globalOutbound: null, limits: { cpuMs: 200 } });
    return Response.json({ verdict: await (await stub.getEntrypoint().fetch('http://check/')).text() });
  } catch (e) {
    return Response.json({ error: e?.message ?? String(e) });
  }
}

const failed = message => new Response(message, { status: 502, headers: { 'x-brod-runtime-error': '1' } });

export default {
  async fetch(request, env, ctx) {
    if (!env.BROD_RUNTIME_SECRET || request.headers.get('x-brod-runtime-secret') !== env.BROD_RUNTIME_SECRET) return new Response('forbidden', { status: 403 });
    const url = new URL(request.url);
    if (url.pathname === '/_runtime/check' && request.method === 'POST') return check(env, await request.json());
    if (url.pathname === '/_runtime/wipe' && request.method === 'POST') {
      await data(env, String((await request.json()).app)).wipe();
      return Response.json({ wiped: true });
    }
    if (url.pathname === '/_runtime/sizes' && request.method === 'POST') {
      // How big each app's database is, for Brod's periodic storage count.
      const apps = ((await request.json()).apps ?? []).map(String).slice(0, 200);
      const sizes = Object.fromEntries(await Promise.all(apps.map(async a => [a, await data(env, a).size()])));
      return Response.json({ sizes });
    }
    if (url.pathname === '/_runtime/health') return Response.json({ ok: true });

    // An app request: the Rust gateway already decided access and set the identity headers.
    const appId = request.headers.get('x-brod-runtime-app');
    const version = Number(request.headers.get('x-brod-runtime-version'));
    const rev = Number(request.headers.get('x-brod-runtime-rev') ?? 0);
    const target = request.headers.get('x-brod-runtime-url');
    if (!appId || !version || !target) return new Response('missing app', { status: 400 });
    const headers = new Headers(request.headers);
    for (const k of [...headers.keys()]) if (k.startsWith('x-brod-runtime-')) headers.delete(k);
    const hasBody = request.method !== 'GET' && request.method !== 'HEAD';
    let res;
    try {
      res = await serverFor(env, ctx, appId, version, rev).fetch(new Request(target, { method: request.method, headers, body: hasBody ? request.body : undefined, redirect: 'manual' }));
    } catch (e) {
      console.error('server app failed', appId, e);
      return failed(e?.message ?? String(e));
    }
    return res;
  },
};
