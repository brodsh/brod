// Server apps. An app's server code is loaded on demand into its own isolate with the Worker Loader, keyed by
// app, version and secrets revision, so a rollback or a secret change takes effect on the next request.
// The app sees only what it is handed in `env`: its secrets, and capabilities scoped to itself by `props`:
//   env.DB     its own SQLite database (a Durable Object per app)
//   env.KV     a small key-value store in the same object
//   env.FILES  file storage under its own R2 prefix
// Its console output and exceptions reach AppLogs through the loader's tail hook.
import { DurableObject, WorkerEntrypoint } from 'cloudflare:workers';
import { AppRow, Env, LIMITS, Problem, now } from './lib';
import { readSecrets } from './secrets';

export interface ServerInfo { main: string; modules: string[] }
interface AppProps { appId: string; version?: number }

export const COMPAT_DATE = '2025-09-01';
type SqlValue = string | number | null | ArrayBuffer;
const sqlValue = (v: unknown): SqlValue => {
  if (v === undefined || v === null) return null;
  if (typeof v === 'boolean') return v ? 1 : 0;
  if (typeof v === 'number' || typeof v === 'string' || v instanceof ArrayBuffer) return v;
  if (ArrayBuffer.isView(v)) return v.buffer.slice(v.byteOffset, v.byteOffset + v.byteLength) as ArrayBuffer;
  return JSON.stringify(v);
};
const fail = (message: string) => { throw new Error(message); };   // errors cross RPC to the app as plain Errors

// ---------- the per-app database ----------

/** One SQLite database and key-value store per app. Created on first use; costs nothing while idle. */
export class AppData extends DurableObject<Env> {
  query(sql: string, params: SqlValue[] = []) {
    const c = this.ctx.storage.sql.exec(sql, ...params);
    const rows = c.toArray();
    return { rows, rowsWritten: c.rowsWritten };
  }
  batch(statements: { sql: string; params?: SqlValue[] }[]) {
    return this.ctx.storage.transactionSync(() => statements.map(s => this.query(s.sql, s.params ?? [])));
  }
  kvGet(key: string) { return this.ctx.storage.kv.get<string>(key) ?? null; }
  kvPut(key: string, value: string) { this.ctx.storage.kv.put(key, value); }
  kvDelete(key: string) { return this.ctx.storage.kv.delete(key); }
  kvList(prefix: string, limit: number) { return [...this.ctx.storage.kv.list({ prefix, limit })].map(([k]) => k); }
  async wipe() { await this.ctx.storage.deleteAll(); }
}
const data = (env: Env, appId: string) => env.APP_DATA.get(env.APP_DATA.idFromName(appId));

/** env.DB inside an app: `await env.DB.query(sql, params)` returns rows; `run` returns how many rows changed. */
export class AppDatabase extends WorkerEntrypoint<Env, AppProps> {
  async query(sql: string, params: unknown[] = []) {
    return (await data(this.env, this.ctx.props.appId).query(String(sql), (params ?? []).map(sqlValue))).rows;
  }
  async run(sql: string, params: unknown[] = []) {
    return { changes: (await data(this.env, this.ctx.props.appId).query(String(sql), (params ?? []).map(sqlValue))).rowsWritten };
  }
  /** Several statements in one transaction: all apply or none do. */
  async batch(statements: { sql: string; params?: unknown[] }[]) {
    const r = await data(this.env, this.ctx.props.appId).batch(statements.map(s => ({ sql: String(s.sql), params: (s.params ?? []).map(sqlValue) })));
    return r.map(x => x.rows);
  }
}

const kvKey = (k: unknown) => {
  const key = String(k ?? '');
  if (!key || key.length > 512) fail('A key is 1 to 512 characters.');
  return key;
};
/** env.KV inside an app: string values, up to 128 KB each. */
export class AppKV extends WorkerEntrypoint<Env, AppProps> {
  async get(key: string) { return data(this.env, this.ctx.props.appId).kvGet(kvKey(key)); }
  async put(key: string, value: string) {
    const v = String(value);
    if (v.length > 128 * 1024) fail('A value can be at most 128 KB.');
    await data(this.env, this.ctx.props.appId).kvPut(kvKey(key), v);
  }
  async delete(key: string) { return data(this.env, this.ctx.props.appId).kvDelete(kvKey(key)); }
  async list(prefix = '', limit = 1000) { return data(this.env, this.ctx.props.appId).kvList(String(prefix), Math.min(Math.max(Number(limit) || 1000, 1), 1000)); }
}

/** env.FILES inside an app: files under the app's own prefix in R2. */
export class AppFiles extends WorkerEntrypoint<Env, AppProps> {
  private key(k: unknown) {
    const key = String(k ?? '').replace(/^\/+/, '');
    if (!key || key.length > 512 || key.split('/').includes('..')) fail('A file key is 1 to 512 characters, without "..".');
    return `${this.ctx.props.appId}/files/${key}`;
  }
  async put(key: string, body: ReadableStream | ArrayBuffer | ArrayBufferView | string, contentType = 'application/octet-stream') {
    const obj = await this.env.BUNDLES.put(this.key(key), body, { httpMetadata: { contentType: String(contentType) } });
    return { key, size: obj?.size ?? 0 };
  }
  /** A Response with the file's body and content type, or null when there is no such file. */
  async get(key: string) {
    const obj = await this.env.BUNDLES.get(this.key(key));
    return obj ? new Response(obj.body, { headers: { 'content-type': obj.httpMetadata?.contentType ?? 'application/octet-stream', etag: obj.httpEtag } }) : null;
  }
  async delete(key: string) { await this.env.BUNDLES.delete(this.key(key)); }
  async list(prefix = '') {
    const base = `${this.ctx.props.appId}/files/`;
    const r = await this.env.BUNDLES.list({ prefix: base + String(prefix), limit: 1000 });
    return r.objects.map(o => ({ key: o.key.slice(base.length), size: o.size, uploaded: o.uploaded.toISOString() }));
  }
}

// ---------- logs ----------

const clip = (s: string, n: number) => (s.length > n ? s.slice(0, n) + '…' : s);
/** Receives the trace of every request a server app handled, and keeps it for get_logs. */
export class AppLogs extends WorkerEntrypoint<Env, AppProps> {
  async tail(events: TraceItem[]) {
    const { appId, version } = this.ctx.props;
    const rows = events.map(e => {
      const ev = e.event as TraceItemFetchEventInfo | null;
      let path = '';
      try { const u = new URL(ev?.request?.url ?? ''); path = u.pathname + u.search; } catch { /* not a fetch event */ }
      const logs = e.logs.map(l => ({ level: l.level, at: l.timestamp, message: (Array.isArray(l.message) ? l.message : [l.message]).map(m => (typeof m === 'string' ? m : JSON.stringify(m))).join(' ') }));
      const exceptions = e.exceptions.map(x => ({ name: x.name, message: x.message, at: x.timestamp }));
      return this.env.DB.prepare('INSERT INTO app_logs (app_id, at, version, method, path, status, outcome, logs, exceptions) VALUES (?,?,?,?,?,?,?,?,?)')
        .bind(appId, e.eventTimestamp ?? now(), version ?? null, ev?.request?.method ?? '', clip(path, 500), ev?.response?.status ?? null, e.outcome,
          clip(JSON.stringify(logs), LIMITS.logBytes), clip(JSON.stringify(exceptions), LIMITS.logBytes));
    });
    if (!rows.length) return;
    // Keep 7 days. Pruning now and then on write keeps this free of a scheduled job.
    if (Math.random() < 0.05) rows.push(this.env.DB.prepare('DELETE FROM app_logs WHERE at < ?').bind(now() - LIMITS.logRetentionMs));
    await this.env.DB.batch(rows);
  }
}

// ---------- loading an app ----------

export function moduleFor(path: string, bytes: ArrayBuffer): string | WorkerLoaderModule {
  const ext = path.split('.').pop()!.toLowerCase();
  const text = () => new TextDecoder().decode(bytes);
  if (ext === 'js' || ext === 'mjs') return { js: text() };
  if (ext === 'cjs') return { cjs: text() };
  if (ext === 'json') { try { return { json: JSON.parse(text()) }; } catch { throw new Problem(400, 'bad_server', `${path} is not valid JSON.`); } }
  if (ext === 'wasm') return { wasm: bytes };
  if (['txt', 'html', 'md', 'css', 'sql', 'svg', 'csv'].includes(ext)) return { text: text() };
  return { data: bytes };
}

/** The entrypoint of an app's server code at a version, loaded once per isolate and reused while warm. */
export function serverFor(env: Env, ctx: ExecutionContext, app: AppRow, version: number, server: ServerInfo, secretsRev: number): Fetcher {
  const props = { appId: app.id, version };
  const exportsOf = ctx.exports as unknown as Record<string, (o: { props: AppProps }) => Fetcher>;
  const stub = env.LOADER.get(`${app.id}:${version}:${secretsRev}`, async () => {
    const modules: Record<string, string | WorkerLoaderModule> = {};
    await Promise.all(server.modules.map(async p => {
      const obj = await env.BUNDLES.get(`${app.id}/${version}/${p}`);
      if (!obj) throw new Problem(500, 'missing_module', `The server module ${p} is missing.`);
      modules[p] = moduleFor(p, await obj.arrayBuffer());
    }));
    return {
      compatibilityDate: COMPAT_DATE,
      compatibilityFlags: ['nodejs_compat'],
      mainModule: server.main,
      modules,
      env: {
        ...(await readSecrets(env, app.id)),
        DB: exportsOf.AppDatabase({ props }), KV: exportsOf.AppKV({ props }), FILES: exportsOf.AppFiles({ props }),
      },
      tails: [exportsOf.AppLogs({ props })],
      limits: { cpuMs: LIMITS.serverCpuMs, subRequests: LIMITS.serverSubrequests },
    };
  });
  return stub.getEntrypoint();
}

/** Server code in a bundle: _worker.js at the top, or a _worker/ folder with index.js (the Cloudflare Pages layout). */
export function findServer(paths: string[]): ServerInfo | null {
  if (paths.includes('_worker.js')) return { main: '_worker.js', modules: ['_worker.js'] };
  const folder = paths.filter(p => p.startsWith('_worker/'));
  if (!folder.length) return null;
  const main = ['_worker/index.js', '_worker/index.mjs'].find(m => folder.includes(m));
  if (!main) throw new Problem(400, 'bad_server', 'A _worker/ folder needs an index.js that exports a fetch handler.');
  return { main, modules: folder };
}
export const isServerPath = (p: string) => p === '_worker.js' || p.startsWith('_worker/');

/** Empty an app's database, key-value store and files when the app is deleted. */
export async function wipeAppData(env: Env, appId: string) {
  await data(env, appId).wipe();
}
