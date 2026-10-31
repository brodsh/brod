// SPDX-License-Identifier: AGPL-3.0-only
// A container app with a managed Postgres database, for Brod's end-to-end test (scripts/e2e-postgres.mjs) and an
// example to start from. Its database comes as DATABASE_URL.
//   /healthz           the health check (never touches the database)
//   /notes             GET: the notes; POST ?text=: add one
//   /sql?q=            run one statement with the app's own role: {ok, rows} or {code, message}
//   /connect?...       connect with the app's URL changed (user, password, database): {ok} or {code, message}
import { createServer } from 'node:http';
import pg from 'pg';

const port = Number(process.env.PORT ?? 3000);
const json = (res, status, v) => { res.writeHead(status, { 'content-type': 'application/json' }); res.end(JSON.stringify(v)); };

async function withClient(url, fn) {
  const client = new pg.Client({ connectionString: url, connectionTimeoutMillis: 10000 });
  try {
    await client.connect();
    return await fn(client);
  } finally {
    await client.end().catch(() => {});
  }
}
const failure = e => ({ ok: false, code: e.code ?? null, message: e.message });

createServer(async (req, res) => {
  const u = new URL(req.url, 'http://x');
  try {
    if (u.pathname === '/healthz') return json(res, 200, { ok: true });
    if (!process.env.DATABASE_URL) return json(res, 503, { error: 'no DATABASE_URL' });
    if (u.pathname === '/notes' && req.method === 'POST') {
      const text = u.searchParams.get('text') ?? '';
      await withClient(process.env.DATABASE_URL, c => c.query('INSERT INTO notes (text) VALUES ($1)', [text]));
      return json(res, 201, { ok: true });
    }
    if (u.pathname === '/notes') {
      const r = await withClient(process.env.DATABASE_URL, c => c.query('SELECT text FROM notes ORDER BY id'));
      return json(res, 200, { notes: r.rows.map(x => x.text) });
    }
    if (u.pathname === '/sql') {
      const r = await withClient(process.env.DATABASE_URL, c => c.query(u.searchParams.get('q') ?? 'SELECT 1'));
      return json(res, 200, { ok: true, rows: r.rows });
    }
    if (u.pathname === '/connect') {
      const url = new URL(process.env.DATABASE_URL);
      for (const k of ['user', 'password']) if (u.searchParams.has(k)) url[k === 'user' ? 'username' : 'password'] = u.searchParams.get(k);
      if (u.searchParams.has('database')) url.pathname = '/' + u.searchParams.get('database');
      if (u.searchParams.has('host')) url.host = u.searchParams.get('host');
      const r = await withClient(url.href, c => c.query('SELECT current_user AS who, current_database() AS db'));
      return json(res, 200, { ok: true, ...r.rows[0] });
    }
    return json(res, 404, { error: 'not found' });
  } catch (e) {
    return json(res, 200, failure(e));
  }
}).listen(port, () => console.log(`listening on ${port}`));
