// SPDX-License-Identifier: AGPL-3.0-only
// On-call rota: who is on call each day this week and next. Brod signs people in and passes who they are as headers;
// the rota lives in the app's own SQLite database (env.DB). Editors and owners can change it; viewers can read it.
// With server code, every request that is not a file in the bundle comes here, "/" included, so the page is served
// from fetch. Files in _worker/ are modules: page.html is imported as text.
import page from './page.html';

const DAYS = 14;

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const me = {
      email: request.headers.get('x-brod-user-email'),
      name: decodeURIComponent(request.headers.get('x-brod-user-name') ?? ''),
      role: request.headers.get('x-brod-role') ?? 'viewer',
    };
    await env.DB.run('CREATE TABLE IF NOT EXISTS shifts (day TEXT PRIMARY KEY, person TEXT NOT NULL, set_by TEXT NOT NULL)');

    if (url.pathname === '/' && request.method === 'GET') {
      return new Response(page, { headers: { 'content-type': 'text/html; charset=utf-8' } });
    }
    if (url.pathname === '/api/rota' && request.method === 'GET') {
      const rows = await env.DB.query('SELECT day, person, set_by FROM shifts WHERE day >= ? ORDER BY day', [today()]);
      return Response.json({ me, days: upcoming(), shifts: rows });
    }
    if (url.pathname === '/api/rota' && request.method === 'PUT') {
      if (me.role === 'viewer') return Response.json({ error: 'Only editors can change the rota.' }, { status: 403 });
      const { day, person } = await request.json();
      if (!upcoming().includes(day) || typeof person !== 'string' || person.length > 80) {
        return Response.json({ error: 'Give a day in the next two weeks and a name.' }, { status: 400 });
      }
      if (person.trim() === '') await env.DB.run('DELETE FROM shifts WHERE day = ?', [day]);
      else await env.DB.run('INSERT INTO shifts (day, person, set_by) VALUES (?, ?, ?) ON CONFLICT(day) DO UPDATE SET person = excluded.person, set_by = excluded.set_by', [day, person.trim(), me.email ?? 'someone']);
      console.log(`${me.email} set ${day} to ${person.trim() || '(nobody)'}`);
      return Response.json({ ok: true });
    }
    return new Response('Not found', { status: 404 });
  },
};

function today() {
  return new Date().toISOString().slice(0, 10);
}

function upcoming() {
  const start = new Date(today());
  return Array.from({ length: DAYS }, (_, i) => new Date(start.getTime() + i * 86_400_000).toISOString().slice(0, 10));
}
