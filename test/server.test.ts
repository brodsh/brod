// Server apps: code that runs per request with its own database, key-value store, files, secrets and logs.
import { env } from 'cloudflare:workers';
import { describe, expect, it } from 'vitest';
import { setup } from './helpers';

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
    if (url.pathname === '/api/kv') {
      await env.KV.put('greeting', 'hej');
      return new Response(await env.KV.get('greeting'));
    }
    if (url.pathname === '/api/file') {
      await env.FILES.put('notes/a.txt', 'file body', 'text/plain');
      const res = await env.FILES.get('notes/a.txt');
      return new Response(await res.text() + ' ' + (await env.FILES.list('notes/')).length);
    }
    if (url.pathname === '/api/me') {
      return Response.json({ email: request.headers.get('x-brod-user-email'), role: request.headers.get('x-brod-role'), cookie: request.headers.get('cookie') });
    }
    if (url.pathname === '/api/secret') return new Response(env.API_TOKEN ?? 'none');
    if (url.pathname === '/api/boom') throw new Error('kaboom');
    if (request.method === 'POST') return new Response('posted ' + await request.text());
    return new Response('<html><body>server home</body></html>', { headers: { 'content-type': 'text/html' } });
  },
};`;

describe('server apps', () => {
  it('runs server code with its own database, key-value store and files', async () => {
    const { admin, tool } = await setup();
    const d = await tool('deploy_app', { name: 'Counter', files: [{ path: '_worker.js', content: WORKER }, { path: 'logo.txt', content: 'static file' }] });
    expect(d.isError).toBe(false);
    expect(d.data).toMatchObject({ kind: 'server', version: 1 });
    const url = d.data.url as string;

    expect(await (await admin.open(url + '/')).text()).toContain('server home');
    expect(await (await admin.go(url + '/api/count')).json()).toEqual({ count: 1 });
    expect(await (await admin.go(url + '/api/count')).json()).toEqual({ count: 2 });
    expect(await (await admin.go(url + '/api/kv')).text()).toBe('hej');
    expect(await (await admin.go(url + '/api/file')).text()).toBe('file body 1');
    expect(await (await admin.go(url + '/logo.txt')).text()).toBe('static file');
    expect(await (await admin.go(url + '/_worker.js')).text()).not.toContain('export default');   // the source is never served
    expect(await (await admin.go(url + '/x', { method: 'POST', body: 'hi' })).text()).toBe('posted hi');
  });

  it('passes the signed-in person and never the platform session cookie', async () => {
    const { admin, deploy, tool } = await setup();
    void deploy;
    const d = await tool('deploy_app', { name: 'Who', files: [{ path: '_worker.js', content: WORKER }] });
    const me = await (await (await admin.open(d.data.url + '/'), admin.go(d.data.url + '/api/me', { headers: { 'x-brod-role': 'owner-forged' } }))).json() as any;
    expect(me).toMatchObject({ email: admin.email, role: 'owner' });
    expect(me.cookie ?? '').not.toContain('brod_session');
  });

  it('keeps each app\'s database separate', async () => {
    const { admin, tool } = await setup();
    const a = await tool('deploy_app', { name: 'A', files: [{ path: '_worker.js', content: WORKER }] });
    const b = await tool('deploy_app', { name: 'B', files: [{ path: '_worker.js', content: WORKER }] });
    await admin.open(a.data.url + '/'); await admin.open(b.data.url + '/');
    await admin.go(a.data.url + '/api/count'); await admin.go(a.data.url + '/api/count');
    expect(await (await admin.go(b.data.url + '/api/count')).json()).toEqual({ count: 1 });
  });

  it('records console output and exceptions in the logs, and shows a plain error page', async () => {
    const { admin, tool } = await setup();
    const d = await tool('deploy_app', { name: 'Logs', files: [{ path: '_worker.js', content: WORKER }] });
    await admin.open(d.data.url + '/');
    await admin.go(d.data.url + '/api/count');
    const boom = await admin.go(d.data.url + '/api/boom');
    expect(boom.status).toBe(502);
    expect(await boom.text()).not.toContain('kaboom');   // visitors never see the error itself
    // Tails are delivered after each request finishes. (Under SELF.fetch only failed requests are traced; console
    // output from successful requests is checked against real wrangler dev in scripts/e2e.mjs.)
    let rows: any[] = [];
    for (let i = 0; i < 30 && !rows.length; i++) {
      rows = (await env.DB.prepare("SELECT path, outcome, exceptions FROM app_logs WHERE app_id = (SELECT id FROM apps WHERE slug = ?) AND path = '/api/boom'").bind(d.data.app).all<any>()).results;
      if (!rows.length) await new Promise(r => setTimeout(r, 100));
    }
    expect(rows[0]).toMatchObject({ outcome: 'exception' });
    expect(rows[0].exceptions).toContain('kaboom');
  });

  it('sets secrets that reach the app on its next request and can never be read back', async () => {
    const { admin, tool } = await setup();
    const d = await tool('deploy_app', { name: 'Secretive', files: [{ path: '_worker.js', content: WORKER }] });
    await admin.open(d.data.url + '/');
    expect(await (await admin.go(d.data.url + '/api/secret')).text()).toBe('none');
    const set = await tool('set_secret', { app: d.data.app, name: 'API_TOKEN', value: 'tok-123' });
    expect(set.isError).toBe(false);
    expect(JSON.stringify(set.data)).not.toContain('tok-123');
    expect(await (await admin.go(d.data.url + '/api/secret')).text()).toBe('tok-123');
    await tool('set_secret', { app: d.data.app, name: 'API_TOKEN', value: 'tok-456' });
    expect(await (await admin.go(d.data.url + '/api/secret')).text()).toBe('tok-456');

    const status = await tool('get_status', { app: d.data.app });
    expect(status.data.secrets.map((x: { name: string }) => x.name)).toEqual(['API_TOKEN']);
    expect(JSON.stringify(status.data)).not.toContain('tok-456');
    const stored = await env.DB.prepare('SELECT value FROM secrets').all<{ value: string }>();
    expect(stored.results.every(r => !r.value.includes('tok-'))).toBe(true);   // encrypted at rest

    expect((await tool('set_secret', { app: d.data.app, name: 'lowercase', value: 'x' })).data.error).toBe('bad_name');
    expect((await tool('set_secret', { app: d.data.app, name: 'DB', value: 'x' })).data.error).toBe('bad_name');
    await tool('set_secret', { app: d.data.app, name: 'API_TOKEN', remove: true });
    expect(await (await admin.go(d.data.url + '/api/secret')).text()).toBe('none');
  });

  it('refuses server code that cannot start, and keeps the live version', async () => {
    const { admin, tool } = await setup();
    const d = await tool('deploy_app', { name: 'Steady', files: [{ path: '_worker.js', content: WORKER }] });
    const syntax = await tool('deploy_app', { app: d.data.app, files: [{ path: '_worker.js', content: 'export default {' }] });
    expect(syntax.data.error).toBe('server_failed');
    const throws = await tool('deploy_app', { app: d.data.app, files: [{ path: '_worker.js', content: 'throw new Error("no config"); export default {}' }] });
    expect(throws.data).toMatchObject({ error: 'server_failed' });
    expect(throws.data.message).toContain('no config');
    const nofetch = await tool('deploy_app', { app: d.data.app, files: [{ path: '_worker.js', content: 'export default { hello: 1 }' }] });
    expect(nofetch.data.error).toBe('server_failed');
    expect((await tool('get_status', { app: d.data.app })).data.versions.length).toBe(1);
    expect(await (await admin.open(d.data.url + '/')).text()).toContain('server home');
  });

  it('loads a _worker/ folder with several modules, and rolls back between server and static versions', async () => {
    const { admin, tool } = await setup();
    const d = await tool('deploy_app', { name: 'Folder', files: [
      { path: 'dist/_worker/index.js', content: "import { greet } from './greet.js'; import cfg from './cfg.json'; export default { fetch: () => new Response(greet(cfg.name)) };" },
      { path: 'dist/_worker/greet.js', content: 'export const greet = n => `hi ${n}`;' },
      { path: 'dist/_worker/cfg.json', content: '{"name":"brod"}' },
    ] });
    expect(d.data).toMatchObject({ kind: 'server', files: 3 });
    expect(await (await admin.open(d.data.url + '/anything')).text()).toBe('hi brod');
    await tool('deploy_app', { app: d.data.app, environment: 'production', files: [{ path: 'index.html', content: '<html><body>static now</body></html>' }] });
    expect(await (await admin.go(d.data.url + '/')).text()).toContain('static now');
    expect((await admin.go(d.data.url + '/', { method: 'POST', body: 'x' })).status).toBe(405);
    await tool('rollback', { app: d.data.app, version: 1 });
    expect(await (await admin.go(d.data.url + '/anything')).text()).toBe('hi brod');
  });

  it('finds failed requests through get_logs', async () => {
    const { admin, tool } = await setup();
    const d = await tool('deploy_app', { name: 'Searchable', files: [{ path: '_worker.js', content: WORKER }] });
    await admin.open(d.data.url + '/');
    await admin.go(d.data.url + '/api/boom');
    let found: any[] = [];
    for (let i = 0; i < 30 && !found.length; i++) {
      found = (await tool('get_logs', { app: d.data.app, search: 'kaboom' })).data.requests;
      if (!found.length) await new Promise(r => setTimeout(r, 100));
    }
    expect(found[0]).toMatchObject({ request: 'GET /api/boom', outcome: 'exception' });
    expect((await tool('get_logs', { app: d.data.app, search: 'nothing-like-this' })).data.requests).toEqual([]);
  });

  it('deleting an app wipes its database, secrets and files', async () => {
    const { admin, tool } = await setup();
    const d = await tool('deploy_app', { name: 'Doomed', files: [{ path: '_worker.js', content: WORKER }] });
    await admin.open(d.data.url + '/');
    await admin.go(d.data.url + '/api/count');
    await admin.go(d.data.url + '/api/file');
    await tool('set_secret', { app: d.data.app, name: 'API_TOKEN', value: 'x' });
    const id = (await env.DB.prepare('SELECT id FROM apps WHERE slug = ?').bind(d.data.app).first<{ id: string }>())!.id;
    expect((await admin.api(`/v1/apps/${d.data.app}`, { method: 'DELETE' })).status).toBe(200);
    expect((await env.BUNDLES.list({ prefix: `${id}/` })).objects.length).toBe(0);
    expect((await env.DB.prepare('SELECT COUNT(*) AS n FROM secrets WHERE app_id = ?').bind(id).first<{ n: number }>())!.n).toBe(0);
    const rows = await env.APP_DATA.get(env.APP_DATA.idFromName(id)).query("SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'hits'");
    expect(rows.rows).toEqual([]);
  });
});
