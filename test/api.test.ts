// Integration tests: the whole Worker through SELF.fetch, on the API host and on app hosts.
import { SELF } from 'cloudflare:test';
import { env } from 'cloudflare:workers';
import { describe, expect, it } from 'vitest';
import { API, Browser, confirmLink, setup, trust, unique } from './helpers';
import { appIdentityKey } from '../src/gateway';
import { unpack } from '../src/tar';
import { AppRow, hmac } from '../src/lib';

describe('sign-in and workspaces', () => {
  it('answers a health check', async () => {
    expect(await (await SELF.fetch(`${API}/healthz`)).json()).toMatchObject({ ok: true });
  });
  it('signs in by emailed link, once', async () => {
    const b = new Browser(`${unique('a')}@acme.test`);
    const { dev_link } = (await (await b.go('/auth/start', { json: { email: b.email } })).json()) as { dev_link: string };
    expect((await b.go(dev_link)).status).toBe(200);   // a page with a button, not a sign-in
    expect(b.jars[new URL(API).host]).toBeUndefined();
    const token = new URL(dev_link).searchParams.get('token')!;
    expect((await b.go('/auth/verify', { form: { token } })).status).toBe(302);
    expect((await b.api('/v1/me')).body.user.email).toBe(b.email);
    expect((await new Browser('x').go('/auth/verify', { form: { token } })).status).toBe(410);
  });
  it('refuses cross-site posts and cookie changes without the dashboard origin', async () => {
    const b = await new Browser(`${unique('a')}@acme.test`).signIn();
    expect((await b.go('/auth/signout', { form: {}, headers: { origin: 'https://evil.test' } })).status).toBe(403);
    expect((await b.go('/v1/workspaces', { method: 'POST', body: '{}', headers: { 'content-type': 'application/json' } })).status).toBe(403);
  });
  it('rate-limits sign-in links per address', async () => {
    const b = new Browser(`${unique('a')}@acme.test`);
    for (let i = 0; i < 5; i++) expect((await b.go('/auth/start', { json: { email: b.email } })).status).toBe(200);
    expect((await b.go('/auth/start', { json: { email: b.email } })).status).toBe(429);
  });
  it('needs the terms accepted to create a workspace', async () => {
    const b = await new Browser(`${unique('a')}@acme.test`).signIn();
    expect((await b.api('/v1/workspaces', { json: { name: 'X' } })).body.error.code).toBe('terms');
    expect((await b.api('/v1/workspaces', { json: { name: 'X', accept_terms: true } })).status).toBe(201);
  });
});

describe('MCP', () => {
  it('lists 13 tools and refuses bad tokens', async () => {
    const { rpc } = await setup();
    const init = await rpc('initialize', { protocolVersion: '2025-06-18' });
    expect(init.body.result.serverInfo.name).toBe('brod');
    expect((await rpc('tools/list')).body.result.tools.map((t: { name: string }) => t.name)).toEqual(
      ['deploy_app', 'list_apps', 'get_files', 'get_status', 'get_logs', 'set_secret', 'publish_staging', 'rollback', 'set_access', 'set_paused', 'invite', 'set_domain', 'get_workspace']);
    expect((await rpc('tools/list', {}, 'brod_nope')).status).toBe(401);
  });
  it('returns tool errors as results an agent can act on', async () => {
    const { tool } = await setup();
    const r = await tool('get_status', { app: 'missing' });
    expect(r).toMatchObject({ isError: true, data: { error: 'not_found' } });
  });
  it('describes the workspace for an agent', async () => {
    const { tool, workspace } = await setup();
    const { data } = await tool('get_workspace');
    expect(data).toMatchObject({ workspace, your_role: 'admin', app_limit: 10, default_app_roles: ['owner', 'editor', 'viewer'] });
    expect(data.identity.how).toContain('/_brod/me');
  });
});

describe('deploying and serving', () => {
  it('serves a private app only after sign-in, with a verifiable identity', async () => {
    const { admin, deploy, workspace } = await setup();
    const app = await deploy('Reading List');
    expect(app).toMatchObject({ version: 1, access: 'private', created: true });
    expect(new URL(app.url).host).toBe(`${app.app}.${workspace}.${env.APPS_DOMAIN}`);
    const anon = await new Browser('anon').go(app.url + '/');
    expect(anon.status).toBe(302);
    expect(anon.headers.get('location')).toBe(`${API}/auth/app?app=${app.app}.${workspace}&return=%2F`);

    const page = await admin.open(app.url + '/');
    expect(page.status).toBe(200);
    expect(await page.text()).toContain('hello');
    const host = new URL(app.url).host;
    expect(Object.keys(admin.jars[host])).toEqual(['brod_session']);

    const me = (await (await admin.go(app.url + '/_brod/me')).json()) as any;
    expect(me).toMatchObject({ user: { email: admin.email }, role: 'owner', app: app.app });
    const row = (await env.DB.prepare('SELECT * FROM apps WHERE slug = ?').bind(app.app).first<AppRow>())!;
    const [body, sig] = me.token.split('.');
    expect(sig).toBe(await hmac(await appIdentityKey(env, row), body));
  });

  it('versions, rolls back, and keeps the live version when a deploy is refused', async () => {
    const { admin, tool, deploy } = await setup();
    const app = await deploy('Versions', 'v1');
    await tool('deploy_app', { app: app.app, environment: 'production', files: [{ path: 'index.html', content: 'v2' }] });
    expect(await (await admin.open(app.url + '/')).text()).toContain('v2');
    const bad = await tool('deploy_app', { app: app.app, files: [{ path: 'main.py', content: 'x' }] });
    expect(bad.data.error).toBe('no_index');
    expect(await (await admin.open(app.url + '/')).text()).toContain('v2');
    expect((await tool('rollback', { app: app.app, version: 1 })).data).toMatchObject({ live_version: 1, changed: true });
    expect(await (await admin.open(app.url + '/')).text()).toContain('v1');
  });

  it('enforces the plan allowance and frees a slot on pause', async () => {
    const { tool, deploy } = await setup();
    const first = await deploy('One');
    for (let i = 2; i <= 10; i++) await deploy(`App ${i}`);
    expect((await tool('deploy_app', { name: 'Four', files: [{ path: 'index.html', content: '4' }] })).data).toMatchObject({ error: 'plan_limit', app_limit: 10 });
    await tool('set_paused', { app: first.app, paused: true });
    expect((await tool('deploy_app', { name: 'Four', files: [{ path: 'index.html', content: '4' }] })).isError).toBe(false);
    expect((await tool('set_paused', { app: first.app, paused: false })).data.error).toBe('plan_limit');
  });

  it('injects a report link into public pages and takes reports', async () => {
    const { admin, deploy, workspace } = await setup();
    const app = await deploy('Public');
    await trust(workspace);
    expect((await admin.api(`/v1/apps/${app.app}/access`, { json: { access: 'public' } })).status).toBe(200);
    const html = await (await SELF.fetch(app.url + '/')).text();
    expect(html).toContain('/_brod/report');
    const rep = await SELF.fetch(app.url + '/_brod/report', { method: 'POST', body: new URLSearchParams({ reason: 'phishing' }) });
    expect(rep.status).toBe(200);
    const queue = (await (await SELF.fetch(`${API}/v1/admin/reports`, { headers: { authorization: 'Bearer test-admin-secret' } })).json()) as any;
    expect(queue.reports.some((r: any) => r.app === app.app && r.reason === 'phishing')).toBe(true);
  });
});

describe('staging', () => {
  it('sends an agent\'s update of a live app to staging, for builders to try, until it is published', async () => {
    const { admin, workspace, tool, deploy } = await setup();
    const app = await deploy('Staged', 'v1');
    const stagingUrl = app.url.replace(`//${app.app}.`, `//${app.app}--staging.`);
    expect(app.staging).toBeNull();

    const d2 = (await tool('deploy_app', { app: app.app, note: 'New look', files: [{ path: 'index.html', content: '<html><body>v2</body></html>' }] })).data;
    expect(d2).toMatchObject({ version: 2, environment: 'staging', live_version: 1, staging: { version: 2, url: stagingUrl }, staging_url: stagingUrl });
    expect(d2.next_step).toContain('publish_staging');
    // Visitors keep v1; the staging address serves v2 to the owner, signed in there through the usual hand-off.
    expect(await (await admin.open(app.url + '/')).text()).toContain('v1');
    const signIn = await admin.go(stagingUrl + '/');
    expect(signIn.headers.get('location')).toContain(`app=${app.app}--staging.${workspace}`);
    const page = await admin.open(stagingUrl + '/');
    expect(await page.text()).toContain('v2');
    expect(page.headers.get('x-brod-version')).toBe('2');
    expect(admin.jars[new URL(stagingUrl).host]).toHaveProperty('brod_session');
    expect(((await (await admin.go(stagingUrl + '/_brod/me')).json()) as any).role).toBe('owner');

    const status = (await tool('get_status', { app: app.app })).data;
    expect(status.staging).toEqual({ version: 2, url: stagingUrl });
    expect(status.versions.map((v: any) => [v.version, v.live, v.staging])).toEqual([[2, false, true], [1, true, false]]);

    // Even a public app keeps staging to the people who build it.
    await admin.api(`/v1/apps/${app.app}/access`, { json: { access: 'workspace' } });
    const member = await new Browser(`${unique('member')}@acme.test`).signIn();
    const ids = (await env.DB.prepare('SELECT u.id AS uid, w.id AS wid FROM users u, workspaces w WHERE u.email = ? AND w.slug = ?').bind(member.email, workspace).first<{ uid: string; wid: string }>())!;
    await env.DB.prepare("INSERT INTO members (workspace_id, user_id, role, created_at) VALUES (?,?,'member',?)").bind(ids.wid, ids.uid, Date.now()).run();
    expect(await (await member.open(app.url + '/')).text()).toContain('v1');
    expect((await member.open(stagingUrl + '/')).status).toBe(404);
    await admin.api(`/v1/apps/${app.app}/access`, { json: { access: 'public' } });
    expect((await new Browser('nobody@else.test').go(stagingUrl + '/')).status).toBe(302);

    const pub = (await tool('publish_staging', { app: app.app })).data;
    expect(pub).toMatchObject({ published: 2, live_version: 2, staging: null });
    expect(await (await admin.open(app.url + '/')).text()).toContain('v2');
    const empty = await admin.open(stagingUrl + '/');
    expect([empty.status, await empty.text()]).toEqual([404, expect.stringContaining('Nothing on staging')]);
    expect((await tool('publish_staging', { app: app.app })).data.error).toBe('nothing_on_staging');
  });

  it('deploys straight to live when asked, discards staging, and leaves a person\'s deploys live', async () => {
    const { admin, tool, deploy } = await setup();
    const app = await deploy('Direct', 'v1');
    expect((await tool('deploy_app', { app: app.app, environment: 'production', files: [{ path: 'index.html', content: 'v2' }] })).data)
      .toMatchObject({ environment: 'production', live_version: 2, staging: null });
    expect((await tool('deploy_app', { app: app.app, environment: 'qa', files: [{ path: 'index.html', content: 'x' }] })).data.error).toBe('bad_environment');
    expect((await tool('deploy_app', { app: app.app, files: [{ path: 'index.html', content: 'v3' }] })).data.staging.version).toBe(3);
    expect((await tool('publish_staging', { app: app.app, discard: true })).data).toMatchObject({ changed: true, staging: null, live_version: 2 });
    expect(await (await admin.open(app.url + '/')).text()).toContain('v2');
    // A person deploying from the dashboard goes live unless they pick staging.
    expect((await admin.api('/v1/deploys', { json: { app: app.app, files: [{ path: 'index.html', content: 'v4' }] } })).body).toMatchObject({ environment: 'production', live_version: 4 });
    const staged = (await admin.api('/v1/deploys', { json: { app: app.app, environment: 'staging', files: [{ path: 'index.html', content: 'v5' }] } })).body;
    expect(staged).toMatchObject({ environment: 'staging', live_version: 4, staging: { version: 5 } });
    expect((await admin.api(`/v1/apps/${app.app}/publish`, { method: 'POST', json: {} })).body).toMatchObject({ published: 5, live_version: 5 });
    await admin.api('/v1/deploys', { json: { app: app.app, environment: 'staging', files: [{ path: 'index.html', content: 'v6' }] } });
    expect((await admin.api(`/v1/apps/${app.app}/staging`, { method: 'DELETE' })).body).toMatchObject({ changed: true, staging: null, live_version: 5 });
    // An upload address remembers where its deploy goes.
    const up = (await tool('deploy_app', { app: app.app, environment: 'production' })).data;
    expect((await env.DB.prepare('SELECT environment FROM uploads WHERE id = ?').bind(new URL(up.upload_url).pathname.split('/').pop()).first<{ environment: string }>())!.environment).toBe('production');
  });
});

describe('several people on one app', () => {
  const page = (body: string) => [{ path: 'index.html', content: `<html><body>${body}</body></html>` }];
  const versions = async (app: string) => (await env.DB.prepare('SELECT v.n FROM versions v JOIN apps a ON a.id = v.app_id WHERE a.slug = ? ORDER BY v.n').bind(app).all<{ n: number }>()).results.map(v => v.n);

  it('refuses a deploy whose files start from an older version, and says who changed what', async () => {
    const { admin, tool, deploy } = await setup();
    const app = await deploy('Together', 'v1');
    expect(app.current_version).toBe(1);
    const d2 = (await tool('deploy_app', { app: app.app, base_version: 1, note: 'New menu', files: page('v2') })).data;
    expect(d2).toMatchObject({ version: 2, based_on: 1, environment: 'staging', current_version: 2 });

    // A person whose files still start from v1 would undo the agent's v2: nothing is deployed and they are told why.
    const stale = await admin.api('/v1/deploys', { json: { app: app.app, base_version: 1, files: page('mine') } });
    expect(stale.status).toBe(409);
    expect(stale.body.error).toMatchObject({ code: 'stale_base', your_base: 1, current_version: 2, current_environment: 'staging', since: [{ version: 2, by: 'claude-code', note: 'New menu' }] });
    expect(stale.body.error.message).toContain('"base_version": 2');
    expect(await versions(app.app)).toEqual([1, 2]);

    // Built on v2, straight to live: it replaces what waited on staging, so publishing that later cannot undo it.
    const d3 = (await admin.api('/v1/deploys', { json: { app: app.app, base_version: 2, environment: 'production', files: page('v3') } })).body;
    expect(d3).toMatchObject({ version: 3, based_on: 2, live_version: 3, staging: null, current_version: 3 });
    const late = (await tool('deploy_app', { app: app.app, base_version: 1, files: page('late') })).data;
    expect(late).toMatchObject({ error: 'stale_base', current_version: 3, current_environment: 'live' });
    expect(late.since.map((v: any) => v.version)).toEqual([3, 2]);
    const status = (await tool('get_status', { app: app.app })).data;
    expect(status.versions.map((v: any) => [v.version, v.based_on])).toEqual([[3, 2], [2, 1], [1, null]]);
    // After a rollback the current version is the older one, and the error says so.
    await tool('rollback', { app: app.app, version: 1 });
    expect((await tool('deploy_app', { app: app.app, base_version: 3, files: page('x') })).data).toMatchObject({ error: 'stale_base', current_version: 1, since: [] });

    expect((await tool('deploy_app', { app: app.app, base_version: 'two', files: page('x') })).data.error).toBe('bad_base_version');
    expect((await tool('deploy_app', { name: unique('New'), base_version: 1, files: page('x') })).data.error).toBe('bad_base_version');
    // An upload address remembers the base too.
    const up = (await tool('deploy_app', { app: app.app, base_version: 1 })).data;
    expect((await env.DB.prepare('SELECT base_version FROM uploads WHERE id = ?').bind(new URL(up.upload_url).pathname.split('/').pop()).first<{ base_version: number }>())!.base_version).toBe(1);
  });

  it('lets only one of two deploys from the same version through, and never gives two deploys one number', async () => {
    const { tool, deploy } = await setup();
    const app = await deploy('Race', 'v1');
    const [a, b] = await Promise.all(['a', 'b'].map(who => tool('deploy_app', { app: app.app, base_version: 1, environment: 'production', files: page(who) })));
    expect([a.isError, b.isError].sort()).toEqual([false, true]);
    const won = (a.isError ? b : a).data, lost = (a.isError ? a : b).data;
    expect(lost).toMatchObject({ error: 'stale_base', current_version: won.version });
    expect(await versions(app.app)).toEqual([1, won.version]);
    // The refused version's files are gone, the winner's are whole.
    const id = (await env.DB.prepare('SELECT id FROM apps WHERE slug = ?').bind(app.app).first<{ id: string }>())!.id;
    const other = won.version === 2 ? 3 : 2;
    expect((await env.BUNDLES.list({ prefix: `${id}/${other}/` })).objects).toEqual([]);
    expect((await env.BUNDLES.list({ prefix: `${id}/${won.version}/` })).objects.map(o => o.key)).toEqual([`${id}/${won.version}/index.html`]);

    // Without a base both go through, each with its own number.
    const both = await Promise.all(['c', 'd'].map(who => tool('deploy_app', { app: app.app, environment: 'production', files: page(who) })));
    expect(new Set(both.map(r => r.data.version)).size).toBe(2);
    expect(Math.min(...both.map(r => r.data.version))).toBeGreaterThan(won.version);
  });
});

describe('getting an app\'s files back', () => {
  it('returns a small version inline, text as text and the rest as base64, ready to deploy again on top', async () => {
    const { tool } = await setup();
    const png = btoa(String.fromCharCode(0x89, 0x50, 0x4e, 0x47, 0xff, 0x00));
    const app = (await tool('deploy_app', { name: unique('Pull'), files: [{ path: 'index.html', content: '<h1>héllo</h1>' }, { path: 'img/logo.png', content: png, encoding: 'base64' }] })).data;
    const got = (await tool('get_files', { app: app.app })).data;
    expect(got).toMatchObject({ app: app.app, version: 1, environment: 'live', current_version: 1, file_count: 2, others_editing: [] });
    expect(got.files).toEqual([{ path: 'img/logo.png', content: png, encoding: 'base64' }, { path: 'index.html', content: '<h1>héllo</h1>' }]);
    expect(got.next_step).toContain('"base_version": 1');
    expect(got.warning).toBeUndefined();
    const again = (await tool('deploy_app', { app: app.app, base_version: got.version, files: got.files.map((f: any) => f.path === 'index.html' ? { ...f, content: '<h1>v2</h1>' } : f) })).data;
    expect(again).toMatchObject({ version: 2, based_on: 1, environment: 'staging' });
    // The current version is what waits on staging; an older one can be asked for by number.
    expect((await tool('get_files', { app: app.app })).data).toMatchObject({ version: 2, environment: 'staging' });
    expect((await tool('get_files', { app: app.app, version: 1 })).data).toMatchObject({ version: 1, environment: 'live' });
    expect((await tool('get_files', { app: app.app, version: 9 })).data.error).toBe('no_version');
  });

  it('gives a larger version as a tar.gz download address that expires', async () => {
    const { admin, deploy } = await setup();
    const app = await deploy('Big');
    const long = `deep/${'a'.repeat(120)}.txt`;
    const files = [{ path: 'index.html', content: 'home' }, { path: long, content: 'long path' }, ...Array.from({ length: 205 }, (_, i) => ({ path: `p/${i}.txt`, content: `page ${i}` }))];
    expect((await admin.api('/v1/deploys', { json: { app: app.app, files } })).status).toBe(201);
    const got = (await admin.api(`/v1/apps/${app.app}/files`)).body;
    expect(got).toMatchObject({ version: 2, file_count: 207 });
    expect(got.files).toBeUndefined();
    expect(got.next_step).toContain(`curl -sS --fail "${got.download_url}" | tar -xzf -`);
    const res = await SELF.fetch(got.download_url);
    expect(res.headers.get('content-type')).toBe('application/gzip');
    const back = await unpack(new Uint8Array(await res.arrayBuffer()));
    const text = new TextDecoder();
    expect(back.length).toBe(207);
    expect(text.decode(back.find(f => f.path === long)!.bytes)).toBe('long path');
    expect(text.decode(back.find(f => f.path === 'p/204.txt')!.bytes)).toBe('page 204');
    await env.DB.prepare('UPDATE downloads SET expires_at = 1 WHERE id = ?').bind(new URL(got.download_url).pathname.split('/').pop()).run();
    expect((await SELF.fetch(got.download_url)).status).toBe(410);
  });

  it('warns, never blocks, when someone else is working on the same app', async () => {
    const { admin, workspace, tool, deploy } = await setup();
    const app = await deploy('Busy');
    const bob = await new Browser(`${unique('bob')}@acme.test`).signIn();
    const ids = (await env.DB.prepare('SELECT u.id AS uid, w.id AS wid FROM users u, workspaces w WHERE u.email = ? AND w.slug = ?').bind(bob.email, workspace).first<{ uid: string; wid: string }>())!;
    await env.DB.prepare("INSERT INTO members (workspace_id, user_id, role, created_at) VALUES (?,?,'builder',?)").bind(ids.wid, ids.uid, Date.now()).run();

    // The admin's agent deployed v1, so Bob is told the admin (through their agent) is working on it.
    const bobs = (await bob.api(`/v1/apps/${app.app}/files`)).body;
    expect(bobs.others_editing).toEqual([expect.objectContaining({ by: admin.email, via: 'claude-code', base_version: 1 })]);
    expect(bobs.warning).toContain(admin.email);
    expect(bobs.warning).toContain('through claude-code');
    // And the admin's agent hears about Bob, on its next deploy and in get_status; the deploy itself goes through.
    const d2 = (await tool('deploy_app', { app: app.app, base_version: 1, files: [{ path: 'index.html', content: 'v2' }] })).data;
    expect(d2).toMatchObject({ version: 2, others_editing: [expect.objectContaining({ by: bob.email, base_version: 1 })] });
    expect(d2.warning).toContain(bob.email);
    expect((await tool('get_status', { app: app.app })).data.others_editing.map((o: any) => o.by)).toEqual([bob.email]);
    // Some hours later nobody is warned.
    await env.DB.prepare('UPDATE editing SET last_at = ? WHERE user_id = ?').bind(Date.now() - 3 * 3600e3, ids.uid).run();
    const later = (await tool('get_files', { app: app.app })).data;
    expect([later.others_editing, later.warning]).toEqual([[], undefined]);
    // Deleting the app clears all of it.
    expect((await admin.api(`/v1/apps/${app.app}`, { method: 'DELETE' })).status).toBe(200);
    expect((await env.DB.prepare('SELECT COUNT(*) AS n FROM editing WHERE user_id = ?').bind(ids.uid).first<{ n: number }>())!.n).toBe(0);
  });
});

describe('people, groups and confirmations', () => {
  it('needs a person to confirm when an agent widens access; narrowing applies at once', async () => {
    const { admin, tool, deploy, workspace } = await setup();
    await trust(workspace);
    const app = await deploy('Shared');
    const req = await tool('set_access', { app: app.app, access: 'workspace' });
    expect(req.data).toMatchObject({ needs_confirmation: true });
    expect((await tool('get_status', { app: app.app })).data.access).toBe('private');
    expect((await confirmLink(admin, req.data.confirm_url)).status).toBe(200);
    expect((await tool('get_status', { app: app.app })).data.access).toBe('workspace');
    expect((await confirmLink(admin, req.data.confirm_url)).status).toBe(410);

    const narrow = await tool('set_access', { app: app.app, access: 'private' });
    expect(narrow.data).toMatchObject({ access: 'private' });
    expect(narrow.data.needs_confirmation).toBeUndefined();

    const declined = await tool('set_access', { app: app.app, access: 'public' });
    await confirmLink(admin, declined.data.confirm_url, 'decline');
    expect((await tool('get_status', { app: app.app })).data.access).toBe('private');
  });

  it('maps groups to app roles, and removing a person ends their access at once', async () => {
    const { admin, deploy, tool } = await setup();
    const bob = new Browser(`${unique('bob')}@acme.test`);
    const inv = await admin.api('/v1/invites', { json: { email: bob.email, role: 'member' } });
    expect(inv.status).toBe(201);
    const acc = await bob.go('/auth/invite', { form: { token: new URL(inv.body.dev_link).searchParams.get('token')! } });
    expect(acc.status).toBe(302);

    const app = await deploy('Ledger');
    expect((await bob.open(app.url + '/')).status).toBe(404);
    await admin.api('/v1/groups', { json: { name: 'finance' } });
    await admin.api('/v1/groups/finance/members', { json: { email: bob.email } });
    await admin.api(`/v1/apps/${app.app}/access`, { json: { access: 'people', add: [{ group: 'finance', role: 'editor' }] } });
    expect((await bob.open(app.url + '/')).status).toBe(200);
    expect(((await (await bob.go(app.url + '/_brod/me')).json()) as any)).toMatchObject({ role: 'editor', groups: ['finance'] });
    expect((await tool('get_status', { app: app.app })).data.who_can_open).toContain('finance');

    expect((await admin.api(`/v1/people/${encodeURIComponent(bob.email)}`, { method: 'DELETE' })).status).toBe(200);
    expect((await bob.go(app.url + '/')).status).toBe(404);
  });

  it('keeps guests to the apps they were given and limits members on the free plan', async () => {
    const { admin, deploy } = await setup();
    const app = await deploy('Guest app'), other = await deploy('Other app');
    await admin.api(`/v1/apps/${other.app}/access`, { json: { access: 'workspace' } });
    const guest = new Browser(`${unique('guest')}@partner.test`);
    const inv = await admin.api('/v1/invites', { json: { email: guest.email, app: app.app } });
    expect(inv.body).toMatchObject({ role: 'guest', app_role: 'viewer' });
    const acc = await guest.go('/auth/invite', { form: { token: new URL(inv.body.dev_link).searchParams.get('token')! } });
    expect((await guest.open(acc.headers.get('location')!)).status).toBe(200);
    expect((await guest.open(other.url + '/')).status).toBe(404);

    // The admin is one of the free plan's 10 people; nine more invites fill it.
    for (let i = 0; i < 9; i++) await admin.api('/v1/invites', { json: { email: `${unique('m')}@acme.test` } });
    const full = await admin.api('/v1/invites', { json: { email: `${unique('m')}@acme.test` } });
    expect(full).toMatchObject({ status: 402, body: { error: { code: 'member_limit' } } });
  });

  it('signing out of one app signs out everywhere', async () => {
    const { admin, deploy } = await setup();
    const app = await deploy('Signout');
    expect((await admin.open(app.url + '/')).status).toBe(200);
    await admin.go(app.url + '/_brod/signout');
    expect((await admin.go(app.url + '/')).status).toBe(302);
    expect((await admin.api('/v1/me')).status).toBe(401);
  });

  it('a member cannot connect an agent, and other workspaces cannot see the app', async () => {
    const { admin, deploy } = await setup();
    const app = await deploy('Isolated');
    const mal = await new Browser(`${unique('mal')}@other.test`).signIn();
    await mal.api('/v1/workspaces', { json: { name: unique('Other'), accept_terms: true } });
    expect((await mal.api(`/v1/apps/${app.app}`)).status).toBe(404);
    const member = new Browser(`${unique('m')}@acme.test`);
    const inv = await admin.api('/v1/invites', { json: { email: member.email } });
    await member.go('/auth/invite', { form: { token: new URL(inv.body.dev_link).searchParams.get('token')! } });
    expect((await member.api('/v1/tokens', { json: { name: 'x' } })).status).toBe(403);
  });
});

describe('addresses', () => {
  it('gives each workspace its own app names', async () => {
    const a = await setup(), b = await setup();
    const name = unique('Todo');
    const one = (await a.tool('deploy_app', { name, files: [{ path: 'index.html', content: '<p>one</p>' }] })).data;
    const two = (await b.tool('deploy_app', { name, files: [{ path: 'index.html', content: '<p>two</p>' }] })).data;
    expect(one.app).toBe(two.app);
    expect(one.url).not.toBe(two.url);
    expect(await (await a.admin.open(one.url + '/')).text()).toContain('one');
    expect(await (await b.admin.open(two.url + '/')).text()).toContain('two');
    expect((await b.admin.open(one.url + '/')).status).toBe(404);
  });
  it('keeps platform names away from workspaces', async () => {
    // One person per name: a person can make only 3 workspaces a day.
    for (const name of ['API', 'www', 'Admin', 'mail', 'support']) {
      const b = await new Browser(`${unique('a')}@acme.test`).signIn();
      const r = await b.api('/v1/workspaces', { json: { name, accept_terms: true } });
      expect(r.body.workspace).toMatch(/^team-/);
    }
  });
  it('sends a workspace address to its home page, and unknown hosts to a 404', async () => {
    const { workspace } = await setup();
    const home = await SELF.fetch(`http://${workspace}.${env.APPS_DOMAIN}/`, { redirect: 'manual' });
    expect(home.headers.get('location')).toBe(`${API}/w/${workspace}`);
    expect((await SELF.fetch(`http://a.b.c.${env.APPS_DOMAIN}/`, { redirect: 'manual' })).status).toBe(404);
    expect((await SELF.fetch(`http://nope.${workspace}.${env.APPS_DOMAIN}/`, { redirect: 'manual' })).status).toBe(404);
  });
});

describe('custom domains', () => {
  const dns = (name: string, value: string) => fetch('http://dns.test/_test/records', { method: 'POST', body: JSON.stringify({ name, value }) });
  const host = () => `${unique('shop')}.example.test`;

  it('serves an app at a domain only after a TXT record proves the workspace owns it', async () => {
    const { admin, tool, deploy } = await setup();
    const app = await deploy('Shop', '<p>shop</p>');
    const domain = host();
    const added = await tool('set_domain', { domain, app: app.app });
    expect(added.isError).toBe(false);
    expect(added.data).toMatchObject({ domain, kind: 'app', app: app.app, status: 'pending' });
    const txt = added.data.dns.find((r: any) => r.type === 'TXT');
    expect(txt.name).toBe(`_brod.${domain}`);
    // Not proven yet: the domain is not served.
    expect((await SELF.fetch(`http://${domain}/`, { redirect: 'manual' })).headers.get('x-brod-app')).toBeNull();
    expect((await tool('set_domain', { domain })).data.status).toBe('pending');

    await dns(txt.name, txt.value);
    const ok = await tool('set_domain', { domain });
    expect(ok.data.status).toBe('verified');

    // Private app on the custom domain: sign-in goes through the API host and comes back to the custom domain.
    const first = await admin.go(`http://${domain}/`);
    expect(first.status).toBe(302);
    expect(first.headers.get('location')).toContain(`host=${encodeURIComponent(domain)}`);
    const page = await admin.open(`http://${domain}/`);
    expect(page.status).toBe(200);
    expect(await page.text()).toContain('shop');
    expect(admin.jars[domain]?.brod_session).toBeTruthy();
    const me = await admin.go(`http://${domain}/_brod/me`);
    expect(((await me.json()) as any).app).toBe(app.app);

    const status = await tool('get_status', { app: app.app });
    expect(status.data.domains).toEqual([{ domain, status: 'verified', url: `http://${domain}` }]);

    // Removing it stops serving it at once.
    expect((await tool('set_domain', { domain, remove: true })).data.removed).toBe(domain);
    expect((await admin.go(`http://${domain}/`)).headers.get('x-brod-app')).toBeNull();
  });

  it('serves every app in a workspace under a wildcard domain, admins only', async () => {
    const { admin, workspace, tool, deploy } = await setup();
    const app = await deploy('Wiki', '<p>wiki</p>');
    const base = host();
    expect((await tool('set_domain', { domain: `*.${base}`, app: app.app })).isError).toBe(true);
    const r = await admin.api('/v1/domains', { json: { domain: `*.${base}` } });
    expect(r.status).toBe(201);
    expect(r.body).toMatchObject({ domain: `*.${base}`, kind: 'workspace', status: 'pending' });
    expect(r.body.dns[1]).toMatchObject({ type: 'CNAME', name: `*.${base}` });
    await dns(r.body.dns[0].name, r.body.dns[0].value);
    expect((await admin.api(`/v1/domains/${base}/verify`, { method: 'POST' })).body.status).toBe('verified');

    const page = await admin.open(`http://${app.app}.${base}/`);
    expect(await page.text()).toContain('wiki');
    expect((await SELF.fetch(`http://${base}/`, { redirect: 'manual' })).headers.get('location')).toBe(`${API}/w/${workspace}`);
    expect((await SELF.fetch(`http://nope.${base}/`, { redirect: 'manual' })).status).toBe(404);
    expect((await admin.api('/v1/domains')).body.domains.map((d: any) => d.domain)).toEqual([`*.${base}`]);
  });

  it('lets only one workspace prove a domain, and hands sign-ins only to an app\'s own domains', async () => {
    const a = await setup(), b = await setup();
    const appA = await a.deploy('A'), appB = await b.deploy('B');
    const domain = host();
    const claimA = (await a.tool('set_domain', { domain, app: appA.app })).data;
    const claimB = (await b.tool('set_domain', { domain, app: appB.app })).data;   // a pending claim does not block others
    expect(claimB.status).toBe('pending');
    await dns(claimA.dns[0].name, claimA.dns[0].value);
    await dns(claimB.dns[0].name, claimB.dns[0].value);
    expect((await a.tool('set_domain', { domain })).data.status).toBe('verified');
    const lost = await b.tool('set_domain', { domain });
    expect(lost.isError).toBe(true);
    expect(lost.data.error).toBe('domain_taken');

    // The sign-in hand-off refuses a host that is not a proven domain of that app.
    const ws = a.workspace;
    const evil = await a.admin.go(`/auth/app?app=${appA.app}.${ws}&host=evil.test&return=%2F`);
    expect(evil.status).toBe(400);
    const otherApp = await a.admin.go(`/auth/app?app=${appB.app}.${b.workspace}&host=${domain}&return=%2F`);
    expect(otherApp.status).toBe(400);
    const good = await a.admin.go(`/auth/app?app=${appA.app}.${ws}&host=${domain}&return=%2F`);
    expect(good.headers.get('location')).toMatch(new RegExp(`^http://${domain.replace(/\./g, '\\.')}/_brod/callback\\?code=`));
  });

  it('refuses Brod\'s own addresses and malformed names', async () => {
    const { tool, deploy } = await setup();
    const app = await deploy('X');
    for (const domain of [`x.${new URL(API).hostname}`, 'localhost', 'not a domain', '1.2.3.4', ''])
      expect((await tool('set_domain', { domain, app: app.app })).data.error).toBe('bad_domain');
  });
});
