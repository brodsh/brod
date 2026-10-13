// Connecting an agent: the connections page, and the OAuth sign-in MCP clients use instead of a pasted token.
import { SELF } from 'cloudflare:test';
import { describe, expect, it } from 'vitest';
import { redirectAllowed } from '../src/connect';
import { API, Browser, setup, unique } from './helpers';

const b64url = (b: Uint8Array) => btoa(String.fromCharCode(...b)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const pkce = async () => {
  const verifier = b64url(crypto.getRandomValues(new Uint8Array(32)));
  return { verifier, challenge: b64url(new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier)))) };
};
const register = async (redirect_uris: unknown, client_name = 'Claude Code') =>
  SELF.fetch(`${API}/oauth/register`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ redirect_uris, client_name }) });
const swap = (form: Record<string, string>) =>
  SELF.fetch(`${API}/oauth/token`, { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams(form).toString() });

describe('OAuth sign-in for MCP clients', () => {
  it('points an unauthenticated MCP client at the metadata', async () => {
    const res = await SELF.fetch(`${API}/mcp`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{"jsonrpc":"2.0","id":1,"method":"ping"}' });
    expect(res.status).toBe(401);
    const meta = /resource_metadata="([^"]+)"/.exec(res.headers.get('www-authenticate') ?? '')?.[1];
    expect(meta).toBe(`${API}/.well-known/oauth-protected-resource/mcp`);
    const pr = (await (await SELF.fetch(meta!)).json()) as any;
    expect(pr).toMatchObject({ resource: `${API}/mcp`, authorization_servers: [API] });
    const as = await SELF.fetch(`${API}/.well-known/oauth-authorization-server`);
    expect(as.headers.get('access-control-allow-origin')).toBe('*');
    expect(await as.json()).toMatchObject({ issuer: API, code_challenge_methods_supported: ['S256'], registration_endpoint: `${API}/oauth/register` });
  });

  it('accepts only safe redirect addresses', async () => {
    for (const ok of ['http://localhost:4567/callback', 'http://127.0.0.1/cb', 'http://[::1]:9/cb', 'https://claude.ai/api/mcp/auth_callback', 'cursor://anysphere.cursor-retrieval/oauth/callback'])
      expect(redirectAllowed(ok), ok).toBe(true);
    for (const bad of ['http://evil.test/cb', 'javascript:alert(1)', 'data:text/html,x', 'https://a.test/cb#x', 'https://user@a.test/', 'HTTPS://a.test/', '/relative', ''])
      expect(redirectAllowed(bad), bad).toBe(false);
    expect((await register(['http://evil.test/cb'])).status).toBe(400);
    expect((await register([])).status).toBe(400);
  });

  it('signs a builder in, lets them pick a workspace, and hands out a working connection token', async () => {
    const { admin, workspace } = await setup();
    const reg = (await (await register(['http://localhost/callback'])).json()) as any;
    expect(reg.client_id).toMatch(/^cli_/);
    const { verifier, challenge } = await pkce();
    const q = new URLSearchParams({ response_type: 'code', client_id: reg.client_id, redirect_uri: 'http://localhost:51234/callback', state: 'st8', code_challenge: challenge, code_challenge_method: 'S256' });

    // Not signed in yet: off to the sign-in page, which comes back here.
    const anon = await new Browser('nobody').go(`/oauth/authorize?${q}`);
    expect(anon.status).toBe(302);
    expect(anon.headers.get('location')).toBe(`/auth/signin?return=${encodeURIComponent(`/oauth/authorize?${q}`)}`);

    const consent = await admin.go(`/oauth/authorize?${q}`);
    expect(consent.status).toBe(200);
    const html = await consent.text();
    expect(html).toContain('Connect Claude Code');
    expect(html).toContain(`value="${workspace}"`);

    const form = Object.fromEntries([...q.entries()]);
    expect((await admin.go('/oauth/authorize', { form: { ...form, workspace, decision: 'allow' }, headers: { origin: 'https://evil.test' } })).status).toBe(403);
    const denied = await admin.go('/oauth/authorize', { form: { ...form, workspace, decision: 'deny' } });
    expect(denied.headers.get('location')).toBe('http://localhost:51234/callback?error=access_denied&state=st8');

    const allowed = await admin.go('/oauth/authorize', { form: { ...form, workspace, decision: 'allow' } });
    const back = new URL(allowed.headers.get('location')!);
    expect(back.origin + back.pathname).toBe('http://localhost:51234/callback');
    expect(back.searchParams.get('state')).toBe('st8');
    const code = back.searchParams.get('code')!;

    const base = { grant_type: 'authorization_code', code, client_id: reg.client_id, redirect_uri: 'http://localhost:51234/callback' };
    expect((await (await swap({ ...base, code_verifier: b64url(new Uint8Array(32)) })).json() as any).error).toBe('invalid_grant');
    // The failed try used the code up, like any other use.
    const again = await admin.go('/oauth/authorize', { form: { ...form, workspace, decision: 'allow' } });
    const code2 = new URL(again.headers.get('location')!).searchParams.get('code')!;
    const tok = await swap({ ...base, code: code2, code_verifier: verifier });
    expect(tok.status).toBe(200);
    const t = (await tok.json()) as any;
    expect(t).toMatchObject({ token_type: 'Bearer' });
    expect(t.access_token).toMatch(/^brod_/);
    expect((await swap({ ...base, code: code2, code_verifier: verifier })).status).toBe(400);

    const ping = await SELF.fetch(`${API}/mcp`, { method: 'POST', headers: { authorization: `Bearer ${t.access_token}`, 'content-type': 'application/json' }, body: '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_workspace","arguments":{}}}' });
    expect(JSON.parse(((await ping.json()) as any).result.content[0].text).workspace).toBe(workspace);
    const list = (await admin.api(`/v1/tokens?workspace=${workspace}`)).body.connections;
    expect(list.some((c: any) => c.name === 'Claude Code' && !c.revoked_at)).toBe(true);
  });

  it('does not let a member or a stranger connect an agent', async () => {
    const reg = (await (await register(['https://client.test/cb'])).json()) as any;
    const { challenge } = await pkce();
    const q = new URLSearchParams({ response_type: 'code', client_id: reg.client_id, redirect_uri: 'https://client.test/cb', code_challenge: challenge, code_challenge_method: 'S256' });
    const stranger = await new Browser(`${unique('s')}@acme.test`).signIn();
    expect((await stranger.go(`/oauth/authorize?${q}`)).status).toBe(403);
    const { admin, workspace } = await setup();
    expect((await stranger.go('/oauth/authorize', { form: { ...Object.fromEntries(q), workspace, decision: 'allow' } })).status).toBe(403);
    expect((await admin.go(`/oauth/authorize?${new URLSearchParams({ ...Object.fromEntries(q), redirect_uri: 'https://other.test/cb' })}`)).status).toBe(400);
    const noPkce = await admin.go(`/oauth/authorize?${new URLSearchParams({ ...Object.fromEntries(q), code_challenge: '' })}`);
    expect(noPkce.headers.get('location')).toContain('error=invalid_request');
  });
});

describe('the connections page', () => {
  it('makes, lists and disconnects tokens for builders', async () => {
    const { admin, workspace } = await setup();
    const home = await (await admin.go(`/w/${workspace}`)).text();
    expect(home).toContain(`/w/${workspace}/connections`);
    const pageRes = await admin.go(`/w/${workspace}/connections`);
    expect(pageRes.status).toBe(200);
    const html = await pageRes.text();
    expect(html).toContain('claude-code');
    expect(html).toContain(`claude mcp add --transport http brod ${API}/mcp`);

    const made = await (await admin.go(`/w/${workspace}/connections`, { form: { name: 'laptop' } })).text();
    const token = /value="(brod_[0-9a-f]+)"/.exec(made)?.[1];
    expect(token).toBeTruthy();
    const ok = await SELF.fetch(`${API}/v1/apps`, { headers: { authorization: `Bearer ${token}` } });
    expect(ok.status).toBe(200);

    const id = /name="revoke" value="(tok_[0-9a-f]+)"/.exec(made.slice(made.indexOf('laptop<br>')))?.[1];
    expect(id).toBeTruthy();
    expect((await admin.go(`/w/${workspace}/connections`, { form: { revoke: id! }, headers: { origin: 'https://evil.test' } })).status).toBe(403);
    expect((await admin.go(`/w/${workspace}/connections`, { form: { revoke: id! } })).status).toBe(200);
    expect((await SELF.fetch(`${API}/v1/apps`, { headers: { authorization: `Bearer ${token}` } })).status).toBe(401);
  });

  it('is for builders and admins only', async () => {
    const { admin, workspace } = await setup();
    const bob = new Browser(`${unique('bob')}@acme.test`);
    const inv = await admin.api('/v1/invites', { json: { email: bob.email, role: 'member' } });
    await bob.go('/auth/invite', { form: { token: new URL(inv.body.dev_link).searchParams.get('token')! } });
    expect((await bob.go(`/w/${workspace}/connections`)).status).toBe(403);
    expect(await (await bob.go(`/w/${workspace}`)).text()).not.toContain('/connections');
    expect((await new Browser('x').go(`/w/${workspace}/connections`)).status).toBe(302);
  });
});
