// Shared test helpers: a cookie-keeping browser, and a workspace with an agent connection.
import { SELF } from 'cloudflare:test';
import { env } from 'cloudflare:workers';
import { expect } from 'vitest';

export const API = env.API_ORIGIN;
let seq = 0;
export const unique = (name: string) => `${name}-${Date.now()}-${++seq}`;

/** A person with a browser that keeps host-only cookies and does not follow redirects on its own. */
export class Browser {
  jars: Record<string, Record<string, string>> = {};
  constructor(public email: string) {}
  async go(url: string, init: RequestInit & { form?: Record<string, string>; json?: unknown } = {}) {
    const u = new URL(url, API);
    const headers = new Headers(init.headers);
    const jar = this.jars[u.host] ?? {};
    if (Object.keys(jar).length) headers.set('cookie', Object.entries(jar).map(([k, v]) => `${k}=${v}`).join('; '));
    let body = init.body;
    if (init.form) { body = new URLSearchParams(init.form).toString(); headers.set('content-type', 'application/x-www-form-urlencoded'); }
    if (init.json !== undefined) { body = JSON.stringify(init.json); headers.set('content-type', 'application/json'); }
    if ((init.form || init.json !== undefined) && !headers.has('origin')) headers.set('origin', API);
    const res = await SELF.fetch(u.href, { method: init.method ?? (body !== undefined && body !== null ? 'POST' : 'GET'), headers, body, redirect: 'manual' });
    for (const sc of res.headers.getSetCookie()) {
      expect(sc).not.toMatch(/domain=/i);
      const [k, v] = sc.split(';')[0].split('=');
      this.jars[u.host] ??= {};
      if (/max-age=0/i.test(sc)) delete this.jars[u.host][k]; else this.jars[u.host][k] = v;
    }
    return res;
  }
  async open(url: string) {
    let res = await this.go(url), at = new URL(url, API).href;
    for (let i = 0; i < 10 && res.status >= 300 && res.status < 400; i++) { at = new URL(res.headers.get('location')!, at).href; res = await this.go(at); }
    return res;
  }
  async signIn() {
    const start = await this.go('/auth/start', { json: { email: this.email } });
    const { dev_link } = (await start.json()) as { dev_link: string };
    const res = await this.go('/auth/verify', { form: { token: new URL(dev_link).searchParams.get('token')! } });
    expect(res.status).toBe(302);
    return this;
  }
  async api<T = any>(path: string, init: RequestInit & { json?: unknown } = {}): Promise<{ status: number; body: T }> {
    const res = await this.go(path, { ...init, headers: { origin: API, ...(init.headers as Record<string, string>) } });
    return { status: res.status, body: (await res.json()) as T };
  }
}

/** An admin with a workspace and an agent connection, plus a JSON-RPC helper for the MCP endpoint. */
export async function setup() {
  const admin = await new Browser(`${unique('admin')}@acme.test`).signIn();
  const ws = await admin.api('/v1/workspaces', { json: { name: unique('Acme'), accept_terms: true } });
  const tok = await admin.api('/v1/tokens', { json: { name: 'claude-code' } });
  const rpc = async (method: string, params: unknown = {}, token = tok.body.token) => {
    const res = await SELF.fetch(`${API}/mcp`, { method: 'POST', headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' }, body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }) });
    return { status: res.status, body: (await res.json()) as any };
  };
  const tool = async (name: string, args: Record<string, unknown> = {}) => {
    const r = (await rpc('tools/call', { name, arguments: args })).body.result;
    return { isError: r.isError as boolean, data: JSON.parse(r.content[0].text) };
  };
  const deploy = async (name: string, html = '<h1>hello</h1>') =>
    (await tool('deploy_app', { name: unique(name), files: [{ path: 'index.html', content: `<html><body>${html}</body></html>` }] })).data;
  return { admin, workspace: ws.body.workspace as string, token: tok.body.token as string, rpc, tool, deploy };
}
/** The platform operator's API (src/abuse.ts), with the test admin secret. */
export async function admin(path: string, body: unknown = {}, method = 'POST') {
  const res = await SELF.fetch(`${API}/v1/admin/${path}`, {
    method, headers: { authorization: 'Bearer test-admin-secret', 'content-type': 'application/json' }, ...(method === 'GET' ? {} : { body: JSON.stringify(body) }),
  });
  return { status: res.status, body: (await res.json()) as any };
}
/** Let a new workspace open apps to everyone (a day-old guardrail otherwise keeps them inside it). */
export const trust = (workspace: string) => admin(`workspaces/${workspace}/trust`);
export const confirmLink = async (b: Browser, url: string, decision = 'confirm') => b.go(new URL(url).pathname, { form: { decision } });

