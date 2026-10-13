// Connecting an agent: the connections page, and sign-in for MCP clients with OAuth instead of a pasted token.
//
// The OAuth side is what MCP clients expect (OAuth 2.1 with PKCE): /mcp answers 401 with a pointer to the resource
// metadata (RFC 9728), which names this server's metadata (RFC 8414); the client registers itself (RFC 7591), sends
// the person to /oauth/authorize, and swaps the code at /oauth/token. The person picks a workspace on the consent page,
// and the access token is an ordinary connection token: it shows on the connections page and is revoked the same way.
import { ABUSE, clientIp, perHour, rateLimit } from './abuse';
import { createToken, listTokens, person, revokeToken } from './control';
import { Caller, Env, LIMITS, Problem, Role, esc, json, notice, now, page, randomId, redirect, sha256 } from './lib';
import { membership, myWorkspaces } from './people';

const CORS = {
  'access-control-allow-origin': '*', 'access-control-allow-methods': 'GET, POST, OPTIONS',
  'access-control-allow-headers': 'authorization, content-type, mcp-protocol-version',
};
const cors = (r: Response) => { for (const [k, v] of Object.entries(CORS)) r.headers.set(k, v); return r; };
const oauthError = (error: string, description: string, status = 400) => cors(json({ error, error_description: description }, status));
const builds = (role: Role) => role === 'admin' || role === 'builder';

/** Where /mcp's 401 points a client to learn how to sign in. */
export const resourceMetadataUrl = (env: Env) => `${env.API_ORIGIN}/.well-known/oauth-protected-resource/mcp`;

// ---------- redirect addresses ----------

const BLOCKED_SCHEMES = new Set(['javascript', 'data', 'file', 'vbscript', 'blob', 'about', 'ftp', 'ws', 'wss']);
const LOOPBACK = new Set(['localhost', '127.0.0.1', '[::1]']);

/** Split an absolute URL into scheme, authority (for scheme://) and the rest, without a URL parser, the same way as connect.rs. */
function parts(uri: string): { scheme: string; authority: string | null; rest: string } | null {
  const m = /^([a-z][a-z0-9+.-]*):(.*)$/.exec(uri);
  if (!m) return null;
  if (!m[2].startsWith('//')) return { scheme: m[1], authority: null, rest: m[2] };
  const after = m[2].slice(2), end = after.search(/[/?]/);
  return { scheme: m[1], authority: end < 0 ? after : after.slice(0, end), rest: end < 0 ? '' : after.slice(end) };
}
const hostOf = (authority: string) => (authority.startsWith('[') ? authority.slice(0, authority.indexOf(']') + 1) : authority.split(':')[0]);

/**
 * A redirect address a client may register: https, http on this machine only (a desktop client's local listener,
 * RFC 8252), or an app's own scheme. Never one that runs code or reads files.
 */
export function redirectAllowed(uri: string): boolean {
  if (!uri || uri.length > 500 || /[\s#\u0000-\u001f\u007f]/.test(uri)) return false;
  const p = parts(uri);
  if (!p) return false;
  if (p.scheme === 'https' || p.scheme === 'http') {
    if (!p.authority || p.authority.includes('@')) return false;
    return p.scheme === 'https' || LOOPBACK.has(hostOf(p.authority));
  }
  return !BLOCKED_SCHEMES.has(p.scheme);
}

/** The registered address matches exactly, or both are on this machine and differ only by port (RFC 8252 7.3). */
function redirectMatches(registered: string[], uri: string): boolean {
  if (registered.includes(uri)) return true;
  const loose = (u: string) => {
    const p = parts(u);
    if (!p || p.scheme !== 'http' || !p.authority || !LOOPBACK.has(hostOf(p.authority))) return null;
    return `http://${hostOf(p.authority)}${p.rest}`;
  };
  const l = loose(uri);
  return l !== null && registered.some(r => loose(r) === l);
}

// ---------- clients and codes ----------

async function client(env: Env, id: string | null) {
  if (!id || !/^cli_[0-9a-f]{16}$/.test(id)) return null;
  const c = await env.DB.prepare('SELECT id, name, redirect_uris FROM oauth_clients WHERE id = ?').bind(id).first<{ id: string; name: string; redirect_uris: string }>();
  return c && { id: c.id, name: c.name, redirectUris: JSON.parse(c.redirect_uris) as string[] };
}

async function register(env: Env, request: Request): Promise<Response> {
  let b: any;
  try { b = await request.json(); } catch { return oauthError('invalid_client_metadata', 'The request body must be JSON.'); }
  const uris = Array.isArray(b?.redirect_uris) ? b.redirect_uris : [];
  if (!uris.length || uris.length > 10 || !uris.every((u: unknown) => typeof u === 'string' && redirectAllowed(u)))
    return oauthError('invalid_redirect_uri', 'Give 1 to 10 redirect_uris: https, http on localhost, or an app scheme.');
  const ip = clientIp(env, request);
  if (ip) {
    try { await rateLimit(env, 'oauth_ip', ip, ABUSE.oauthClientsPerIpHour, perHour, 'Too many clients registered from this address in the last hour.'); }
    catch (e) { if (e instanceof Problem) return oauthError('temporarily_unavailable', e.message, 429); throw e; }
  }
  const recent = await env.DB.prepare('SELECT COUNT(*) AS n FROM oauth_clients WHERE created_at > ?').bind(now() - 3600e3).first<{ n: number }>();
  if ((recent?.n ?? 0) >= LIMITS.oauthClientsPerHour) return oauthError('temporarily_unavailable', 'Too many clients registered in the last hour. Try again later.', 429);
  const name = String(b.client_name ?? '').trim().slice(0, 60) || 'MCP client';
  const id = randomId('cli_', 8), at = now();
  await env.DB.prepare('INSERT INTO oauth_clients (id, name, redirect_uris, created_at) VALUES (?,?,?,?)').bind(id, name, JSON.stringify(uris), at).run();
  return cors(json({
    client_id: id, client_id_issued_at: Math.floor(at / 1000), client_name: name, redirect_uris: uris,
    grant_types: ['authorization_code'], response_types: ['code'], token_endpoint_auth_method: 'none',
  }, 201));
}

/** The parameters of an authorization request, checked. A bad client or redirect address gets a page; anything else goes back to the client. */
type Authz = { client: { id: string; name: string }; redirectUri: string; state: string; challenge: string };
async function authorizeRequest(env: Env, q: Record<string, string>): Promise<Authz | Response> {
  const c = await client(env, q.client_id ?? null);
  if (!c) return notice(400, 'Unknown app', 'This sign-in request comes from an app Brod does not know. Start again from your agent.');
  const redirectUri = q.redirect_uri ?? '';
  if (!redirectMatches(c.redirectUris, redirectUri)) return notice(400, 'Wrong return address', 'This sign-in request asks to return somewhere the app did not register. Start again from your agent.');
  const state = q.state ?? '';
  if (q.response_type !== 'code') return back(redirectUri, { error: 'unsupported_response_type', state });
  if (!/^[A-Za-z0-9_-]{43,128}$/.test(q.code_challenge ?? '') || q.code_challenge_method !== 'S256')
    return back(redirectUri, { error: 'invalid_request', error_description: 'PKCE with S256 is required.', state });
  return { client: c, redirectUri, state, challenge: q.code_challenge };
}

function back(redirectUri: string, params: Record<string, string>): Response {
  const q = new URLSearchParams(Object.entries(params).filter(([, v]) => v));
  return redirect(`${redirectUri}${redirectUri.includes('?') ? '&' : '?'}${q}`);
}

function consentPage(env: Env, a: Authz, email: string, workspaces: { slug: string; name: string }[]) {
  const target = parts(a.redirectUri);
  const where = target?.authority ? hostOf(target.authority) : `${target?.scheme}:`;
  const hidden = Object.entries({ client_id: a.client.id, redirect_uri: a.redirectUri, state: a.state, code_challenge: a.challenge, code_challenge_method: 'S256', response_type: 'code' })
    .map(([k, v]) => `<input type="hidden" name="${k}" value="${esc(v)}">`).join('');
  const pick = workspaces.length === 1
    ? `<p>Workspace: <b>${esc(workspaces[0].name)}</b></p><input type="hidden" name="workspace" value="${esc(workspaces[0].slug)}">`
    : `<p><label>Workspace<br><select name="workspace" aria-label="Workspace">${workspaces.map(w => `<option value="${esc(w.slug)}">${esc(w.name)}</option>`).join('')}</select></label></p>`;
  return page(200, 'Connect an agent', `<h1>Connect ${esc(a.client.name)}</h1>
<p><b>${esc(a.client.name)}</b> wants to act as you (<b>${esc(email)}</b>) in Brod: deploy and manage apps, and invite people, in the workspace you pick.</p>
<form method="post" action="/oauth/authorize">${hidden}${pick}
<p class="muted">You will be sent back to ${esc(where)}. You can disconnect it any time from the workspace's connections page.</p>
<div class="actions"><button name="decision" value="allow">Allow</button><button name="decision" value="deny" class="secondary">Cancel</button></div></form>`);
}

async function authorize(env: Env, request: Request, url: URL): Promise<Response> {
  const post = request.method === 'POST';
  if (post && request.headers.get('origin') !== env.API_ORIGIN) throw new Problem(403, 'bad_origin', 'This form must be sent from Brod itself.');
  const q = post ? Object.fromEntries([...(await request.formData()).entries()].map(([k, v]) => [k, String(v)])) : Object.fromEntries(url.searchParams);
  const a = await authorizeRequest(env, q);
  if (a instanceof Response) return a;
  const who = await person(env, request);
  if (!who) return redirect(`/auth/signin?return=${encodeURIComponent(url.pathname + url.search)}`);
  const workspaces = (await myWorkspaces(env, who.user)).filter(w => builds(w.role));
  if (!post) {
    if (!workspaces.length) return notice(403, 'No workspace to connect', 'An agent works in a workspace where you are a builder or admin. Create a workspace, or ask an admin to make you a builder.', '<p><a class="btn" href="/new">Create a workspace</a></p>');
    return consentPage(env, a, who.user.email, workspaces);
  }
  if (q.decision !== 'allow') return back(a.redirectUri, { error: 'access_denied', state: a.state });
  const mem = await membership(env, who.user, q.workspace ?? '');
  if (!mem || !builds(mem.role)) return notice(403, 'Not allowed', 'You can connect an agent only to a workspace where you are a builder or admin.');
  const code = randomId('', 24);
  await env.DB.prepare('INSERT INTO oauth_codes (hash, client_id, user_id, workspace_id, redirect_uri, challenge, expires_at) VALUES (?,?,?,?,?,?,?)')
    .bind(await sha256(code), a.client.id, who.user.id, mem.workspace.id, a.redirectUri, a.challenge, now() + LIMITS.oauthCodeTtlMs).run();
  return back(a.redirectUri, { code, state: a.state, iss: env.API_ORIGIN });
}

async function challengeOf(verifier: string) {
  const d = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier)));
  return btoa(String.fromCharCode(...d)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

async function token(env: Env, request: Request): Promise<Response> {
  const ct = request.headers.get('content-type') ?? '';
  let b: Record<string, string> = {};
  try {
    b = ct.includes('application/json') ? await request.json() : Object.fromEntries([...(await request.formData()).entries()].map(([k, v]) => [k, String(v)]));
  } catch { return oauthError('invalid_request', 'Send the parameters as a form.'); }
  if (b.grant_type !== 'authorization_code') return oauthError('unsupported_grant_type', 'Only authorization_code is supported. Connections do not expire, so there is nothing to refresh.');
  const row = await env.DB.prepare('UPDATE oauth_codes SET used_at = ? WHERE hash = ? AND used_at IS NULL AND expires_at > ? RETURNING client_id, user_id, workspace_id, redirect_uri, challenge')
    .bind(now(), await sha256(String(b.code ?? '')), now()).first<{ client_id: string; user_id: string; workspace_id: string; redirect_uri: string; challenge: string }>();
  if (!row) return oauthError('invalid_grant', 'This code has expired or was already used. Sign in again.');
  if (row.client_id !== b.client_id || row.redirect_uri !== b.redirect_uri) return oauthError('invalid_grant', 'The code was issued to another client or redirect address.');
  if (!/^[A-Za-z0-9._~-]{43,128}$/.test(b.code_verifier ?? '') || (await challengeOf(b.code_verifier)) !== row.challenge) return oauthError('invalid_grant', 'The code_verifier does not match.');
  const who = await env.DB.prepare(
    `SELECT u.id AS uid, u.email, u.name AS uname, u.email_verified_at, m.role AS mrole, w.* FROM users u JOIN members m ON m.user_id = u.id
     JOIN workspaces w ON w.id = m.workspace_id WHERE u.id = ? AND w.id = ?`,
  ).bind(row.user_id, row.workspace_id).first<any>();
  if (!who || !builds(who.mrole)) return oauthError('invalid_grant', 'The person who signed in is no longer a builder in that workspace.');
  const c: Caller = {
    workspace: { id: who.id, slug: who.slug, name: who.name, plan: who.plan, color: who.color, icon: who.icon, created_at: who.created_at },
    user: { id: who.uid, email: who.email, name: who.uname, email_verified_at: who.email_verified_at }, role: who.mrole, actor: who.email, agent: false,
  };
  const name = (await client(env, row.client_id))?.name ?? 'MCP client';
  const t = await createToken(env, c, name);
  return cors(json({ access_token: t.token, token_type: 'Bearer', scope: 'brod' }, 200, { 'cache-control': 'no-store' }));
}

// ---------- the connections page ----------

async function connectionsPage(env: Env, request: Request, slug: string): Promise<Response> {
  const p = await person(env, request);
  if (!p) return redirect(`/auth/signin?return=${encodeURIComponent(`/w/${slug}/connections`)}`);
  const mem = await membership(env, p.user, slug);
  if (!mem) return notice(404, 'Not your workspace', 'You are not in this workspace. Ask an admin to invite you.');
  const c: Caller = { workspace: mem.workspace, user: p.user, role: mem.role, actor: p.user.email, agent: false };
  if (!builds(c.role)) return notice(403, 'Builders only', 'Only a workspace builder or admin can connect agents. Ask an admin to make you a builder.');
  let made = '';
  if (request.method === 'POST') {
    if (request.headers.get('origin') !== env.API_ORIGIN) throw new Problem(403, 'bad_origin', 'This form must be sent from Brod itself.');
    const f = await request.formData();
    if (f.get('revoke')) await revokeToken(env, c, String(f.get('revoke')));
    else {
      const t = await createToken(env, c, String(f.get('name') ?? ''));
      const add = `claude mcp add --transport http brod ${env.API_ORIGIN}/mcp --header "Authorization: Bearer ${t.token}"`;
      made = `<div role="status"><p><b>Connection “${esc(t.name)}” made.</b> Copy its token now: it is shown only this once.</p>
<input readonly value="${esc(t.token)}" aria-label="Token" onclick="this.select()">
<p class="muted">For Claude Code:</p><input readonly value="${esc(add)}" aria-label="Claude Code command" onclick="this.select()"></div>`;
    }
  }
  const active = ((await listTokens(env, c)) as { id: string; name: string; made_by: string; created_at: number; last_used_at: number | null; revoked_at: number | null }[]).filter(t => !t.revoked_at);
  const day = (ms: number | null) => (ms ? new Date(ms).toISOString().slice(0, 10) : 'never');
  const rows = active.map(t => `<li><span>${esc(t.name)}<br><small>${esc(t.made_by)} · made ${day(t.created_at)} · last used ${day(t.last_used_at)}</small></span>
${c.role === 'admin' || t.made_by === p.user.email ? `<form method="post"><button name="revoke" value="${esc(t.id)}" class="secondary small">Disconnect</button></form>` : ''}</li>`).join('');
  const w = mem.workspace;
  return page(200, `Connections · ${w.name}`, `<p class="muted"><a href="/w/${esc(w.slug)}">${esc(w.name)}</a></p><h1>Connect an agent</h1>
<p>Add Brod to your agent as an MCP server. It opens this site so you can sign in and pick this workspace; no token to copy.</p>
<input readonly value="${esc(`claude mcp add --transport http brod ${env.API_ORIGIN}/mcp`)}" aria-label="Claude Code command" onclick="this.select()">
<p class="muted">Other MCP clients: add the server address ${esc(env.API_ORIGIN)}/mcp.</p>
<h2>Or make a token</h2><p>For an agent that cannot sign in with a browser.</p>${made}
<form method="post"><input name="name" maxlength="40" placeholder="Connection name, for example laptop" aria-label="Connection name"><button>Make a token</button></form>
<h2>Connections</h2>${rows ? `<ul>${rows}</ul>` : '<p>None yet.</p>'}`, { color: w.color });
}

// ---------- routes ----------

export async function serveConnect(env: Env, request: Request, url: URL): Promise<Response | null> {
  const p = url.pathname.replace(/\/+$/, ''), m = request.method;
  const open = p.startsWith('/.well-known/oauth-') || p === '/oauth/register' || p === '/oauth/token';
  if (open && m === 'OPTIONS') return cors(new Response(null, { status: 204 }));
  if ((p === '/.well-known/oauth-protected-resource' || p === '/.well-known/oauth-protected-resource/mcp') && m === 'GET') {
    return cors(json({ resource: `${env.API_ORIGIN}/mcp`, authorization_servers: [env.API_ORIGIN], bearer_methods_supported: ['header'], resource_name: 'Brod' }));
  }
  if (p === '/.well-known/oauth-authorization-server' && m === 'GET') {
    return cors(json({
      issuer: env.API_ORIGIN, authorization_endpoint: `${env.API_ORIGIN}/oauth/authorize`, token_endpoint: `${env.API_ORIGIN}/oauth/token`,
      registration_endpoint: `${env.API_ORIGIN}/oauth/register`, response_types_supported: ['code'], grant_types_supported: ['authorization_code'],
      code_challenge_methods_supported: ['S256'], token_endpoint_auth_methods_supported: ['none'], scopes_supported: ['brod'],
    }));
  }
  if (p === '/oauth/register' && m === 'POST') return await register(env, request);
  if (p === '/oauth/authorize' && (m === 'GET' || m === 'POST')) return await authorize(env, request, url);
  if (p === '/oauth/token' && m === 'POST') return await token(env, request);
  const conn = /^\/w\/([a-z0-9-]+)\/connections$/.exec(p);
  if (conn && (m === 'GET' || m === 'POST')) return await connectionsPage(env, request, conn[1]);
  return null;
}
