// The gateway. Every visitor request to <slug>.<APPS_DOMAIN> passes through here before it reaches an app's files.
// It signs people in (through the API host), decides access, gives the app the identity contract under /_brod/,
// and serves the app: its files from R2, and anything else from its server code when it has some.
import { ABUSE, clientIp, perHour, rateLimit, takenDownPage } from './abuse';
import type { DomainTarget } from './domains';
import { AppRow, Env, LIMITS, Problem, STAGING_SUFFIX, User, appUrl, cookie, esc, hmac, hostOrigin, json, notFound, notice, now, page, randomId, redirect, safeEqual, setCookie, sha256, signToken, stagingUrl, verifyPassword } from './lib';
import { Decision, createSession, decide, event, revokeSession, sessionUser } from './people';
import { appendToBodyResponse } from './platform/html';
import { ServerInfo, isServerPath, serverFor } from './runtime';

const APP_COOKIE = 'brod_session';
const PASS_COOKIE = 'brod_pass';

const CLIENT_JS = `// Brod client: who is signed in to this app.
window.Brod = {
  async me() { const r = await fetch('/_brod/me', { credentials: 'same-origin' }); return r.ok ? r.json() : null; },
  signIn(path) { location.href = '/_brod/signin?return=' + encodeURIComponent(path || location.pathname + location.search); },
  signOut() { location.href = '/_brod/signout'; },
};
`;

/** The key an app uses to check identity tokens. Each app has its own, derived from the platform secret. */
export const appIdentityKey = (env: Env, app: AppRow) => hmac(env.IDENTITY_SECRET, `identity:${app.id}`);

/**
 * An app found by its address: the row, its workspace's slug, and the origin it was opened at (its own address, or a
 * custom domain, which `domain` then names so the sign-in can be handed back there). Cookies belong to that origin.
 */
type HostedApp = AppRow & { wslug: string; origin: string; domain: string | null; staging: boolean };

function signInUrl(env: Env, app: HostedApp, ret: string) {
  const host = app.domain ? `&host=${encodeURIComponent(app.domain)}` : '';
  return `${env.API_ORIGIN}/auth/app?app=${app.slug}${app.staging ? STAGING_SUFFIX : ''}.${app.wslug}${host}&return=${encodeURIComponent(ret)}`;
}

/**
 * Who may open an app's staging address: the people who can change the app (its owner, workspace admins and builders)
 * and anyone granted its top role. Nobody gets in anonymously or with the app's password, whatever its access mode.
 */
function admitStaging(app: AppRow, d: Decision, user: Visitor): Decision {
  if (!user) return { allowed: false, signInNeeded: true, role: null, groups: [], member: null };
  const top = (JSON.parse(app.roles) as string[])[0];
  // The people who can change the app try it as its owner would.
  if (app.owner_id === user.user.id || d.member === 'admin' || d.member === 'builder') return { ...d, allowed: true, signInNeeded: false, role: top };
  return { ...d, allowed: d.allowed && d.role === top, signInNeeded: false };
}
const appReturn = (r: string | null) => (r && r.startsWith('/') && !r.startsWith('//') && !r.startsWith('/\\') ? r : '/');

async function special(env: Env, request: Request, url: URL, app: HostedApp, user: Visitor): Promise<Response> {
  const reportLink = '<p><small><a href="/_brod/report">Report this app</a></small></p>';
  switch (url.pathname) {
    case '/_brod/client.js':
      return new Response(CLIENT_JS, { headers: { 'content-type': 'text/javascript; charset=utf-8', 'cache-control': 'public, max-age=300' } });

    case '/_brod/signin':
      return redirect(signInUrl(env, app, appReturn(url.searchParams.get('return'))));

    case '/_brod/callback': {
      const hash = await sha256(url.searchParams.get('code') ?? '');
      const code = await env.DB.prepare('UPDATE app_codes SET used_at = ? WHERE hash = ? AND app_id = ? AND used_at IS NULL AND expires_at > ? RETURNING user_id, parent')
        .bind(now(), hash, app.id, now()).first<{ user_id: string; parent: string }>();
      if (!code) return notice(400, 'Sign-in expired', 'That sign-in link has expired. Try again.', `<p><a class="btn" href="/_brod/signin">Sign in</a></p>`);
      const token = await createSession(env, code.user_id, app.id, code.parent);
      return redirect(appReturn(url.searchParams.get('return')), { 'set-cookie': setCookie(app.origin, APP_COOKIE, token, LIMITS.sessionTtlMs / 1000) });
    }

    case '/_brod/signout':
      // One sign-in, so signing out of one app signs out of all of them.
      if (user?.parent) await revokeSession(env, user.parent);
      return page(200, 'Signed out', '<h1>Signed out</h1><p>You are signed out of every Brod app.</p><p><a class="btn" href="/_brod/signin">Sign in again</a></p>',
        { headers: { 'set-cookie': setCookie(app.origin, APP_COOKIE, '', 0) } });

    case '/_brod/password': {
      if (app.access !== 'password' || !app.password_hash) return redirect(appReturn(url.searchParams.get('return')));
      if (request.method !== 'POST') return passwordPage(app, appReturn(url.searchParams.get('return')));
      const f = await request.formData().catch(() => null);
      const ret = appReturn(String(f?.get('return') ?? ''));
      const since = now() - 15 * 60 * 1000;
      const tries = await env.DB.prepare("SELECT COUNT(*) AS n FROM events WHERE app_id = ? AND at > ? AND action = 'password_failed'").bind(app.id, since).first<{ n: number }>();
      if ((tries?.n ?? 0) >= LIMITS.passwordTriesPer15Min) return passwordPage(app, ret, 'Too many wrong passwords. Wait a few minutes and try again.', 429);
      if (!(await verifyPassword(String(f?.get('password') ?? ''), app.password_hash))) {
        await event(env, app.workspace_id, user?.user.email ?? 'visitor', app.id, 'password_failed', 'a wrong password').run();
        return passwordPage(app, ret, 'That password is not right. Check it and try again.', 401);
      }
      return redirect(ret, { 'set-cookie': setCookie(app.origin, PASS_COOKIE, await passToken(env, app), LIMITS.sessionTtlMs / 1000) });
    }

    case '/_brod/me': {
      const d = await access(env, request, app, user);
      if (!user || !d.allowed) return json({ error: { code: 'signed_out', message: 'Nobody is signed in to this app.', sign_in: '/_brod/signin' } }, 401, { 'cache-control': 'no-store' });
      const { identity, token } = await identityFor(env, app, user.user, d.role, d.groups);
      return json({ ...identity, token }, 200, { 'cache-control': 'private, no-store' });
    }

    case '/_brod/report': {
      if (request.method === 'POST') {
        const f = await request.formData().catch(() => null);
        const reason = String(f?.get('reason') ?? '').trim().slice(0, 1000);
        if (!reason) return notice(400, 'Tell us what is wrong', 'Describe the problem in a sentence or two.', '<p><a href="/_brod/report">Back</a></p>');
        const reporter = user?.user.email ?? (String(f?.get('email') ?? '').trim().slice(0, 254) || 'anonymous');
        const ip = clientIp(env, request);
        try { if (ip) await rateLimit(env, 'report_ip', ip, ABUSE.reportsPerIpHour, perHour, 'Too many reports were sent from your network in the last hour.'); }
        catch (e) { if (e instanceof Problem) return notice(429, 'Too many reports', e.message); throw e; }
        await env.DB.batch([
          env.DB.prepare('INSERT INTO reports (id, app_id, reporter, reason, created_at) VALUES (?,?,?,?,?)').bind(randomId('rep_', 8), app.id, reporter, reason, now()),
          event(env, app.workspace_id, 'visitor', app.id, 'report', reason.slice(0, 120)),
        ]);
        return notice(200, 'Thank you', 'Your report was sent to the Brod team for review.');
      }
      return page(200, 'Report this app', `<h1>Report this app</h1><p>Tell the Brod team if this app is phishing, malware, spam, or otherwise abusive.</p>
<form method="post"><input name="email" type="email" placeholder="Your email (optional)" aria-label="Your email"><input name="reason" required maxlength="1000" placeholder="What is wrong?" aria-label="What is wrong"><button class="block">Send report</button></form>`);
    }
  }
  return notice(404, 'Not found', 'There is nothing at this address.', reportLink);
}

const REPORT_LINK = '<a href="/_brod/report" style="position:fixed;right:8px;bottom:8px;font:12px system-ui,sans-serif;opacity:.6;color:inherit;background:transparent;z-index:2147483647">Report</a>';
/** Every public page carries a small way to report abuse. */
// HTMLRewriter is Cloudflare-only; other hosts (Vercel, Node) insert before the last </body> instead.
const withReportLink = (res: Response): Response | Promise<Response> => typeof HTMLRewriter === 'undefined' ? appendToBodyResponse(res, REPORT_LINK)
  : new HTMLRewriter().on('body', { element(el) { el.append(REPORT_LINK, { html: true }); } }).transform(res);

type Visitor = { user: User; hash: string; parent: string | null } | null;

/** The cookie a correct password earns: bound to the app and to its current password, so setting a new one ends it. */
const passToken = (env: Env, app: AppRow) => hmac(env.IDENTITY_SECRET, `password:${app.id}:${app.password_hash}`);

/**
 * The access decision for this request. On a password-protected app, a visitor nobody granted a role gets in with the
 * password cookie (as the app's lowest role when signed in, and anonymously otherwise), or is asked for the password.
 */
async function admit(env: Env, request: Request, app: HostedApp, user: Visitor): Promise<Decision & { passwordNeeded?: boolean }> {
  const d = await decide(env, app, user?.user ?? null);
  if (d.allowed || app.access !== 'password' || !app.password_hash) return d;
  if (safeEqual(cookie(request, app.origin, PASS_COOKIE), await passToken(env, app))) {
    const roles: string[] = JSON.parse(app.roles);
    return { ...d, allowed: true, signInNeeded: false, role: user ? roles[roles.length - 1] : null };
  }
  return { ...d, signInNeeded: false, passwordNeeded: true };
}

/** The access decision for this request: the staging rule on a staging address, the app's own everywhere else. */
const access = async (env: Env, request: Request, app: HostedApp, user: Visitor): Promise<Decision & { passwordNeeded?: boolean }> =>
  app.staging ? admitStaging(app, await decide(env, app, user?.user ?? null), user) : admit(env, request, app, user);

/** The page a password-protected app shows until its password is given. */
function passwordPage(app: AppRow, ret: string, error = '', status = 401): Response {
  const name = esc(app.title || app.name);
  return page(status, `${app.title || app.name}: password`, `<div class="icon" aria-hidden="true">🔒</div><h1>${name} needs a password</h1>
<p>Whoever shared this app with you has the password. Enter it to open the app.</p>${error ? `<p role="alert">${esc(error)}</p>` : ''}
<form method="post" action="/_brod/password"><input type="hidden" name="return" value="${esc(ret)}">
<input name="password" type="password" required autofocus autocomplete="current-password" placeholder="Password" aria-label="Password"><button class="block">Open ${name}</button></form>
<p><small>Have a Brod account with access? <a href="/_brod/signin?return=${encodeURIComponent(ret)}">Sign in instead</a></small></p>`);
}

/** The identity contract: who is signed in, their role in this app, and a token signed with the app's key. */
async function identityFor(env: Env, app: AppRow, user: User, role: string | null, groups: string[]) {
  const ws = await env.DB.prepare('SELECT slug FROM workspaces WHERE id = ?').bind(app.workspace_id).first<{ slug: string }>();
  const t = Math.floor(now() / 1000);
  const identity = { user: { id: user.id, email: user.email, name: user.name }, role, groups, app: app.slug, workspace: ws?.slug ?? '' };
  return { identity, token: await signToken(await appIdentityKey(env, app), { ...identity, iat: t, exp: t + LIMITS.identityTtlSec }) };
}

/** Serve an app found by <app>.<workspace>, or by id for a custom domain (`domain` is then the host it was opened at). */
export async function serveApp(env: Env, request: Request, where: Exclude<DomainTarget, { home: string }>, ctx: ExecutionContext, domain: string | null = null): Promise<Response> {
  const url = new URL(request.url);
  const staging = 'staging' in where && where.staging === true;
  const sql = `SELECT a.*, w.slug AS wslug, w.suspended_at AS ws_suspended_at, v.server FROM apps a JOIN workspaces w ON w.id = a.workspace_id LEFT JOIN versions v ON v.app_id = a.id AND v.n = a.${staging ? 'staging_version' : 'live_version'} WHERE `;
  const row = await ('appId' in where ? env.DB.prepare(sql + 'a.id = ?').bind(where.appId) : env.DB.prepare(sql + 'w.slug = ? AND a.slug = ?').bind(where.workspace, where.slug))
    .first<AppRow & { wslug: string; server: string | null; taken_down_at: number | null; ws_suspended_at: number | null }>();
  if (!row) return notFound(env);
  // Taken down by the Brod team, or in a suspended workspace: nothing of the app is served, its /_brod/ pages included.
  if (row.taken_down_at || row.ws_suspended_at) return takenDownPage();
  const origin = domain ? hostOrigin(env, domain) : staging ? stagingUrl(env, row.wslug, row.slug) : appUrl(env, row.wslug, row.slug);
  // On the staging address the staging version is the one served, and staging is never public or shared by password.
  const app: HostedApp & { server: string | null } = staging
    ? { ...row, domain, origin, staging, live_version: row.staging_version ?? null, access: ['public', 'password', 'signed_in'].includes(row.access) ? 'people' : row.access }
    : { ...row, domain, origin, staging };
  const user = await sessionUser(env, cookie(request, app.origin, APP_COOKIE), app.id);
  if (url.pathname.startsWith('/_brod/')) return special(env, request, url, app, user);

  const server: ServerInfo | null = app.server ? JSON.parse(app.server) : null;
  if (!server && request.method !== 'GET' && request.method !== 'HEAD') return notice(405, 'Not supported', 'This app is a static site and only answers page requests.');
  if (app.live_version === null && !staging) return notFound(env);

  const d = await access(env, request, app, user);
  if (!d.allowed) {
    if (d.passwordNeeded) return passwordPage(app, url.pathname + url.search);
    if (d.signInNeeded) return redirect(signInUrl(env, app, url.pathname + url.search));
    // Someone signed in whom the app was not shared with sees what an empty address shows, so nothing leaks about it.
    await event(env, app.workspace_id, user!.user.email, app.id, 'refused', `${user!.user.email} opened ${url.pathname}`).run();
    return notFound(env);
  }
  if (app.status === 'paused') return notice(503, 'Paused', 'The owner has paused this app.');
  // Only reached on a staging address, by someone allowed to see it.
  if (app.live_version === null) return notice(404, 'Nothing on staging', 'Nothing is waiting on staging for this app: it was published or discarded. Deploy a new version to staging to try it here.');

  let path: string;
  try { path = decodeURIComponent(url.pathname).replace(/^\/+/, ''); } catch { return notice(400, 'Bad address', 'That address is not valid.'); }
  if (path.split('/').includes('..')) return notice(400, 'Bad address', 'That address is not valid.');
  const base = `${app.id}/${app.live_version}/`;

  if (server) {
    // A file that exists in the bundle is served as is; every other request goes to the server code.
    if ((request.method === 'GET' || request.method === 'HEAD') && path && !path.endsWith('/') && !isServerPath(path)) {
      const obj = await env.BUNDLES.get(base + path);
      if (obj) return fileResponse(request, app, obj, path);
    }
    return dispatch(env, ctx, request, app, server, user, d);
  }

  const hasExt = /\.[a-z0-9]+$/i.test(path);
  // Exact file, then folder index, then the single-page-app fallback to the root index.html.
  const candidates = path === '' || path.endsWith('/') ? [`${path}index.html`] : hasExt ? [path] : [path, `${path}/index.html`, `${path}.html`, 'index.html'];
  let obj: R2ObjectBody | null = null, hit = '';
  for (const c of candidates) { obj = await env.BUNDLES.get(base + c); if (obj) { hit = c; break; } }
  if (!obj) {
    const custom = await env.BUNDLES.get(base + '404.html');
    return custom ? new Response(custom.body, { status: 404, headers: { 'content-type': 'text/html; charset=utf-8' } }) : notice(404, 'Not found', 'This app has no page at that address.');
  }
  return fileResponse(request, app, obj, hit);
}

function fileResponse(request: Request, app: AppRow, obj: R2ObjectBody, hit: string): Response | Promise<Response> {
  const html = hit.endsWith('.html');
  const isPublic = app.access === 'public';
  const headers = new Headers({
    'content-type': obj.httpMetadata?.contentType ?? 'application/octet-stream',
    etag: obj.httpEtag,
    // Always revalidate, so a rollback, a new version or an access change shows on the next request.
    'cache-control': isPublic ? 'public, no-cache' : 'private, no-cache',
    'x-content-type-options': 'nosniff',
    'x-brod-app': app.slug,
    'x-brod-version': String(app.live_version),
  });
  if (!isPublic) headers.set('vary', 'cookie');
  if (html && !isPublic) headers.set('x-robots-tag', 'noindex');
  if (request.headers.get('if-none-match') === obj.httpEtag) return new Response(null, { status: 304, headers });
  if (request.method === 'HEAD') {
    // A public page grows by its report link, so its stored size is not the length GET sends.
    if (!(html && isPublic)) headers.set('content-length', String(obj.size));
    return new Response(null, { headers });
  }
  if (html && isPublic) return withReportLink(new Response(obj.body, { headers }));
  headers.set('content-length', String(obj.size));
  return new Response(obj.body, { headers });
}

/**
 * Hand a request to the app's server code. The app gets the request as the visitor sent it, minus the platform's
 * session cookie and any X-Brod-* headers the visitor tried to set, plus the signed-in person as X-Brod-* headers.
 */
async function dispatch(env: Env, ctx: ExecutionContext, request: Request, app: AppRow, server: ServerInfo, user: Visitor, d: Decision): Promise<Response> {
  const headers = new Headers(request.headers);
  for (const k of [...headers.keys()]) if (k.startsWith('x-brod-')) headers.delete(k);
  const cookies = (headers.get('cookie') ?? '').split(/;\s*/).filter(c => c && !c.startsWith(`${APP_COOKIE}=`) && !c.startsWith(`__Host-${APP_COOKIE}=`)).join('; ');
  if (cookies) headers.set('cookie', cookies); else headers.delete('cookie');
  if (user) {
    const { identity, token } = await identityFor(env, app, user.user, d.role, d.groups);
    headers.set('x-brod-user-id', identity.user.id);
    headers.set('x-brod-user-email', identity.user.email);
    headers.set('x-brod-user-name', encodeURIComponent(identity.user.name));
    headers.set('x-brod-role', identity.role ?? '');
    headers.set('x-brod-groups', identity.groups.join(','));
    headers.set('x-brod-identity', token);
  }
  let res: Response;
  try {
    res = await serverFor(env, ctx, app, app.live_version!, server, app.secrets_rev ?? 0).fetch(new Request(request, { headers, redirect: 'manual' }));
  } catch (e) {
    console.error('server app failed', app.slug, e);
    return notice(502, 'This app failed', 'The app\'s server code failed on this request. Its owner can see the error in the app\'s logs.');
  }
  const out = new Response(res.body, res);
  out.headers.set('x-brod-app', app.slug);
  out.headers.set('x-brod-version', String(app.live_version));
  if (app.access !== 'public') {
    // A private app's answers are for one person: never let a shared cache keep them.
    const cc = out.headers.get('cache-control') ?? '';
    if (!/\b(private|no-store)\b/.test(cc)) out.headers.set('cache-control', 'private, no-cache');
    out.headers.append('vary', 'cookie');
  }
  if (app.access === 'public' && (out.headers.get('content-type') ?? '').startsWith('text/html')) return withReportLink(out);
  return out;
}
