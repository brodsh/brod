// Pages and sign-in on the API host: magic links, Google, the hand-off of a sign-in to an app's own address,
// invitations, confirmations of agent requests, and the workspace home page.
//
// One sign-in, many addresses: the platform session cookie lives only on the API host. When an app needs a person,
// the gateway sends them to /auth/app, which hands the app a one-time code; the app's host swaps it for its own
// session cookie. Apps never see the platform cookie, and signing out ends every app session made from it.
import { ABUSE, clientIp, perHour, rateLimit } from './abuse';
import { PLATFORM_COOKIE, confirm, getConfirmation, person } from './control';
import { devMode, sendEmail } from './email';
import { allowedHost } from './domains';
import { HOME_ETAG, HOME_HTML, OG_PNG_BASE64, OG_PNG_ETAG } from './home';
import { AppRow, Env, LIMITS, Problem, STAGING_SUFFIX, Workspace, appUrl, esc, hostOrigin, isEmail, json, normEmail, notFound, notice, now, page, randomId, redirect, setCookie, sha256, stagingUrl } from './lib';
import { acceptInvite, createSession, createWorkspace, decide, membership, myWorkspaces, revokeSession, verifiedUser } from './people';

const safeReturn = (r: unknown) => (typeof r === 'string' && r.startsWith('/') && !r.startsWith('//') && !r.startsWith('/\\') ? r : '/');
const wantsJson = (request: Request) => (request.headers.get('content-type') ?? '').includes('application/json');

async function input(request: Request): Promise<Record<string, string>> {
  if (wantsJson(request)) {
    try { const b = await request.json(); return b && typeof b === 'object' ? (b as Record<string, string>) : {}; }
    catch { throw new Problem(400, 'bad_json', 'The request body must be JSON.'); }
  }
  const f = await request.formData();
  return Object.fromEntries([...f.entries()].map(([k, v]) => [k, String(v)]));
}

/** Forms on these pages post back to the API host only. A missing or foreign Origin is refused. */
function sameOrigin(env: Env, request: Request) {
  if (request.headers.get('origin') !== env.API_ORIGIN) throw new Problem(403, 'bad_origin', 'This form must be sent from Brod itself.');
}

const signedIn = async (env: Env, token: string) =>
  setCookie(env.API_ORIGIN, PLATFORM_COOKIE, token, LIMITS.sessionTtlMs / 1000);

/**
 * Find an app from an "app" parameter, written <app>.<workspace> like the first labels of its address, or
 * <app>--staging.<workspace> for its staging address, so the sign-in is handed back there.
 */
async function appByRef(env: Env, ref: string | null) {
  const m = /^([a-z0-9-]+)\.([a-z0-9-]+)$/.exec(ref ?? '');
  if (!m) return null;
  const staging = m[1].endsWith(STAGING_SUFFIX) && m[1].length > STAGING_SUFFIX.length;
  const app = await env.DB.prepare('SELECT a.*, w.slug AS wslug, w.name AS wname, w.color, w.icon FROM apps a JOIN workspaces w ON w.id = a.workspace_id WHERE a.slug = ? AND w.slug = ?')
    .bind(staging ? m[1].slice(0, -STAGING_SUFFIX.length) : m[1], m[2]).first<AppRow & { wslug: string; wname: string; color: string; icon: string }>();
  return app && {
    ...app, ref: `${app.slug}${staging ? STAGING_SUFFIX : ''}.${app.wslug}`,
    url: staging ? stagingUrl(env, app.wslug, app.slug) : appUrl(env, app.wslug, app.slug),
  };
}

// ---------- pages ----------

async function signInPage(env: Env, url: URL, sent?: { email: string; link?: string }) {
  const ret = safeReturn(url.searchParams.get('return'));
  const app = await appByRef(env, url.searchParams.get('app'));
  const brand = app ? `${app.icon ? `<div class="icon">${esc(app.icon)}</div>` : ''}<p class="muted">${esc(app.wname)}</p>` : '';
  const heading = app ? `Sign in to ${esc(app.title || app.name)}` : 'Sign in to Brod';
  const welcome = app?.welcome ? `<p>${esc(app.welcome)}</p>` : '<p>We email you a link. No password needed.</p>';
  const report = app ? `<p><small><a href="${app.url}/_brod/report">Report this app</a></small></p>` : '';
  if (sent) {
    return page(200, 'Check your email', `${brand}<h1>Check your email</h1><p>We sent a sign-in link to <b>${esc(sent.email)}</b>. It works once and expires in 15 minutes.</p>` +
      (sent.link ? `<p><small>Dev mode: <a href="${esc(sent.link)}">open the link</a></small></p>` : '') + report, { color: app?.color });
  }
  const google = env.GOOGLE_CLIENT_ID ? `<p><a class="btn secondary block" href="/auth/google?return=${encodeURIComponent(ret)}">Continue with Google</a></p><div class="or">or</div>` : '';
  const newcomer = app ? '' : '<p class="muted">New to Brod? <a href="/auth/signup">Create a workspace</a></p>';
  return page(200, 'Sign in', `${brand}<h1>${heading}</h1>${welcome}${google}
<form method="post" action="/auth/start"><input type="hidden" name="return" value="${esc(ret)}"><input type="hidden" name="app" value="${esc(app?.ref ?? '')}">
<input type="email" name="email" required autocomplete="email" placeholder="you@example.com" aria-label="Email address"><button class="block">Email me a link</button></form>${report}${newcomer}`, { color: app?.color });
}

// Where "Start free" on the landing page leads: the same email form, written for someone who has no account yet.
// After the link, / sends a person with no workspace on to /new.
function signUpPage(env: Env) {
  const google = env.GOOGLE_CLIENT_ID ? `<p><a class="btn secondary block" href="/auth/google?return=%2F">Continue with Google</a></p><div class="or">or</div>` : '';
  return page(200, 'Create your workspace', `<h1>Create your workspace</h1><p>Free to start. No password and no card.</p>
<ol><li>We email you a sign-in link.</li><li>You name your workspace: one sign-in and one home page for your team's apps.</li><li>You connect your agent and ask it to put something online.</li></ol>${google}
<form method="post" action="/auth/start"><input type="hidden" name="return" value="/"><input type="hidden" name="app" value="">
<input type="email" name="email" required autocomplete="email" placeholder="you@example.com" aria-label="Email address"><button class="block">Email me a link</button></form>
<p class="muted">Already use Brod? <a href="/auth/signin">Sign in</a></p>`);
}

async function homePage(env: Env, request: Request, slug: string) {
  const p = await person(env, request);
  if (!p) return redirect(`/auth/signin?return=${encodeURIComponent(`/w/${slug}`)}`);
  const mem = await membership(env, p.user, slug);
  if (!mem) return notice(404, 'Not your workspace', 'You are not in this workspace. Ask an admin to invite you.');
  const w: Workspace = mem.workspace;
  const apps = await env.DB.prepare("SELECT * FROM apps WHERE workspace_id = ? AND status = 'live' AND live_version IS NOT NULL ORDER BY name").bind(w.id).all<AppRow>();
  const mine = (await Promise.all(apps.results.map(async a => ((await decide(env, a, p.user)).allowed ? a : null)))).filter((a): a is AppRow => !!a);
  const others = (await myWorkspaces(env, p.user)).filter(x => x.slug !== w.slug);
  const builds = mem.role === 'admin' || mem.role === 'builder';
  const list = mine.length
    ? `<input type="search" id="q" placeholder="Search apps" aria-label="Search apps"><ul id="apps">${mine.map(a =>
      `<li data-name="${esc((a.title || a.name).toLowerCase())}"><a href="${appUrl(env, w.slug, a.slug)}/">${esc(a.title || a.name)}</a>${a.welcome ? `<br><small>${esc(a.welcome)}</small>` : ''}</li>`).join('')}</ul>
<script>q.oninput=()=>{for(const li of apps.children)li.hidden=!li.dataset.name.includes(q.value.toLowerCase())}</script>`
    : `<p>No apps here yet that you can open.${builds ? '' : ' Builders deploy them with their agent.'}</p>`;
  return page(200, w.name, `${w.icon ? `<div class="icon">${esc(w.icon)}</div>` : ''}<h1>${esc(w.name)}</h1>
<p class="muted">Signed in as ${esc(p.user.email)} · ${esc(mem.role)}</p>${list}
${builds ? `<div class="actions"><a class="btn secondary" href="/w/${esc(w.slug)}/connections">Connect an agent</a></div>` : ''}
${others.length ? `<p class="muted">Other workspaces: ${others.map(o => `<a href="/w/${esc(o.slug)}">${esc(o.name)}</a>`).join(', ')}</p>` : ''}
<form method="post" action="/auth/signout"><button class="secondary small">Sign out</button></form>`, { color: w.color });
}

function newWorkspacePage(error = '') {
  return page(error ? 400 : 200, 'Create a workspace', `<h1>Create a workspace</h1><p>One workspace for your team or company: one sign-in, one set of groups, one home page for every app.</p>
${error ? `<p role="alert"><b>${esc(error)}</b></p>` : ''}<form method="post" action="/new"><input name="name" required maxlength="60" placeholder="Workspace name, for example Acme" aria-label="Workspace name">
<p><label><input type="checkbox" name="accept_terms" value="1" required> I accept the <a href="/terms">terms of use and acceptable-use policy</a>.</label></p><button class=\"block\">Create workspace</button></form>`);
}

const TERMS = `<h1>Terms of use (draft)</h1><p>This is a working draft for the private beta and will be replaced by reviewed terms before public launch.</p>
<p>You may host apps for yourself, your team and people you invite. You may not host phishing, malware, spam, sign-in pages that imitate another brand,
content that is illegal where you or your visitors are, or anything that attacks other systems. We may take an app down and tell you why; you can appeal.</p>
<p>You own your apps and their data. For people who sign in to your apps, you are the controller and Brod is your processor. You can export or delete
your data at any time.</p>`;

// The public landing page. / answers signed-in people with a redirect, so the page may be cached only with
// revalidation and "Vary: Cookie": someone who has just signed in is never shown a stored copy of it.
function landingPage(request: Request): Response {
  const headers: Record<string, string> = { 'cache-control': 'public, no-cache', vary: 'Cookie', etag: HOME_ETAG, 'x-frame-options': 'DENY' };
  const tags = (request.headers.get('if-none-match') ?? '').split(',').map(t => t.trim());
  if (tags.includes(HOME_ETAG)) return new Response(null, { status: 304, headers });
  return new Response(HOME_HTML, { headers: { 'content-type': 'text/html; charset=utf-8', ...headers } });
}

// The link preview picture (og:image), and what search engines read first. All three name the request's own origin
// where they need one, so a self-hosted Brod points at itself.
let ogPng: Uint8Array | undefined;
function ogImage(request: Request): Response {
  const headers: Record<string, string> = { 'cache-control': 'public, max-age=86400', etag: OG_PNG_ETAG };
  const tags = (request.headers.get('if-none-match') ?? '').split(',').map(t => t.trim());
  if (tags.includes(OG_PNG_ETAG)) return new Response(null, { status: 304, headers });
  ogPng ??= Uint8Array.from(atob(OG_PNG_BASE64), c => c.charCodeAt(0));
  return new Response(ogPng, { headers: { 'content-type': 'image/png', ...headers } });
}

const robots = (origin: string) => `User-agent: *
Disallow: /auth/
Disallow: /w/
Disallow: /v1/
Disallow: /oauth/
Disallow: /mcp
Disallow: /new

Sitemap: ${origin}/sitemap.xml
`;

const sitemap = (origin: string) => `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>${origin}/</loc></url>
</urlset>
`;

// ---------- routes ----------

export async function serveAuth(env: Env, request: Request, url: URL): Promise<Response | null> {
  const p = url.pathname.replace(/\/+$/, '') || '/', m = request.method;

  if (p === '/' && m === 'GET') {
    const who = await person(env, request);
    if (!who) {
      // Links made as /?return=... or /?app=... still reach the sign-in form; everyone else gets the landing page.
      if (url.searchParams.has('return') || url.searchParams.has('app')) return signInPage(env, url);
      return landingPage(request);
    }
    const ws = await myWorkspaces(env, who.user);
    return redirect(ws.length ? `/w/${ws[0].slug}` : '/new');
  }
  if (p === '/signin' && m === 'GET') return redirect(`/auth/signin${url.search}`);
  if (p === '/terms') return page(200, 'Terms of use', TERMS);
  if (p === '/auth/signin' && m === 'GET') return signInPage(env, url);
  if (p === '/auth/signup' && m === 'GET') return (await person(env, request)) ? redirect('/') : signUpPage(env);
  if (p === '/og.png' && m === 'GET') return ogImage(request);
  if (p === '/robots.txt' && m === 'GET') return new Response(robots(url.origin), { headers: { 'content-type': 'text/plain; charset=utf-8', 'cache-control': 'public, max-age=3600' } });
  if (p === '/sitemap.xml' && m === 'GET') return new Response(sitemap(url.origin), { headers: { 'content-type': 'application/xml; charset=utf-8', 'cache-control': 'public, max-age=3600' } });

  if (p === '/auth/start' && m === 'POST') {
    if (!wantsJson(request)) sameOrigin(env, request);
    const b = await input(request);
    const email = normEmail(b.email);
    if (!isEmail(email)) throw new Problem(400, 'bad_email', 'That does not look like an email address.');
    const ip = clientIp(env, request);
    if (ip) await rateLimit(env, 'signin_ip', ip, ABUSE.signInLinksPerIpHour, perHour, 'Too many sign-in links were asked for from your network in the last hour.');
    const recent = await env.DB.prepare('SELECT COUNT(*) AS n FROM login_links WHERE email = ? AND created_at > ?').bind(email, now() - 3600e3).first<{ n: number }>();
    if ((recent?.n ?? 0) >= LIMITS.loginLinksPerHour) throw new Problem(429, 'rate_limited', 'Too many sign-in links for this address. Wait a little and try again.');
    const token = randomId('', 24);
    await env.DB.prepare('INSERT INTO login_links (hash, email, return_to, created_at, expires_at) VALUES (?,?,?,?,?)')
      .bind(await sha256(token), email, safeReturn(b.return), now(), now() + LIMITS.loginLinkTtlMs).run();
    const link = `${env.API_ORIGIN}/auth/verify?token=${token}`;
    await sendEmail(env, email, 'Your Brod sign-in link',
      `Open this link to sign in. It works once and expires in 15 minutes:\n${link}\n\nIf you did not ask for it, ignore this email.`);
    const dev = devMode(env) ? link : undefined;
    if (wantsJson(request)) return json({ sent: true, email, ...(dev ? { dev_link: dev } : {}) });
    const back = new URL(url); back.search = b.app ? `?app=${encodeURIComponent(b.app)}` : '';
    return signInPage(env, back, { email, link: dev });
  }

  // GET only shows a button, so a mail scanner that opens the link does not use it up.
  if (p === '/auth/verify' && m === 'GET') {
    const token = url.searchParams.get('token') ?? '';
    return page(200, 'Sign in', `<h1>Sign in</h1><p>Continue to finish signing in.</p><form method="post" action="/auth/verify"><input type="hidden" name="token" value="${esc(token)}"><button>Continue</button></form>`);
  }
  if (p === '/auth/verify' && m === 'POST') {
    sameOrigin(env, request);
    const b = await input(request);
    const hash = await sha256(String(b.token ?? ''));
    const link = await env.DB.prepare('SELECT email, return_to, expires_at, used_at FROM login_links WHERE hash = ?').bind(hash)
      .first<{ email: string; return_to: string; expires_at: number; used_at: number | null }>();
    if (!link || link.used_at || link.expires_at < now() || !link.email) return notice(410, 'Link expired', 'This sign-in link has expired or was already used. Ask for a new one.', '<p><a class="btn" href="/auth/signin">Sign in</a></p>');
    const claimed = await env.DB.prepare('UPDATE login_links SET used_at = ? WHERE hash = ? AND used_at IS NULL').bind(now(), hash).run();
    if (!claimed.meta.changes) return notice(410, 'Link expired', 'This sign-in link was already used.');
    const user = await verifiedUser(env, link.email);
    return redirect(link.return_to, { 'set-cookie': await signedIn(env, await createSession(env, user.id)) });
  }

  if (p === '/auth/google' && m === 'GET') {
    if (!env.GOOGLE_CLIENT_ID) return notice(404, 'Not available', 'Google sign-in is not set up on this server.');
    const state = randomId('', 16);
    await env.DB.prepare("INSERT INTO login_links (hash, email, return_to, created_at, expires_at) VALUES (?, '', ?, ?, ?)")
      .bind(await sha256(`g:${state}`), safeReturn(url.searchParams.get('return')), now(), now() + LIMITS.loginLinkTtlMs).run();
    const q = new URLSearchParams({ client_id: env.GOOGLE_CLIENT_ID, redirect_uri: `${env.API_ORIGIN}/auth/google/callback`, response_type: 'code', scope: 'openid email profile', state, prompt: 'select_account' });
    return redirect(`https://accounts.google.com/o/oauth2/v2/auth?${q}`);
  }
  if (p === '/auth/google/callback' && m === 'GET') {
    if (!env.GOOGLE_CLIENT_ID || !env.GOOGLE_CLIENT_SECRET) return notice(404, 'Not available', 'Google sign-in is not set up on this server.');
    const hash = await sha256(`g:${url.searchParams.get('state') ?? ''}`);
    const st = await env.DB.prepare("UPDATE login_links SET used_at = ? WHERE hash = ? AND email = '' AND used_at IS NULL AND expires_at > ? RETURNING return_to")
      .bind(now(), hash, now()).first<{ return_to: string }>();
    if (!st) return notice(400, 'Sign-in expired', 'That Google sign-in took too long or was already used. Try again.', '<p><a class="btn" href="/auth/signin">Sign in</a></p>');
    const r = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ code: url.searchParams.get('code') ?? '', client_id: env.GOOGLE_CLIENT_ID, client_secret: env.GOOGLE_CLIENT_SECRET, redirect_uri: `${env.API_ORIGIN}/auth/google/callback`, grant_type: 'authorization_code' }),
    });
    const t = (await r.json().catch(() => ({}))) as { id_token?: string };
    // The ID token came straight from Google's token endpoint over TLS, so its claims are checked but its signature need not be.
    let claims: { aud?: string; iss?: string; email?: string; email_verified?: boolean; name?: string } = {};
    try { claims = JSON.parse(atob((t.id_token ?? '').split('.')[1].replace(/-/g, '+').replace(/_/g, '/'))); } catch { /* handled below */ }
    if (!r.ok || claims.aud !== env.GOOGLE_CLIENT_ID || !['accounts.google.com', 'https://accounts.google.com'].includes(claims.iss ?? '') || !claims.email || claims.email_verified !== true)
      return notice(401, 'Sign-in failed', 'Google did not confirm a verified email address. Try again, or use an emailed link.');
    const user = await verifiedUser(env, claims.email, claims.name ?? '');
    return redirect(st.return_to, { 'set-cookie': await signedIn(env, await createSession(env, user.id)) });
  }

  // Hand a sign-in to an app's own host with a one-time code.
  if (p === '/auth/app' && m === 'GET') {
    const app = await appByRef(env, url.searchParams.get('app'));
    if (!app) return notFound(env);
    const ret = safeReturn(url.searchParams.get('return'));
    // A custom domain gets the code only when it is a proven address of this very app; anything else would leak it.
    const host = url.searchParams.get('host');
    if (host && !(await allowedHost(env, app, host))) return notice(400, 'Unknown address', 'That address is not a domain of this app.');
    const target = host ? hostOrigin(env, host.toLowerCase()) : app.url;
    const hostParam = host ? `&host=${encodeURIComponent(host)}` : '';
    const s = await person(env, request);
    if (!s) return redirect(`/auth/signin?app=${app.ref}&return=${encodeURIComponent(`/auth/app?app=${app.ref}${hostParam}&return=${encodeURIComponent(ret)}`)}`);
    const code = randomId('', 24);
    await env.DB.prepare('INSERT INTO app_codes (hash, app_id, user_id, parent, expires_at) VALUES (?,?,?,?,?)')
      .bind(await sha256(code), app.id, s.user.id, s.hash, now() + LIMITS.appCodeTtlMs).run();
    return redirect(`${target}/_brod/callback?code=${code}&return=${encodeURIComponent(ret)}`);
  }

  if (p === '/auth/signout' && m === 'POST') {
    sameOrigin(env, request);
    const s = await person(env, request);
    if (s) await revokeSession(env, s.hash);
    return redirect('/auth/signin', { 'set-cookie': setCookie(env.API_ORIGIN, PLATFORM_COOKIE, '', 0) });
  }

  if (p === '/auth/invite' && m === 'GET') {
    const token = url.searchParams.get('token') ?? '';
    const inv = await env.DB.prepare('SELECT i.email, i.role, w.name, a.name AS aname FROM invites i JOIN workspaces w ON w.id = i.workspace_id LEFT JOIN apps a ON a.id = i.app_id WHERE i.hash = ? AND i.used_at IS NULL AND i.revoked_at IS NULL AND i.expires_at > ?')
      .bind(await sha256(token), now()).first<{ email: string; role: string; name: string; aname: string | null }>();
    if (!inv) return notice(410, 'Invitation expired', 'This invitation has expired, was already used, or was withdrawn. Ask for a new one.');
    return page(200, 'Accept invitation', `<h1>Join ${esc(inv.aname ?? inv.name)}</h1><p>You were invited as <b>${esc(inv.email)}</b>${inv.aname ? ` to the app ${esc(inv.aname)} in ${esc(inv.name)}` : ` as a ${esc(inv.role)}`}.</p>
<form method="post" action="/auth/invite"><input type="hidden" name="token" value="${esc(token)}"><button class=\"block\">Accept and sign in</button></form>`);
  }
  if (p === '/auth/invite' && m === 'POST') {
    sameOrigin(env, request);
    const { user, appRef, workspaceSlug } = await acceptInvite(env, String((await input(request)).token ?? ''));
    const to = appRef ? `/auth/app?app=${appRef}&return=%2F` : `/w/${workspaceSlug}`;
    return redirect(to, { 'set-cookie': await signedIn(env, await createSession(env, user.id)) });
  }

  if (p === '/new' && m === 'GET') return (await person(env, request)) ? newWorkspacePage() : redirect('/auth/signin?return=%2Fnew');
  if (p === '/new' && m === 'POST') {
    sameOrigin(env, request);
    const s = await person(env, request);
    if (!s) return redirect('/auth/signin?return=%2Fnew');
    const b = await input(request);
    try { return redirect(`/w/${(await createWorkspace(env, s.user, b.name, b.accept_terms === '1')).workspace}`); }
    catch (e) { if (e instanceof Problem) return newWorkspacePage(e.message); throw e; }
  }

  const home = /^\/w\/([a-z0-9-]+)$/.exec(p);
  if (home && m === 'GET') return homePage(env, request, home[1]);

  const cf = /^\/confirm\/(cf_[0-9a-f]+)$/.exec(p);
  if (cf) {
    const s = await person(env, request);
    if (!s) return redirect(`/auth/signin?return=${encodeURIComponent(p)}`);
    const row = await getConfirmation(env, cf[1]);
    if (!row || row.done_at || row.expires_at < now()) return notice(410, 'Already handled', 'This request has expired or was already confirmed or declined.');
    if (m === 'GET') {
      return page(200, 'Confirm a change', `<h1>Confirm a change</h1><p>Your agent connection <b>${esc(row.requested_by)}</b> asked to:</p><p><b>${esc(row.summary)}</b></p>
<form method="post"><button name="decision" value="confirm">Confirm</button> <button name="decision" value="decline" class="secondary">Decline</button></form>`);
    }
    if (m === 'POST') {
      sameOrigin(env, request);
      if ((await input(request)).decision !== 'confirm') {
        await env.DB.prepare("UPDATE confirmations SET done_at = ?, done_by = ? WHERE id = ? AND done_at IS NULL").bind(now(), `declined by ${s.user.email}`, row.id).run();
        return notice(200, 'Declined', 'Nothing was changed.');
      }
      try { await confirm(env, s.user, row.id); }
      catch (e) { if (e instanceof Problem) return notice(e.status, 'Could not do that', e.message); throw e; }
      return notice(200, 'Done', `${row.summary}: done.`);
    }
  }
  return null;
}
