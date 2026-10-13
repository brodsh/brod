// The control plane. The REST API, the MCP endpoint and the confirmation pages call only these functions.
import {
  ACCESS, Access, AppRow, BundleFile, Caller, Env, EventRow, LIMITS, Problem, Role, User, VersionRow, Workspace,
  appUrl, checkPassword, contentType, cookie, hashPassword, now, plan, randomId, sha256, slugify, stagingUrl,
} from './lib';
import { COMPAT_DATE, ServerInfo, findServer, moduleFor, wipeAppData } from './runtime';
import { checkSecretName, deleteSecret, listSecrets, putSecret } from './secrets';
import {
  GrantInput, InviteInput, checkInvite, event, invite, listGrants, membership, requireRole, resolveSubject, sessionUser, whoCanOpen,
} from './people';
import { appDomains } from './domains';
import { directUpload } from './platform/uploads';
import {
  CHECKER, abuseState, checkCanOpenOutside, checkNotFlagged, checkUp, checkWorkspaceUp, flagOf, narrowIfFlagged,
} from './abuse';
import { scanBundle } from './scan';
import { pack } from './tar';

// ---------- who is calling ----------

export const PLATFORM_COOKIE = 'brod_platform';

/** The signed-in person behind a dashboard request, from the platform session cookie. */
export async function person(env: Env, request: Request): Promise<{ user: User; hash: string } | null> {
  const s = await sessionUser(env, cookie(request, env.API_ORIGIN, PLATFORM_COOKIE), null);
  return s ? { user: s.user, hash: s.hash } : null;
}

/** A cookie-signed-in browser may only change things from the platform's own pages. */
export function checkOrigin(env: Env, request: Request) {
  if (request.method === 'GET' || request.method === 'HEAD') return;
  const origin = request.headers.get('origin');
  if (origin !== env.API_ORIGIN) throw new Problem(403, 'bad_origin', 'Changes made with a sign-in cookie must come from the Brod dashboard.');
}

/**
 * Authenticate an API or MCP request. An agent sends its connection token; a person's browser sends the
 * platform session cookie and names the workspace with the X-Brod-Workspace header or ?workspace=.
 */
export async function authenticate(env: Env, request: Request): Promise<Caller> {
  const m = /^Bearer\s+(\S+)$/i.exec(request.headers.get('authorization') ?? '');
  if (m) {
    const row = await env.DB.prepare(
      `SELECT t.id AS tid, t.name AS tname, u.id AS uid, u.email, u.name AS uname, u.email_verified_at, mb.role, w.*
       FROM tokens t JOIN workspaces w ON w.id = t.workspace_id JOIN users u ON u.id = t.user_id
       LEFT JOIN members mb ON mb.workspace_id = t.workspace_id AND mb.user_id = t.user_id
       WHERE t.hash = ? AND t.revoked_at IS NULL`,
    ).bind(await sha256(m[1])).first<Workspace & { tid: string; tname: string; uid: string; email: string; uname: string; email_verified_at: number | null; role: Role | null }>();
    if (!row) throw new Problem(401, 'unauthorized', 'That token is not valid or has been revoked.');
    if (!row.role || row.role === 'guest') throw new Problem(401, 'unauthorized', 'The person who made this connection is no longer a builder in the workspace.');
    await env.DB.prepare('UPDATE tokens SET last_used_at = ? WHERE id = ?').bind(now(), row.tid).run();
    return {
      workspace: { id: row.id, slug: row.slug, name: row.name, plan: row.plan, color: row.color, icon: row.icon, created_at: row.created_at },
      user: { id: row.uid, email: row.email, name: row.uname, email_verified_at: row.email_verified_at },
      role: row.role, actor: row.tname, agent: true,
    };
  }
  const p = await person(env, request);
  if (!p) throw new Problem(401, 'unauthorized', 'Sign in, or send an agent token as "Authorization: Bearer <token>".');
  checkOrigin(env, request);
  const ws = request.headers.get('x-brod-workspace') ?? new URL(request.url).searchParams.get('workspace') ?? undefined;
  const mem = await membership(env, p.user, ws);
  if (!mem) throw ws ? new Problem(404, 'no_workspace', `You are not in a workspace called "${ws}".`)
    : new Problem(409, 'no_workspace', 'You are not in any workspace yet. Create one with POST /v1/workspaces.');
  return { workspace: mem.workspace, user: p.user, role: mem.role, actor: p.user.email, agent: false };
}

// ---------- agent connections ----------

/** A token is one named, revocable connection, for example one agent. It is shown once and stored only as a hash. */
export async function createToken(env: Env, c: Caller, name: string): Promise<{ id: string; name: string; token: string }> {
  if (c.agent) throw new Problem(403, 'forbidden', 'An agent cannot create connections. Ask the person to do it from the dashboard.');
  requireRole(c, 'builder', 'connect an agent');
  const clean = name.trim().slice(0, 40) || 'agent';
  const token = randomId('brod_', 24), id = randomId('tok_', 8);
  await env.DB.batch([
    env.DB.prepare('INSERT INTO tokens (id, workspace_id, user_id, name, hash, created_at) VALUES (?,?,?,?,?,?)').bind(id, c.workspace.id, c.user.id, clean, await sha256(token), now()),
    event(env, c.workspace.id, c.actor, null, 'token_created', `connection "${clean}"`),
  ]);
  return { id, name: clean, token };
}
export async function listTokens(env: Env, c: Caller) {
  requireRole(c, 'builder', 'see agent connections');
  const r = await env.DB.prepare(
    'SELECT t.id, t.name, u.email AS made_by, t.created_at, t.last_used_at, t.revoked_at FROM tokens t JOIN users u ON u.id = t.user_id WHERE t.workspace_id = ? ORDER BY t.created_at',
  ).bind(c.workspace.id).all();
  return r.results;
}
export async function revokeToken(env: Env, c: Caller, id: string) {
  requireRole(c, 'builder', 'revoke agent connections');
  // Builders revoke their own connections; admins revoke any.
  const r = await env.DB.prepare('UPDATE tokens SET revoked_at = ? WHERE id = ? AND workspace_id = ? AND revoked_at IS NULL AND (? OR user_id = ?)')
    .bind(now(), id, c.workspace.id, c.role === 'admin' ? 1 : 0, c.user.id).run();
  if (!r.meta.changes) throw new Problem(404, 'not_found', 'No active connection of yours with that id.');
  await event(env, c.workspace.id, c.actor, null, 'token_revoked', id).run();
}

// ---------- reading ----------

export async function getApp(env: Env, c: Caller, slug: string): Promise<AppRow> {
  const app = await env.DB.prepare('SELECT * FROM apps WHERE slug = ? AND workspace_id = ?').bind(String(slug).trim().toLowerCase(), c.workspace.id).first<AppRow>();
  if (!app) throw new Problem(404, 'not_found', `There is no app called "${slug}" in this workspace. Use list_apps to see them.`);
  return app;
}
type Grants = Awaited<ReturnType<typeof listGrants>>;
export function describe(env: Env, c: Caller, app: AppRow, grants: Grants) {
  return {
    app: app.slug, name: app.name, url: appUrl(env, c.workspace.slug, app.slug), status: app.status, access: app.access,
    who_can_open: whoCanOpen(app, grants, c.workspace.name), live_version: app.live_version,
    // The version waiting on staging and where to try it, or null when nothing is waiting.
    staging: app.staging_version != null ? { version: app.staging_version, url: stagingUrl(env, c.workspace.slug, app.slug) } : null,
    // What the next update builds on: pass it as base_version so a deploy never undoes someone else's.
    current_version: currentVersion(app),
    roles: JSON.parse(app.roles) as string[], shared_with: grants,
    ...(app.title ? { title: app.title } : {}), ...(app.welcome ? { welcome: app.welcome } : {}),
  };
}
/** The app as describe() shows it, plus whether the Brod team took it down or the phishing check flagged it. */
async function described(env: Env, c: Caller, app: AppRow) { return { ...describe(env, c, app, await listGrants(env, app)), ...(await abuseState(env, app)) }; }

export async function listApps(env: Env, c: Caller) {
  const r = await env.DB.prepare('SELECT * FROM apps WHERE workspace_id = ? ORDER BY created_at DESC').bind(c.workspace.id).all<AppRow>();
  const running = r.results.filter(a => a.status === 'live').length;
  const apps = await Promise.all(r.results.map(a => described(env, c, a)));
  return { workspace: c.workspace.slug, plan: c.workspace.plan, running_apps: running, app_limit: plan(c.workspace).apps, apps };
}
export async function getStatus(env: Env, c: Caller, slug: string) {
  requireRole(c, 'builder', 'see app versions');
  const app = await getApp(env, c, slug);
  const v = await env.DB.prepare('SELECT n, note, actor, file_count, bytes, created_at, server, based_on FROM versions WHERE app_id = ? ORDER BY n DESC LIMIT 50').bind(app.id).all<VersionRow & { server: string | null; based_on: number | null }>();
  return {
    ...(await described(env, c, app)),
    versions: v.results.map(x => ({ version: x.n, live: x.n === app.live_version, staging: x.n === app.staging_version, kind: x.server ? 'server' : 'static', based_on: x.based_on, note: x.note, by: x.actor, files: x.file_count, bytes: x.bytes, at: new Date(x.created_at).toISOString() })),
    // Names only: secret values are never returned.
    secrets: await listSecrets(env, app.id),
    domains: await appDomains(env, app),
    // Who else got its files or deployed it lately: a warning to pass on, never a lock.
    ...(await editingNotice(env, c, app)),
  };
}
const shapeEvents = (rows: (EventRow & { slug?: string | null })[]) =>
  rows.map(e => ({ at: new Date(e.at).toISOString(), by: e.actor, action: e.action, ...(e.slug ? { app: e.slug } : {}), detail: e.detail }));
export async function getLogs(env: Env, c: Caller, slug: string, search?: string | null) {
  requireRole(c, 'builder', 'read app activity');
  const app = await getApp(env, c, slug);
  const r = await env.DB.prepare('SELECT at, actor, action, detail FROM events WHERE app_id = ? ORDER BY id DESC LIMIT 50').bind(app.id).all<EventRow>();
  return { app: app.slug, events: shapeEvents(r.results), requests: await requestLogs(env, app, search) };
}

/** What a server app's code did per request: console output and exceptions, newest first, kept 7 days. */
async function requestLogs(env: Env, app: AppRow, search?: string | null) {
  const q = search ? `%${search.replace(/[%_\\]/g, m => '\\' + m)}%` : null;
  const r = await env.DB.prepare(
    `SELECT at, version, method, path, status, outcome, logs, exceptions FROM app_logs WHERE app_id = ? AND at > ?
     AND (? IS NULL OR logs LIKE ? ESCAPE '\\' OR exceptions LIKE ? ESCAPE '\\' OR path LIKE ? ESCAPE '\\') ORDER BY id DESC LIMIT 50`,
  ).bind(app.id, now() - LIMITS.logRetentionMs, q, q, q, q).all<{ at: number; version: number | null; method: string; path: string; status: number | null; outcome: string; logs: string; exceptions: string }>();
  return r.results.map(x => ({
    at: new Date(x.at).toISOString(), version: x.version, request: `${x.method} ${x.path}`, status: x.status, outcome: x.outcome,
    logs: JSON.parse(x.logs).map((l: { level: string; message: string }) => `${l.level}: ${l.message}`), exceptions: JSON.parse(x.exceptions),
  }));
}

/** Set (or with value null, remove) one secret. Agents may set secrets but, like everyone, never read them back. */
export async function setSecret(env: Env, c: Caller, slug: string, name: string, value: string | null) {
  requireRole(c, 'builder', 'set app secrets');
  const app = await getApp(env, c, slug);
  const clean = String(name ?? '').trim();
  checkSecretName(clean);
  const stmts = value === null ? deleteSecret(env, app.id, clean) : await putSecret(env, app.id, clean, value, c.actor);
  await env.DB.batch([...stmts, event(env, c.workspace.id, c.actor, app.id, value === null ? 'secret_removed' : 'secret_set', clean)]);
  return { app: app.slug, secret: clean, [value === null ? 'removed' : 'set']: true, secrets: await listSecrets(env, app.id),
    note: 'The value is stored encrypted and is never shown again. The app sees it as env.' + clean + ' from its next request.' };
}
/** One audit log across every app in the workspace, filterable by app and action. */
export async function listEvents(env: Env, c: Caller, o: { app?: string | null; action?: string | null; limit?: number }) {
  requireRole(c, 'builder', 'read the audit log');
  const appId = o.app ? (await getApp(env, c, o.app)).id : null;
  const limit = Math.min(Math.max(Number(o.limit) || 100, 1), 500);
  const r = await env.DB.prepare(
    `SELECT e.at, e.actor, e.action, e.detail, a.slug FROM events e LEFT JOIN apps a ON a.id = e.app_id
     WHERE e.workspace_id = ? AND (? IS NULL OR e.app_id = ?) AND (? IS NULL OR e.action = ?) ORDER BY e.id DESC LIMIT ?`,
  ).bind(c.workspace.id, appId, appId, o.action ?? null, o.action ?? null, limit).all<EventRow & { slug: string | null }>();
  return { workspace: c.workspace.slug, events: shapeEvents(r.results) };
}

// ---------- deploying ----------

/** Clean bundle paths, drop junk files, and strip a single wrapping folder such as dist/. */
export function normalise(files: BundleFile[]): BundleFile[] {
  let out = files.map(f => ({ path: f.path.replace(/\\/g, '/').replace(/^(\.\/)+/, '').replace(/^\/+/, ''), bytes: f.bytes }))
    .filter(f => f.path && !/(^|\/)(\._[^/]*|\.DS_Store|Thumbs\.db)$/.test(f.path) && !/(^|\/)\.git\//.test(f.path));
  for (const f of out) {
    if (f.path.split('/').some(p => p === '..' || p === '.')) throw new Problem(400, 'bad_path', `File path "${f.path}" is not allowed.`);
    if (f.path.length > 400) throw new Problem(400, 'bad_path', 'A file path is longer than 400 characters.');
    if (f.path.startsWith('_brod/')) throw new Problem(400, 'bad_path', 'Paths under _brod/ are reserved for the platform.');
    if (f.bytes.byteLength > LIMITS.fileBytes) throw new Problem(413, 'too_large', `${f.path} is larger than ${LIMITS.fileBytes / 1048576} MB.`);
  }
  const marks = (prefix: string) => out.some(f => [`${prefix}index.html`, `${prefix}_worker.js`].includes(f.path) || f.path.startsWith(`${prefix}_worker/`));
  if (!marks('')) {
    const tops = new Set(out.map(f => f.path.split('/')[0]));
    const top = [...tops][0];
    if (tops.size === 1 && marks(`${top}/`)) out = out.map(f => ({ path: f.path.slice(top.length + 1), bytes: f.bytes }));
  }
  if (!out.length) throw new Problem(400, 'empty_bundle', 'The bundle has no files.');
  if (out.length > LIMITS.files) throw new Problem(413, 'too_many_files', `A bundle can hold at most ${LIMITS.files} files.`);
  if (!out.some(f => f.path === 'index.html') && !findServer(out.map(f => f.path)))
    throw new Problem(400, 'no_index', 'There is no index.html or _worker.js at the top of the bundle. Upload the built output folder (for example dist/ or build/), not the source folder. ' +
      'For server code, add a _worker.js module (or a _worker/ folder with index.js) that exports default { fetch(request, env) }.');
  if (out.reduce((n, f) => n + f.bytes.byteLength, 0) > LIMITS.unpackedBytes) throw new Problem(413, 'too_large', 'The bundle is larger than 60 MB unpacked.');
  return out;
}

async function newSlug(env: Env, c: Caller, name: string): Promise<string> {
  const base = slugify(name);
  for (let i = 0; i < 6; i++) {
    const s = i === 0 ? base : `${base}-${randomId('', 2)}`;
    if (!(await env.DB.prepare('SELECT 1 FROM apps WHERE workspace_id = ? AND slug = ?').bind(c.workspace.id, s).first())) return s;
  }
  return `${base}-${randomId('', 4)}`;
}

async function checkRate(env: Env, c: Caller) {
  const r = await env.DB.prepare("SELECT COUNT(*) AS n FROM events WHERE workspace_id = ? AND action = 'deploy' AND at > ?").bind(c.workspace.id, now() - 3600e3).first<{ n: number }>();
  if ((r?.n ?? 0) >= LIMITS.deploysPerHour) throw new Problem(429, 'rate_limited', `This workspace has deployed ${LIMITS.deploysPerHour} times in the last hour. Wait a little and try again.`);
}

async function planFull(env: Env, c: Caller, verb: string) {
  const r = await env.DB.prepare("SELECT slug FROM apps WHERE workspace_id = ? AND status = 'live'").bind(c.workspace.id).all<{ slug: string }>();
  const limit = plan(c.workspace).apps;
  if (r.results.length >= limit)
    throw new Problem(402, 'plan_limit', `Your ${c.workspace.plan} plan runs ${limit} apps and all ${limit} are in use. Pause one with set_paused, or upgrade the plan, to ${verb}. Existing apps keep running.`,
      { running_apps: r.results.length, app_limit: limit, running: r.results.map(a => a.slug), upgrade_url: `${env.API_ORIGIN}/w/${c.workspace.slug}` });
}

/** Resolve which app a deploy targets, creating it (inside the plan allowance) when it is new. */
async function targetApp(env: Env, c: Caller, o: { app?: string; name?: string }): Promise<{ app: AppRow; created: boolean }> {
  if (o.app) return { app: await getApp(env, c, o.app), created: false };
  const name = (o.name ?? '').trim().slice(0, 60);
  if (!name) throw new Problem(400, 'need_name', 'Give "name" for a new app, or "app" to deploy a new version of an existing one.');
  await planFull(env, c, 'add another');
  const app: AppRow = {
    id: randomId('app_'), workspace_id: c.workspace.id, owner_id: c.user.id, slug: await newSlug(env, c, name), name, title: '', welcome: '',
    status: 'live', access: 'private', roles: '["owner","editor","viewer"]', live_version: null, created_at: now(),
  };
  await env.DB.prepare('INSERT INTO apps (id, workspace_id, owner_id, slug, name, status, access, roles, live_version, created_at) VALUES (?,?,?,?,?,?,?,?,?,?)')
    .bind(app.id, app.workspace_id, app.owner_id, app.slug, app.name, app.status, app.access, app.roles, null, app.created_at).run();
  return { app, created: true };
}

/** Where a deploy goes: "staging" or "production" ("live" too). Anything else is refused before anything is uploaded. */
function checkEnvironment(e: unknown): 'staging' | 'production' | null {
  const v = e === undefined || e === null ? '' : String(e).trim().toLowerCase();
  if (!v) return null;
  if (v === 'staging') return 'staging';
  if (v === 'production' || v === 'live') return 'production';
  throw new Problem(400, 'bad_environment', '"environment" is "staging" or "production".');
}

/**
 * Whether a deploy goes to staging instead of live. An agent updating an app that already has a live version deploys to
 * staging unless it asks for production, so the person can try the change before visitors see it. A person, and any
 * first version, goes live unless staging is asked for.
 */
const toStaging = (c: Caller, app: AppRow, created: boolean, asked: 'staging' | 'production' | null) =>
  asked ? asked === 'staging' : c.agent && !created && app.live_version !== null;

export async function deploy(env: Env, c: Caller, o: { app?: string; name?: string; note?: string; environment?: unknown; base_version?: unknown; files: BundleFile[] }) {
  requireRole(c, 'builder', 'deploy apps');
  await checkRate(env, c);
  const asked = checkEnvironment(o.environment);
  const base = checkBase(o.base_version, o.app);
  const files = normalise(o.files);
  const server = findServer(files.map(f => f.path));
  if (server) await checkServer(env, server, files);
  await checkWorkspaceUp(env, c);
  if (o.app) await checkUp(env, await getApp(env, c, o.app));
  const { app, created } = await targetApp(env, c, o);
  // Refuse before uploading when someone else already deployed past the base; checked again when the pointer moves.
  if (base !== null && currentVersion(app) !== base) throw await staleBase(env, app, base);
  const n = await reserveVersion(env, app.id), note = (o.note ?? '').trim().slice(0, 200) || (created ? 'First version' : 'Update');
  // Files are written under a new version prefix first; visitors only see them once the pointer moves.
  for (let i = 0; i < files.length; i += 20)
    await Promise.all(files.slice(i, i + 20).map(f => env.BUNDLES.put(`${app.id}/${n}/${f.path}`, f.bytes, { httpMetadata: { contentType: contentType(f.path) } })));
  const bytes = files.reduce((s, f) => s + f.bytes.byteLength, 0);
  const staging = toStaging(c, app, created, asked);
  // The phishing check: a flagged version still deploys, but its app stays private or people-only and the Brod team gets a report.
  const scan = scanBundle(files);
  const flagged = scan.flagged ? scan.reasons : null;
  await env.DB.prepare('INSERT INTO versions (app_id, n, note, actor, file_count, bytes, created_at, server, scan, based_on) VALUES (?,?,?,?,?,?,?,?,?,?)')
    .bind(app.id, n, note, c.actor, files.length, bytes, now(), server ? JSON.stringify(server) : null, JSON.stringify(scan.reasons), base).run();
  // The pointer moves only if the app's current version is still the base, so a deploy that raced past ours is never undone.
  // A based deploy straight to live builds on what was waiting on staging, so it replaces it: publishing that later would undo this one.
  const replaced = !staging && base !== null ? app.staging_version ?? null : null;
  const set = staging ? 'staging_version = ?' : base !== null ? 'live_version = ?, staging_version = NULL' : 'live_version = ?';
  const moved = base === null
    ? await env.DB.prepare(`UPDATE apps SET ${set} WHERE id = ?`).bind(n, app.id).run()
    : await env.DB.prepare(`UPDATE apps SET ${set} WHERE id = ? AND COALESCE(staging_version, live_version, 0) = ?`).bind(n, app.id, base).run();
  if (!moved.meta.changes) {
    await dropVersion(env, app.id, n);
    throw await staleBase(env, app, base ?? 0);
  }
  await env.DB.batch([
    // Still a "deploy" event, so staging deploys count toward the hourly limit.
    event(env, c.workspace.id, c.actor, app.id, 'deploy', `v${n}${staging ? ' to staging' : ''}${base !== null ? ` (from v${base})` : ''}${replaced !== null ? `, replacing v${replaced} on staging` : ''}: ${note} (${files.length} files)`),
    ...(flagged ? [
      env.DB.prepare("INSERT INTO reports (id, app_id, reporter, reason, created_at, kind) VALUES (?,?,?,?,?,'automatic')")
        .bind(randomId('rep_', 8), app.id, CHECKER, `Phishing check on v${n}: ${flagged.join('; ')}`, now()),
      event(env, c.workspace.id, CHECKER, app.id, 'flagged', `v${n}: ${flagged.join('; ')}`),
      // Staging is never open beyond the app's builders; the check runs again when it is published.
      ...(staging ? [] : narrowIfFlagged(env, app, n, flagged)),
    ] : []),
  ]);
  if (staging) app.staging_version = n; else app.live_version = n;
  if (replaced !== null) app.staging_version = null;
  await markEditing(env, c, app.id, n);
  const out = { ...(await described(env, c, app)), version: n, based_on: base, ...(await editingNotice(env, c, app)), environment: staging ? 'staging' : 'production', files: files.length, bytes, created, kind: server ? 'server' : 'static' };
  if (!staging) return out;
  const url = stagingUrl(env, c.workspace.slug, app.slug);
  return {
    ...out, staging_url: url,
    next_step: `v${n} is on staging, not live: visitors still get ${app.live_version !== null ? `v${app.live_version}` : 'nothing yet'}. Give the person the staging address ${url} to try it (only the app's builders can open it). ` +
      `When they say it is ready, call publish_staging to make v${n} live.`,
  };
}

/** The version an update builds on: what is waiting on staging, or else what is live. */
export const currentVersion = (app: AppRow) => app.staging_version ?? app.live_version ?? null;

/** "base_version": the version a deploy's files started from. Only for an existing app. */
function checkBase(v: unknown, app: string | undefined): number | null {
  if (v === undefined || v === null || v === '') return null;
  const n = Number(v);
  if (!Number.isInteger(n) || n < 1) throw new Problem(400, 'bad_base_version', '"base_version" is the version number your files started from, such as 3.');
  if (!app) throw new Problem(400, 'bad_base_version', '"base_version" goes with "app", for a new version of an existing app.');
  return n;
}

/** Take the next version number for an app in one statement, so two deploys at once never get the same one. */
async function reserveVersion(env: Env, appId: string): Promise<number> {
  const r = await env.DB.prepare('UPDATE apps SET last_version = COALESCE(last_version, 0) + 1 WHERE id = ? RETURNING last_version').bind(appId).first<{ last_version: number }>();
  if (!r) throw new Problem(404, 'not_found', 'The app was deleted during the deploy.');
  return r.last_version;
}

/** Remove a version that never went live or to staging: its row and its files. */
async function dropVersion(env: Env, appId: string, n: number) {
  await env.DB.prepare('DELETE FROM versions WHERE app_id = ? AND n = ?').bind(appId, n).run();
  let cursor: string | undefined;
  do {
    const page = await env.BUNDLES.list({ prefix: `${appId}/${n}/`, cursor });
    if (page.objects.length) await env.BUNDLES.delete(page.objects.map(o => o.key));
    cursor = page.truncated ? page.cursor : undefined;
  } while (cursor);
}

/**
 * The refusal for a deploy whose files started from an older version than the app's current one: deploying them would
 * silently undo what someone else deployed since. It names who changed what, so the agent can tell the person.
 */
async function staleBase(env: Env, app: AppRow, base: number) {
  const fresh = await env.DB.prepare('SELECT * FROM apps WHERE id = ?').bind(app.id).first<AppRow>();
  if (!fresh) return new Problem(404, 'not_found', 'The app was deleted during the deploy.');
  const current = currentVersion(fresh);
  const r = await env.DB.prepare('SELECT n, note, actor, created_at FROM versions WHERE app_id = ? AND n > ? AND n <= ? ORDER BY n DESC LIMIT 10')
    .bind(app.id, base, current ?? 0).all<{ n: number; note: string; actor: string; created_at: number }>();
  const since = r.results.map(v => ({ version: v.n, by: v.actor, note: v.note, at: new Date(v.created_at).toISOString() }));
  const environment = current === null ? null : current === fresh.staging_version ? 'staging' : 'live';
  const what = since.length
    ? `Since v${base}, ${since.map(v => `v${v.version} by ${v.by} ("${v.note}")`).join(', ')} ${since.length === 1 ? 'was' : 'were'} deployed.`
    : `The app's current version is ${current === null ? 'none' : `v${current}`}, not v${base}.`;
  const again = current === null ? 'without "base_version"' : `with "base_version": ${current}`;
  return new Problem(409, 'stale_base',
    `Nothing was deployed: your files start from v${base}, but ${fresh.slug} has changed. ${what} Deploying your files would undo those changes. ` +
    `Tell the person who changed what. Then get the current files with get_files, add your changes to them, and deploy again ${again}, ` +
    `or, only if the person says to replace that work, deploy your files as they are ${again}.`,
    { your_base: base, current_version: current, current_environment: environment, since });
}

/**
 * Refuse server code that cannot start, so a broken deploy never replaces the live version. A wrapper module imports
 * the app's main module (running its top-level code) and checks it exports a fetch handler, without calling it.
 */
async function checkServer(env: Env, server: ServerInfo, files: BundleFile[]) {
  // Server code runs on Cloudflare's Worker Loader. Hosts without it (Vercel, plain Node) serve static apps only.
  if (!env.LOADER) throw new Problem(400, 'server_apps_unavailable', `This Brod host serves static apps only: server code (${server.main}) needs the Cloudflare deployment. Remove _worker.js or _worker/ and deploy the static files, or deploy on Cloudflare.`);
  const modules: Record<string, string | WorkerLoaderModule> = {};
  for (const f of files) if (server.modules.includes(f.path)) modules[f.path] = moduleFor(f.path, f.bytes.slice().buffer as ArrayBuffer);
  modules['__brod_check.js'] = { js: `import * as m from './${server.main}';
export default { fetch() { const h = m.default; return new Response(h && typeof h.fetch === 'function' ? 'ok' : 'no_fetch'); } };` };
  let verdict: string;
  try {
    const stub = env.LOADER.load({ compatibilityDate: COMPAT_DATE, compatibilityFlags: ['nodejs_compat'], mainModule: '__brod_check.js', modules, env: {}, globalOutbound: null, limits: { cpuMs: 200 } });
    verdict = await (await stub.getEntrypoint().fetch('http://check/')).text();
  } catch (e) {
    throw new Problem(400, 'server_failed', `The server code did not start: ${(e as Error).message}. Nothing was deployed; the live version is unchanged.`);
  }
  if (verdict !== 'ok') throw new Problem(400, 'server_failed', `${server.main} must export default an object with a fetch(request, env, ctx) method. Nothing was deployed.`);
}

// ---------- working together ----------

/** Files returned inline by getFiles, at most; larger versions come as a download address instead. */
const INLINE_FILES = 200;

/** Read one version's files from the file store. */
async function readVersion(env: Env, appId: string, n: number): Promise<BundleFile[]> {
  const base = `${appId}/${n}/`, files: BundleFile[] = [];
  let cursor: string | undefined;
  do {
    const page = await env.BUNDLES.list({ prefix: base, cursor });
    for (const o of page.objects) {
      const obj = await env.BUNDLES.get(o.key);
      if (obj) files.push({ path: o.key.slice(base.length), bytes: new Uint8Array(await obj.arrayBuffer()) });
    }
    cursor = page.truncated ? page.cursor : undefined;
  } while (cursor);
  return files.sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
}

/**
 * One version's files (by default the current one), so an agent can start from what is deployed instead of from its own
 * older copy, then deploy with base_version. Small versions come inline; larger ones as a short-lived tar.gz address.
 * Getting the files counts as working on the app, so others are told (see othersEditing).
 */
export async function getFiles(env: Env, c: Caller, slug: string, version?: unknown) {
  requireRole(c, 'builder', 'get app files');
  const app = await getApp(env, c, slug);
  const n = version === undefined || version === null || version === '' ? currentVersion(app) : Number(version);
  if (n === null) throw new Problem(409, 'no_version', `${app.slug} has no version yet.`);
  const v = Number.isInteger(n) ? await env.DB.prepare('SELECT n, file_count, bytes, created_at FROM versions WHERE app_id = ? AND n = ?').bind(app.id, n).first<VersionRow>() : null;
  if (!v) throw new Problem(404, 'no_version', `${app.slug} has no version ${version}. Use get_status to see its versions.`);
  await markEditing(env, c, app.id, n);
  const where = n === app.staging_version ? 'staging' : n === app.live_version ? 'live' : null;
  const out = {
    app: app.slug, version: n, environment: where, current_version: currentVersion(app), file_count: v.file_count, bytes: v.bytes,
    ...(await editingNotice(env, c, app)),
  };
  const then = `Make your changes there, then call deploy_app with "app": "${app.slug}" and "base_version": ${n}, so a change someone else deploys meanwhile is never undone. ` +
    'These are the files as deployed (the built output): if the app was built from source with a build step, change the source if you have it rather than these.';
  if (v.bytes <= LIMITS.inlineBytes && v.file_count <= INLINE_FILES) {
    const utf8 = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });
    const files = (await readVersion(env, app.id, n)).map(f => {
      try { return { path: f.path, content: utf8.decode(f.bytes) }; }
      catch { let b = ''; for (const x of f.bytes) b += String.fromCharCode(x); return { path: f.path, content: btoa(b), encoding: 'base64' }; }
    });
    return { ...out, files, next_step: `Write these files into an empty folder, keeping their paths (decode "base64" ones). ${then}` };
  }
  const id = randomId('dl_', 20);
  await env.DB.prepare('INSERT INTO downloads (id, workspace_id, app_id, version, user_id, expires_at) VALUES (?,?,?,?,?,?)')
    .bind(id, c.workspace.id, app.id, n, c.user.id, now() + LIMITS.downloadTtlMs).run();
  const download_url = `${env.API_ORIGIN}/v1/downloads/${id}`;
  return {
    ...out, download_url, expires_in_seconds: LIMITS.downloadTtlMs / 1000,
    next_step: `Download the files into an empty folder with one command:\n  mkdir -p <folder> && curl -sS --fail "${download_url}" | tar -xzf - -C <folder>\n${then}`,
  };
}

/** A download address: the version's files as a tar.gz. The address is its own credential and works until it expires. */
export async function download(env: Env, id: string): Promise<{ name: string; body: Uint8Array }> {
  const d = await env.DB.prepare('SELECT d.app_id, d.version, d.expires_at, a.slug, v.created_at FROM downloads d JOIN apps a ON a.id = d.app_id JOIN versions v ON v.app_id = d.app_id AND v.n = d.version WHERE d.id = ?')
    .bind(id).first<{ app_id: string; version: number; expires_at: number; slug: string; created_at: number }>();
  if (!d || d.expires_at < now()) throw new Problem(410, 'download_gone', 'This download address has expired. Call get_files again for a new one.');
  return { name: `${d.slug}-v${d.version}.tar.gz`, body: await pack(await readVersion(env, d.app_id, d.version), d.created_at) };
}

/** Note that this person is working on the app (getting its files or deploying it). Others are told, never blocked. */
async function markEditing(env: Env, c: Caller, appId: string, base: number | null) {
  await env.DB.prepare(
    `INSERT INTO editing (app_id, user_id, email, actor, base_version, since, last_at) VALUES (?,?,?,?,?,?,?)
     ON CONFLICT (app_id, user_id) DO UPDATE SET email = excluded.email, actor = excluded.actor, base_version = excluded.base_version, last_at = excluded.last_at,
       since = CASE WHEN editing.last_at < ? THEN excluded.since ELSE editing.since END`,
  ).bind(appId, c.user.id, c.user.email, c.actor, base, now(), now(), now() - LIMITS.editingWindowMs).run();
}

/** Everyone else who got the app's files or deployed it lately, newest first. */
async function othersEditing(env: Env, c: Caller, appId: string) {
  const r = await env.DB.prepare('SELECT email, actor, base_version, since, last_at FROM editing WHERE app_id = ? AND user_id != ? AND last_at > ? ORDER BY last_at DESC')
    .bind(appId, c.user.id, now() - LIMITS.editingWindowMs).all<{ email: string; actor: string; base_version: number | null; since: number; last_at: number }>();
  return r.results.map(e => ({
    by: e.email, ...(e.actor !== e.email ? { via: e.actor } : {}), base_version: e.base_version,
    since: new Date(e.since).toISOString(), last_active: new Date(e.last_at).toISOString(),
  }));
}

const ago = (iso: string) => { const m = Math.round((now() - Date.parse(iso)) / 60000); return m < 1 ? 'just now' : m < 60 ? `${m} minute${m === 1 ? '' : 's'} ago` : `${Math.round(m / 60)} hour${m < 90 ? '' : 's'} ago`; };

/** `others_editing`, plus a `warning` to pass on when anyone else is working on the app. A warning only: nothing is blocked. */
export async function editingNotice(env: Env, c: Caller, app: AppRow) {
  const others = await othersEditing(env, c, app.id);
  if (!others.length) return { others_editing: others };
  const who = others.map(o => `${o.by}${o.via ? ` (through ${o.via})` : ''}, ${o.base_version !== null ? `working from v${o.base_version}, ` : ''}last active ${ago(o.last_active)}`);
  return {
    others_editing: others,
    warning: `Someone else is also working on ${app.slug}: ${who.join('; ')}. Tell the person, so they can agree who changes what. ` +
      'Nothing is blocked, and a deploy that would undo someone else\'s changes is refused (stale_base).',
  };
}

/** For bundles too large to pass inline: a one-time address the agent uploads a tar.gz to. */
export async function createUpload(env: Env, c: Caller, o: { app?: string; name?: string; note?: string; environment?: unknown; base_version?: unknown }) {
  requireRole(c, 'builder', 'deploy apps');
  const environment = checkEnvironment(o.environment);
  const base = checkBase(o.base_version, o.app);
  await checkWorkspaceUp(env, c);
  if (o.app) await checkUp(env, await getApp(env, c, o.app));
  else if (!(o.name ?? '').trim()) throw new Problem(400, 'need_name', 'Give "name" for a new app, or "app" to deploy a new version of an existing one.');
  const id = randomId('up_', 20);
  await env.DB.prepare('INSERT INTO uploads (id, workspace_id, user_id, actor, app_slug, name, note, expires_at, environment, base_version) VALUES (?,?,?,?,?,?,?,?,?,?)')
    .bind(id, c.workspace.id, c.user.id, c.actor, o.app ?? null, o.name ?? null, o.note ?? '', now() + LIMITS.uploadTtlMs, environment, base).run();
  const direct = await directUpload(env, id);   // hosts that cap request bodies (Vercel) take the archive straight into the bucket
  if (direct) return direct;
  const upload_url = `${env.API_ORIGIN}/v1/uploads/${id}`;
  return {
    upload_url, expires_in_seconds: LIMITS.uploadTtlMs / 1000,
    next_step: `Upload the built output folder as a tar.gz with one command. The response is the deploy result.\n  tar -czf - -C <build folder> . | curl -sS -X PUT --data-binary @- "${upload_url}"`,
  };
}
export async function claimUpload(env: Env, id: string): Promise<{ caller: Caller; app?: string; name?: string; note: string; environment: string | null; base_version: number | null }> {
  const u = await env.DB.prepare('SELECT * FROM uploads WHERE id = ?').bind(id)
    .first<{ workspace_id: string; user_id: string; actor: string; app_slug: string | null; name: string | null; note: string; expires_at: number; used_at: number | null; environment: string | null; base_version: number | null }>();
  if (!u || u.used_at || u.expires_at < now()) throw new Problem(410, 'upload_gone', 'This upload address has expired or was already used. Call deploy_app again for a new one.');
  const who = await env.DB.prepare(
    'SELECT w.*, u.email, u.name AS uname, u.email_verified_at, m.role FROM workspaces w JOIN members m ON m.workspace_id = w.id JOIN users u ON u.id = m.user_id WHERE w.id = ? AND u.id = ?',
  ).bind(u.workspace_id, u.user_id).first<Workspace & { email: string; uname: string; email_verified_at: number | null; role: Role }>();
  if (!who) throw new Problem(410, 'upload_gone', 'The person who asked for this upload address is no longer in the workspace.');
  const r = await env.DB.prepare('UPDATE uploads SET used_at = ? WHERE id = ? AND used_at IS NULL').bind(now(), id).run();
  if (!r.meta.changes) throw new Problem(410, 'upload_gone', 'This upload address was already used.');
  const { email, uname, email_verified_at, role, ...w } = who;
  return {
    caller: { workspace: w, user: { id: u.user_id, email, name: uname, email_verified_at }, role, actor: u.actor, agent: true },
    app: u.app_slug ?? undefined, name: u.name ?? undefined, note: u.note, environment: u.environment, base_version: u.base_version,
  };
}

export async function releaseUpload(env: Env, id: string) {
  await env.DB.prepare('UPDATE uploads SET used_at = NULL WHERE id = ? AND expires_at > ?').bind(id, now()).run();
}

// ---------- confirmations (M6) ----------

/** An agent asked for a change a person must confirm. Nothing changes until they do. */
async function needsConfirmation(env: Env, c: Caller, app: AppRow | null, kind: string, payload: unknown, summary: string) {
  const id = randomId('cf_', 16);
  await env.DB.batch([
    env.DB.prepare('INSERT INTO confirmations (id, workspace_id, app_id, kind, payload, summary, requested_by, created_at, expires_at) VALUES (?,?,?,?,?,?,?,?,?)')
      .bind(id, c.workspace.id, app?.id ?? null, kind, JSON.stringify(payload), summary, c.actor, now(), now() + LIMITS.confirmTtlMs),
    event(env, c.workspace.id, c.actor, app?.id ?? null, 'confirmation_requested', summary),
  ]);
  return {
    needs_confirmation: true, summary, confirm_url: `${env.API_ORIGIN}/confirm/${id}`,
    message: `Nothing has changed yet. ${summary} needs the owner's confirmation: give them this link to open and confirm. It expires in 24 hours.`,
  };
}

export async function getConfirmation(env: Env, id: string) {
  return env.DB.prepare('SELECT * FROM confirmations WHERE id = ?').bind(id)
    .first<{ id: string; workspace_id: string; app_id: string | null; kind: string; payload: string; summary: string; requested_by: string; expires_at: number; done_at: number | null }>();
}

/** A person confirms an agent's request. They must be signed in to the same workspace with a role that could make the change. */
export async function confirm(env: Env, user: User, id: string) {
  const cf = await getConfirmation(env, id);
  if (!cf || cf.done_at || cf.expires_at < now()) throw new Problem(410, 'confirmation_gone', 'This request has expired or was already handled.');
  const w = await env.DB.prepare('SELECT slug FROM workspaces WHERE id = ?').bind(cf.workspace_id).first<{ slug: string }>();
  const mem = w && (await membership(env, user, w.slug));
  if (!mem) throw new Problem(403, 'forbidden', 'Only someone in this workspace can confirm this.');
  const c: Caller = { workspace: mem.workspace, user, role: mem.role, actor: user.email, agent: false };
  const claimed = await env.DB.prepare('UPDATE confirmations SET done_at = ?, done_by = ? WHERE id = ? AND done_at IS NULL').bind(now(), user.email, id).run();
  if (!claimed.meta.changes) throw new Problem(410, 'confirmation_gone', 'This request was already handled.');
  const p = JSON.parse(cf.payload);
  const appSlug = cf.app_id ? (await env.DB.prepare('SELECT slug FROM apps WHERE id = ?').bind(cf.app_id).first<{ slug: string }>())?.slug : undefined;
  try {
    if (cf.kind === 'access') return await setAccess(env, c, appSlug!, p, p.password_hash);
    if (cf.kind === 'invite') return await invite(env, c, p, s => getApp(env, c, s));
    if (cf.kind === 'delete') return await deleteApp(env, c, appSlug!);
  } catch (e) {
    // Give the request back so it can be retried once the problem is fixed.
    await env.DB.prepare('UPDATE confirmations SET done_at = NULL, done_by = NULL WHERE id = ?').bind(id).run();
    throw e;
  }
  throw new Problem(400, 'bad_confirmation', 'Unknown request.');
}

// ---------- changing an app ----------

export async function rollback(env: Env, c: Caller, slug: string, version: number) {
  requireRole(c, 'builder', 'roll back apps');
  const app = await getApp(env, c, slug);
  if (!(await env.DB.prepare('SELECT 1 FROM versions WHERE app_id = ? AND n = ?').bind(app.id, version).first()))
    throw new Problem(404, 'no_version', `${app.slug} has no version ${version}. Use get_status to see its versions.`);
  if (app.live_version === version) return { ...(await described(env, c, app)), changed: false };
  await checkUp(env, app);
  const from = app.live_version;
  await env.DB.batch([
    env.DB.prepare('UPDATE apps SET live_version = ? WHERE id = ?').bind(version, app.id),
    event(env, c.workspace.id, c.actor, app.id, 'rollback', `v${from} to v${version}`),
    ...narrowIfFlagged(env, app, version, await flagOf(env, app.id, version)),
  ]);
  return { ...(await described(env, c, { ...app, live_version: version })), changed: true };
}

/** Make the version on staging live. Staging is then empty until the next staging deploy. */
export async function publishStaging(env: Env, c: Caller, slug: string) {
  requireRole(c, 'builder', 'publish apps');
  const app = await getApp(env, c, slug);
  const n = app.staging_version;
  if (n === null || n === undefined) throw new Problem(409, 'nothing_on_staging', `${app.slug} has nothing on staging. Deploy with "environment": "staging" first.`);
  // Only if staging still holds this version, so two publishes at once cannot make an older one live.
  await checkUp(env, app);
  const r = await env.DB.prepare('UPDATE apps SET live_version = ?, staging_version = NULL WHERE id = ? AND staging_version = ?').bind(n, app.id, n).run();
  if (!r.meta.changes) throw new Problem(409, 'nothing_on_staging', 'Staging changed while publishing. Look at get_status and try again.');
  // Publishing is a pointer move like a rollback, so a flagged version narrows the app as it goes live.
  await env.DB.batch([
    event(env, c.workspace.id, c.actor, app.id, 'publish', `v${n} from staging (was ${app.live_version !== null ? `v${app.live_version}` : 'nothing'})`),
    ...narrowIfFlagged(env, app, n, await flagOf(env, app.id, n)),
  ]);
  return { ...(await described(env, c, { ...app, live_version: n, staging_version: null })), published: n };
}

/** Take the version off staging without making it live. The version itself is kept, for a rollback or a later deploy. */
export async function discardStaging(env: Env, c: Caller, slug: string) {
  requireRole(c, 'builder', 'change staging');
  const app = await getApp(env, c, slug);
  if (app.staging_version === null || app.staging_version === undefined) return { ...(await described(env, c, app)), changed: false };
  await env.DB.batch([
    env.DB.prepare('UPDATE apps SET staging_version = NULL WHERE id = ?').bind(app.id),
    event(env, c.workspace.id, c.actor, app.id, 'staging_discarded', `v${app.staging_version}`),
  ]);
  return { ...(await described(env, c, { ...app, staging_version: null })), changed: true };
}

export interface AccessInput { access?: unknown; add?: unknown; remove?: unknown; password?: unknown }

/**
 * Change an app's access mode and who holds which app role. Widening access (a more open mode, new grants, or a new
 * password) asked for by an agent waits for a person to confirm it. Narrowing takes effect at once. `passwordHash` is a
 * password already hashed when the request was made, for a confirmation, which never stores the password itself.
 */
export async function setAccess(env: Env, c: Caller, slug: string, o: AccessInput, passwordHash?: string) {
  requireRole(c, 'builder', 'change who can open apps');
  const app = await getApp(env, c, slug);
  let access = (o.access === undefined || o.access === null ? app.access : String(o.access)) as Access;
  if (!ACCESS.includes(access)) throw new Problem(400, 'bad_access', `Access is one of ${ACCESS.join(', ')}.`);
  const roles: string[] = JSON.parse(app.roles);
  const asList = (v: unknown, what: string): GrantInput[] => {
    if (v === undefined || v === null) return [];
    if (!Array.isArray(v)) throw new Problem(400, 'bad_grant', `"${what}" is a list of grants such as { "group": "finance", "role": "editor" }.`);
    return v.map(x => (typeof x === 'string' ? (x.includes('@') ? { email: x } : { group: x }) : (x ?? {})) as GrantInput);
  };
  const add = await Promise.all(asList(o.add, 'add').map(async g => {
    const role = String(g.role ?? roles[roles.length - 1]);
    if (!roles.includes(role)) throw new Problem(400, 'bad_role', `${app.slug} understands the roles ${roles.join(', ')}.`);
    return { ...(await resolveSubject(env, c, g)), role };
  }));
  const remove = await Promise.all(asList(o.remove, 'remove').map(g => resolveSubject(env, c, g)));
  const modeGiven = o.access !== undefined && o.access !== null;
  const password = o.password === undefined || o.password === null || o.password === '' ? null : checkPassword(o.password);
  // A password on its own means sharing with it; sharing a private app with someone means opening it to named people.
  if (password !== null && !modeGiven) access = 'password';
  if (access === 'private' && add.length && !modeGiven) access = 'people';
  if (password !== null && access !== 'password') throw new Problem(400, 'bad_password', 'A password only works with "access": "password".');
  if (access === 'public' && !c.user.email_verified_at) throw new Problem(403, 'unverified', 'Confirm your email address before making an app public.');
  // Only a password-protected app keeps a password; leaving that mode forgets it.
  const hash = access !== 'password' ? null : passwordHash ?? (password !== null ? await hashPassword(password) : app.password_hash ?? null);
  if (access === 'password' && !hash) throw new Problem(400, 'password_needed', 'Give a "password" (6 to 128 characters) to share the app with. Anyone with the address and the password can open it, without signing in.');
  const newPassword = access === 'password' && hash !== app.password_hash;

  const opening = ACCESS.indexOf(access) > ACCESS.indexOf(app.access);
  const widening = opening || add.length > 0 || newPassword;
  if (widening) await checkUp(env, app);
  if (opening) {
    await checkCanOpenOutside(env, c, access);
    await checkNotFlagged(env, app, access);
  }
  if (c.agent && widening) {
    const parts = [
      ...(access !== app.access ? [`change ${app.slug} from ${app.access} to ${access}${access === 'password' ? ' (anyone with the address and the password can open it)' : ''}`]
        : newPassword ? [`give ${app.slug} a new password`] : []),
      ...(add.length ? [`give ${add.map(a => `${a.label} the ${a.role} role`).join(', ')} on ${app.slug}`] : []),
    ];
    const summary = parts.join(' and ').replace(/^./, s => s.toUpperCase());
    return needsConfirmation(env, c, app, 'access', { access, add: o.add ?? [], remove: o.remove ?? [], ...(newPassword ? { password_hash: hash } : {}) }, summary);
  }
  const stmts: D1PreparedStatement[] = [];
  if (access !== app.access || hash !== (app.password_hash ?? null)) stmts.push(env.DB.prepare('UPDATE apps SET access = ?, password_hash = ? WHERE id = ?').bind(access, hash, app.id));
  if (access !== app.access) stmts.push(event(env, c.workspace.id, c.actor, app.id, 'access', `${app.access} to ${access}`));
  else if (newPassword) stmts.push(event(env, c.workspace.id, c.actor, app.id, 'password', 'a new password'));
  for (const r of remove) stmts.push(env.DB.prepare('DELETE FROM grants WHERE app_id = ? AND subject = ?').bind(app.id, r.subject), event(env, c.workspace.id, c.actor, app.id, 'ungrant', r.label));
  for (const a of add) {
    stmts.push(
      env.DB.prepare('INSERT INTO grants (app_id, subject, role, created_at) VALUES (?,?,?,?) ON CONFLICT(app_id, subject) DO UPDATE SET role = excluded.role').bind(app.id, a.subject, a.role, now()),
      event(env, c.workspace.id, c.actor, app.id, 'grant', `${a.label} as ${a.role}`),
    );
  }
  if (stmts.length) await env.DB.batch(stmts);
  return described(env, c, { ...app, access, password_hash: hash });
}

/** Title, welcome line and the app roles the app understands. Changing these needs no redeploy. */
export async function updateApp(env: Env, c: Caller, slug: string, o: { title?: unknown; welcome?: unknown; roles?: unknown }) {
  requireRole(c, 'builder', 'change app settings');
  const app = await getApp(env, c, slug);
  const title = o.title === undefined ? app.title : String(o.title).trim().slice(0, 80);
  const welcome = o.welcome === undefined ? app.welcome : String(o.welcome).trim().slice(0, 200);
  let roles = app.roles;
  if (o.roles !== undefined) {
    const list = Array.isArray(o.roles) ? o.roles.map(r => String(r).trim().toLowerCase()) : [];
    if (!list.length || list.length > 8 || new Set(list).size !== list.length || !list.every(r => /^[a-z][a-z0-9_-]{0,23}$/.test(r)))
      throw new Problem(400, 'bad_roles', '"roles" is a list of up to 8 distinct lowercase role names, most powerful first, for example ["owner","editor","viewer"].');
    const used = await env.DB.prepare('SELECT DISTINCT role FROM grants WHERE app_id = ?').bind(app.id).all<{ role: string }>();
    const orphaned = used.results.map(r => r.role).filter(r => !list.includes(r));
    if (orphaned.length) throw new Problem(409, 'roles_in_use', `People hold the role ${orphaned.join(', ')} on ${app.slug}. Move them to another role first.`);
    roles = JSON.stringify(list);
  }
  await env.DB.batch([
    env.DB.prepare('UPDATE apps SET title = ?, welcome = ?, roles = ? WHERE id = ?').bind(title, welcome, roles, app.id),
    event(env, c.workspace.id, c.actor, app.id, 'settings', `title "${title}", roles ${roles}`),
  ]);
  return described(env, c, { ...app, title, welcome, roles });
}

export async function setPaused(env: Env, c: Caller, slug: string, paused: boolean) {
  requireRole(c, 'builder', 'pause or resume apps');
  const app = await getApp(env, c, slug);
  const status = paused ? 'paused' : 'live';
  if (!paused) await checkUp(env, app);
  if (!paused && app.status === 'paused') await planFull(env, c, 'resume this one');
  await env.DB.batch([env.DB.prepare('UPDATE apps SET status = ? WHERE id = ?').bind(status, app.id), event(env, c.workspace.id, c.actor, app.id, paused ? 'pause' : 'resume', '')]);
  return described(env, c, { ...app, status });
}

export async function deleteApp(env: Env, c: Caller, slug: string) {
  requireRole(c, 'builder', 'delete apps');
  const app = await getApp(env, c, slug);
  await checkUp(env, app);   // a taken-down app is kept for the Brod team's review
  if (c.agent) return needsConfirmation(env, c, app, 'delete', {}, `Delete ${app.slug}, all its versions, and its data`);
  let cursor: string | undefined;
  do {
    const page = await env.BUNDLES.list({ prefix: `${app.id}/`, cursor });
    if (page.objects.length) await env.BUNDLES.delete(page.objects.map(o => o.key));
    cursor = page.truncated ? page.cursor : undefined;
  } while (cursor);
  if (env.APP_DATA) await wipeAppData(env, app.id);   // absent off Cloudflare, where no app has a server database
  await env.DB.batch([
    env.DB.prepare('DELETE FROM secrets WHERE app_id = ?').bind(app.id),
    env.DB.prepare('DELETE FROM app_logs WHERE app_id = ?').bind(app.id),
    env.DB.prepare('DELETE FROM versions WHERE app_id = ?').bind(app.id),
    env.DB.prepare('DELETE FROM downloads WHERE app_id = ?').bind(app.id),
    env.DB.prepare('DELETE FROM editing WHERE app_id = ?').bind(app.id),
    env.DB.prepare('DELETE FROM grants WHERE app_id = ?').bind(app.id),
    env.DB.prepare('DELETE FROM domains WHERE app_id = ?').bind(app.id),
    env.DB.prepare('DELETE FROM apps WHERE id = ?').bind(app.id),
    event(env, c.workspace.id, c.actor, null, 'delete', `${app.slug} deleted`),
  ]);
  return { deleted: app.slug };
}

/** Invite someone. From an agent this waits for a person to confirm, because it widens who can get in. */
export async function inviteFrom(env: Env, c: Caller, o: InviteInput) {
  const getter = (s: string) => getApp(env, c, s);
  if (!c.agent) return invite(env, c, o, getter);
  const { email, role, app, appRole } = await checkInvite(env, c, o, getter);
  const summary = app ? `Invite ${email} to ${app.slug} as ${appRole}${role !== 'guest' ? ` (workspace ${role})` : ''}` : `Invite ${email} to the workspace as ${role}`;
  return needsConfirmation(env, c, app, 'invite', { email, role, app: app?.slug, app_role: appRole }, summary);
}
