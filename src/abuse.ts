// Abuse protection: takedowns and suspended workspaces, rate limits for anonymous and new users, the guardrail that
// keeps a new workspace's apps inside it for its first day, the flag the deploy-time phishing check (scan.ts) puts on
// a version, and the operator's API under /v1/admin/ (ADMIN_SECRET). server/src/abuse.rs is the same.
import { ACCESS, Access, AppRow, Caller, Env, Problem, json, notice, now, safeEqual } from './lib';
import { event } from './people';

export const ABUSE = {
  signInLinksPerIpHour: 20,        // on top of the 5 an hour per email address
  oauthClientsPerIpHour: 10,
  workspacesPerUserDay: 3,
  reportsPerIpHour: 10,
  newWorkspaceMs: 24 * 3600 * 1000,   // a workspace this young cannot open apps to people outside it (password, signed_in, public)
};
const HOUR = 3600 * 1000, DAY = 24 * HOUR;
/** Who the audit log names for the operator's actions and for the phishing check. */
export const OPERATOR = 'Brod operator';
export const CHECKER = 'brod';

// ---------- client addresses and rate limits ----------

/**
 * The visitor's address: Cloudflare's cf-connecting-ip on the Worker, or x-brod-client-ip, which the Node listener
 * (src/node/listener.ts) sets from the socket or Vercel's forwarded header after dropping any the visitor sent.
 * IPv6 addresses count per /64, the block one customer usually gets. Null when the host does not say.
 */
export function clientIp(env: Env, request: Request): string | null {
  const raw = (env.HOST ? request.headers.get('x-brod-client-ip') : request.headers.get('cf-connecting-ip'))?.trim();
  return raw ? ipKey(raw) : null;
}

/** An address as a rate-limit key: IPv4 as is (also when mapped into IPv6), IPv6 as its first four groups. */
export function ipKey(ip: string): string {
  const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/i.exec(ip);
  if (mapped) return mapped[1];
  if (!ip.includes(':')) return ip;
  const [head, tail = ''] = ip.toLowerCase().split('%')[0].split('::');
  const a = head ? head.split(':') : [], b = ip.includes('::') && tail ? tail.split(':') : [];
  const groups = ip.includes('::') ? [...a, ...Array(Math.max(0, 8 - a.length - b.length)).fill('0'), ...b] : a;
  return groups.slice(0, 4).map(g => g.replace(/^0+(?=.)/, '')).join(':') + '::/64';
}

/**
 * Count one more request in a fixed window ("<bucket>:<who>:<window number>" in rate_limits) and refuse with 429
 * once there are more than `limit` in it.
 */
export async function rateLimit(env: Env, bucket: string, who: string, limit: number, windowMs: number, message: string) {
  const t = now(), win = Math.floor(t / windowMs), ends = (win + 1) * windowMs;
  const row = await env.DB.prepare('INSERT INTO rate_limits (key, n, expires_at) VALUES (?, 1, ?) ON CONFLICT(key) DO UPDATE SET n = rate_limits.n + 1 RETURNING n')
    .bind(`${bucket}:${who}:${win}`, ends).first<{ n: number }>();
  await env.DB.prepare('DELETE FROM rate_limits WHERE expires_at < ?').bind(t).run();
  if ((row?.n ?? 0) > limit) {
    const retry = Math.ceil((ends - t) / 1000);
    throw new Problem(429, 'rate_limited', `${message} Try again in ${retry < 120 ? `${retry} seconds` : `${Math.ceil(retry / 60)} minutes`}.`, { retry_after_seconds: retry });
  }
}
export const perHour = HOUR, perDay = DAY;

// ---------- takedowns and suspensions ----------

export interface Hold { kind: 'taken_down' | 'suspended'; reason: string; since: number }
interface AbuseRow { taken_down_at?: number | null; takedown_reason?: string }

/** What keeps an app down, if anything: its own takedown first, then its workspace's suspension. */
export async function holdOf(env: Env, app: AppRow & AbuseRow): Promise<Hold | null> {
  if (app.taken_down_at) return { kind: 'taken_down', reason: app.takedown_reason ?? '', since: app.taken_down_at };
  return workspaceHold(env, app.workspace_id);
}
export async function workspaceHold(env: Env, workspaceId: string): Promise<Hold | null> {
  const w = await env.DB.prepare('SELECT suspended_at, suspended_reason FROM workspaces WHERE id = ?').bind(workspaceId).first<{ suspended_at: number | null; suspended_reason: string }>();
  return w?.suspended_at ? { kind: 'suspended', reason: w.suspended_reason, since: w.suspended_at } : null;
}

export function holdMessage(h: Hold, slug?: string): string {
  const why = h.reason ? ` (${h.reason})` : '';
  const what = h.kind === 'taken_down' ? `The Brod team took ${slug ?? 'this app'} down${why}. It shows a "taken down" page to everyone` :
    `The Brod team suspended this workspace${why}. Its apps are offline and it cannot deploy new ones`;
  return `${what}, and it cannot be resumed, redeployed, rolled back, deleted or shared more widely until the Brod team restores it. ` +
    'If you think this is a mistake, contact the Brod team; there is nothing an agent can change to fix it.';
}
const holdProblem = (h: Hold, slug?: string) =>
  new Problem(403, h.kind === 'taken_down' ? 'taken_down' : 'workspace_suspended', holdMessage(h, slug), { since: new Date(h.since).toISOString() });

/** Refuse a change that would bring an app (back) up while it is taken down or its workspace is suspended. */
export async function checkUp(env: Env, app: AppRow) {
  const h = await holdOf(env, app);
  if (h) throw holdProblem(h, app.slug);
}
/** Refuse deploying a new app into a suspended workspace. */
export async function checkWorkspaceUp(env: Env, c: Caller) {
  const h = await workspaceHold(env, c.workspace.id);
  if (h) throw holdProblem(h);
}

/** The neutral page a visitor gets instead of an app that is down. It says nothing about why. */
export const takenDownPage = () => notice(410, 'This app has been taken down', 'This app is no longer available.');

// ---------- the new-workspace guardrail ----------

/** For its first day, a free workspace that the operator has not trusted keeps its apps to people inside it. */
export async function checkCanOpenOutside(env: Env, c: Caller, access: Access) {
  if (access !== 'password' && access !== 'signed_in' && access !== 'public') return;
  const opens = c.workspace.created_at + ABUSE.newWorkspaceMs;
  if (now() >= opens || c.workspace.plan !== 'free') return;
  const w = await env.DB.prepare('SELECT trusted_at FROM workspaces WHERE id = ?').bind(c.workspace.id).first<{ trusted_at: number | null }>();
  if (w?.trusted_at) return;
  const at = new Date(opens).toISOString();
  throw new Problem(403, 'workspace_too_new',
    `${c.workspace.slug} is less than a day old, so its apps cannot be opened by people outside it yet ("${access}" access). That becomes possible at ${at}. ` +
    'Until then, share the app inside the workspace with access "workspace", or with named people and groups ("people" with "add"); or upgrade to a paid plan to lift this now.',
    { available_at: at });
}

// ---------- the phishing check's flag ----------

/** The reasons a version was flagged by the phishing check, or null when it was not (or the operator cleared it). */
export async function flagOf(env: Env, appId: string, n: number | null): Promise<string[] | null> {
  if (n === null) return null;
  const v = await env.DB.prepare('SELECT scan, scan_cleared_at FROM versions WHERE app_id = ? AND n = ?').bind(appId, n).first<{ scan: string | null; scan_cleared_at: number | null }>();
  if (!v?.scan || v.scan_cleared_at) return null;
  const reasons = JSON.parse(v.scan) as string[];
  return reasons.length ? reasons : null;
}
export const flagMessage = (slug: string, n: number, reasons: string[]) =>
  `The phishing check flagged v${n} of ${slug} (${reasons.join('; ')}), so the app stays private or shared with named people until the Brod team reviews it. ` +
  'If the page is legitimate, deploy a version without a password or card form that names another company, or ask the Brod team to clear it.';

/** A flagged version keeps its app to private or people access: anything wider is narrowed to people. */
export function narrowIfFlagged(env: Env, app: AppRow, n: number, reasons: string[] | null): D1PreparedStatement[] {
  if (!reasons || ACCESS.indexOf(app.access) <= ACCESS.indexOf('people')) return [];
  const was = app.access;
  app.access = 'people';
  app.password_hash = null;
  return [
    env.DB.prepare("UPDATE apps SET access = 'people', password_hash = NULL WHERE id = ?").bind(app.id),
    event(env, app.workspace_id, CHECKER, app.id, 'access', `${was} to people: the phishing check flagged v${n}`),
  ];
}

/** Refuse access wider than people while the live version is flagged. */
export async function checkNotFlagged(env: Env, app: AppRow, access: Access) {
  if (ACCESS.indexOf(access) <= ACCESS.indexOf('people')) return;
  const reasons = await flagOf(env, app.id, app.live_version);
  if (reasons) throw new Problem(403, 'flagged', flagMessage(app.slug, app.live_version!, reasons), { reasons });
}

/** What get_status and list_apps add about an app that is down or flagged. */
export async function abuseState(env: Env, app: AppRow): Promise<Record<string, unknown>> {
  const out: Record<string, unknown> = {};
  const h = await holdOf(env, app);
  if (h) out[h.kind === 'taken_down' ? 'taken_down' : 'workspace_suspended'] = { reason: h.reason, since: new Date(h.since).toISOString(), message: holdMessage(h, app.slug) };
  const reasons = await flagOf(env, app.id, app.live_version);
  if (reasons) out.flagged = { reasons, message: flagMessage(app.slug, app.live_version!, reasons) };
  return out;
}

// ---------- the operator's API ----------

async function body(request: Request): Promise<Record<string, unknown>> {
  try { const b = await request.json(); return b && typeof b === 'object' ? b as Record<string, unknown> : {}; } catch { return {}; }
}
const text = (v: unknown, max: number) => String(v ?? '').trim().slice(0, max);

/**
 * /v1/admin/... with "Authorization: Bearer <ADMIN_SECRET>":
 *   GET  reports?status=open|resolved|dismissed      POST reports/<id> {status: resolved|dismissed, note}
 *   POST apps/<workspace>/<app>/takedown {reason}, /restore, /clear (the phishing check's flag)
 *   POST workspaces/<workspace>/suspend {reason}, /unsuspend, /trust (may open apps to everyone before it is a day old)
 */
export async function adminApi(env: Env, request: Request, seg: string[], url: URL): Promise<Response> {
  const given = /^Bearer\s+(\S+)$/i.exec(request.headers.get('authorization') ?? '')?.[1] ?? '';
  if (!env.ADMIN_SECRET || !safeEqual(given, env.ADMIN_SECRET)) throw new Problem(401, 'unauthorized', 'The admin API needs the admin secret.');
  const m = request.method, [, what, a, b, action] = seg;
  const t = now();

  if (what === 'reports' && !a && m === 'GET') {
    const status = url.searchParams.get('status');
    if (status && !['open', 'resolved', 'dismissed'].includes(status)) throw new Problem(400, 'bad_status', 'status is open, resolved or dismissed.');
    const r = await env.DB.prepare(
      `SELECT r.id, a.slug AS app, w.slug AS workspace, r.kind, r.reporter, r.reason, r.created_at, r.status, r.resolved_at, r.note,
              a.taken_down_at, w.suspended_at FROM reports r LEFT JOIN apps a ON a.id = r.app_id LEFT JOIN workspaces w ON w.id = a.workspace_id
       WHERE (? IS NULL OR r.status = ?) ORDER BY r.created_at DESC LIMIT 200`,
    ).bind(status, status).all();
    return json({ reports: r.results });
  }
  if (what === 'reports' && a && !b && m === 'POST') {
    const o = await body(request);
    const status = String(o.status ?? 'resolved');
    if (status !== 'resolved' && status !== 'dismissed') throw new Problem(400, 'bad_status', 'status is resolved or dismissed.');
    const rep = await env.DB.prepare('SELECT r.id, r.app_id, a.workspace_id FROM reports r LEFT JOIN apps a ON a.id = r.app_id WHERE r.id = ?').bind(a)
      .first<{ id: string; app_id: string; workspace_id: string | null }>();
    if (!rep) throw new Problem(404, 'not_found', `There is no report ${a}.`);
    const note = text(o.note, 1000);
    await env.DB.batch([
      env.DB.prepare('UPDATE reports SET status = ?, resolved_at = ?, note = ? WHERE id = ?').bind(status, t, note, a),
      ...(rep.workspace_id ? [event(env, rep.workspace_id, OPERATOR, rep.app_id, `report_${status}`, `${a}${note ? `: ${note}` : ''}`)] : []),
    ]);
    return json({ report: a, status, note });
  }

  if (what === 'apps' && a && b && action && m === 'POST') {
    const app = await env.DB.prepare('SELECT a.* FROM apps a JOIN workspaces w ON w.id = a.workspace_id WHERE w.slug = ? AND a.slug = ?').bind(a, b)
      .first<AppRow & AbuseRow>();
    if (!app) throw new Problem(404, 'not_found', `There is no app ${b} in workspace ${a}.`);
    const o = await body(request);
    if (action === 'takedown') {
      const reason = text(o.reason, 500);
      if (!reason) throw new Problem(400, 'need_reason', 'Give a "reason". The owner sees it in get_status and list_apps.');
      await env.DB.batch([
        env.DB.prepare('UPDATE apps SET taken_down_at = ?, takedown_reason = ? WHERE id = ?').bind(t, reason, app.id),
        env.DB.prepare("UPDATE reports SET status = 'resolved', resolved_at = ?, note = ? WHERE app_id = ? AND status = 'open'").bind(t, `taken down: ${reason}`, app.id),
        event(env, app.workspace_id, OPERATOR, app.id, 'takedown', reason),
      ]);
      return json({ workspace: a, app: b, taken_down: true, reason });
    }
    if (action === 'restore') {
      await env.DB.batch([
        env.DB.prepare("UPDATE apps SET taken_down_at = NULL, takedown_reason = '' WHERE id = ?").bind(app.id),
        event(env, app.workspace_id, OPERATOR, app.id, 'restore', text(o.note, 500)),
      ]);
      return json({ workspace: a, app: b, taken_down: false });
    }
    if (action === 'clear') {
      const r = await env.DB.batch([
        env.DB.prepare("UPDATE versions SET scan_cleared_at = ? WHERE app_id = ? AND scan IS NOT NULL AND scan <> '[]' AND scan_cleared_at IS NULL").bind(t, app.id),
        env.DB.prepare("UPDATE reports SET status = 'resolved', resolved_at = ?, note = 'cleared' WHERE app_id = ? AND kind = 'automatic' AND status = 'open'").bind(t, app.id),
        event(env, app.workspace_id, OPERATOR, app.id, 'scan_cleared', text(o.note, 500)),
      ]);
      return json({ workspace: a, app: b, cleared_versions: r[0].meta.changes });
    }
  }

  if (what === 'workspaces' && a && b && !action && m === 'POST') {
    const w = await env.DB.prepare('SELECT id FROM workspaces WHERE slug = ?').bind(a).first<{ id: string }>();
    if (!w) throw new Problem(404, 'not_found', `There is no workspace ${a}.`);
    const o = await body(request);
    if (b === 'suspend') {
      const reason = text(o.reason, 500);
      if (!reason) throw new Problem(400, 'need_reason', 'Give a "reason". The workspace sees it in get_status and list_apps.');
      await env.DB.batch([
        env.DB.prepare('UPDATE workspaces SET suspended_at = ?, suspended_reason = ? WHERE id = ?').bind(t, reason, w.id),
        event(env, w.id, OPERATOR, null, 'suspend', reason),
      ]);
      return json({ workspace: a, suspended: true, reason });
    }
    if (b === 'unsuspend') {
      await env.DB.batch([
        env.DB.prepare("UPDATE workspaces SET suspended_at = NULL, suspended_reason = '' WHERE id = ?").bind(w.id),
        event(env, w.id, OPERATOR, null, 'unsuspend', text(o.note, 500)),
      ]);
      return json({ workspace: a, suspended: false });
    }
    if (b === 'trust') {
      await env.DB.batch([
        env.DB.prepare('UPDATE workspaces SET trusted_at = COALESCE(trusted_at, ?) WHERE id = ?').bind(t, w.id),
        event(env, w.id, OPERATOR, null, 'trust', text(o.note, 500)),
      ]);
      return json({ workspace: a, trusted: true });
    }
  }
  throw new Problem(404, 'not_found', `No such admin route: ${m} ${url.pathname}`);
}
