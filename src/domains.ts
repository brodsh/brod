// Custom domains. A workspace can serve one app at a domain it owns (shop.example.com), or point a whole domain at
// the workspace (*.apps.example.com: <app>.apps.example.com opens that app, apps.example.com the home page).
//
// A domain is claimed by a workspace, then proven with a TXT record at _brod.<domain> holding brod-verify=<token>.
// Only proven domains are served, and only one workspace can prove a name. Signing in still happens on the API host:
// /auth/app hands the one-time code only to an address that is a proven domain of that same app (see allowedHost).
import { getApp } from './control';
import { AppRow, Caller, Env, LIMITS, Problem, hostOrigin, isLocal, now, randomId } from './lib';
import { event, requireRole } from './people';

export interface DomainRow {
  id: string; hostname: string; workspace_id: string; app_id: string | null; token: string;
  verified_at: number | null; created_by: string; created_at: number;
}
type Row = DomainRow & { slug: string | null };

const LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const hostnameOf = (hostAndPort: string) => hostAndPort.split(':')[0].toLowerCase();

/** "Shop.Example.com." -> shop.example.com; "*.apps.example.com" -> apps.example.com as a wildcard. */
export function normDomain(env: Env, raw: unknown): { hostname: string; wildcard: boolean } {
  let h = String(raw ?? '').trim().toLowerCase().replace(/^https?:\/\//, '').replace(/[/?#].*$/, '').replace(/\.$/, '');
  const wildcard = h.startsWith('*.');
  if (wildcard) h = h.slice(2);
  const labels = h.split('.');
  if (h.length > 253 || labels.length < 2 || !labels.every(l => LABEL.test(l)) || /^[0-9]+$/.test(labels[labels.length - 1]))
    throw new Problem(400, 'bad_domain', `"${String(raw ?? '')}" is not a domain name. Give one like shop.example.com, or *.apps.example.com to serve every app in the workspace.`);
  for (const own of [hostnameOf(new URL(env.API_ORIGIN).host), hostnameOf(env.APPS_DOMAIN)])
    if (h === own || h.endsWith(`.${own}`)) throw new Problem(400, 'bad_domain', `${h} is one of Brod's own addresses. Use a domain you own.`);
  return { hostname: h, wildcard };
}

/** The TXT strings at a name, from a DNS-over-HTTPS resolver. null when the resolver could not be reached. */
export async function txtRecords(env: Env, name: string): Promise<string[] | null> {
  const url = new URL(env.DNS_RESOLVER_URL || 'https://cloudflare-dns.com/dns-query');
  url.searchParams.set('name', name);
  url.searchParams.set('type', 'TXT');
  try {
    const r = await fetch(url, { headers: { accept: 'application/dns-json' } });
    if (!r.ok) return null;
    const j = (await r.json()) as { Answer?: { type: number; data: string }[] };
    return (j.Answer ?? []).filter(a => a.type === 16).map(a => parseTxt(a.data));
  } catch {
    return null;
  }
}
/** A TXT record as resolvers print it: one or more quoted strings ("a" "b"), joined. */
export function parseTxt(data: string): string {
  const parts = [...data.matchAll(/"((?:[^"\\]|\\.)*)"/g)].map(m => m[1].replace(/\\(.)/g, '$1'));
  return parts.length ? parts.join('') : data;
}

function describe(env: Env, d: Row) {
  const wildcard = d.app_id === null;
  const target = env.CUSTOM_DOMAIN_TARGET || hostnameOf(new URL(env.API_ORIGIN).host);
  const verified = d.verified_at !== null;
  return {
    domain: wildcard ? `*.${d.hostname}` : d.hostname,
    kind: wildcard ? 'workspace' : 'app',
    ...(wildcard ? {} : { app: d.slug }),
    status: verified ? 'verified' : 'pending',
    url: hostOrigin(env, wildcard ? `<app>.${d.hostname}` : d.hostname),
    ...(verified ? { verified_at: new Date(d.verified_at!).toISOString() } : {}),
    dns: [
      { type: 'TXT', name: `_brod.${d.hostname}`, value: `brod-verify=${d.token}`, purpose: 'Proves the workspace owns the domain. Keep it.' },
      { type: 'CNAME', name: wildcard ? `*.${d.hostname}` : d.hostname, value: target, purpose: 'Sends visitors to Brod.' },
    ],
    next_step: verified
      ? (wildcard ? `Every app in the workspace opens at <app>.${d.hostname}.` : `The app opens at ${hostOrigin(env, d.hostname)}.`)
      : 'Add both DNS records at your DNS provider, then verify (POST /v1/domains/<domain>/verify, or set_domain again). DNS changes can take a few minutes to show. ' +
        `A bare domain such as example.com cannot have a CNAME: use your provider's ALIAS, ANAME or CNAME flattening to ${target} instead.`,
  };
}

async function find(env: Env, c: Caller, hostname: string): Promise<Row | null> {
  return env.DB.prepare('SELECT d.*, a.slug FROM domains d LEFT JOIN apps a ON a.id = d.app_id WHERE d.hostname = ? AND d.workspace_id = ?')
    .bind(hostname, c.workspace.id).first<Row>();
}
const roleFor = (c: Caller, wildcard: boolean, verb: string) =>
  requireRole(c, wildcard ? 'admin' : 'builder', wildcard ? `${verb} a domain for the whole workspace` : `${verb} custom domains`);

/** Look for the TXT record and mark the domain proven when it is there. Returns the row as it now stands. */
async function check(env: Env, c: Caller, d: Row, quiet: boolean): Promise<Row & { found?: string[] }> {
  if (d.verified_at !== null) return d;
  const found = await txtRecords(env, `_brod.${d.hostname}`);
  if (found === null) {
    if (quiet) return d;
    throw new Problem(502, 'dns_unavailable', 'The DNS lookup failed. Try verifying again in a minute.');
  }
  if (!found.some(v => v.trim() === `brod-verify=${d.token}`)) return { ...d, found };
  if (await env.DB.prepare('SELECT 1 FROM domains WHERE hostname = ? AND verified_at IS NOT NULL').bind(d.hostname).first())
    throw new Problem(409, 'domain_taken', `Another workspace has already proven it owns ${d.hostname}.`);
  const at = now();
  try {
    await env.DB.batch([
      env.DB.prepare('UPDATE domains SET verified_at = ? WHERE id = ? AND verified_at IS NULL').bind(at, d.id),
      event(env, c.workspace.id, c.actor, d.app_id, 'domain_verified', describe(env, d).domain),
    ]);
  } catch {
    throw new Problem(409, 'domain_taken', `Another workspace has already proven it owns ${d.hostname}.`);   // lost a race on domains_verified
  }
  return { ...d, verified_at: at };
}
const result = (env: Env, d: Row & { found?: string[] }) =>
  ({ ...describe(env, d), ...(d.found ? { txt_found: d.found } : {}) });

export async function listDomains(env: Env, c: Caller) {
  requireRole(c, 'builder', 'see custom domains');
  const r = await env.DB.prepare('SELECT d.*, a.slug FROM domains d LEFT JOIN apps a ON a.id = d.app_id WHERE d.workspace_id = ? ORDER BY d.hostname')
    .bind(c.workspace.id).all<Row>();
  return { workspace: c.workspace.slug, domains: r.results.map(d => describe(env, d)) };
}

/** Claim a domain for an app (give app) or, as an admin, for the whole workspace (give *.domain). */
export async function addDomain(env: Env, c: Caller, o: { domain?: unknown; app?: unknown }) {
  const { hostname, wildcard } = normDomain(env, o.domain);
  const appRef = typeof o.app === 'string' && o.app.trim() ? o.app : null;
  if (wildcard && appRef) throw new Problem(400, 'bad_domain', `*.${hostname} serves every app in the workspace, so leave out "app". To give one app a domain, name it without "*.".`);
  if (!wildcard && !appRef) throw new Problem(400, 'need_app', `Give "app" to serve one app at ${hostname}, or ask for *.${hostname} to serve every app in the workspace under it.`);
  roleFor(c, wildcard, 'add');
  const app = appRef ? await getApp(env, c, appRef) : null;
  const had = await find(env, c, hostname);
  if (had) {
    if (had.app_id !== (app?.id ?? null))
      throw new Problem(409, 'domain_in_use', `${hostname} is already set up in this workspace ${had.slug ? `for ${had.slug}` : 'for every app'}. Remove it first.`);
    return result(env, await check(env, c, had, true));
  }
  if (await env.DB.prepare('SELECT 1 FROM domains WHERE hostname = ? AND verified_at IS NOT NULL').bind(hostname).first())
    throw new Problem(409, 'domain_taken', `Another workspace has already proven it owns ${hostname}.`);
  const n = await env.DB.prepare('SELECT COUNT(*) AS n FROM domains WHERE workspace_id = ?').bind(c.workspace.id).first<{ n: number }>();
  if ((n?.n ?? 0) >= LIMITS.domainsPerWorkspace) throw new Problem(429, 'too_many_domains', `A workspace can have ${LIMITS.domainsPerWorkspace} custom domains. Remove one first.`);
  const d: Row = {
    id: randomId('dom_', 8), hostname, workspace_id: c.workspace.id, app_id: app?.id ?? null, token: randomId('', 16),
    verified_at: null, created_by: c.actor, created_at: now(), slug: app?.slug ?? null,
  };
  await env.DB.batch([
    env.DB.prepare('INSERT INTO domains (id, hostname, workspace_id, app_id, token, verified_at, created_by, created_at) VALUES (?,?,?,?,?,?,?,?)')
      .bind(d.id, d.hostname, d.workspace_id, d.app_id, d.token, null, d.created_by, d.created_at),
    event(env, c.workspace.id, c.actor, d.app_id, 'domain_added', describe(env, d).domain),
  ]);
  // The records may already be there, for example when a domain moves between apps.
  return result(env, await check(env, c, d, true));
}

async function mine(env: Env, c: Caller, domain: unknown, verb: string): Promise<Row> {
  const { hostname } = normDomain(env, domain);
  const d = await find(env, c, hostname);
  if (!d) throw new Problem(404, 'not_found', `${hostname} is not set up in this workspace. Add it first.`);
  roleFor(c, d.app_id === null, verb);
  return d;
}

export async function verifyDomain(env: Env, c: Caller, domain: unknown) {
  return result(env, await check(env, c, await mine(env, c, domain, 'verify'), false));
}

export async function removeDomain(env: Env, c: Caller, domain: unknown) {
  const d = await mine(env, c, domain, 'remove');
  const name = describe(env, d).domain;
  await env.DB.batch([env.DB.prepare('DELETE FROM domains WHERE id = ?').bind(d.id), event(env, c.workspace.id, c.actor, d.app_id, 'domain_removed', name)]);
  return { removed: name };
}

/** For set_domain: add a domain, check a pending one again, or remove one. */
export async function setDomain(env: Env, c: Caller, o: { domain?: unknown; app?: unknown; remove?: unknown }) {
  // return await: these can reject before their first await, and a promise adopted later is reported as unhandled.
  if (o.remove === true) return await removeDomain(env, c, o.domain);
  const had = await find(env, c, normDomain(env, o.domain).hostname);
  if (had && (typeof o.app !== 'string' || !o.app.trim() || o.app.trim().toLowerCase() === had.slug)) return await verifyDomain(env, c, o.domain);
  return await addDomain(env, c, o);
}

/** An app's own domains and the addresses it gets from the workspace's wildcard domains, for get_status. */
export async function appDomains(env: Env, app: AppRow) {
  const r = await env.DB.prepare('SELECT * FROM domains WHERE (app_id = ? OR (app_id IS NULL AND workspace_id = ?)) ORDER BY hostname')
    .bind(app.id, app.workspace_id).all<DomainRow>();
  return r.results.map(d => ({
    domain: d.app_id ? d.hostname : `${app.slug}.${d.hostname}`, status: d.verified_at !== null ? 'verified' : 'pending',
    url: hostOrigin(env, d.app_id ? d.hostname : `${app.slug}.${d.hostname}`),
  }));
}

// ---------- serving ----------

/** The hostname of a request's host, or null when it carries a port outside local development. */
function servedName(env: Env, host: string): string | null {
  const [name, port] = host.toLowerCase().split(':');
  return port !== undefined && !isLocal(env) ? null : name;
}

/** `staging` marks an app's staging address, <app>--staging.<workspace>; custom domains never serve staging. */
export type DomainTarget = { appId: string } | { workspace: string; slug: string; staging?: boolean } | { home: string };

/** What a custom domain serves: one app, an app under a workspace's wildcard domain, or the workspace home page. */
export async function resolveHost(env: Env, host: string): Promise<DomainTarget | null> {
  const name = servedName(env, host);
  if (!name) return null;
  const dot = name.indexOf('.');
  const first = name.slice(0, dot), parent = name.slice(dot + 1);
  const d = await env.DB.prepare(
    `SELECT d.hostname, d.app_id, w.slug AS wslug FROM domains d JOIN workspaces w ON w.id = d.workspace_id
     WHERE d.verified_at IS NOT NULL AND (d.hostname = ? OR (d.hostname = ? AND d.app_id IS NULL)) ORDER BY length(d.hostname) DESC LIMIT 1`,
  ).bind(name, parent).first<{ hostname: string; app_id: string | null; wslug: string }>();
  if (!d) return null;
  if (d.hostname === name) return d.app_id ? { appId: d.app_id } : { home: d.wslug };
  return LABEL.test(first) ? { workspace: d.wslug, slug: first } : null;
}

/** Whether `host` is a proven address of this app, so a sign-in for it may be handed there. */
export async function allowedHost(env: Env, app: AppRow, host: string): Promise<boolean> {
  const name = servedName(env, host);
  if (!name) return false;
  const dot = name.indexOf('.');
  const r = await env.DB.prepare(
    `SELECT 1 FROM domains WHERE verified_at IS NOT NULL AND ((hostname = ? AND app_id = ?) OR (hostname = ? AND app_id IS NULL AND workspace_id = ? AND ? = ?))`,
  ).bind(name, app.id, name.slice(dot + 1), app.workspace_id, name.slice(0, dot), app.slug).first();
  return !!r;
}
