// One Worker, three jobs, split by hostname and path:
//   <slug>.<APPS_DOMAIN>  -> gateway (signs people in, decides access, serves an app)
//   a proven custom domain -> the same gateway (domains.ts)
//   anything else, /mcp   -> MCP endpoint for agents
//   anything else, /v1/*  -> REST control-plane API (agents with a token, the dashboard with a session)
//   anything else         -> sign-in, invitations, confirmations and workspace home pages,
//                            the connections page and OAuth sign-in for agents (connect.ts)
import { adminApi } from './abuse';
import { serveAuth } from './auth';
import { serveConnect } from './connect';
import * as cp from './control';
import * as dm from './domains';
import { serveApp } from './gateway';
import { BundleFile, Env, LIMITS, Problem, STAGING_SUFFIX, json, notFound, notice, problemResponse, readCapped, redirect } from './lib';
import { serveMcp } from './mcp';
import * as pp from './people';
import { takeStaged } from './platform/uploads';
import { unpack } from './tar';

// Durable Object and entrypoints that server apps reach through the Worker Loader (see runtime.ts).
export { AppData, AppDatabase, AppFiles, AppKV, AppLogs } from './runtime';

async function body(request: Request): Promise<Record<string, any>> {
  try { const b = await request.json(); return b && typeof b === 'object' ? (b as Record<string, any>) : {}; }
  catch { throw new Problem(400, 'bad_json', 'The request body must be JSON.'); }
}

function decodeFiles(raw: unknown): BundleFile[] {
  if (!Array.isArray(raw)) throw new Problem(400, 'bad_files', '"files" must be a list of { path, content }.');
  const enc = new TextEncoder();
  let total = 0;
  const files = raw.map((f: any) => {
    let bytes: Uint8Array;
    if (f?.encoding === 'base64') { try { bytes = Uint8Array.from(atob(String(f.content)), ch => ch.charCodeAt(0)); } catch { throw new Problem(400, 'bad_files', `${f?.path} is not valid base64.`); } }
    else bytes = enc.encode(String(f?.content ?? ''));
    total += bytes.byteLength;
    return { path: String(f?.path ?? ''), bytes };
  });
  if (total > LIMITS.inlineBytes) throw new Problem(413, 'too_large', 'Files passed inline can total 1 MB. Leave out "files" to get an upload address for larger apps.');
  return files;
}

async function deployUpload(env: Env, id: string, archive: Uint8Array): Promise<Response> {
  const files = await unpack(archive);
  const u = await cp.claimUpload(env, id);
  try { return json(await cp.deploy(env, u.caller, { app: u.app, name: u.name, note: u.note, environment: u.environment, base_version: u.base_version, files }), 201); }
  catch (e) { await cp.releaseUpload(env, id); throw e; }   // a refused deploy leaves the address usable
}

async function api(env: Env, request: Request, url: URL): Promise<Response> {
  const p = url.pathname.replace(/\/+$/, ''), m = request.method;
  const seg = p.split('/').slice(2).map(decodeURIComponent);   // after /v1

  // A one-time upload address is its own credential, so it is checked before sign-in.
  if (seg[0] === 'uploads' && seg[1] && !seg[2] && m === 'PUT') {
    if (Number(request.headers.get('content-length') ?? 0) > LIMITS.bundleBytes) throw new Problem(413, 'too_large', 'The bundle is larger than 25 MB.');
    return deployUpload(env, seg[1], await readCapped(request.body, LIMITS.bundleBytes, 'The bundle'));
  }
  // Where the archive went straight to the bucket (hosts with a small request limit, see platform/uploads.ts), deploy it from there.
  if (seg[0] === 'uploads' && seg[1] && seg[2] === 'finish' && m === 'POST') return deployUpload(env, seg[1], await takeStaged(env, seg[1]));

  // A download address, like an upload address, is its own credential.
  if (seg[0] === 'downloads' && seg[1] && !seg[2] && m === 'GET') {
    const d = await cp.download(env, seg[1]);
    return new Response(d.body, { headers: { 'content-type': 'application/gzip', 'content-disposition': `attachment; filename="${d.name}"`, 'cache-control': 'no-store' } });
  }

  // The platform operator's API: the report queue, takedowns, suspensions (abuse.ts).
  if (seg[0] === 'admin') return await adminApi(env, request, seg, url);

  // Routes for a signed-in person before they pick a workspace.
  if ((seg[0] === 'me' && m === 'GET') || (seg[0] === 'workspaces' && m === 'POST')) {
    const who = await cp.person(env, request);
    if (!who) throw new Problem(401, 'unauthorized', 'Sign in first.');
    cp.checkOrigin(env, request);
    if (seg[0] === 'me') return json({ user: who.user, workspaces: await pp.myWorkspaces(env, who.user) });
    const b = await body(request);
    return json(await pp.createWorkspace(env, who.user, String(b.name ?? ''), b.accept_terms === true), 201);
  }

  const c = await cp.authenticate(env, request);
  const getApp = (s: string) => cp.getApp(env, c, s);
  switch (seg[0]) {
    case 'workspace':
      if (m === 'GET') return json(await pp.describeWorkspace(env, c));
      if (m === 'PATCH') return json(await pp.updateWorkspace(env, c, await body(request)));
      break;
    case 'people':
      if (m === 'GET' && !seg[1]) return json(await pp.listPeople(env, c));
      if (m === 'PATCH' && seg[1]) return json(await pp.setPersonRole(env, c, seg[1], String((await body(request)).role ?? '')));
      if (m === 'DELETE' && seg[1]) return json(await pp.removePerson(env, c, seg[1]));
      break;
    case 'invites':
      if (m === 'GET' && !seg[1]) return json(await pp.listInvites(env, c));
      if (m === 'POST' && !seg[1]) return json(await cp.inviteFrom(env, c, await body(request)), 201);
      if (m === 'DELETE' && seg[1]) return json(await pp.revokeInvite(env, c, seg[1]));
      break;
    case 'groups':
      if (m === 'GET' && !seg[1]) return json(await pp.listGroups(env, c));
      if (m === 'POST' && !seg[1]) return json(await pp.createGroup(env, c, String((await body(request)).name ?? '')), 201);
      if (m === 'DELETE' && seg[1] && !seg[2]) return json(await pp.deleteGroup(env, c, seg[1]));
      if (seg[1] && seg[2] === 'members') {
        if (m === 'POST' && !seg[3]) return json(await pp.setGroupMember(env, c, seg[1], String((await body(request)).email ?? ''), true));
        if (m === 'DELETE' && seg[3]) return json(await pp.setGroupMember(env, c, seg[1], seg[3], false));
      }
      break;
    case 'tokens':
      if (m === 'GET' && !seg[1]) return json({ connections: await cp.listTokens(env, c) });
      if (m === 'POST' && !seg[1]) return json(await cp.createToken(env, c, String((await body(request)).name ?? '')), 201);
      if (m === 'DELETE' && seg[1]) { await cp.revokeToken(env, c, seg[1]); return json({ revoked: seg[1] }); }
      break;
    case 'events':
      if (m === 'GET') return json(await cp.listEvents(env, c, { app: url.searchParams.get('app'), action: url.searchParams.get('action'), limit: Number(url.searchParams.get('limit')) }));
      break;
    case 'deploys':
      if (m === 'POST') {
        const b = await body(request);
        if (b.files === undefined) return json(await cp.createUpload(env, c, b), 201);
        return json(await cp.deploy(env, c, { app: b.app, name: b.name, note: b.note, environment: b.environment, base_version: b.base_version, files: decodeFiles(b.files) }), 201);
      }
      break;
    case 'domains':
      if (m === 'GET' && !seg[1]) return json(await dm.listDomains(env, c));
      if (m === 'POST' && !seg[1]) return json(await dm.addDomain(env, c, await body(request)), 201);
      if (m === 'POST' && seg[1] && seg[2] === 'verify') return json(await dm.verifyDomain(env, c, seg[1]));
      if (m === 'DELETE' && seg[1] && !seg[2]) return json(await dm.removeDomain(env, c, seg[1]));
      break;
    case 'apps': {
      const slug = seg[1], action = seg[2];
      if (!slug && m === 'GET') return json(await cp.listApps(env, c));
      if (slug && !action && m === 'GET') return json(await cp.getStatus(env, c, slug));
      if (slug && !action && m === 'PATCH') return json(await cp.updateApp(env, c, slug, await body(request)));
      if (slug && !action && m === 'DELETE') return json(await cp.deleteApp(env, c, slug));
      if (slug && action === 'files' && m === 'GET') return json(await cp.getFiles(env, c, slug, url.searchParams.get('version')));
      if (slug && action === 'logs' && m === 'GET') return json(await cp.getLogs(env, c, slug, url.searchParams.get('search')));
      if (slug && action === 'secrets' && !seg[3] && m === 'GET') return json(await cp.getStatus(env, c, slug).then(s => ({ app: s.app, secrets: s.secrets })));
      if (slug && action === 'secrets' && seg[3] && m === 'PUT') return json(await cp.setSecret(env, c, slug, seg[3], String((await body(request)).value ?? '')));
      if (slug && action === 'secrets' && seg[3] && m === 'DELETE') return json(await cp.setSecret(env, c, slug, seg[3], null));
      if (slug && action === 'access' && m === 'GET') { const app = await getApp(slug); return json({ access: app.access, shared_with: await pp.listGrants(env, app) }); }
      if (slug && action === 'staging' && !seg[3] && m === 'DELETE') return json(await cp.discardStaging(env, c, slug));
      if (slug && m === 'POST') {
        if (action === 'publish') return json(await cp.publishStaging(env, c, slug));
        if (action === 'rollback') return json(await cp.rollback(env, c, slug, Number((await body(request)).version)));
        if (action === 'access') return json(await cp.setAccess(env, c, slug, await body(request)));
        if (action === 'pause') return json(await cp.setPaused(env, c, slug, true));
        if (action === 'resume') return json(await cp.setPaused(env, c, slug, false));
      }
      break;
    }
  }
  throw new Problem(404, 'not_found', `No such API route: ${m} ${p}`);
}

/** The labels in front of APPS_DOMAIN ("todo.acme.<APPS_DOMAIN>" -> ["todo", "acme"]), [] for a malformed one, null for any other host. */
function appLabels(env: Env, host: string): string[] | null {
  const suffix = '.' + env.APPS_DOMAIN.toLowerCase();
  if (!host.endsWith(suffix)) return null;
  const labels = host.slice(0, -suffix.length).split('.');
  return labels.every(l => /^[a-z0-9-]{1,63}$/.test(l)) ? labels : [];
}

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    try {
      const url = new URL(request.url);
      const host = url.host.toLowerCase(), labels = appLabels(env, host);
      if (labels && host !== new URL(env.API_ORIGIN).host) {
        // <app>.<workspace>.<APPS_DOMAIN> is an app. <workspace>.<APPS_DOMAIN> and www go to the workspace home and the front page.
        if (labels.length === 2) {
          // <app>--staging.<workspace> is the app's staging address.
          const staging = labels[0].endsWith(STAGING_SUFFIX) && labels[0].length > STAGING_SUFFIX.length;
          return await serveApp(env, request, { workspace: labels[1], slug: staging ? labels[0].slice(0, -STAGING_SUFFIX.length) : labels[0], staging }, ctx);
        }
        if (labels.length === 1) return redirect(labels[0] === 'www' ? env.API_ORIGIN : `${env.API_ORIGIN}/w/${labels[0]}`);
        return notFound(env);
      }
      if (host !== new URL(env.API_ORIGIN).host) {
        // A custom domain a workspace has proven it owns (domains.ts).
        const target = await dm.resolveHost(env, host);
        if (target && 'home' in target) return redirect(`${env.API_ORIGIN}/w/${target.home}`);
        if (target) return await serveApp(env, request, target, ctx, url.host);
      }
      if (url.pathname === '/mcp') return await serveMcp(env, request);
      // HEAD on the API host is GET without the body (uptime monitors and link previews use it): the same status,
      // redirects, cookies and headers, and the length of the body that was left out. App hosts answer HEAD in gateway.ts.
      if (request.method === 'HEAD') return withoutBody(await apiHost(env, new Request(request, { method: 'GET' }), url));
      return await apiHost(env, request, url);
    } catch (e) {
      return problemResponse(e);
    }
  },
} satisfies ExportedHandler<Env>;

/** A response for HEAD: the headers of the GET response, with content-length when the body's size is known. */
async function withoutBody(res: Response): Promise<Response> {
  const headers = new Headers(res.headers);
  if (res.body && !headers.has('content-length')) headers.set('content-length', String((await res.arrayBuffer()).byteLength));
  else await res.body?.cancel();
  return new Response(null, { status: res.status, statusText: res.statusText, headers });
}

async function apiHost(env: Env, request: Request, url: URL): Promise<Response> {
  try {
    if (url.pathname.startsWith('/v1/')) return await api(env, request, url);
    if (url.pathname === '/healthz') return json({ service: 'brod', ok: true, mcp: `${url.origin}/mcp`, api: `${url.origin}/v1` });
    try { return (await serveConnect(env, request, url)) ?? (await serveAuth(env, request, url)) ?? json({ error: { code: 'not_found', message: 'Nothing here.' } }, 404); }
    catch (e) {
      // People filling in a form get a page, not JSON.
      if (e instanceof Problem && !(request.headers.get('content-type') ?? '').includes('application/json'))
        return notice(e.status, 'Something needs attention', e.message, '<p><a href="/">Back</a></p>');
      throw e;
    }
  } catch (e) {
    return problemResponse(e);
  }
}
