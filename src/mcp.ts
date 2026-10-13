// MCP endpoint (Streamable HTTP, stateless, JSON responses). Each tool is a thin wrapper over the control plane.
import { resourceMetadataUrl } from './connect';
import * as cp from './control';
import { BundleFile, Caller, Env, LIMITS, Problem, json } from './lib';
import { setDomain } from './domains';
import { describeWorkspace } from './people';

const VERSIONS = ['2025-06-18', '2025-03-26', '2024-11-05'];
const text = (v: unknown) => (typeof v === 'string' ? v : JSON.stringify(v, null, 2));

const str = (description: string) => ({ type: 'string', description });
const appArg = { app: str('The app\'s short name (slug), as shown by list_apps.') };
const grantItem = {
  type: 'object',
  description: 'Exactly one of email, group, domain or everyone, plus a role.',
  properties: {
    email: str('A person already in the workspace.'), group: str('A workspace group name, for example "finance".'),
    domain: str('An email domain, for example "example.com".'), everyone: { type: 'string', enum: ['workspace', 'signed_in'] },
    role: str('One of the app\'s roles (default owner, editor, viewer).'),
  },
};

const TOOLS = [
  {
    name: 'deploy_app',
    title: 'Deploy an app',
    description:
      'Put a web app online and get its address back, or publish a new version of an existing app. ' +
      'For a small app (up to 1 MB total), pass its files directly in "files". ' +
      'For anything larger, call this WITHOUT "files": you get a one-time upload address and a one-line command that uploads the built output folder (such as dist/ or build/). ' +
      'Give "name" to create a new app, or "app" to add a version to an existing one. New apps start private to their owner; use set_access to share them (with people or groups, the workspace, or anyone who has a password). ' +
      'Static files are served as they are. For server code, include "_worker.js" (or a "_worker/" folder with index.js): an ES module with ' +
      '`export default { async fetch(request, env, ctx) { ... } }`. Files that exist in the bundle are served directly; every other request goes to fetch. ' +
      'Inside fetch, env holds the app\'s secrets (set_secret) plus its own storage: env.DB (SQLite: await env.DB.query(sql, params) returns rows, await env.DB.run(sql, params), ' +
      'await env.DB.batch([{sql, params}]) in one transaction), env.KV (get, put, delete, list; string values) and env.FILES (put(key, body, contentType), get(key) returns a Response or null, delete, list(prefix)). ' +
      'The signed-in person arrives as request headers x-brod-user-id, x-brod-user-email, x-brod-role and x-brod-groups (the platform strips any a visitor sends). ' +
      'Never build a login or user table. A version whose server code does not start is refused, and the live version stays. Use get_logs to see console output and errors. ' +
      'STAGING: when you update an app that already has a live version, ask the person first whether to try it on staging before it goes live (recommended) or to publish straight away. ' +
      'Updates to a live app go to staging unless "environment" is "production": the result\'s staging_url serves the new version to the app\'s builders only, while visitors keep the live one. ' +
      'Give the person the staging_url to test, and call publish_staging only once they say it is ready. Staging and live share the app\'s data (env.DB, env.KV, env.FILES) and secrets. ' +
      'SEVERAL PEOPLE: others may update the same app. When updating, pass "base_version": the version your files started from (the "version" your last deploy_app returned, or "current_version" from get_status when you began). ' +
      'If someone deployed since, nothing is deployed and the error stale_base says who changed what: call get_files for the current version, add your changes to it, and deploy again; do not deploy over their work unless the person says to. ' +
      'If the result has a "warning", someone else is also working on the app: tell the person.',
    inputSchema: {
      type: 'object',
      properties: {
        name: str('Name for a NEW app, for example "Reading list". The address is derived from it.'),
        app: str('Slug of an EXISTING app to publish a new version of.'),
        note: str('One line on what this version is or what changed.'),
        environment: {
          type: 'string', enum: ['staging', 'production'],
          description: 'Where this version goes. "staging": only to the app\'s staging address for testing; the live version is unchanged. "production": live at once. Default: staging when updating an app that is already live, production for a new app.',
        },
        base_version: {
          type: 'integer', minimum: 1,
          description: 'For an update: the version your files started from. The deploy is refused (stale_base) if the app\'s current version (staging, else live) is no longer this one, so you never undo someone else\'s changes.',
        },
        files: {
          type: 'array', description: 'The app\'s files, for small apps. Must include index.html at the top level.',
          items: { type: 'object', properties: { path: str('Path inside the app, for example "index.html" or "assets/app.js".'), content: str('File content.'), encoding: { type: 'string', enum: ['utf8', 'base64'], description: 'How content is encoded. Default utf8.' } }, required: ['path', 'content'] },
        },
      },
    },
    annotations: { readOnlyHint: false, destructiveHint: false, openWorldHint: true },
  },
  { name: 'list_apps', title: 'List apps', description: 'List the workspace\'s apps with address, status, who can open each, live version, plus how many plan slots are in use.', inputSchema: { type: 'object', properties: {} }, annotations: { readOnlyHint: true } },
  {
    name: 'get_files', title: 'Get an app\'s files',
    description: 'Get the files of an app\'s current version (the one on staging, else the live one), or of the "version" you name, to change them. ' +
      'Call this before changing an app someone else may have changed, so you start from what is deployed rather than an older copy, then deploy_app with "base_version" set to the "version" returned. ' +
      'Small apps come back inline in "files" (base64 when "encoding" says so); larger ones as a download_url with a one-line curl | tar command. ' +
      'The files are the built output as deployed. If the result has a "warning", someone else is working on the app too: tell the person.',
    inputSchema: { type: 'object', properties: { ...appArg, version: { type: 'integer', minimum: 1, description: 'A version number. Default: the current version.' } }, required: ['app'] },
    annotations: { readOnlyHint: true },
  },
  { name: 'get_status', title: 'App status', description: 'Show one app: address, status, access, roles, who it is shared with, its versions with which one is live, and what is on staging (version and address).', inputSchema: { type: 'object', properties: appArg, required: ['app'] }, annotations: { readOnlyHint: true } },
  {
    name: 'get_logs', title: 'App activity and logs',
    description: 'Show one app\'s recent activity (deploys, rollbacks, access changes, sign-in refusals, pauses, and which connection or person made each) ' +
      'and, for server apps, its last 50 requests with their console output and exceptions (kept 7 days). Use "search" to find requests whose logs, errors or path contain some text.',
    inputSchema: { type: 'object', properties: { ...appArg, search: str('Only requests whose logs, exceptions or path contain this text.') }, required: ['app'] },
    annotations: { readOnlyHint: true },
  },
  {
    name: 'set_secret', title: 'Set a secret',
    description: 'Store a secret for an app\'s server code, such as an API key. The app reads it as env.NAME from its next request. Values are encrypted and write-only: ' +
      'nobody, you included, can read one back. get_status lists the names. Give "remove": true instead of a value to delete one.',
    inputSchema: {
      type: 'object',
      properties: { ...appArg, name: str('UPPER_SNAKE_CASE name, for example "STRIPE_KEY".'), value: str('The secret value, up to 5 KB.'), remove: { type: 'boolean', description: 'Delete this secret.' } },
      required: ['app', 'name'],
    },
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true },
  },
  {
    name: 'publish_staging', title: 'Publish staging',
    description: 'Make the version on an app\'s staging address live, after the person has tried it there and said it is ready. Takes effect on the next request. ' +
      'Give "discard": true instead to take it off staging without publishing (the version is kept; rollback can still serve it). get_status shows what is on staging.',
    inputSchema: { type: 'object', properties: { ...appArg, discard: { type: 'boolean', description: 'Take the version off staging instead of publishing it.' } }, required: ['app'] },
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false },
  },
  { name: 'rollback', title: 'Roll back', description: 'Make an earlier version live again. Takes effect on the next request and rebuilds nothing. Use get_status to see version numbers.', inputSchema: { type: 'object', properties: { ...appArg, version: { type: 'integer', description: 'Version number to serve.' } }, required: ['app', 'version'] }, annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true } },
  {
    name: 'set_access', title: 'Change who can open an app',
    description: 'Set an app\'s access mode and who holds which app role. Modes: "private" (owner and admins only), "people" (only granted people and groups), "workspace" (everyone in the workspace), ' +
      '"password" (anyone with the address and the password, no sign-in or account needed: give "password" too), "signed_in" (anyone who signs in), "public" (anyone, no sign-in). ' +
      'To share an app quietly with people outside the workspace, use "password": visitors see a password page, and the address plus the password is all they need. Brod keeps only a hash, so tell the owner the password you set; ' +
      'setting a new one signs out everyone who used the old one, and moving the app to another mode removes it. Grants give a person (by email, must already be in the workspace), a group, an email domain, or everyone ("workspace"/"signed_in") one of the app\'s roles. ' +
      'Narrowing access applies at once. Widening it (a more open mode, new grants or a new password) does NOT apply yet: the result has a confirm_url the owner must open and confirm. Give them that link.',
    inputSchema: {
      type: 'object',
      properties: {
        ...appArg,
        access: { type: 'string', enum: ['private', 'people', 'workspace', 'password', 'signed_in', 'public'] },
        password: str('With "access": "password": the password to share the app with, 6 to 128 characters. Giving it alone switches the app to "password".'),
        add: { type: 'array', description: 'Grants to add or change.', items: grantItem },
        remove: { type: 'array', description: 'Grants to remove (role is ignored).', items: grantItem },
      },
      required: ['app'],
    },
    annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: true },
  },
  { name: 'set_paused', title: 'Pause or resume', description: 'Pause an app (visitors see a "paused" page and its plan slot is freed) or resume it.', inputSchema: { type: 'object', properties: { ...appArg, paused: { type: 'boolean' } }, required: ['app', 'paused'] }, annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true } },
  {
    name: 'invite', title: 'Invite someone',
    description: 'Invite a person by email: into the workspace (role admin, builder or member), or as a guest to one app (give "app" and optionally "app_role"). Someone already in the workspace who is given an app just gets the role on it. ' +
      'This needs the owner\'s confirmation: the result has a confirm_url to give them. The invitation email goes out once they confirm.',
    inputSchema: {
      type: 'object',
      properties: {
        email: str('Their email address.'),
        role: { type: 'string', enum: ['admin', 'builder', 'member', 'guest'], description: 'Workspace role. Default member, or guest when "app" is given.' },
        app: str('Slug of an app to give them.'),
        app_role: str('Their role on that app, one of the roles the app declares. Default its lowest role.'),
      },
      required: ['email'],
    },
    annotations: { readOnlyHint: false, destructiveHint: false, openWorldHint: true },
  },
  {
    name: 'set_domain', title: 'Custom domain',
    description: 'Serve an app at a domain the workspace owns, such as "shop.example.com" (give "app"), or every app in the workspace under a domain, such as "*.apps.example.com" ' +
      '(<app>.apps.example.com opens that app; admins only). The result lists two DNS records the owner must add: a TXT record that proves they own the domain, and a CNAME that sends visitors to Brod. ' +
      'Call set_domain again with the same domain once the records are in to check them; the domain is served only after it is verified. Sign-in, roles and access work the same as on the app\'s own address. ' +
      'Give "remove": true to stop serving a domain. get_status lists an app\'s domains.',
    inputSchema: {
      type: 'object',
      properties: { domain: str('The domain, for example "shop.example.com", or "*.apps.example.com" for the whole workspace.'), app: str('Slug of the app to serve there. Leave out for a "*." domain.'), remove: { type: 'boolean', description: 'Stop serving this domain.' } },
      required: ['domain'],
    },
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: true },
  },
  {
    name: 'get_workspace', title: 'Workspace and identity',
    description: 'Read the workspace an app will live in: its groups, the default app roles, the access modes, plan slots, and how an app reads the signed-in person (the identity contract). ' +
      'Call this before building an app that needs sign-in or roles: apps never keep their own user table.',
    inputSchema: { type: 'object', properties: {} }, annotations: { readOnlyHint: true },
  },
];

function inlineFiles(raw: unknown): BundleFile[] {
  if (!Array.isArray(raw)) throw new Problem(400, 'bad_files', '"files" must be a list of { path, content }.');
  const enc = new TextEncoder();
  let total = 0;
  const out = raw.map((f: any) => {
    if (typeof f?.path !== 'string' || typeof f?.content !== 'string') throw new Problem(400, 'bad_files', 'Each file needs a "path" and a "content" string.');
    let bytes: Uint8Array;
    if (f.encoding === 'base64') { try { bytes = Uint8Array.from(atob(f.content), ch => ch.charCodeAt(0)); } catch { throw new Problem(400, 'bad_files', `${f.path} is not valid base64.`); } }
    else bytes = enc.encode(f.content);
    total += bytes.byteLength;
    return { path: f.path, bytes };
  });
  if (total > LIMITS.inlineBytes) throw new Problem(413, 'too_large', 'Files passed inline can total 1 MB. Call deploy_app without "files" to get an upload address for larger apps.');
  return out;
}

async function call(env: Env, c: Caller, name: string, a: Record<string, any>): Promise<unknown> {
  switch (name) {
    case 'deploy_app':
      return a.files === undefined
        ? cp.createUpload(env, c, { app: a.app, name: a.name, note: a.note, environment: a.environment, base_version: a.base_version })
        : cp.deploy(env, c, { app: a.app, name: a.name, note: a.note, environment: a.environment, base_version: a.base_version, files: inlineFiles(a.files) });
    case 'list_apps': return cp.listApps(env, c);
    case 'get_status': return cp.getStatus(env, c, String(a.app ?? ''));
    case 'get_logs': return cp.getLogs(env, c, String(a.app ?? ''), a.search ? String(a.search) : null);
    case 'set_secret':
      if (a.remove !== true && typeof a.value !== 'string') throw new Problem(400, 'bad_value', 'Give "value", or "remove": true to delete the secret.');
      return cp.setSecret(env, c, String(a.app ?? ''), String(a.name ?? ''), a.remove === true ? null : a.value);
    case 'get_files': return cp.getFiles(env, c, String(a.app ?? ''), a.version);
    case 'publish_staging': return a.discard === true ? cp.discardStaging(env, c, String(a.app ?? '')) : cp.publishStaging(env, c, String(a.app ?? ''));
    case 'rollback': return cp.rollback(env, c, String(a.app ?? ''), Number(a.version));
    case 'set_access': return cp.setAccess(env, c, String(a.app ?? ''), { access: a.access, add: a.add, remove: a.remove, password: a.password });
    case 'set_paused': return cp.setPaused(env, c, String(a.app ?? ''), a.paused === true);
    case 'invite': return cp.inviteFrom(env, c, { email: a.email, role: a.role, app: a.app, app_role: a.app_role });
    case 'set_domain': return await setDomain(env, c, a);
    case 'get_workspace': return describeWorkspace(env, c);
    default: throw new Problem(404, 'unknown_tool', `There is no tool called "${name}".`);
  }
}

type Rpc = { jsonrpc?: string; id?: string | number | null; method?: string; params?: any };

async function handle(env: Env, c: Caller, m: Rpc): Promise<object | null> {
  const reply = (result: unknown) => ({ jsonrpc: '2.0', id: m.id, result });
  if (m.id === undefined || m.id === null) return null;   // notifications get no reply
  switch (m.method) {
    case 'initialize':
      return reply({
        protocolVersion: VERSIONS.includes(m.params?.protocolVersion) ? m.params.protocolVersion : VERSIONS[0],
        capabilities: { tools: { listChanged: false } },
        serverInfo: { name: 'brod', title: 'Brod', version: '0.2.0' },
        instructions: 'Brod puts small web apps online inside a team workspace with one sign-in. Call get_workspace before building an app that needs to know who is using it: ' +
          'the platform signs people in and the app reads them from /_brod/me, so never build a login or user table. Use deploy_app to publish and return the address. ' +
          'Apps start private. To share one with people outside the workspace without accounts, set_access with "access": "password" and a password, then give them the address and the password. ' +
          'Sharing more widely and inviting people need the owner to confirm: pass on the confirm_url you get back. ' +
          'Once an app is live, ask before changing it whether to deploy to staging first: updates go to its staging address, the person tests there, and publish_staging makes it live. ' +
          'Other people may change the same app: before changing one, call get_files for its current version, and pass base_version (the version your files started from) to deploy_app, so a deploy never undoes someone else\'s. ' +
          'When a result has a "warning" that someone else is working on the app, tell the person.',
      });
    case 'ping': return reply({});
    case 'tools/list': return reply({ tools: TOOLS });
    case 'tools/call': {
      try {
        const result = await call(env, c, String(m.params?.name ?? ''), m.params?.arguments ?? {});
        return reply({ content: [{ type: 'text', text: text(result) }], structuredContent: result, isError: false });
      } catch (e) {
        if (!(e instanceof Problem)) { console.error(e); return reply({ content: [{ type: 'text', text: 'Something went wrong on our side. Try again.' }], isError: true }); }
        // Tool errors go back as results the agent can read and act on, not as protocol errors.
        return reply({ content: [{ type: 'text', text: text({ error: e.code, message: e.message, ...e.extra }) }], isError: true });
      }
    }
    default: return { jsonrpc: '2.0', id: m.id, error: { code: -32601, message: `Method not found: ${m.method}` } };
  }
}

export async function serveMcp(env: Env, request: Request): Promise<Response> {
  if (request.method !== 'POST') return json({ error: { code: 'method_not_allowed', message: 'This MCP endpoint takes POST requests only.' } }, 405, { allow: 'POST' });
  let caller: Caller;
  try { caller = await cp.authenticate(env, request); }
  catch (e) { return json({ jsonrpc: '2.0', id: null, error: { code: -32001, message: (e as Error).message } }, 401, { 'www-authenticate': `Bearer realm="brod", resource_metadata="${resourceMetadataUrl(env)}"` }); }
  let body: unknown;
  try { body = await request.json(); } catch { return json({ jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } }, 400); }
  if (Array.isArray(body)) {
    const replies = (await Promise.all(body.map(m => handle(env, caller, m)))).filter(Boolean);
    return replies.length ? json(replies) : new Response(null, { status: 202 });
  }
  const r = await handle(env, caller, body as Rpc);
  return r ? json(r) : new Response(null, { status: 202 });
}
