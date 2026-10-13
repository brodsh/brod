// Shared types and small helpers.
import type { AppData } from './runtime';

export interface Env {
  DB: D1Database;
  BUNDLES: R2Bucket;
  LOADER: WorkerLoader;                         // runs server apps
  APP_DATA: DurableObjectNamespace<AppData>;    // one database per server app
  SECRETS_KEY: string;
  APPS_DOMAIN: string;
  API_ORIGIN: string;
  ADMIN_SECRET: string;
  IDENTITY_SECRET: string;
  DEV_MODE?: string;          // "1" locally: sign-in links are returned in responses instead of emailed
  RESEND_API_KEY?: string;
  EMAIL_FROM?: string;
  GOOGLE_CLIENT_ID?: string;
  GOOGLE_CLIENT_SECRET?: string;
  DNS_RESOLVER_URL?: string;     // DNS-over-HTTPS (JSON) endpoint that checks custom domains; default Cloudflare's
  CUSTOM_DOMAIN_TARGET?: string; // the name custom domains point their CNAME at; default the API host
  HOST?: Host;                // set only off Cloudflare (src/node); absent on the Worker
}

/**
 * What a host other than Cloudflare can do. Server apps (step 3) are Cloudflare-only: code that runs app servers
 * should check `env.HOST?.serverApps === false` and refuse with a Problem that says this host serves static apps only.
 */
export interface Host {
  name: string;               // "vercel" or "node"
  serverApps: boolean;
  /** A presigned PUT straight to the file store, for hosts whose request-body limit is below LIMITS.bundleBytes. */
  presignPut?: (key: string, expiresSec: number) => Promise<string>;
}

export type Role = 'admin' | 'builder' | 'member' | 'guest';
export type Access = 'private' | 'people' | 'workspace' | 'password' | 'signed_in' | 'public';
/** Access modes, least open first. Moving right is widening, which an agent needs a person to confirm. */
export const ACCESS: Access[] = ['private', 'people', 'workspace', 'password', 'signed_in', 'public'];

export interface User { id: string; email: string; name: string; email_verified_at: number | null }
export interface Workspace { id: string; slug: string; name: string; plan: string; color: string; icon: string; created_at: number }
export interface AppRow {
  id: string; workspace_id: string; owner_id: string; slug: string; name: string; title: string; welcome: string;
  status: 'live' | 'paused'; access: Access; roles: string; live_version: number | null; created_at: number; secrets_rev?: number;
  password_hash?: string | null;
  /** The version waiting on staging (<slug>--staging.<workspace>), if any. It goes live with publishStaging. */
  staging_version?: number | null;
}
export interface VersionRow { app_id: string; n: number; note: string; actor: string; file_count: number; bytes: number; created_at: number }
export interface EventRow { at: number; actor: string; action: string; detail: string; app_id?: string | null }
/** Who is acting: a person signed in to the dashboard, or an agent connection acting for the person who made it. */
export interface Caller { workspace: Workspace; user: User; role: Role; actor: string; agent: boolean }
export interface BundleFile { path: string; bytes: Uint8Array }

/** An error the caller can act on. `code` is stable; `message` is written for a person or an agent. */
export class Problem extends Error {
  constructor(public status: number, public code: string, message: string, public extra: Record<string, unknown> = {}) { super(message); }
}

export const LIMITS = {
  bundleBytes: 25 * 1024 * 1024,   // compressed upload
  unpackedBytes: 60 * 1024 * 1024,
  fileBytes: 10 * 1024 * 1024,
  files: 2000,
  inlineBytes: 1024 * 1024,        // files passed directly in a tool call
  deploysPerHour: 30,
  uploadTtlMs: 15 * 60 * 1000,
  downloadTtlMs: 15 * 60 * 1000,
  editingWindowMs: 2 * 3600 * 1000,  // how long after someone last worked on an app others are told
  loginLinkTtlMs: 15 * 60 * 1000,
  loginLinksPerHour: 5,            // per email address
  inviteTtlMs: 7 * 24 * 3600 * 1000,
  sessionTtlMs: 30 * 24 * 3600 * 1000,
  appCodeTtlMs: 60 * 1000,
  confirmTtlMs: 24 * 3600 * 1000,
  oauthCodeTtlMs: 10 * 60 * 1000,
  oauthClientsPerHour: 100,       // MCP clients registering themselves, across the server
  identityTtlSec: 300,
  serverCpuMs: 50,                 // per request, for an app's server code
  serverSubrequests: 50,
  logBytes: 8 * 1024,              // per request, for its console output and exceptions
  logRetentionMs: 7 * 24 * 3600 * 1000,
  domainsPerWorkspace: 50,         // custom domains, proven or not
  passwordTriesPer15Min: 30,       // wrong passwords for one password-protected app, from anyone
};

/** Plan allowances. Only running apps count; guests do not count as members. Prices and billing arrive in step 4. */
export const PLANS: Record<string, { apps: number; members: number }> = {
  free: { apps: 10, members: 10 },
  solo: { apps: 15, members: 1 },
  team: { apps: 50, members: 25 },
};
export const plan = (w: Workspace) => PLANS[w.plan] ?? PLANS.free;

export const now = () => Date.now();

export const json = (data: unknown, status = 200, headers: Record<string, string> = {}) =>
  new Response(JSON.stringify(data, null, 2), { status, headers: { 'content-type': 'application/json; charset=utf-8', ...headers } });

export function problemResponse(e: unknown): Response {
  if (e instanceof Problem) return json({ error: { code: e.code, message: e.message, ...e.extra } }, e.status);
  console.error(e);
  return json({ error: { code: 'internal', message: 'Something went wrong on our side. Try again.' } }, 500);
}

export function randomId(prefix: string, bytes = 12): string {
  const b = crypto.getRandomValues(new Uint8Array(bytes));
  return prefix + [...b].map(x => x.toString(16).padStart(2, '0')).join('');
}

export async function sha256(text: string): Promise<string> {
  const d = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
  return [...new Uint8Array(d)].map(x => x.toString(16).padStart(2, '0')).join('');
}

export function safeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let r = 0;
  for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}

const b64url = (b: Uint8Array) => btoa(String.fromCharCode(...b)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
export async function hmac(secret: string, data: string): Promise<string> {
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return b64url(new Uint8Array(await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(data))));
}
/** A compact signed token: base64url(JSON payload) + "." + HMAC-SHA256 signature. */
export async function signToken(secret: string, payload: object): Promise<string> {
  const body = b64url(new TextEncoder().encode(JSON.stringify(payload)));
  return `${body}.${await hmac(secret, body)}`;
}

// ---------- app passwords (access mode "password") ----------

const PASSWORD_ITERATIONS = 100_000;   // the most PBKDF2 iterations Cloudflare Workers allow
const unb64url = (s: string) => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
async function pbkdf2(password: string, salt: Uint8Array, iterations: number): Promise<string> {
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits']);
  return b64url(new Uint8Array(await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations }, key, 256)));
}
/** A password an app is shared with: 6 to 128 characters, kept exactly as typed. */
export function checkPassword(p: unknown): string {
  if (typeof p !== 'string' || p.length < 6 || p.length > 128) throw new Problem(400, 'bad_password', '"password" is 6 to 128 characters. Pick one that is hard to guess: anyone who has it can open the app.');
  return p;
}
/** Store a password as "pbkdf2$<iterations>$<salt>$<hash>" (base64url), never the password itself. */
export async function hashPassword(password: string): Promise<string> {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  return `pbkdf2$${PASSWORD_ITERATIONS}$${b64url(salt)}$${await pbkdf2(password, salt, PASSWORD_ITERATIONS)}`;
}
export async function verifyPassword(password: string, stored: string): Promise<boolean> {
  const [kind, n, salt, hash] = stored.split('$');
  const iterations = Number(n);
  if (kind !== 'pbkdf2' || !hash || !(iterations > 0 && iterations <= PASSWORD_ITERATIONS)) return false;
  return safeEqual(await pbkdf2(password, unb64url(salt), iterations), hash);
}

export const isLocal = (env: Env) => /^(localhost|127\.0\.0\.1)(:|$)/.test(env.APPS_DOMAIN);
/** Apps live at <app>.<workspace>.<APPS_DOMAIN>, so app names only need to be unique inside a workspace. */
export const appUrl = (env: Env, workspace: string, slug: string) => `${isLocal(env) ? 'http' : 'https'}://${slug}.${workspace}.${env.APPS_DOMAIN}`;
/**
 * What ends the first label of an app's staging address: <slug>--staging.<workspace>.<APPS_DOMAIN>. Slugs never hold
 * "--" (slugify folds runs of separators into one hyphen), so the staging address can never be another app's.
 */
export const STAGING_SUFFIX = '--staging';
/** The address an app's staging version is served at. */
export const stagingUrl = (env: Env, workspace: string, slug: string) => appUrl(env, workspace, slug + STAGING_SUFFIX);
/** The origin of any address Brod serves apps at, a custom domain included: https, except in local development. */
export const hostOrigin = (env: Env, host: string) => `${isLocal(env) ? 'http' : 'https'}://${host}`;

const RESERVED = new Set(['api', 'www', 'app', 'apps', 'admin', 'mcp', 'dashboard', 'mail', 'status', 'docs', 'help', 'login', 'auth']);
/** Workspace names are the first label under APPS_DOMAIN, so they must not take a name the platform or a visitor would expect to be ours. */
export const RESERVED_WORKSPACES = new Set([
  ...RESERVED, 'about', 'abuse', 'account', 'accounts', 'assets', 'autoconfig', 'autodiscover', 'billing', 'blog', 'brod', 'cdn', 'console',
  'dev', 'developer', 'developers', 'download', 'email', 'ftp', 'git', 'hostmaster', 'id', 'identity', 'imap', 'info', 'internal', 'legal',
  'localhost', 'm', 'manage', 'media', 'mta-sts', 'mx', 'my', 'new', 'news', 'noc', 'ns', 'ns1', 'ns2', 'oauth', 'pop', 'pop3', 'portal',
  'postmaster', 'pricing', 'privacy', 'registry', 'root', 'security', 'settings', 'signin', 'signup', 'smtp', 'sso', 'staff', 'stage', 'staging',
  'static', 'store', 'support', 'system', 'team', 'terms', 'test', 'u', 'user', 'users', 'w', 'webmail', 'webmaster', 'ws', 'wss',
]);
export function slugify(name: string, reserved: Set<string> = RESERVED, prefix = 'app'): string {
  const s = name.toLowerCase().normalize('NFKD').replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 40).replace(/-+$/, '');
  return !s || reserved.has(s) ? `${prefix}-${s || 'x'}` : s;
}
export const normEmail = (e: unknown) => String(e ?? '').trim().toLowerCase();
export const isEmail = (e: string) => /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(e) && e.length <= 254;

const TYPES: Record<string, string> = {
  html: 'text/html; charset=utf-8', htm: 'text/html; charset=utf-8', css: 'text/css; charset=utf-8', js: 'text/javascript; charset=utf-8',
  mjs: 'text/javascript; charset=utf-8', json: 'application/json; charset=utf-8', map: 'application/json', txt: 'text/plain; charset=utf-8',
  md: 'text/markdown; charset=utf-8', xml: 'application/xml', csv: 'text/csv; charset=utf-8', svg: 'image/svg+xml', png: 'image/png',
  jpg: 'image/jpeg', jpeg: 'image/jpeg', gif: 'image/gif', webp: 'image/webp', avif: 'image/avif', ico: 'image/x-icon',
  woff: 'font/woff', woff2: 'font/woff2', ttf: 'font/ttf', otf: 'font/otf', wasm: 'application/wasm', pdf: 'application/pdf',
  mp4: 'video/mp4', webm: 'video/webm', mp3: 'audio/mpeg', wav: 'audio/wav', webmanifest: 'application/manifest+json',
};
export const contentType = (path: string) => TYPES[path.split('.').pop()!.toLowerCase()] ?? 'application/octet-stream';

/** Read a request body with a hard cap, so an oversized upload fails early. */
export async function readCapped(stream: ReadableStream<Uint8Array> | null, cap: number, what: string): Promise<Uint8Array> {
  if (!stream) return new Uint8Array();
  const reader = stream.getReader(), chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > cap) { await reader.cancel(); throw new Problem(413, 'too_large', `${what} is larger than ${Math.round(cap / 1048576)} MB.`); }
    chunks.push(value);
  }
  const out = new Uint8Array(total);
  let o = 0;
  for (const c of chunks) { out.set(c, o); o += c.byteLength; }
  return out;
}

// ---------- cookies ----------

/**
 * Cookie names for the site at `origin`. On HTTPS they carry the __Host- prefix, so browsers refuse to let any other
 * host set or overwrite them: an app on a sibling subdomain (for example x.apps.brod.sh next to brod.sh) cannot
 * plant a sign-in cookie. Local HTTP development keeps plain names.
 */
export const cookieName = (origin: string, name: string) => (origin.startsWith('https:') ? `__Host-${name}` : name);
export function cookie(request: Request, origin: string, name: string): string {
  const m = new RegExp(`(?:^|;\\s*)${cookieName(origin, name)}=([^;]*)`).exec(request.headers.get('cookie') ?? '');
  return m ? m[1] : '';
}
export function setCookie(origin: string, name: string, value: string, maxAgeSec: number): string {
  return `${cookieName(origin, name)}=${value}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${maxAgeSec}${origin.startsWith('https:') ? '; Secure' : ''}`;
}

// ---------- HTML pages (sign-in, notices, home page) ----------

export const esc = (s: unknown) => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]!);
const safeColor = (c: string) => (/^#[0-9a-f]{6}$/i.test(c) ? c : '#1f6f4a');

/** The look shared by every platform page. Keep it in step with PAGE_CSS in server/src/http.rs. */
const PAGE_CSS = `:root{--bg:#F1F5F2;--surface:#FBFCFB;--sunk:#E7EDE8;--ink:#15201B;--muted:#5A6860;--line:#D7E0D9;--deploy:#F4B62E;--green:#1E5B4A;--ok:#2B7A4B;--bad:#B2372E;--bad-bg:#FBECEA;--display:'Bricolage Grotesque','Segoe UI',system-ui,sans-serif;--body:'Instrument Sans','Segoe UI',system-ui,sans-serif;--mono:'JetBrains Mono',ui-monospace,'SF Mono',Menlo,monospace;color-scheme:light}
@media(prefers-color-scheme:dark){:root{--bg:#111815;--surface:#182019;--sunk:#0C120F;--ink:#E6EDE8;--muted:#93A199;--line:#2A3630;--green:#7FD0B0;--ok:#6CC48D;--bad:#F0857A;--bad-bg:#2E1A18;color-scheme:dark}}
*{box-sizing:border-box}
body{margin:0;min-height:100vh;display:flex;flex-direction:column;align-items:center;background:var(--bg);color:var(--ink);font:15px/1.5 var(--body);-webkit-font-smoothing:antialiased}
.top{padding:40px 16px 20px}
.brand{display:flex;align-items:center;gap:9px;font:650 1.15rem var(--display)}
.logo{width:22px;height:14px;border-radius:8px;background:var(--deploy);box-shadow:7px -5px 0 -2px var(--deploy)}
main{width:min(28rem,calc(100% - 32px));background:var(--surface);border:1px solid var(--line);border-radius:14px;padding:28px;margin:0 0 20px;overflow:hidden;display:flex;flex-direction:column;gap:14px}
main::before{content:"";display:block;height:6px;background:var(--accent);margin:-28px -28px 6px}
main>*{margin:0}
h1,h2{font-family:var(--display);letter-spacing:-.01em;text-wrap:balance}
h1{font-size:1.6rem;font-weight:650;line-height:1.15}
h2{font-size:1.1rem;font-weight:600;margin-top:10px;padding-top:20px;border-top:1px solid var(--line)}
p{margin:0}
b{font-weight:600}
a{color:var(--green);text-decoration-color:color-mix(in srgb,var(--green) 35%,transparent);text-underline-offset:3px}
a:hover{text-decoration-color:currentColor}
small,.muted{color:var(--muted);font-size:.85rem}
:focus-visible{outline:2px solid var(--green);outline-offset:2px;border-radius:4px}
form{display:flex;flex-direction:column;gap:10px;margin:0}
form>button:not(.block){align-self:flex-start}
form p{margin:0}
input,button,select{font:inherit;color:inherit}
input:not([type=checkbox]):not([type=hidden]),select{width:100%;border:1px solid var(--line);background:var(--surface);border-radius:8px;padding:9px 11px}
input:focus-visible,select:focus-visible{outline:2px solid var(--green);outline-offset:0;border-radius:8px}
input[readonly]{font:.82rem/1.5 var(--mono);background:var(--sunk);cursor:copy}
input[type=checkbox]{accent-color:var(--green);margin:0 6px 0 0;vertical-align:-2px}
label{display:block}
button,.btn{display:inline-flex;align-items:center;justify-content:center;gap:6px;border:1px solid var(--accent);background:var(--accent);color:#fff;padding:8px 16px;border-radius:9px;font-weight:600;cursor:pointer;text-decoration:none;white-space:nowrap}
button:hover,.btn:hover{filter:brightness(1.08)}
button.secondary,.btn.secondary{background:var(--surface);border-color:var(--line);color:var(--ink);font-weight:550}
button.secondary:hover,.btn.secondary:hover{filter:none;border-color:var(--muted)}
button.small{padding:4px 12px;font-size:.85rem}
.block{width:100%}
.actions{display:flex;flex-wrap:wrap;gap:8px}
form .actions{margin-top:4px}
.or{display:flex;align-items:center;gap:12px;color:var(--muted);font-size:.78rem;text-transform:uppercase;letter-spacing:.09em;font-weight:600}
.or::before,.or::after{content:"";flex:1;height:1px;background:var(--line)}
.icon{font-size:2rem;line-height:1}
ul{list-style:none;margin:0;padding:0;border-top:1px solid var(--line)}
li{display:flex;flex-wrap:wrap;align-items:center;gap:8px 16px;padding:12px 0;border-bottom:1px solid var(--line);position:relative}
li>span{flex:1 1 12rem;min-width:0;overflow-wrap:anywhere}
li form{display:block}
#apps li>a{color:var(--ink);font:650 1.02rem var(--display);text-decoration:none}
#apps li>a::before{content:"";position:absolute;inset:0}
#apps li:hover>a{text-decoration:underline}
#apps li::after{content:"→";margin-left:auto;color:var(--muted)}
#apps li small{flex-basis:100%;margin-top:-8px;order:3}
#apps li br{display:none}
[role=alert]{background:var(--bad-bg);color:var(--bad);border:1px solid color-mix(in srgb,var(--bad) 35%,transparent);border-radius:10px;padding:12px 14px}
[role=status]{border-left:3px solid var(--green);background:var(--sunk);padding:12px 14px;border-radius:0 10px 10px 0;display:flex;flex-direction:column;gap:8px}
footer{color:var(--muted);font-size:.8rem;padding:0 16px 32px}
[hidden]{display:none!important}`;
const LOGO = '<span class="logo" aria-hidden="true"></span>';
const FONTS = '<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Bricolage+Grotesque:opsz,wght@12..96,500..700&family=Instrument+Sans:wght@400..700&family=JetBrains+Mono:wght@400;600&display=swap">';

/** A plain page in the platform's style. `body` is trusted HTML: callers escape what they put in it. */
export function page(status: number, title: string, body: string, o: { color?: string; headers?: Record<string, string> } = {}): Response {
  return new Response(
    `<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${esc(title)}</title>
${FONTS}
<style>:root{--accent:${safeColor(o.color ?? '')}}
${PAGE_CSS}</style>
<header class="top"><span class="brand">${LOGO}Brod</span></header>
<main>${body}</main>
<footer>Powered by Brod</footer></html>`,
    { status, headers: { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store', 'x-robots-tag': 'noindex', 'x-frame-options': 'DENY', ...o.headers } });
}
export const notice = (status: number, title: string, text: string, extra = '') => page(status, title, `<h1>${esc(title)}</h1><p>${esc(text)}</p>${extra}`);

/** Keep in step with NOT_FOUND_CSS in server/src/http.rs. */
const NOT_FOUND_CSS = `<style>
.nf{display:flex;flex-direction:column;align-items:center;text-align:center;gap:12px;padding:6px 0 2px}
.nf-art{position:relative;width:176px;height:116px;margin:6px 0 8px}
.nf-win{position:absolute;inset:0;border:2px dashed var(--line);border-radius:16px;background:repeating-linear-gradient(135deg,transparent 0 11px,color-mix(in srgb,var(--line) 45%,transparent) 11px 12px)}
.nf-win::before{content:"";position:absolute;left:12px;top:11px;width:7px;height:7px;border-radius:50%;background:var(--line);box-shadow:11px 0 var(--line),22px 0 var(--line)}
.nf-code{position:absolute;inset:0;display:grid;place-items:center;font:700 2.7rem/1 var(--display);letter-spacing:-.04em;color:var(--muted);opacity:.5}
.nf-pill{position:absolute;right:-18px;top:-20px;width:46px;height:28px;border-radius:16px;background:var(--deploy);box-shadow:15px -10px 0 -4px var(--deploy);animation:nf-drift 5s ease-in-out infinite}
@keyframes nf-drift{50%{transform:translate(-8px,9px) rotate(-7deg)}}
@media(prefers-reduced-motion:reduce){.nf-pill{animation:none}}
.nf .actions{justify-content:center;margin-top:6px}
</style>`;
/**
 * The page for an app that is not there. A visitor who may not open an app sees exactly this too, so an address
 * says nothing about whether an app lives at it. Keep in step with not_found() in server/src/http.rs.
 */
export const notFound = (env: Env) => page(404, 'App not found', `${NOT_FOUND_CSS}<div class="nf">
<div class="nf-art" aria-hidden="true"><div class="nf-win"></div><div class="nf-code">404</div><div class="nf-pill"></div></div>
<h1>App not found</h1>
<p class="muted">There is no app at this address, or it has not been shared with you.</p>
<p class="muted">Check the link, or ask whoever sent it to share the app with you.</p>
<div class="actions"><a class="btn secondary" href="${esc(env.API_ORIGIN)}">Go to Brod</a></div>
</div>`);
export const redirect = (location: string, headers: Record<string, string> = {}) =>
  new Response(null, { status: 302, headers: { location, 'cache-control': 'no-store', ...headers } });
