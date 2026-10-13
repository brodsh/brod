// Brod's own HTTPS (BROD_TLS=acme, server/src/tls.rs) against Pebble, Let's Encrypt's test CA: certificates are
// issued on demand over real HTTP-01 challenges, only for names Brod serves, custom domains included.
// Downloads Pebble v2.8.0 into node_modules/.cache/pebble the first time (or set PEBBLE_DIR to a folder holding the
// pebble and pebble-challtestsrv binaries and Pebble's test/certs). Uses ports 8053, 8055, 14000, 15000, 5002, 8443,
// 8790 (fake DNS-over-HTTPS) and 8792 on 127.0.0.1.
// Usage: npm run e2e:tls
import { execFileSync, spawn } from 'node:child_process';
import { chmodSync, existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import https from 'node:https';
import tls from 'node:tls';
import http from 'node:http';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { serveFakeDns } from './fake-dns.mjs';

const VERSION = 'v2.8.0';
const API_HOST = 'brod.test', APPS = 'apps.brod.test', HTTPS_PORT = 8443, HTTP_PORT = 5002, INTERNAL = 8792;
let passed = 0, failed = 0;
const check = (name, ok, detail = '') => { ok ? passed++ : failed++; console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${ok || !detail ? '' : `\n      ${detail}`}`); };

// ---------- Pebble ----------

const pebbleDir = resolve(process.env.PEBBLE_DIR ?? join('node_modules', '.cache', 'pebble', VERSION));
const bin = name => join(pebbleDir, name);
if (!existsSync(bin('pebble'))) {
  mkdirSync(join(pebbleDir, 'test', 'certs', 'localhost'), { recursive: true });
  const get = (url, to) => execFileSync('curl', ['-fsSL', '-o', to, url]);
  const rel = `https://github.com/letsencrypt/pebble/releases/download/${VERSION}`, raw = `https://raw.githubusercontent.com/letsencrypt/pebble/${VERSION}`;
  for (const name of ['pebble', 'pebble-challtestsrv']) {
    const tgz = join(pebbleDir, `${name}.tgz`);
    get(`${rel}/${name}-linux-amd64.tar.gz`, tgz);
    execFileSync('tar', ['xzf', tgz, '-C', pebbleDir, '--strip-components=3', `${name}-linux-amd64/linux/amd64/${name}`]);
    chmodSync(bin(name), 0o755);
  }
  for (const f of ['pebble.minica.pem', 'localhost/cert.pem', 'localhost/key.pem']) get(`${raw}/test/certs/${f}`, join(pebbleDir, 'test', 'certs', f));
}
const minica = join(pebbleDir, 'test', 'certs', 'pebble.minica.pem');
const state = mkdtempSync(join(tmpdir(), 'brod-e2e-tls-'));
writeFileSync(join(state, 'pebble.json'), JSON.stringify({
  pebble: {
    listenAddress: '0.0.0.0:14000', managementListenAddress: '0.0.0.0:15000', httpPort: HTTP_PORT, tlsPort: 5001,
    certificate: join(pebbleDir, 'test/certs/localhost/cert.pem'), privateKey: join(pebbleDir, 'test/certs/localhost/key.pem'),
    externalAccountBindingRequired: false,
  },
}));

const procs = [], logs = {};
const start = (name, cmd, args, env = {}) => {
  const p = spawn(cmd, args, { stdio: ['ignore', 'pipe', 'pipe'], env: { ...process.env, ...env }, cwd: state });
  logs[name] = ''; p.stdout.on('data', d => (logs[name] += d)); p.stderr.on('data', d => (logs[name] += d));
  procs.push(p);
  return p;
};
// Every name resolves to this machine, so Pebble's HTTP-01 checks reach Brod's port 80 listener (here HTTP_PORT).
start('dns', bin('pebble-challtestsrv'), ['-defaultIPv4', '127.0.0.1', '-defaultIPv6', '', '-dns01', '127.0.0.1:8053', '-http01', '', '-tlsalpn01', '', '-https01', '', '-doh', '', '-management', '127.0.0.1:8055']);
start('pebble', bin('pebble'), ['-config', join(state, 'pebble.json'), '-dnsserver', '127.0.0.1:8053'], { PEBBLE_VA_NOSLEEP: '1', PEBBLE_WFE_NONCEREJECT: '0' });
const doh = await serveFakeDns(8790);

if (process.env.BROD_BIN === undefined) execFileSync('cargo', ['build', '--release', '--manifest-path', 'server/Cargo.toml'], { stdio: 'inherit' });
const brodBin = resolve(process.env.BROD_BIN ?? join('server', 'target', 'release', 'brod'));

const wait = async (what, probe) => {
  const deadline = Date.now() + 30_000;
  for (;;) {
    try { if (await probe()) return; } catch { /* not up yet */ }
    if (Date.now() > deadline) throw new Error(`${what} did not start:\n${Object.entries(logs).map(([k, v]) => `--- ${k}\n${v.slice(-2000)}`).join('\n')}`);
    await new Promise(r => setTimeout(r, 200));
  }
};

/** One HTTPS request to Brod's TLS port for `host`, trusting only `ca`. Resolves to { status, headers, body, cert } or rejects on a failed handshake. */
const get = (host, path, { ca, method = 'GET', headers = {}, body } = {}) => new Promise((resolve, reject) => {
  const req = https.request({ host: '127.0.0.1', port: HTTPS_PORT, servername: host, path, method, headers: { host, ...headers }, ca, agent: false }, res => {
    let data = ''; res.on('data', c => (data += c));
    res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: data, cert: res.socket.getPeerCertificate?.() }));
  });
  req.on('error', reject); if (body) req.write(body); req.end();
});
const fails = p => p.then(() => false, () => true);

let code = 1;
try {
  await wait('Pebble', () => new Promise(r => https.get({ host: '127.0.0.1', port: 15000, path: '/roots/0', ca: [execFileSync('cat', [minica])], servername: 'localhost', agent: false }, res => r(res.statusCode === 200)).on('error', () => r(false))));
  start('brod', brodBin, [], {
    API_ORIGIN: `https://${API_HOST}`, APPS_DOMAIN: APPS, ADMIN_SECRET: 'dev-admin-secret', IDENTITY_SECRET: 'dev-identity-secret',
    SECRETS_KEY: 'dev-secrets-key-0123456789', DEV_MODE: '1', BROD_DATA_DIR: join(state, 'data'), BROD_LISTEN: `127.0.0.1:${INTERNAL}`,
    BROD_TLS: 'acme', ACME_DIRECTORY: 'https://localhost:14000/dir', ACME_CA_ROOT: minica, ACME_EMAIL: 'ops@brod.test',
    BROD_HTTPS_LISTEN: `127.0.0.1:${HTTPS_PORT}`, BROD_HTTP_LISTEN: `127.0.0.1:${HTTP_PORT}`, DNS_RESOLVER_URL: `http://127.0.0.1:${doh.port}/dns-query`,
  });
  await wait('Brod', async () => (await fetch(`http://127.0.0.1:${INTERNAL}/healthz`)).ok);
  // Pebble makes a new root on every start: trust only that one from here on.
  const root = await new Promise((resolve, reject) => https.get({ host: '127.0.0.1', port: 15000, path: '/roots/0', ca: [execFileSync('cat', [minica])], servername: 'localhost', agent: false }, res => {
    let d = ''; res.on('data', c => (d += c)); res.on('end', () => resolve(d));
  }).on('error', reject));
  const ca = [root];

  const health = await get(API_HOST, '/healthz', { ca });
  check('the API host gets a certificate from the ACME CA on its first visit (HTTP-01)', health.status === 200 && JSON.parse(health.body).api === `https://${API_HOST}/v1`, health.body);
  check('requests over Brod\'s own TLS are https to the app', JSON.parse(health.body).mcp.startsWith('https://'));
  check('a name Brod does not serve gets no certificate', await fails(get(`nope.example.test`, '/', { ca })));
  check('an unknown app under APPS_DOMAIN gets no certificate', await fails(get(`nope.nowhere.${APPS}`, '/', { ca })));
  const alpn = await new Promise(r => { const s = tls.connect({ host: '127.0.0.1', port: HTTPS_PORT, servername: API_HOST, ca, ALPNProtocols: ['h2', 'http/1.1'] }, () => { r(s.alpnProtocol); s.end(); }).on('error', () => r(null)); });
  check('HTTP/2 is offered', alpn === 'h2', String(alpn));
  check('internal endpoints are refused on the public listener', (await get(API_HOST, `/_caddy/ask?domain=${API_HOST}`, { ca })).status === 404);

  // A person, a workspace, a public app.
  const jar = {};
  const cookie = () => Object.entries(jar).map(([k, v]) => `${k}=${v}`).join('; ');
  const call = async (path, o = {}) => {
    const body = o.json ? JSON.stringify(o.json) : o.form ? new URLSearchParams(o.form).toString() : undefined;
    const r = await get(API_HOST, path, { ca, method: o.method ?? (body ? 'POST' : 'GET'), body, headers: {
      origin: `https://${API_HOST}`, cookie: cookie(), ...(o.json ? { 'content-type': 'application/json' } : o.form ? { 'content-type': 'application/x-www-form-urlencoded' } : {}), ...(o.headers ?? {}),
    } });
    for (const sc of [].concat(r.headers['set-cookie'] ?? [])) { const [k, v] = sc.split(';')[0].split('='); jar[k] = v; }
    return { ...r, json: r.body && r.headers['content-type']?.includes('json') ? JSON.parse(r.body) : null };
  };
  const link = (await call('/auth/start', { json: { email: 'tls@acme.test' } })).json.dev_link;
  await call('/auth/verify', { form: { token: new URL(link).searchParams.get('token') } });
  check('sign-in sets a __Host- cookie over HTTPS', !!jar['__Host-brod_platform']);
  const W = (await call('/v1/workspaces', { json: { name: 'TLS', accept_terms: true } })).json.workspace;
  const d = await call('/v1/deploys', { json: { name: 'Shop', files: [{ path: 'index.html', content: '<html><body>shop</body></html>' }] }, headers: { 'x-brod-workspace': W } });
  const APP = d.json.app;
  // A new free workspace keeps its apps inside it for a day unless the operator trusts it (server/src/abuse.rs).
  await call(`/v1/admin/workspaces/${W}/trust`, { method: 'POST', headers: { authorization: 'Bearer dev-admin-secret' } });
  await call(`/v1/apps/${APP}/access`, { json: { access: 'public' }, headers: { 'x-brod-workspace': W } });
  const page = await get(`${APP}.${W}.${APPS}`, '/', { ca });
  check('an app\'s address gets its own certificate and serves the app', page.status === 200 && page.body.includes('shop') && page.cert?.subjectaltname?.includes(`${APP}.${W}.${APPS}`), page.cert?.subjectaltname);

  // A custom domain: nothing before it is proven, a certificate after.
  const SHOP = 'shop.example.test';
  const dom = await call('/v1/domains', { json: { domain: SHOP, app: APP }, headers: { 'x-brod-workspace': W } });
  check('a custom domain gets no certificate before it is proven', dom.status === 201 && await fails(get(SHOP, '/', { ca })));
  await fetch(`http://127.0.0.1:${doh.port}/_test/records`, { method: 'POST', body: JSON.stringify({ name: dom.json.dns[0].name, value: dom.json.dns[0].value }) });
  const v = await call(`/v1/domains/${SHOP}/verify`, { method: 'POST', headers: { 'x-brod-workspace': W } });
  // The failed handshake above is remembered for a while; a proven domain must not wait for that.
  const onDomain = await get(SHOP, '/', { ca }).catch(e => ({ status: 0, body: String(e) }));
  check('a proven custom domain gets a certificate and serves the app', v.json?.status === 'verified' && onDomain.status === 200 && onDomain.body.includes('shop'), onDomain.body);

  const plain = await new Promise((resolve, reject) => http.get({ host: '127.0.0.1', port: HTTP_PORT, path: '/x?y=1', headers: { host: SHOP }, agent: false }, res => resolve(res)).on('error', reject));
  check('port 80 sends visitors to https', plain.statusCode === 308 && plain.headers.location === `https://${SHOP}/x?y=1`);
  code = failed ? 1 : 0;
} catch (e) {
  console.error(e);
} finally {
  console.log(`\n${passed} passed, ${failed} failed`);
  if (code !== 0) console.error(`\n--- brod log ---\n${(logs.brod ?? '').slice(-4000)}`);
  for (const p of procs) p.kill('SIGTERM');
  doh.close();
  rmSync(state, { recursive: true, force: true });
}
process.exit(code);
