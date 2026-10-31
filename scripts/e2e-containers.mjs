// SPDX-License-Identifier: AGPL-3.0-only
// End-to-end check of container apps (server/src/deployments.rs, node/src/work.rs) with real Docker: Brod, a brod-node
// on this machine and a registry:2 container that only Brod talks to. The app is examples/container-app (a small Node
// HTTP server with a Dockerfile). Checks: upload -> built -> pushed -> serving through the gateway, sign-in and the
// identity header, stripped client headers, open paths, a broken Dockerfile and a failing health check leaving what is
// live untouched, rollback without a rebuild, staging and publish, the container's hardening, and a node going away.
// Network isolation (no metadata service, no Brod listener) needs a Linux node with iptables and root; elsewhere those
// checks are skipped with the reason.
// Usage: npm run e2e:containers   (builds both release binaries unless BROD_BIN and BROD_NODE_BIN are set)
// Needs Docker with buildx. Everything it creates is named brod-e2e* and removed at the end.
import { execFileSync, spawn } from 'node:child_process';
import { mkdtempSync, readFileSync, readdirSync, rmSync, existsSync } from 'node:fs';
import http from 'node:http';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { createLocalJWKSet, createRemoteJWKSet, jwtVerify } from 'jose';

const PORT = process.env.E2E_PORT ?? '8833';
const REGISTRY_PORT = process.env.E2E_REGISTRY_PORT ?? String(Number(PORT) + 8);
const API = `http://localhost:${PORT}`;
const ADMIN = 'dev-admin-secret';
const PREFIX = 'brod-e2e';
const BUILDER = `${PREFIX}-builder`;
const REGISTRY = `${PREFIX}-registry`;
const REGISTRY_IMAGE = 'registry:2@sha256:a3d8aaa63ed8681a604f1dea0aa03f100d5895b6a58ace528858a7b332415373';
const FIXTURE = resolve('examples', 'container-app');
const state = mkdtempSync(join(tmpdir(), 'brod-e2e-containers-'));
if (process.env.BROD_BIN === undefined) execFileSync('cargo', ['build', '--release', '--manifest-path', 'server/Cargo.toml'], { stdio: 'inherit' });
if (process.env.BROD_NODE_BIN === undefined) execFileSync('cargo', ['build', '--release', '--manifest-path', 'node/Cargo.toml'], { stdio: 'inherit' });
const bin = resolve(process.env.BROD_BIN ?? join('server', 'target', 'release', 'brod'));
const nodeBin = resolve(process.env.BROD_NODE_BIN ?? join('node', 'target', 'release', 'brod-node'));
const tokenFile = join(state, 'node-join', 'token');
const certFile = join(state, 'registry', 'token.crt');
const linux = process.platform === 'linux';

let passed = 0, failed = 0, skipped = 0;
const check = (name, ok, detail = '') => { ok ? passed++ : failed++; console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${ok || !detail ? '' : `\n      ${detail}`}`); };
const skip = (name, why) => { skipped++; console.log(`SKIP  ${name}\n      ${why}`); };
const sleep = ms => new Promise(r => setTimeout(r, ms));
async function until(fn, ms, every = 500) {
  const deadline = Date.now() + ms;
  for (;;) {
    const v = await fn().catch(() => undefined);
    if (v) return v;
    if (Date.now() > deadline) return undefined;
    await sleep(every);
  }
}
const docker = (...args) => execFileSync('docker', args, { stdio: ['ignore', 'pipe', 'pipe'] }).toString().trim();
const dockerQuiet = (...args) => { try { return docker(...args); } catch { return ''; } };

// ---------- HTTP with cookies, for apps on <slug>.<workspace>.localhost ----------

const api = new URL(API);
function send(url, { method = 'GET', headers = {}, body } = {}) {
  const u = new URL(url);
  return new Promise((resolve, reject) => {
    const req = http.request({ host: api.hostname, port: api.port, path: u.pathname + u.search, method, headers: { host: u.host, ...headers } }, res => {
      const chunks = []; res.on('data', c => chunks.push(c)); res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks).toString() }));
    });
    req.on('error', reject); if (body) req.write(body); req.end();
  });
}
class Browser {
  constructor(email) { this.email = email; this.jars = {}; }
  async go(url, o = {}) {
    const u = new URL(url, API), headers = { ...(o.headers ?? {}) };
    const c = Object.entries(this.jars[u.host] ?? {}).map(([k, v]) => `${k}=${v}`).join('; ');
    if (c) headers.cookie = [headers.cookie, c].filter(Boolean).join('; ');
    let body = o.body;
    if (o.form) { body = new URLSearchParams(o.form).toString(); headers['content-type'] = 'application/x-www-form-urlencoded'; headers.origin ??= API; }
    if (o.json) { body = JSON.stringify(o.json); headers['content-type'] = 'application/json'; headers.origin ??= API; }
    const r = await send(u.href, { method: o.method ?? (body ? 'POST' : 'GET'), headers, body });
    for (const sc of [].concat(r.headers['set-cookie'] ?? [])) {
      const [k, v] = sc.split(';')[0].split('='); (this.jars[u.host] ??= {});
      if (/max-age=0/i.test(sc)) delete this.jars[u.host][k]; else this.jars[u.host][k] = v;
    }
    return { ...r, url: u.href };
  }
  async open(url) {
    let r = await this.go(url), hops = 0;
    while (r.status >= 300 && r.status < 400 && hops++ < 10) r = await this.go(new URL(r.headers.location, r.url).href);
    return r;
  }
  async api(path, o = {}) {
    const r = await this.go(path, { ...o, headers: { ...(o.headers ?? {}), origin: API } });
    let body = null; try { body = r.body ? JSON.parse(r.body) : null; } catch { body = r.body; }
    return { status: r.status, body };
  }
}
const parse = r => { try { return JSON.parse(r.body); } catch { return {}; } };

// ---------- the pieces: Brod, the registry, a node ----------

const server = spawn(bin, [], {
  cwd: state, stdio: ['ignore', 'pipe', 'pipe'],
  env: { PATH: process.env.PATH, APPS_DOMAIN: `localhost:${PORT}`, API_ORIGIN: API, ADMIN_SECRET: ADMIN, IDENTITY_SECRET: 'dev-identity-secret',
    SECRETS_KEY: 'dev-secrets-key-0123456789', DEV_MODE: '1', BROD_LISTEN: `127.0.0.1:${PORT}`, BROD_DATA_DIR: join(state, 'data'),
    BROD_NODE_JOIN_TOKEN_FILE: tokenFile, BROD_CONTAINERS: 'on', BROD_REGISTRY_URL: `http://127.0.0.1:${REGISTRY_PORT}`,
    BROD_REGISTRY_CERT_FILE: certFile, BROD_CONTAINER_PREFIX: PREFIX },
});
let log = '';
server.stdout.on('data', d => (log += d)); server.stderr.on('data', d => (log += d));

function startNode() {
  const p = spawn(nodeBin, ['run'], { stdio: ['ignore', 'pipe', 'pipe'],
    env: { PATH: process.env.PATH, HOME: process.env.HOME, DOCKER_HOST: process.env.DOCKER_HOST ?? '', BROD_NODE_DIR: join(state, 'node'), BROD_URL: API,
      BROD_NODE_JOIN_TOKEN_FILE: tokenFile, BROD_NODE_NAME: 'e2e-docker', BROD_NODE_BUILDER: BUILDER,
      ...(process.env.BROD_NODE_DOCKER_SOCKET ? { BROD_NODE_DOCKER_SOCKET: process.env.BROD_NODE_DOCKER_SOCKET } : {}) } });
  p.log = '';
  p.stdout.on('data', d => (p.log += d)); p.stderr.on('data', d => (p.log += d));
  return p;
}
const stopNode = p => new Promise(r => { if (!p || p.exitCode !== null) return r(); p.once('exit', r); p.kill('SIGTERM'); });

function cleanup() {
  const containers = dockerQuiet('ps', '-aq', '--filter', `name=^${PREFIX}`).split('\n').filter(Boolean);
  if (containers.length) dockerQuiet('rm', '-f', '-v', ...containers);
  const networks = dockerQuiet('network', 'ls', '-q', '--filter', `name=^${PREFIX}`).split('\n').filter(Boolean);
  if (networks.length) dockerQuiet('network', 'rm', ...networks);
  const images = dockerQuiet('images', '--format', '{{.Repository}}:{{.Tag}}').split('\n').filter(i => i.startsWith(`${PREFIX}-`));
  if (images.length) dockerQuiet('rmi', '-f', ...images);
  dockerQuiet('buildx', 'rm', '-f', BUILDER);
  dockerQuiet('volume', 'rm', `${REGISTRY}-data`);
}

/** The container of a deployment (deployments.rs container_of). */
const cname = id => `${PREFIX}-${id.replaceAll('_', '-')}`;

/** The fixture as files for an inline deploy, with some changed. */
function fixture(changes = {}) {
  const files = readdirSync(FIXTURE).map(path => ({ path, content: readFileSync(join(FIXTURE, path), 'utf8') }));
  for (const [path, content] of Object.entries(changes)) {
    const f = files.find(x => x.path === path);
    if (f) f.content = content; else files.push({ path, content });
  }
  return files;
}

let node, code = 1;
try {
  cleanup();
  const deadline = Date.now() + 30_000;
  for (;;) {
    try { if ((await fetch(`${API}/healthz`)).ok) break; } catch { /* not up yet */ }
    if (Date.now() > deadline || server.exitCode !== null) throw new Error(`Brod did not start:\n${log}`);
    await sleep(100);
  }
  check('Brod writes the registry token certificate for registry:2', existsSync(certFile) && readFileSync(certFile, 'utf8').includes('BEGIN CERTIFICATE'));
  check('and generates REGISTRY_SIGNING_KEY into secrets.env', /REGISTRY_SIGNING_KEY=/.test(readFileSync(join(state, 'data', 'secrets.env'), 'utf8')));

  // The registry, as in docker-compose.yml but published on 127.0.0.1 because Brod runs on this machine here.
  docker('run', '-d', '--name', REGISTRY, '-p', `127.0.0.1:${REGISTRY_PORT}:5000`, '-v', `${REGISTRY}-data:/var/lib/registry`,
    '-v', `${certFile}:/certs/registry-token.crt:ro`,
    '-e', 'REGISTRY_AUTH=token', '-e', `REGISTRY_AUTH_TOKEN_REALM=${API}/v1/registry/token`, '-e', 'REGISTRY_AUTH_TOKEN_SERVICE=brod-registry',
    '-e', 'REGISTRY_AUTH_TOKEN_ISSUER=brod', '-e', 'REGISTRY_AUTH_TOKEN_ROOTCERTBUNDLE=/certs/registry-token.crt',
    '-e', 'REGISTRY_STORAGE_DELETE_ENABLED=true', REGISTRY_IMAGE);
  const reg = await until(async () => (await fetch(`http://127.0.0.1:${REGISTRY_PORT}/v2/`)).status === 401, 30_000);
  check('the registry refuses requests without a token from Brod (401)', !!reg);
  const compose = readFileSync('docker-compose.yml', 'utf8');
  const registryService = compose.match(/\n  registry:\n[\s\S]*?(?=\n\n|\n\S)/)?.[0] ?? '';
  check('docker-compose.yml: the registry service publishes no port and is pinned by digest',
    !!registryService && !/\n\s+ports:/.test(registryService) && registryService.includes('registry:2@sha256:'), registryService.slice(0, 300));

  node = startNode();
  const joined = await until(async () => {
    const r = await (await fetch(`${API}/v1/admin/nodes`, { headers: { authorization: `Bearer ${ADMIN}` } })).json();
    const n = r.nodes?.[0];
    return n?.status === 'online' && n.connected && n.capabilities?.engine === 'docker' && n;
  }, 30_000);
  check('the node joins with Docker as its engine', !!joined, node.log.slice(-800));
  if (!joined) throw new Error('no node');
  console.log(`Brod at ${API}, node ${joined.id} (${joined.capabilities.arch}), registry on 127.0.0.1:${REGISTRY_PORT}\n`);

  // A person with a workspace, and an agent token.
  const alice = new Browser(`alice-${Date.now()}@acme.test`);
  const started = await alice.go('/auth/start', { json: { email: alice.email } });
  await alice.go('/auth/verify', { form: { token: new URL(JSON.parse(started.body).dev_link).searchParams.get('token') } });
  const W = (await alice.api('/v1/workspaces', { json: { name: `Containers ${Date.now()}`, accept_terms: true } })).body.workspace;
  await send(`${API}/v1/admin/workspaces/${W}/trust`, { method: 'POST', headers: { authorization: `Bearer ${ADMIN}`, 'content-type': 'application/json' }, body: '{}' });
  const agentToken = (await alice.api('/v1/tokens', { json: { name: 'container-agent' } })).body.token;
  const mcp = async (name, args) => {
    const r = await send(`${API}/mcp`, { method: 'POST', headers: { authorization: `Bearer ${agentToken}`, 'content-type': 'application/json', accept: 'application/json, text/event-stream' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name, arguments: args } }) });
    const msg = JSON.parse(r.body.startsWith('{') ? r.body : r.body.split('\n').find(l => l.startsWith('data:')).slice(5));
    const text = msg.result?.content?.[0]?.text ?? '{}';
    return { error: msg.result?.isError ? JSON.parse(text) : null, value: msg.result?.isError ? null : JSON.parse(text), raw: msg };
  };
  const deployment = (slug, id) => alice.api(`/v1/apps/${slug}/deployments/${id}`);
  /** Wait for a deployment to settle; its last view (or problem). */
  async function settle(slug, id, ms = 600_000) {
    let last;
    await until(async () => {
      last = await deployment(slug, id);
      const s = last.body?.state ?? last.body?.error?.deployment?.state;
      return last.status === 422 || ['serving', 'stopped', 'failed'].includes(s);
    }, ms, 1000);
    return last;
  }

  // ---------- upload -> build -> push -> serving ----------

  const secretFirst = await mcp('deploy_app', { name: 'Box' });
  check('deploy_app without files gives an upload address', !!secretFirst.value?.upload_url, JSON.stringify(secretFirst.raw).slice(0, 500));
  const tarball = execFileSync('tar', ['-czf', '-', '-C', FIXTURE, '.'], { env: { ...process.env, COPYFILE_DISABLE: '1' }, maxBuffer: 64 << 20 });
  const up = await fetch(secretFirst.value.upload_url, { method: 'PUT', body: tarball });
  const v1 = await up.json();
  check('uploading the source answers at once: a container app, building', up.status === 201 && v1.kind === 'container' && v1.deployment?.state === 'scheduled'
    && v1.container?.port === 3000 && v1.container?.health === '/healthz', JSON.stringify(v1));
  const slug = v1.app, url = v1.url;
  const t0 = Date.now();
  const d1 = await settle(slug, v1.deployment.id);
  const log1 = d1.body?.log ?? d1.body?.error?.log ?? [];
  check(`v1 builds, is pushed and serves (${((Date.now() - t0) / 1000).toFixed(0)} s)`, d1.body?.state === 'serving', JSON.stringify(d1.body).slice(0, 3000));
  check('the deployment log has the build output and the push', log1.some(l => /^#\d+ /.test(l)) && log1.some(l => /^pushed /.test(l)), log1.join('\n').slice(-2000));
  const viaMcp = await mcp('get_deployment', { app: slug, deployment: v1.deployment.id });
  check('get_deployment over MCP shows it serving', viaMcp.value?.state === 'serving', JSON.stringify(viaMcp.raw).slice(0, 500));
  const status = await mcp('get_status', { app: slug });
  check('get_status lists the deployment', status.value?.deployments?.[0]?.state === 'serving' && status.value?.deployments?.[0]?.node === joined.id, JSON.stringify(status.value?.deployments));
  const tags = await until(async () => (await registryTags(slug)), 5000);
  async function registryTags() { return dockerQuiet('exec', REGISTRY, 'ls', `/var/lib/registry/docker/registry/v2/repositories/apps`).split('\n').filter(Boolean); }
  check('the image is in Brod\'s registry under apps/<app id>', (tags ?? []).some(t => t.startsWith('app_')), JSON.stringify(tags));

  // ---------- the gateway: sign-in, identity, headers ----------

  const anon = new Browser('');
  const anonHome = await anon.go(url + '/');
  check('a private container app sends anonymous visitors to sign in', anonHome.status === 302 && anonHome.headers.location?.startsWith(`${API}/auth/app`), `${anonHome.status} ${anonHome.headers.location}`);
  const home = await alice.open(url + '/');
  check('signed in, the container answers through the gateway', home.status === 200 && home.body.includes('hello from v1'), `${home.status} ${home.body.slice(0, 200)}`);
  const hdrs = parse(await alice.go(url + '/headers', { headers: { 'x-brod-user-email': 'evil@x.test', 'x-brod-identity': 'forged', 'x-brod-role': 'owner-forged' } }));
  check('the container gets the person as x-brod-* headers; the client\'s own are replaced', hdrs['x-brod-user-email'] === alice.email && hdrs['x-brod-identity'] !== 'forged'
    && hdrs['x-brod-role'] === 'owner' && !(hdrs.cookie ?? '').includes('brod_session'), JSON.stringify(hdrs));
  const probe = parse(await alice.go(url + '/probe'));
  const jwks = createRemoteJWKSet(new URL(`${API}/.well-known/jwks.json`));
  const verified = await jwtVerify(hdrs['x-brod-identity'] ?? '', jwks, { issuer: API, audience: `brod:app:${probe.env?.BROD_APP_ID}` }).catch(e => ({ error: e.message }));
  check('x-brod-identity verifies with jose against /.well-known/jwks.json', verified.payload?.email === alice.email, JSON.stringify(verified));
  const offline = probe.env?.jwks ? await jwtVerify(hdrs['x-brod-identity'], createLocalJWKSet(JSON.parse(execFileSync('docker', ['exec', cname(v1.deployment.id), 'printenv', 'BROD_IDENTITY_JWKS']).toString())),
    { issuer: probe.env.BROD_ISSUER, audience: `brod:app:${probe.env.BROD_APP_ID}` }).catch(e => ({ error: e.message })) : {};
  check('the container has BROD_ISSUER, BROD_APP_ID and BROD_IDENTITY_JWKS, enough to verify offline', probe.env?.BROD_ISSUER === API && /^app_/.test(probe.env?.BROD_APP_ID ?? '')
    && offline.payload?.email === alice.email, JSON.stringify([probe.env, offline]));
  check('forwarded host and proto reach the container', hdrs['x-forwarded-host'] === new URL(url).host && hdrs['x-forwarded-proto'] === 'http', JSON.stringify(hdrs));
  const big = await alice.go(url + '/echo', { method: 'POST', body: 'x'.repeat(5 << 20) }).catch(e => ({ status: 0, body: e.message }));
  check('a 5 MB request body reaches the container', parse(big).bytes === 5 << 20, `${big.status} ${big.body.slice(0, 200)}`);
  // Brod may answer 413 and close before the whole body is sent: a reset after that counts as refused too.
  const tooBig = await alice.go(url + '/echo', { method: 'POST', body: 'x'.repeat(33 << 20) }).catch(e => ({ status: e.code === 'ECONNRESET' || e.code === 'EPIPE' ? 413 : 0, body: e.message }));
  check('a body over 32 MB is refused (413)', tooBig.status === 413, `${tooBig.status} ${tooBig.body?.slice(0, 200)}`);

  // ---------- hardening ----------

  const inspected = JSON.parse(docker('inspect', cname(v1.deployment.id)))[0];
  const hc = inspected.HostConfig;
  check('the container runs as a non-root user (10001)', probe.uid === 10001 && inspected.Config.User === '10001:10001', JSON.stringify([probe.uid, inspected.Config.User]));
  check('its root file system is read-only; /tmp is writable', probe.write_root === false && probe.write_tmp === true && hc.ReadonlyRootfs === true, JSON.stringify(probe));
  check('all capabilities dropped, no new privileges, pids/memory/cpu limits',
    hc.CapDrop?.includes('ALL') && hc.SecurityOpt?.some(o => o.startsWith('no-new-privileges')) && hc.PidsLimit === 512 && hc.Memory === 512 * 1024 * 1024 && hc.NanoCpus === 5e8,
    JSON.stringify({ CapDrop: hc.CapDrop, SecurityOpt: hc.SecurityOpt, PidsLimit: hc.PidsLimit, Memory: hc.Memory, NanoCpus: hc.NanoCpus }));
  check('it sits on its own bridge network named for the app', Object.keys(inspected.NetworkSettings.Networks).some(n => n.startsWith(`${PREFIX}-app-`)), JSON.stringify(Object.keys(inspected.NetworkSettings.Networks)));
  const published = Object.values(hc.PortBindings ?? {}).flat().map(b => b.HostIp);
  check('any published port is on 127.0.0.1 only', published.every(ip => ip === '127.0.0.1'), JSON.stringify(hc.PortBindings));
  if (linux && !existsSync('/.dockerenv')) {
    const reach = parse(await alice.go(url + `/probe?target=169.254.169.254:80&target=${inspected.NetworkSettings.Networks[Object.keys(inspected.NetworkSettings.Networks)[0]].Gateway}:${PORT}&target=1.1.1.1:443`));
    if (/No network rules/.test(log1.join('\n'))) skip('the container cannot reach the metadata service or the node', log1.find(l => /No network rules/.test(l)));
    else check('the container cannot reach 169.254.169.254 or Brod on the node, but reaches the internet',
      !Object.entries(reach.reached ?? {}).some(([t, ok]) => ok && !t.startsWith('1.1.1.1')), JSON.stringify(reach.reached));
  } else {
    skip('the container cannot reach 169.254.169.254 or Brod\'s internal listener',
      `network rules need a Linux node with iptables and root; this is ${process.platform} (Docker Desktop runs containers in a VM). The deploy log says: ${log1.find(l => /No network rules/.test(l)) ?? 'nothing'}`);
  }

  // ---------- open paths ----------

  check('deploying open paths gives a confirm_url', !!v1.confirm_url, JSON.stringify(v1.open_paths));
  const beforeConfirm = await anon.go(url + '/public/hello');
  const confirmed = await alice.go(new URL(v1.confirm_url).pathname, { form: { decision: 'confirm' } });
  const openNow = await anon.go(url + '/public/hello', { headers: { 'x-brod-user-id': 'forged' } });
  check('after a person confirms, /public/* answers anonymously (and forged headers are stripped)', beforeConfirm.status === 302 && confirmed.status === 200
    && openNow.status === 200 && parse(openNow).open === true && parse(openNow).signed_in === false, `${beforeConfirm.status} ${confirmed.status} ${openNow.status} ${openNow.body.slice(0, 200)}`);
  check('the rest stays private', (await anon.go(url + '/headers')).status === 302);

  // ---------- updates, failures, rollback ----------

  await alice.api(`/v1/apps/${slug}/secrets/GREETING`, { method: 'PUT', json: { value: 'hej' } });
  const v2 = await alice.api('/v1/deploys', { json: { app: slug, files: fixture({ 'version.txt': 'v2\n' }), environment: 'production' } });
  const d2 = await settle(slug, v2.body?.deployment?.id);
  check('v2 from inline files builds and replaces v1', v2.status === 201 && d2.body?.state === 'serving' && (await alice.go(url + '/')).body.includes('hello from v2'), JSON.stringify(d2.body).slice(0, 2000));
  check('secrets reach the container as environment variables', parse(await alice.go(url + '/probe')).env?.GREETING === 'hej');
  const old = await until(async () => (await deployment(slug, v1.deployment.id)).body?.state === 'stopped', 90_000, 2000);
  check('the old deployment drains and stops', !!old, JSON.stringify((await deployment(slug, v1.deployment.id)).body).slice(0, 500));

  const broken = await alice.api('/v1/deploys', { json: { app: slug, files: fixture({ Dockerfile: 'FROM node:22-alpine\nRUN exit 3\n' }), environment: 'production' } });
  const d3 = await settle(slug, broken.body?.deployment?.id);
  check('a broken Dockerfile fails as build_failed with the build log', d3.status === 422 && d3.body?.error?.code === 'build_failed'
    && d3.body.error.log?.length > 0 && d3.body.error.log.length <= 50 && d3.body.error.log.some(l => /exit 3|exit code: 3|did not complete/.test(l)), JSON.stringify(d3.body).slice(0, 2500));
  check('and v2 keeps serving', (await alice.go(url + '/')).body.includes('hello from v2'));
  const failMcp = await mcp('get_deployment', { app: slug, deployment: broken.body.deployment.id });
  check('get_deployment over MCP answers the problem build_failed', failMcp.error?.error === 'build_failed' && failMcp.error.log?.length > 0, JSON.stringify(failMcp.raw).slice(0, 400));

  const sick = await alice.api('/v1/deploys', { json: { app: slug, files: fixture({ 'version.txt': 'v4\n', Dockerfile: readFileSync(join(FIXTURE, 'Dockerfile'), 'utf8').replace('CMD', 'ENV UNHEALTHY=1\nCMD') }), environment: 'production' } });
  const d4 = await settle(slug, sick.body?.deployment?.id);
  check('a failing health check fails as deployment_failed, with the container\'s output', d4.status === 422 && d4.body?.error?.code === 'deployment_failed'
    && d4.body.error.log?.some(l => /listening on 3000, v4/.test(l)), JSON.stringify(d4.body).slice(0, 2500));
  check('and v2 still serves', (await alice.go(url + '/')).body.includes('hello from v2'));
  check('the failed container is removed', !dockerQuiet('ps', '-a', '--format', '{{.Names}}').split('\n').includes(cname(sick.body.deployment.id)));

  const back = await alice.api(`/v1/apps/${slug}/rollback`, { json: { version: 1 } });
  const d5 = await settle(slug, back.body?.deployment?.id);
  const log5 = d5.body?.log ?? [];
  check('rollback to v1 starts it again from its stored image: no build step', d5.body?.state === 'serving' && log5.some(l => /reusing the image sha256:/.test(l))
    && !log5.some(l => /building for/.test(l)), JSON.stringify(d5.body).slice(0, 2000));
  check('v1 serves again', (await alice.go(url + '/')).body.includes('hello from v1'));

  // ---------- staging ----------

  const v6 = await mcp('deploy_app', { app: slug, files: fixture({ 'version.txt': 'v6\n' }) });
  check('an agent update goes to staging', v6.value?.environment === 'staging' && !!v6.value?.staging_url, JSON.stringify(v6.raw).slice(0, 600));
  const d6 = await settle(slug, v6.value?.deployment?.id);
  check('the staging deployment serves at the staging address; live is unchanged', d6.body?.state === 'serving'
    && (await alice.open(v6.value.staging_url + '/')).body.includes('hello from v6') && (await alice.go(url + '/')).body.includes('hello from v1'), JSON.stringify(d6.body).slice(0, 1500));
  const pub = await alice.api(`/v1/apps/${slug}/publish`, { method: 'POST', json: {} });
  const live6 = await until(async () => (await alice.go(url + '/')).body.includes('hello from v6'), 30_000);
  check('publish_staging makes v6 live without a rebuild', pub.status === 200 && !!live6, JSON.stringify(pub.body).slice(0, 500));

  // ---------- logs ----------

  const logs = await until(async () => {
    const r = await alice.api(`/v1/apps/${slug}/logs?search=listening`);
    return (r.body?.requests ?? r.body?.lines ?? r.body?.logs ?? []).length > 0 && r.body;
  }, 30_000, 1000);
  check('the container\'s output reaches the app\'s logs', !!logs, JSON.stringify(logs).slice(0, 400));

  // ---------- the node goes away ----------

  await stopNode(node);
  const gone = await until(async () => (await alice.go(url + '/')).status === 503, 60_000, 1000);
  check('with its node offline the app answers 503', !!gone);

  code = failed === 0 ? 0 : 1;
} catch (e) {
  console.error(e.stack ?? e.message);
} finally {
  await stopNode(node);
  server.kill('SIGTERM');
  console.log(`\n${passed} passed, ${failed} failed, ${skipped} skipped`);
  if (code !== 0) console.error(`\n--- server log ---\n${log.slice(-6000)}\n--- node log ---\n${node?.log.slice(-4000) ?? ''}`);
  cleanup();
  rmSync(state, { recursive: true, force: true });
}
process.exit(code);
