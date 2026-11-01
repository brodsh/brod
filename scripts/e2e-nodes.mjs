// SPDX-License-Identifier: AGPL-3.0-only
// End-to-end check of nodes (server/src/nodes.rs, node/): Brod and one brod-node on this machine. The node joins the
// way the one in docker-compose.yml does (a join token Brod writes to a file), connects over the reversed HTTP/2
// tunnel and sends heartbeats. Then: requests through the tunnel (a large body streamed both ways), offline detection
// after a kill, the same id after a restart from the same state, refused join tokens and forged heartbeats, drain,
// disable, enable and delete.
// Usage: npm run e2e:nodes   (builds both release binaries unless BROD_BIN and BROD_NODE_BIN are set)
import { execFileSync, spawn } from 'node:child_process';
import { createHash, createPrivateKey, generateKeyPairSync, sign } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

const PORT = process.env.E2E_PORT ?? '8807';
const API = `http://localhost:${PORT}`;
const ADMIN = 'dev-admin-secret';
const state = mkdtempSync(join(tmpdir(), 'brod-e2e-nodes-'));
if (process.env.BROD_BIN === undefined) execFileSync('cargo', ['build', '--release', '--manifest-path', 'server/Cargo.toml'], { stdio: 'inherit' });
if (process.env.BROD_NODE_BIN === undefined) execFileSync('cargo', ['build', '--release', '--manifest-path', 'node/Cargo.toml'], { stdio: 'inherit' });
const bin = resolve(process.env.BROD_BIN ?? join('server', 'target', 'release', 'brod'));
const nodeBin = resolve(process.env.BROD_NODE_BIN ?? join('node', 'target', 'release', 'brod-node'));
const tokenFile = join(state, 'node-join', 'token');

let passed = 0, failed = 0;
const check = (name, ok, detail = '') => { ok ? passed++ : failed++; console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${ok || !detail ? '' : `\n      ${detail}`}`); };
const sleep = ms => new Promise(r => setTimeout(r, ms));
async function until(what, fn, ms) {
  const deadline = Date.now() + ms;
  for (;;) {
    const v = await fn().catch(() => undefined);
    if (v) return v;
    if (Date.now() > deadline) return undefined;
    await sleep(250);
  }
}

const admin = (path, { method = 'GET', body, headers = {} } = {}) =>
  fetch(`${API}/v1/admin/nodes${path}`, { method, headers: { authorization: `Bearer ${ADMIN}`, ...headers }, body, duplex: 'half' });
const adminJson = async (path, opts) => { const r = await admin(path, opts); return { status: r.status, json: await r.json().catch(() => null) }; };
const nodeView = async id => (await adminJson(`/${id}`)).json?.node;

const server = spawn(bin, [], {
  cwd: state, stdio: ['ignore', 'pipe', 'pipe'],
  env: { PATH: process.env.PATH, APPS_DOMAIN: `localhost:${PORT}`, API_ORIGIN: API, ADMIN_SECRET: ADMIN, IDENTITY_SECRET: 'dev-identity-secret',
    SECRETS_KEY: 'dev-secrets-key-0123456789', DEV_MODE: '1', BROD_LISTEN: `127.0.0.1:${PORT}`, BROD_DATA_DIR: join(state, 'data'),
    BROD_NODE_JOIN_TOKEN_FILE: tokenFile },
});
let log = '';
server.stdout.on('data', d => (log += d)); server.stderr.on('data', d => (log += d));

/** Start brod-node with state in `dir`. */
function startNode(dir, extra = {}) {
  const p = spawn(nodeBin, ['run'], { stdio: ['ignore', 'pipe', 'pipe'],
    env: { PATH: process.env.PATH, BROD_NODE_DIR: dir, BROD_URL: API, BROD_NODE_JOIN_TOKEN_FILE: tokenFile, BROD_NODE_NAME: 'e2e-1', ...extra } });
  p.log = '';
  p.stdout.on('data', d => (p.log += d)); p.stderr.on('data', d => (p.log += d));
  return p;
}
const stopNode = (p, signal = 'SIGTERM') => new Promise(r => { if (p.exitCode !== null) return r(); p.once('exit', r); p.kill(signal); });
const nodeId = dir => execFileSync(nodeBin, ['id'], { env: { BROD_NODE_DIR: dir } }).toString().trim();
const joinCli = (dir, token) => {
  try {
    execFileSync(nodeBin, ['join', API, token, '--name', 'cli'], { env: { BROD_NODE_DIR: dir }, stdio: 'pipe' });
    return { ok: true, out: '' };
  } catch (e) { return { ok: false, out: `${e.stderr}` }; }
};

/** A heartbeat for `id` signed with `key`, as brod-node signs it. */
function heartbeat(id, key, ts = Date.now(), body = '{"version":"e2e","capabilities":{},"usage":{}}') {
  const hash = createHash('sha256').update(body).digest('hex');
  const msg = `brod-node/1 POST /_node/heartbeat\n${id}\n${ts}\n${hash}`;
  const sig = sign(null, Buffer.from(msg), key).toString('base64url');
  return fetch(`${API}/_node/heartbeat`, { method: 'POST', body, headers: { 'x-brod-node': id, 'x-brod-timestamp': `${ts}`, 'x-brod-signature': sig } });
}

let node, code = 1;
const dir1 = join(state, 'node1');
try {
  const deadline = Date.now() + 30_000;
  for (;;) {
    try { if ((await fetch(`${API}/healthz`)).ok) break; } catch { /* not up yet */ }
    if (Date.now() > deadline || server.exitCode !== null) throw new Error(`Brod did not start:\n${log}`);
    await sleep(100);
  }
  console.log(`Brod at ${API}, brod-node ${nodeBin}\n`);

  // Join and connect, as the node in docker-compose.yml does: the token Brod wrote to the shared file.
  const firstToken = readFileSync(tokenFile, 'utf8').trim();
  check('Brod writes a join token for the local node when none has joined', /^bnj_[0-9a-f]{64}$/.test(firstToken));
  node = startNode(dir1);
  const id = nodeId(dir1);
  check('the node id is node_ and 32 hex digits', /^node_[0-9a-f]{32}$/.test(id), id);
  let v = await until('online', async () => { const n = await nodeView(id); return n?.status === 'online' && n.connected && n; }, 15_000);
  check('join -> online, connected', !!v, JSON.stringify(v ?? (await nodeView(id))));
  v = await until('heartbeat', async () => { const n = await nodeView(id); return n?.resources?.memory_total > 0 && n; }, 15_000);
  check('GET /v1/admin/nodes shows the heartbeat\'s resources and capabilities',
    v?.resources?.disk_total > 0 && v?.capabilities?.cpus >= 1 && ['amd64', 'arm64'].includes(v?.capabilities?.arch) && v?.version === '0.1.0' && v?.name === 'e2e-1',
    JSON.stringify(v));
  const list = await adminJson('');
  check('the node list has it', list.json?.nodes?.length === 1 && list.json.nodes[0].id === id, JSON.stringify(list.json));

  // Brod -> node through the tunnel.
  let r = await admin(`/${id}/tunnel/v1/ping`);
  check('a request from Brod reaches the node over the tunnel (/v1/ping)', r.status === 200 && (await r.text()) === 'pong');
  r = await admin(`/${id}/tunnel/v1/info`);
  const info = await r.json().catch(() => null);
  check('/v1/info from the node', info?.id === id && info?.capabilities?.cpus >= 1, JSON.stringify(info));
  {
    const size = 32 << 20, chunk = 256 << 10;
    const sent = createHash('sha256');
    let made = 0;
    const body = new ReadableStream({
      pull(c) {
        if (made >= size) return c.close();
        const b = Buffer.alloc(chunk, made / chunk % 251);
        sent.update(b); made += chunk; c.enqueue(b);
      },
    });
    const t0 = Date.now();
    r = await admin(`/${id}/tunnel/v1/echo`, { method: 'POST', body, headers: { 'content-type': 'application/octet-stream' } });
    const got = createHash('sha256');
    let n = 0;
    for await (const c of r.body) { got.update(c); n += c.length; }
    const ms = Date.now() - t0;
    check(`32 MB streamed to the node and back unchanged (${ms} ms)`, r.status === 200 && n === size && got.digest('hex') === sent.digest('hex'), `status ${r.status}, ${n} bytes`);
  }
  const many = await Promise.all(Array.from({ length: 20 }, (_, i) =>
    admin(`/${id}/tunnel/v1/echo`, { method: 'POST', body: `request ${i}` }).then(x => x.text())));
  check('20 requests at once each get their own answer', many.every((t, i) => t === `request ${i}`), JSON.stringify(many.slice(0, 3)));

  // Refused join tokens and forged heartbeats.
  const reused = joinCli(join(state, 'other'), firstToken);
  check('a used join token is refused', !reused.ok && /already used/.test(reused.out), reused.out);
  const minted = await adminJson('/join-tokens', { method: 'POST' });
  check('an operator mints a join token', minted.status === 201 && /^bnj_/.test(minted.json?.token ?? ''), JSON.stringify(minted.json));
  const cli = joinCli(join(state, 'node2'), minted.json.token);
  const again = joinCli(join(state, 'node3'), minted.json.token);
  check('brod-node join works once with it, then the token is refused', cli.ok && !again.ok && /already used/.test(again.out), `${cli.out} | ${again.out}`);
  const id2 = nodeId(join(state, 'node2'));
  check('a joined node that never connected is joining', (await nodeView(id2))?.status === 'joining');
  const { privateKey: forger } = generateKeyPairSync('ed25519');
  r = await heartbeat(id, forger);
  check('a heartbeat signed with another key is refused', r.status === 401, `${r.status}`);
  let realKey;
  try { realKey = createPrivateKey({ key: readFileSync(join(dir1, 'node.key')), format: 'der', type: 'pkcs8' }); } catch { /* PKCS#8 v2 not readable here */ }
  if (realKey) {
    const ts = Date.now();
    const ok = await heartbeat(id, realKey, ts);
    const replay = await heartbeat(id, realKey, ts);
    const stale = await heartbeat(id, realKey, Date.now() - 120_000);
    check('a heartbeat signed with the node\'s key is accepted once; a replay and a stale one are refused',
      ok.status === 200 && replay.status === 401 && stale.status === 401, `${ok.status} ${replay.status} ${stale.status}`);
  }

  // Kill the node: offline within about 35 s. Restart it from the same state: the same node, online again.
  await stopNode(node, 'SIGKILL');
  const killedAt = Date.now();
  v = await until('offline', async () => { const n = await nodeView(id); return n?.status === 'offline' && n; }, 45_000);
  const took = (Date.now() - killedAt) / 1000;
  check(`killed node -> offline in ${took.toFixed(1)} s (at most 35)`, !!v && took <= 35, JSON.stringify(await nodeView(id)));
  r = await admin(`/${id}/tunnel/v1/ping`);
  check('a request to an offline node is 503 node_unreachable', r.status === 503 && (await r.json()).error?.code === 'node_unreachable');
  // From another address for Brod (127.0.0.1 instead of localhost): what changes is where it connects from, not who it is.
  node = startNode(dir1, { BROD_URL: `http://127.0.0.1:${PORT}` });
  check('restarted from the same state dir: the same node id', nodeId(dir1) === id);
  v = await until('online again', async () => { const n = await nodeView(id); return n?.status === 'online' && n.connected && n; }, 15_000);
  check('restarted node -> online again, no new node', !!v && (await adminJson('')).json?.nodes?.length === 2, JSON.stringify(await adminJson('')));

  // Drain, disable, enable, delete.
  v = (await adminJson(`/${id}/drain`, { method: 'POST' })).json?.node;
  check('drain -> draining, still connected', v?.status === 'draining' && v.connected, JSON.stringify(v));
  r = await admin(`/${id}/tunnel/v1/ping`);
  check('a draining node still answers through the tunnel', r.status === 200);
  v = (await adminJson(`/${id}/enable`, { method: 'POST' })).json?.node;
  check('enable after drain -> online', v?.status === 'online', JSON.stringify(v));
  r = await admin(`/${id}`, { method: 'DELETE' });
  check('deleting a connected node is refused', r.status === 409);
  v = (await adminJson(`/${id}/disable`, { method: 'POST' })).json?.node;
  check('disable -> disabled, the tunnel closed', v?.status === 'disabled' && !v.connected, JSON.stringify(v));
  const refused = await until('refused', async () => /Brod refused the connection \(403\)/.test(node.log), 40_000);
  check('a disabled node\'s connect is refused (403)', !!refused && !(await nodeView(id)).connected, node.log.slice(-500));
  v = (await adminJson(`/${id}/enable`, { method: 'POST' })).json?.node;
  check('enable a disabled node -> offline until it reconnects', v?.status === 'offline', JSON.stringify(v));
  v = await until('reconnected', async () => { const n = await nodeView(id); return n?.status === 'online' && n.connected && n; }, 45_000);
  check('it reconnects by itself -> online', !!v, JSON.stringify(await nodeView(id)));
  await adminJson(`/${id}/disable`, { method: 'POST' });
  r = await admin(`/${id}`, { method: 'DELETE' });
  check('a disabled node can be deleted', r.status === 200);
  const gone = await until('unknown', async () => /This node is not known/.test(node.log), 45_000);
  check('a deleted node\'s connect is refused until it joins again', !!gone && (await admin(`/${id}`)).status === 404, node.log.slice(-500));

  code = failed === 0 ? 0 : 1;
} catch (e) {
  console.error(e.stack ?? e.message);
} finally {
  if (node) await stopNode(node);
  server.kill('SIGTERM');
  console.log(`\n${passed} passed, ${failed} failed`);
  if (code !== 0) console.error(`\n--- server log ---\n${log.slice(-5000)}\n--- node log ---\n${node?.log.slice(-3000) ?? ''}`);
  rmSync(state, { recursive: true, force: true });
}
process.exit(code);
