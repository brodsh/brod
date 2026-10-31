// SPDX-License-Identifier: AGPL-3.0-only
// A small container app for Brod's end-to-end test (scripts/e2e-containers.mjs) and an example to start from.
//   /            hello, with the version baked into the image
//   /healthz     the health check Brod waits for (brod.json); 500 when UNHEALTHY is set, to test a failing deploy
//   /me          who is signed in, from the headers Brod adds
//   /headers     every request header, as JSON
//   /public/*    an open path: anyone may reach it without signing in (brod.json)
//   /probe       what the container may do: its user, writing files, reaching addresses (?target=host:port)
import { createServer } from 'node:http';
import { readFileSync, writeFileSync } from 'node:fs';
import { connect } from 'node:net';

const port = Number(process.env.PORT ?? 3000);
const version = readFileSync(new URL('./version.txt', import.meta.url), 'utf8').trim();
const json = (res, status, v) => { res.writeHead(status, { 'content-type': 'application/json' }); res.end(JSON.stringify(v)); };

/** Whether a TCP connection to host:port opens within 2 s. */
const reach = target => new Promise(resolve => {
  const [host, p] = target.split(/:(?=\d+$)/);
  const s = connect({ host, port: Number(p), timeout: 2000 });
  const done = ok => { s.destroy(); resolve(ok); };
  s.on('connect', () => done(true)); s.on('timeout', () => done(false)); s.on('error', () => done(false));
});

const tryWrite = path => { try { writeFileSync(path, 'x'); return true; } catch { return false; } };

createServer(async (req, res) => {
  const url = new URL(req.url, 'http://app');
  console.log(`${req.method} ${url.pathname}`);
  if (url.pathname === '/healthz') return json(res, process.env.UNHEALTHY ? 500 : 200, { ok: !process.env.UNHEALTHY });
  if (url.pathname === '/headers') return json(res, 200, req.headers);
  if (url.pathname === '/me') return json(res, 200, { id: req.headers['x-brod-user-id'] ?? null, email: req.headers['x-brod-user-email'] ?? null });
  if (url.pathname.startsWith('/public/')) return json(res, 200, { open: true, signed_in: !!req.headers['x-brod-user-id'], version });
  if (url.pathname === '/probe') {
    const targets = url.searchParams.getAll('target');
    const reached = {};
    for (const t of targets) reached[t] = await reach(t);
    return json(res, 200, {
      uid: process.getuid(), gid: process.getgid(),
      write_root: tryWrite('/app/written'), write_tmp: tryWrite('/tmp/written'),
      env: { BROD_ISSUER: process.env.BROD_ISSUER, BROD_APP_ID: process.env.BROD_APP_ID, jwks: !!process.env.BROD_IDENTITY_JWKS, GREETING: process.env.GREETING ?? null },
      reached,
    });
  }
  if (req.method === 'POST' && url.pathname === '/echo') {
    let n = 0; for await (const c of req) n += c.length;
    return json(res, 200, { bytes: n });
  }
  res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
  res.end(`<h1>hello from ${version}</h1>`);
}).listen(port, () => console.log(`listening on ${port}, ${version}`));
