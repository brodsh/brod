// SPDX-License-Identifier: AGPL-3.0-only
// Brod's preview service: a headless Chromium that screenshots and records marketplace releases (server/src/preview.rs).
//
// Brod opens a release in an empty sandbox at http://<token>.brod-preview.internal on its internal listener and asks
// here for POST /capture { host }. This service maps *.brod-preview.internal to Brod's address, opens the sandbox and
// answers a desktop screenshot, a short screencast that scrolls through the page, and a phone screenshot, as base64.
//
// The page is the publisher's code, so it is treated as untrusted: it may reach the sandbox and the public internet,
// nothing else. Requests to private addresses, single-label names (brod, runtime, postgres) and .internal / .local /
// localhost names are aborted, so the page cannot probe the private network this service sits in (service workers,
// which would get around the check, are blocked). Brod's internal endpoints need their own secrets besides. One
// capture runs at a time. Every request needs BROD_PREVIEW_SECRET.
//
//   BROD_PREVIEW_SECRET  shared with Brod (16 characters or more)
//   BROD_INTERNAL_URL    where Brod's internal listener is, default http://brod:8080
//   PREVIEW_LISTEN       host:port to listen on, default 0.0.0.0:8790
//   CHROMIUM_PATH        a Chromium binary, when it is not the one Playwright downloaded
import http from 'node:http';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { timingSafeEqual } from 'node:crypto';
import { chromium } from 'playwright';
import { SUFFIX, allowedResolved } from './guard.mjs';

const SECRET = process.env.BROD_PREVIEW_SECRET ?? '';
if (SECRET.length < 16) { console.error('Set BROD_PREVIEW_SECRET to a random value of at least 16 characters.'); process.exit(1); }
const BROD = new URL(process.env.BROD_INTERNAL_URL ?? 'http://brod:8080');
const [LISTEN_HOST, LISTEN_PORT] = (process.env.PREVIEW_LISTEN ?? '0.0.0.0:8790').split(/:(?=\d+$)/);
const DESKTOP = { width: 1280, height: 800 };
const PHONE = { width: 390, height: 844 };

const browser = await chromium.launch({
  executablePath: process.env.CHROMIUM_PATH || undefined,
  args: [`--host-resolver-rules=MAP *${SUFFIX} ${BROD.hostname}`],
});

async function guard(context, sandbox) {
  await context.route('**/*', async route => ((await allowedResolved(route.request().url(), sandbox)) ? route.continue() : route.abort('blockedbyclient')));
}

/** Open the page and let it settle: the load event, then the network going quiet (or 4 seconds, whichever is first). */
async function open(page, url) {
  await page.goto(url, { waitUntil: 'load', timeout: 20_000 });
  await page.waitForLoadState('networkidle', { timeout: 4_000 }).catch(() => {});
  await page.waitForTimeout(500);
}

async function capture(sandbox) {
  const url = `${BROD.protocol}//${sandbox}${BROD.port ? ':' + BROD.port : ''}/`;
  const dir = await mkdtemp(join(tmpdir(), 'brod-preview-'));
  const shots = [];
  try {
    // Desktop: a screenshot once the page has settled, recorded as a screencast that then scrolls down and back.
    const desk = await browser.newContext({ viewport: DESKTOP, recordVideo: { dir, size: DESKTOP }, colorScheme: 'light', serviceWorkers: 'block' });
    await guard(desk, sandbox);
    const page = await desk.newPage();
    await open(page, url);
    const title = (await page.title().catch(() => '')) || '';
    shots.push({ name: 'desktop', data: (await page.screenshot({ type: 'png' })).toString('base64') });
    await page.evaluate(async () => {
      const max = Math.max(0, document.documentElement.scrollHeight - innerHeight);
      const step = (to, ms) => new Promise(done => {
        const from = scrollY, t0 = performance.now();
        const tick = now => { const k = Math.min(1, (now - t0) / ms); scrollTo(0, from + (to - from) * (k < .5 ? 2 * k * k : 1 - (-2 * k + 2) ** 2 / 2)); k < 1 ? requestAnimationFrame(tick) : done(); };
        requestAnimationFrame(tick);
      });
      await new Promise(r => setTimeout(r, 800));
      if (max > 0) { await step(Math.min(max, innerHeight * 2.5), 2500); await new Promise(r => setTimeout(r, 700)); await step(0, 1500); }
      await new Promise(r => setTimeout(r, max > 0 ? 500 : 2500));
    });
    const video = page.video();
    await desk.close();
    if (video) shots.push({ name: 'screencast', data: (await readFile(await video.path())).toString('base64') });

    const phone = await browser.newContext({ viewport: PHONE, deviceScaleFactor: 2, isMobile: true, hasTouch: true, colorScheme: 'light', serviceWorkers: 'block' });
    await guard(phone, sandbox);
    const p2 = await phone.newPage();
    await open(p2, url);
    shots.push({ name: 'phone', data: (await p2.screenshot({ type: 'png' })).toString('base64') });
    await phone.close();
    return { title, shots };
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

const same = (a, b) => a.length === b.length && timingSafeEqual(Buffer.from(a), Buffer.from(b));
let queue = Promise.resolve();
const server = http.createServer((req, res) => {
  const send = (status, body) => { res.writeHead(status, { 'content-type': 'application/json' }); res.end(JSON.stringify(body)); };
  if (req.url === '/health') return send(200, { ok: true });
  if (req.method !== 'POST' || req.url !== '/capture') return send(404, { error: 'not found' });
  if (!same(String(req.headers['x-brod-preview-secret'] ?? ''), SECRET)) return send(403, { error: 'forbidden' });
  let body = '';
  req.on('data', c => { body += c; if (body.length > 4096) req.destroy(); });
  req.on('end', () => {
    let host;
    try { host = String(JSON.parse(body).host ?? ''); } catch { return send(400, { error: 'bad json' }); }
    if (!/^[0-9a-f]{32}\.brod-preview\.internal$/.test(host)) return send(400, { error: 'bad host' });
    queue = queue.then(() => capture(host).then(r => send(200, r), e => send(502, { error: String(e?.message ?? e).slice(0, 500) })));
  });
});
server.listen(Number(LISTEN_PORT), LISTEN_HOST, () => console.log(`Brod preview service on ${LISTEN_HOST}:${LISTEN_PORT}, Brod at ${BROD.origin}`));
const stop = async () => { server.close(); await browser.close(); process.exit(0); };
process.on('SIGTERM', stop); process.on('SIGINT', stop);
