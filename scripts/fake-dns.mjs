// SPDX-License-Identifier: AGPL-3.0-only
// A small DNS-over-HTTPS resolver (the JSON API Cloudflare and Google serve) that answers lookups from records tests
// set, for custom domains. POST /_test/records {name, value, type?} adds a record (TXT unless type says otherwise);
// DELETE removes all. POST /_test/outage {on} makes the resolver fail until turned off.
// It also plays a Domain Connect provider under /dc: POST /_test/domain-connect {zone, settings} sets what
// /dc/v2/<zone>/settings answers, and {template: "<provider>/<service>"} makes that template known.
// The same handler runs as a Node HTTP server (e2e) and as Miniflare's outbound service (vitest).
// Usage: node scripts/fake-dns.mjs [port]
import http from 'node:http';
import { fileURLToPath } from 'node:url';

const TYPES = { A: 1, NS: 2, CNAME: 5, TXT: 16 };

export function fakeDns() {
  const records = new Map();
  let outage = false;
  const settings = new Map(), templates = new Set();
  /** (Request) -> Response, for Miniflare's outboundService. */
  return async function handle(request) {
    const url = new URL(request.url);
    if (url.pathname === '/_test/records' && request.method === 'POST') {
      const { name, value, type = 'TXT' } = await request.json();
      const key = `${type} ${String(name).toLowerCase().replace(/\.$/, '')}`;
      records.set(key, [...(records.get(key) ?? []), String(value)]);
      return Response.json({ ok: true });
    }
    if (url.pathname === '/_test/outage' && request.method === 'POST') { ({ on: outage } = await request.json()); return Response.json({ ok: true }); }
    if (url.pathname === '/_test/records' && request.method === 'DELETE') { records.clear(); settings.clear(); templates.clear(); return Response.json({ ok: true }); }
    if (url.pathname === '/_test/domain-connect' && request.method === 'POST') {
      const b = await request.json();
      if (b.zone) settings.set(b.zone, b.settings);
      if (b.template) templates.add(b.template);
      return Response.json({ ok: true });
    }
    const dcSettings = /^\/dc\/v2\/([^/]+)\/settings$/.exec(url.pathname);
    if (dcSettings) return settings.has(dcSettings[1]) ? Response.json(settings.get(dcSettings[1])) : new Response('unknown zone', { status: 404 });
    const dcTemplate = /^\/dc\/v2\/domainTemplates\/providers\/([^/]+)\/services\/([^/]+)$/.exec(url.pathname);
    if (dcTemplate) return templates.has(`${dcTemplate[1]}/${dcTemplate[2]}`) ? Response.json({ version: 1 }) : new Response('unknown template', { status: 404 });
    if (url.pathname === '/dns-query' && request.method === 'GET') {
      if (outage) return new Response('resolver down', { status: 503 });
      const name = (url.searchParams.get('name') ?? '').toLowerCase().replace(/\.$/, '');
      const qtype = url.searchParams.get('type');
      const type = TYPES[qtype];
      const values = records.get(`${qtype} ${name}`) ?? [];
      return Response.json({ Status: values.length ? 0 : 3, Question: [{ name, type }],
        Answer: values.map(v => ({ name, type, TTL: 60, data: qtype === 'TXT' ? JSON.stringify(v) : v })) }, { headers: { 'content-type': 'application/dns-json' } });
    }
    return new Response('not found', { status: 404 });
  };
}

/** Serve the fake on 127.0.0.1:<port> (0 picks one). Resolves to { port, close }. */
export function serveFakeDns(port = 0) {
  const handle = fakeDns();
  const server = http.createServer(async (req, res) => {
    let body = '';
    for await (const c of req) body += c;
    const r = await handle(new Request(`http://${req.headers.host}${req.url}`, { method: req.method, headers: req.headers, body: body || undefined }));
    res.writeHead(r.status, Object.fromEntries(r.headers));
    res.end(await r.text());
  });
  return new Promise(resolve => server.listen(port, '127.0.0.1', () => resolve({ port: server.address().port, close: () => server.close() })));
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const { port } = await serveFakeDns(Number(process.argv[2] ?? 8790));
  console.log(`fake DNS-over-HTTPS on http://127.0.0.1:${port}/dns-query`);
}
