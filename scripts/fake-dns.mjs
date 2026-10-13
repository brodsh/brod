// A small DNS-over-HTTPS resolver (the JSON API Cloudflare and Google serve) that answers TXT lookups from records
// tests set, for custom-domain verification. POST /_test/records {name, value} adds a TXT record; DELETE removes all.
// The same handler runs as a Node HTTP server (e2e) and as Miniflare's outbound service (vitest).
// Usage: node scripts/fake-dns.mjs [port]
import http from 'node:http';
import { fileURLToPath } from 'node:url';

export function fakeDns() {
  const records = new Map();
  /** (Request) -> Response, for Miniflare's outboundService. */
  return async function handle(request) {
    const url = new URL(request.url);
    if (url.pathname === '/_test/records' && request.method === 'POST') {
      const { name, value } = await request.json();
      const key = String(name).toLowerCase().replace(/\.$/, '');
      records.set(key, [...(records.get(key) ?? []), String(value)]);
      return Response.json({ ok: true });
    }
    if (url.pathname === '/_test/records' && request.method === 'DELETE') { records.clear(); return Response.json({ ok: true }); }
    if (url.pathname === '/dns-query' && request.method === 'GET') {
      const name = (url.searchParams.get('name') ?? '').toLowerCase().replace(/\.$/, '');
      if (url.searchParams.get('type') !== 'TXT') return Response.json({ Status: 0, Question: [{ name, type: 16 }] });
      const values = records.get(name) ?? [];
      return Response.json({ Status: values.length ? 0 : 3, Question: [{ name, type: 16 }],
        Answer: values.map(v => ({ name, type: 16, TTL: 60, data: JSON.stringify(v) })) }, { headers: { 'content-type': 'application/dns-json' } });
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
