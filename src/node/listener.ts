// Turn a Web-standard fetch handler into a Node.js request listener. Used by the Vercel Function and the local Node server.
import type { IncomingMessage, ServerResponse } from 'node:http';
import { Readable } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import type { ReadableStream as NodeReadableStream } from 'node:stream/web';

const one = (v: string | string[] | undefined) => (Array.isArray(v) ? v[0] : v)?.split(',')[0].trim();

export function toNodeListener(handle: (request: Request) => Promise<Response>, o: { trustForwarded?: boolean } = {}) {
  return async (req: IncomingMessage, res: ServerResponse) => {
    try {
      // Behind Vercel's proxy the forwarded headers carry the address the visitor used; locally only Host is trusted.
      const host = (o.trustForwarded && one(req.headers['x-forwarded-host'])) || req.headers.host || 'localhost';
      const proto = (o.trustForwarded && one(req.headers['x-forwarded-proto'])) || 'http';
      const headers = new Headers();
      for (const [k, v] of Object.entries(req.headers)) for (const x of v === undefined ? [] : Array.isArray(v) ? v : [v]) headers.append(k, x);
      // The visitor's address for rate limits (src/abuse.ts): from Vercel's proxy, or the socket. Never one the visitor sent.
      headers.delete('x-brod-client-ip');
      const ip = (o.trustForwarded && one(req.headers['x-forwarded-for'])) || req.socket?.remoteAddress;
      if (ip) headers.set('x-brod-client-ip', ip);
      const method = req.method ?? 'GET';
      const hasBody = method !== 'GET' && method !== 'HEAD';
      const request = new Request(`${proto}://${host}${req.url ?? '/'}`, {
        method, headers, ...(hasBody ? { body: Readable.toWeb(req), duplex: 'half' } : {}),
      } as RequestInit);
      const response = await handle(request);
      res.statusCode = response.status;
      response.headers.forEach((v, k) => { if (k !== 'set-cookie') res.setHeader(k, v); });
      const cookies = response.headers.getSetCookie();
      if (cookies.length) res.setHeader('set-cookie', cookies);
      if (!response.body || method === 'HEAD') { await response.body?.cancel(); res.end(); return; }
      await pipeline(Readable.fromWeb(response.body as unknown as NodeReadableStream), res);
    } catch (e) {
      console.error(e);
      if (res.headersSent) { res.destroy(); return; }
      res.statusCode = 500;
      res.setHeader('content-type', 'application/json; charset=utf-8');
      res.end(JSON.stringify({ error: { code: 'internal', message: 'Something went wrong on our side. Try again.' } }));
    }
  };
}
