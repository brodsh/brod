// The Vercel Function (and the local Node server): every path on every host goes to the Worker's own fetch handler.
// scripts/build-vercel.mjs bundles this file into .vercel/output/functions/index.func/index.mjs.
import worker from '../index';
import type { Env } from '../lib';
import { ConfigError, hostEnv } from './env';
import { toNodeListener } from './listener';

const host = process.env.VERCEL ? 'vercel' : 'node';
let env: Promise<Env> | undefined;   // one database client and bucket per function instance

// A corrupt gzip upload also surfaces as an unhandled rejection inside DecompressionStream, after unpack() has
// already answered 400. Log it rather than let Node end the instance.
process.on('unhandledRejection', e => console.error('unhandled rejection', e));

async function handle(request: Request): Promise<Response> {
  env ??= hostEnv(process.env, host);
  let e: Env;
  try { e = await env; }
  catch (err) {
    env = undefined;
    const message = err instanceof ConfigError ? err.message : 'Brod could not start. Check the function logs.';
    if (!(err instanceof ConfigError)) console.error(err);
    return Response.json({ error: { code: 'not_configured', message } }, { status: 503 });
  }
  return worker.fetch(request, e, ctx);
}

// Only server apps use ctx (exports, props), and they are refused off Cloudflare. waitUntil work just runs on.
const ctx = {
  waitUntil(p: Promise<unknown>) { p.catch(err => console.error('waitUntil', err)); },
  passThroughOnException() {},
  props: {},
} as unknown as ExecutionContext;

export default toNodeListener(handle, { trustForwarded: host === 'vercel' });
