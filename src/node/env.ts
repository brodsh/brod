// Build the Worker's `env` from process.env for hosts other than Cloudflare: libSQL for env.DB, an S3-compatible
// bucket (or a local folder) for env.BUNDLES. Every variable is listed in .env.example.
import { createClient as createWebClient } from '@libsql/client/web';
import type { Env } from '../lib';
import { asR2 } from '../platform/bucket';
import { SqlClient, libsqlD1 } from '../platform/d1';
import { s3Store } from '../platform/s3';
import { fsStore } from './fs-bucket';

type Vars = Record<string, string | undefined>;

/** A configuration problem the operator must fix. Its message names variables, never their values. */
export class ConfigError extends Error {}

async function sqlClient(url: string, authToken: string | undefined): Promise<SqlClient> {
  if (/^(file:|:memory:)/.test(url)) {
    // The native SQLite client is loaded only for local files, so the Vercel bundle stays pure JS.
    const mod = '@libsql/client';
    const { createClient } = (await import(/* @vite-ignore */ mod)) as typeof import('@libsql/client');
    return createClient({ url, intMode: 'number' }) as unknown as SqlClient;
  }
  // libsql:// URLs are sent over HTTP, which suits short-lived functions better than a WebSocket.
  return createWebClient({ url, authToken, intMode: 'number' }) as unknown as SqlClient;
}

export async function hostEnv(v: Vars, host: string): Promise<Env> {
  const onVercel = host === 'vercel';
  const need = ['APPS_DOMAIN', 'API_ORIGIN', 'ADMIN_SECRET', 'IDENTITY_SECRET', 'TURSO_DATABASE_URL'].filter(k => !v[k]);
  const s3Keys = ['S3_ENDPOINT', 'S3_BUCKET', 'S3_ACCESS_KEY_ID', 'S3_SECRET_ACCESS_KEY'];
  const s3 = s3Keys.some(k => v[k]);
  if (s3) need.push(...s3Keys.filter(k => !v[k]));
  else if (onVercel || !v.FILES_DIR) need.push(onVercel ? 'S3_ENDPOINT, S3_BUCKET, S3_ACCESS_KEY_ID, S3_SECRET_ACCESS_KEY' : 'S3_* or FILES_DIR');
  if (need.length) throw new ConfigError(`Brod is not configured yet. Set these environment variables: ${need.join(', ')}. See .env.example and "Run it on Vercel" in README.md.`);
  if (onVercel && v.DEV_MODE === '1' && v.VERCEL_ENV === 'production') throw new ConfigError('DEV_MODE=1 returns sign-in links in API responses. Remove it from the Production environment.');
  if (onVercel && /^(file:|:memory:)/.test(v.TURSO_DATABASE_URL!)) throw new ConfigError('TURSO_DATABASE_URL must be a remote libsql:// or https:// database on Vercel: a function has no lasting disk.');

  const db = libsqlD1(await sqlClient(v.TURSO_DATABASE_URL!, v.TURSO_AUTH_TOKEN));
  let presignPut: ((key: string, expiresSec: number) => Promise<string>) | undefined;
  let bundles: R2Bucket;
  if (s3) {
    const store = s3Store({
      endpoint: v.S3_ENDPOINT!, bucket: v.S3_BUCKET!, accessKeyId: v.S3_ACCESS_KEY_ID!, secretAccessKey: v.S3_SECRET_ACCESS_KEY!,
      region: v.S3_REGION, virtualHosted: v.S3_VIRTUAL_HOSTED === '1',
    });
    bundles = asR2(store);
    // Vercel caps a request body at 4.5 MB, below the 25 MB bundle limit, so uploads go straight to the bucket there.
    if (onVercel || v.DIRECT_UPLOADS === '1') presignPut = store.presignPut;
  } else bundles = asR2(fsStore(v.FILES_DIR!));

  const env: Omit<Env, 'LOADER' | 'APP_DATA'> = {
    DB: db, BUNDLES: bundles,
    APPS_DOMAIN: v.APPS_DOMAIN!, API_ORIGIN: v.API_ORIGIN!.replace(/\/+$/, ''), ADMIN_SECRET: v.ADMIN_SECRET!, IDENTITY_SECRET: v.IDENTITY_SECRET!,
    DEV_MODE: v.DEV_MODE, RESEND_API_KEY: v.RESEND_API_KEY, EMAIL_FROM: v.EMAIL_FROM, GOOGLE_CLIENT_ID: v.GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET: v.GOOGLE_CLIENT_SECRET,
    DNS_RESOLVER_URL: v.DNS_RESOLVER_URL, CUSTOM_DOMAIN_TARGET: v.CUSTOM_DOMAIN_TARGET,
    SECRETS_KEY: v.SECRETS_KEY ?? '',
    HOST: { name: host, serverApps: false, presignPut },
  };
  // No Worker Loader or Durable Objects here: deploys with server code are refused (checkServer) and static apps work.
  return env as Env;
}
