// Seal a known value with src/secrets.ts, for the Rust server's compatibility test (server/tests/fixtures/sealed-by-ts.txt).
// Usage: npx esbuild scripts/seal-fixture.ts --bundle --platform=node --format=esm --outfile=/tmp/seal.mjs && node /tmp/seal.mjs
import type { Env } from '../src/lib';
import { putSecret } from '../src/secrets';

const bound: unknown[][] = [];
const DB = { prepare: () => ({ bind: (...a: unknown[]) => { bound.push(a); return { first: async () => ({ n: 0 }) }; } }) };
await putSecret({ DB, SECRETS_KEY: 'dev-secrets-key-0123456789' } as unknown as Env, 'app_compat', 'API_TOKEN', 'sk_live_ünïcode ✓', 'test');
console.log(bound.find(a => a.length === 5)![2]);
