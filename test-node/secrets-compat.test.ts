// Secrets sealed by the Rust server (server/src/secrets.rs) open with src/secrets.ts, so a database moves between the
// two unchanged. The other direction is server/src/secrets.rs's test `opens_a_value_sealed_by_src_secrets_ts`.
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import type { Env } from '../src/lib';
import { readSecrets } from '../src/secrets';

describe('secrets sealed by the Rust server', () => {
  it('decrypt with the same SECRETS_KEY and app id', async () => {
    const sealed = readFileSync(new URL('../server/tests/fixtures/sealed-by-rust.txt', import.meta.url), 'utf8').trim();
    const DB = { prepare: () => ({ bind: () => ({ all: async () => ({ results: [{ name: 'API_TOKEN', value: sealed }] }) }) }) };
    const env = { DB, SECRETS_KEY: 'dev-secrets-key-0123456789' } as unknown as Env;
    expect(await readSecrets(env, 'app_compat')).toEqual({ API_TOKEN: 'sk_live_ünïcode ✓' });
    await expect(readSecrets(env, 'app_other')).rejects.toThrow();
  });
});
