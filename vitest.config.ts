// Tests run inside the Workers runtime (workerd) with in-memory D1 and R2, using the bindings from wrangler.jsonc.
import { cloudflareTest, readD1Migrations } from '@cloudflare/vitest-plugin';
import { defineConfig } from 'vitest/config';
// @ts-expect-error: a plain .mjs helper shared with the e2e scripts
import { fakeDns } from './scripts/fake-dns.mjs';

export default defineConfig({
  plugins: [
    cloudflareTest(async () => ({
      wrangler: { configPath: './wrangler.jsonc' },
      miniflare: {
        bindings: {
          TEST_MIGRATIONS: await readD1Migrations('./migrations'),
          ADMIN_SECRET: 'test-admin-secret',
          IDENTITY_SECRET: 'test-identity-secret',
          SECRETS_KEY: 'test-secrets-key-0123456789',
          DEV_MODE: '1',
          // Custom domains are checked against a fake resolver that tests add TXT records to (scripts/fake-dns.mjs).
          DNS_RESOLVER_URL: 'http://dns.test/dns-query',
        },
        outboundService: fakeDns(),
      },
    })),
  ],
  test: {
    include: ['test/**/*.test.ts'],
    setupFiles: ['./test/setup.ts'],
    // workerd also reports a corrupt gzip upload as an unhandled rejection inside DecompressionStream, even though
    // unpack() catches it and answers 400 (tested in unit.test.ts). Ignore only that one; anything else fails the run.
    onUnhandledError: e => (e as { message?: string })?.message !== 'Decompression failed.',
  },
});
