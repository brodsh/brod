// Tests for the Vercel and Node build (src/platform, src/node) in plain Node.js, not workerd: the libSQL database
// adapter with the real migrations, the S3 and folder file stores, the HTMLRewriter fallback and the Node adapter.
import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: { include: ['test-node/**/*.test.ts'], environment: 'node' },
});
