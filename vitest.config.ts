// SPDX-License-Identifier: AGPL-3.0-only
// Unit tests that run in plain Node.js. The Rust server has its own tests (cargo test) and the end-to-end suite
// (npm run e2e:rust).
import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: { include: ['test/**/*.test.ts'], environment: 'node' },
});
