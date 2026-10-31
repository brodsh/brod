import { fileURLToPath } from 'node:url';
import { defineConfig } from 'vitest/config';

export default defineConfig({
  resolve: { alias: [{ find: /^@brod\/auth$/, replacement: fileURLToPath(new URL('./src/index.ts', import.meta.url)) }] },
  test: { include: ['test/**/*.test.ts'], environment: 'node' },
});
