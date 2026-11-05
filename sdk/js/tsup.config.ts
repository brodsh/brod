import { defineConfig, type Options } from 'tsup';

// ESM and CommonJS builds with their own .d.ts / .d.cts. next is an optional peer, used only by the ./next entry.
// ./next imports '@brodsh/auth' itself (kept external), so both entries share one key cache and one BrodAuthError class.
// jose, the one dependency, is ESM only: the ESM build imports it, and the CommonJS build carries its own copy so that
// require('@brodsh/auth') works on every Node 20, not only on those with require(esm). The output uses nothing from
// Node, so it runs on Node 20+, in Next.js middleware (edge) and on workerd.
const common: Options = {
  entry: { index: 'src/index.ts', next: 'src/next.ts' },
  dts: true,
  sourcemap: true,
  target: 'es2022',
  platform: 'neutral',
  treeshake: true,
};

export default defineConfig([
  { ...common, format: ['esm'], clean: true, external: ['jose', 'next', 'next/headers', '@brodsh/auth'] },
  { ...common, format: ['cjs'], external: ['next', 'next/headers', '@brodsh/auth'], noExternal: ['jose'] },
]);
