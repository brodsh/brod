// Run the end-to-end suite against a fresh local Worker: new database, `wrangler dev`, e2e.mjs, shut down.
// Usage: npm run e2e:local   (used by CI; needs DEV_MODE=1, which .dev.vars sets)
import { execFileSync, spawn } from 'node:child_process';
import { existsSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { serveFakeDns } from './fake-dns.mjs';

const PORT = process.env.E2E_PORT ?? '8787';
const API = `http://localhost:${PORT}`;
const state = mkdtempSync(join(tmpdir(), 'brod-e2e-'));
const wrangler = join('node_modules', '.bin', 'wrangler');
if (!existsSync('.dev.vars')) throw new Error('.dev.vars is missing: the e2e suite needs DEV_MODE=1 and the dev secrets.');

execFileSync(wrangler, ['d1', 'migrations', 'apply', 'brod', '--local', '--persist-to', state], { stdio: 'inherit', env: { ...process.env, CI: '1' } });
// Custom domains are proven against a fake DNS-over-HTTPS resolver.
const dns = await serveFakeDns();
const dev = spawn(wrangler, ['dev', '--port', PORT, '--persist-to', state, '--var', `DNS_RESOLVER_URL:http://127.0.0.1:${dns.port}/dns-query`], { stdio: ['ignore', 'pipe', 'pipe'], env: { ...process.env, CI: '1' } });
let log = '';
dev.stdout.on('data', d => (log += d)); dev.stderr.on('data', d => (log += d));

const stop = () => { dev.kill('SIGTERM'); dns.close(); rmSync(state, { recursive: true, force: true }); };
let code = 1;
try {
  const deadline = Date.now() + 60_000;
  for (;;) {
    try { if ((await fetch(`${API}/healthz`)).ok) break; } catch { /* not up yet */ }
    if (Date.now() > deadline || dev.exitCode !== null) throw new Error(`wrangler dev did not start:\n${log}`);
    await new Promise(r => setTimeout(r, 500));
  }
  code = await new Promise(resolve => spawn(process.execPath, ['scripts/e2e.mjs', API], { stdio: 'inherit', env: { ...process.env, E2E_DNS: `http://127.0.0.1:${dns.port}` } }).on('exit', resolve));
  if (code !== 0) console.error(`\n--- wrangler dev log ---\n${log.slice(-5000)}`);
} catch (e) {
  console.error(e.message);
} finally {
  stop();
}
process.exit(code ?? 1);
