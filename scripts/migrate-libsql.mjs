// Apply migrations/*.sql to a libSQL database (Turso, or a local file) in order, each in its own transaction,
// recording them in d1_migrations the way `wrangler d1 migrations apply` does. Safe to run again: applied ones are skipped.
// Usage: TURSO_DATABASE_URL=libsql://… TURSO_AUTH_TOKEN=… npm run migrate:libsql
//        TURSO_DATABASE_URL=file:local.db npm run migrate:libsql
import { createClient } from '@libsql/client';
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const DIR = fileURLToPath(new URL('../migrations', import.meta.url));

/** Apply pending migrations. Returns the names applied this time. */
export async function migrate(url, authToken, log = console.log) {
  const db = createClient({ url, authToken });
  try {
    await db.execute(`CREATE TABLE IF NOT EXISTS d1_migrations (
      id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT UNIQUE, applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL)`);
    const done = new Set((await db.execute('SELECT name FROM d1_migrations')).rows.map(r => r.name));
    const applied = [];
    for (const name of readdirSync(DIR).filter(f => f.endsWith('.sql')).sort()) {
      if (done.has(name)) continue;
      const sql = readFileSync(join(DIR, name), 'utf8');
      const record = `INSERT INTO d1_migrations (name) VALUES ('${name.replace(/'/g, "''")}')`;
      // Foreign keys off, as SQLite's procedure for rebuilding a table says (0003, 0009 rebuild apps); it is a no-op inside BEGIN.
      try { await db.executeMultiple(`PRAGMA foreign_keys = OFF;\nBEGIN;\n${sql}\n;${record};\nCOMMIT;`); }
      catch (e) {
        await db.execute('ROLLBACK').catch(() => {});
        throw new Error(`Migration ${name} failed and was rolled back: ${e.message}`);
      }
      log(`applied ${name}`);
      applied.push(name);
    }
    if (!applied.length) log('No migrations to apply.');
    return applied;
  } finally {
    db.close();
  }
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const url = process.env.TURSO_DATABASE_URL;
  if (!url) { console.error('Set TURSO_DATABASE_URL (and TURSO_AUTH_TOKEN for Turso). See .env.example.'); process.exit(1); }
  await migrate(url, process.env.TURSO_AUTH_TOKEN).catch(e => { console.error(e.message); process.exit(1); });
}
