// The D1 adapter over libSQL, against a fresh database built by the real migrations.
import { createClient } from '@libsql/client';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { migrate } from '../scripts/migrate-libsql.mjs';
import { rateLimit } from '../src/abuse';
import type { Env } from '../src/lib';
import { libsqlD1, SqlClient } from '../src/platform/d1';

const dir = mkdtempSync(join(tmpdir(), 'brod-d1-'));
const url = `file:${join(dir, 'test.db')}`;
const client = createClient({ url, intMode: 'number' });
const DB = libsqlD1(client as unknown as SqlClient);
const t = Date.now();

beforeAll(async () => {
  expect(await migrate(url, undefined, () => {})).toEqual(['0001_init.sql', '0002_server_apps.sql', '0003_app_slug_per_workspace.sql', '0004_oauth.sql', '0005_billing_visits_spaces.sql', '0006_app_data_bytes.sql', '0007_custom_domains.sql', '0008_marketplace.sql', '0009_app_password.sql', '0010_abuse.sql', '0011_listing_media.sql', '0012_analytics.sql', '0013_staging.sql', '0014_listing_previews.sql', '0015_app_settings.sql', '0016_network.sql', '0017_token_expiry_scopes.sql', '0018_version_history.sql', '0019_files_and_editing.sql']);
  await DB.batch([
    DB.prepare('INSERT INTO users (id, email, name, created_at) VALUES (?,?,?,?)').bind('u1', 'ana@acme.test', 'Ana', t),
    DB.prepare('INSERT INTO users (id, email, name, created_at) VALUES (?,?,?,?)').bind('u2', 'bo@acme.test', '', t),
    DB.prepare('INSERT INTO workspaces (id, slug, name, created_at) VALUES (?,?,?,?)').bind('w1', 'acme', 'Acme', t),
    DB.prepare('INSERT INTO groups (id, workspace_id, name, created_at) VALUES (?,?,?,?)').bind('g1', 'w1', 'finance', t),
    DB.prepare('INSERT INTO group_members (group_id, user_id) VALUES (?,?)').bind('g1', 'u1'),
    DB.prepare('INSERT INTO group_members (group_id, user_id) VALUES (?,?)').bind('g1', 'u2'),
  ]);
});
afterAll(() => { client.close(); rmSync(dir, { recursive: true, force: true }); });

describe('migrations', () => {
  it('are recorded like wrangler does, and skipped the second time', async () => {
    expect(await migrate(url, undefined, () => {})).toEqual([]);
    const r = await DB.prepare('SELECT name FROM d1_migrations').all<{ name: string }>();
    expect(r.results.map(x => x.name)).toEqual(['0001_init.sql', '0002_server_apps.sql', '0003_app_slug_per_workspace.sql', '0004_oauth.sql', '0005_billing_visits_spaces.sql', '0006_app_data_bytes.sql', '0007_custom_domains.sql', '0008_marketplace.sql', '0009_app_password.sql', '0010_abuse.sql', '0011_listing_media.sql', '0012_analytics.sql', '0013_staging.sql', '0014_listing_previews.sql', '0015_app_settings.sql', '0016_network.sql', '0017_token_expiry_scopes.sql', '0018_version_history.sql', '0019_files_and_editing.sql']);
  });
});

describe('statements', () => {
  it('first() gives a plain object with numbers, or null', async () => {
    const u = await DB.prepare('SELECT id, email, created_at, email_verified_at FROM users WHERE id = ?').bind('u1').first();
    expect(u).toEqual({ id: 'u1', email: 'ana@acme.test', created_at: t, email_verified_at: null });
    expect(Object.getPrototypeOf(u)).toBe(Object.prototype);
    expect(await DB.prepare('SELECT * FROM users WHERE id = ?').bind('nobody').first()).toBeNull();
    expect(await DB.prepare('SELECT email FROM users WHERE id = ?').bind('u1').first('email')).toBe('ana@acme.test');
  });

  it('all() gives results; run() gives meta.changes', async () => {
    const all = await DB.prepare('SELECT id FROM users ORDER BY id').all<{ id: string }>();
    expect(all.results).toEqual([{ id: 'u1' }, { id: 'u2' }]);
    const r = await DB.prepare("UPDATE users SET name = 'x' WHERE id = ? AND name = ''").bind('u2').run();
    expect(r.meta.changes).toBe(1);
    expect((await DB.prepare("UPDATE users SET name = 'x' WHERE id = ? AND name = ''").bind('u2').run()).meta.changes).toBe(0);
  });

  it('UPDATE … RETURNING works through first()', async () => {
    await DB.prepare('INSERT INTO app_codes (hash, app_id, user_id, parent, expires_at) VALUES (?,?,?,?,?)').bind('h1', 'a1', 'u1', 'p1', t + 60e3).run();
    const claim = () => DB.prepare('UPDATE app_codes SET used_at = ? WHERE hash = ? AND used_at IS NULL AND expires_at > ? RETURNING user_id, parent').bind(t, 'h1', t).first();
    expect(await claim()).toEqual({ user_id: 'u1', parent: 'p1' });
    expect(await claim()).toBeNull();
  });

  it('"IS ?" matches a null bind (platform sessions have no app)', async () => {
    await DB.prepare('INSERT INTO sessions (hash, user_id, app_id, parent, created_at, expires_at) VALUES (?,?,?,?,?,?)').bind('s1', 'u1', null, null, t, t + 1e6).run();
    expect(await DB.prepare('SELECT hash FROM sessions WHERE app_id IS ?').bind(null).first('hash')).toBe('s1');
    expect(await DB.prepare('SELECT hash FROM sessions WHERE app_id IS ?').bind('a1').first()).toBeNull();
  });

  it('ON CONFLICT … DO UPDATE with excluded and the existing row', async () => {
    const upsert = (name: string) => DB.prepare(
      `INSERT INTO users (id, email, name, email_verified_at, created_at) VALUES (?,?,?,?,?)
       ON CONFLICT(email) DO UPDATE SET email_verified_at = COALESCE(users.email_verified_at, excluded.email_verified_at),
         name = CASE WHEN users.name = '' THEN excluded.name ELSE users.name END`).bind('u9', 'ana@acme.test', name, t, t).run();
    await upsert('Other');
    expect(await DB.prepare('SELECT id, name, email_verified_at FROM users WHERE email = ?').bind('ana@acme.test').first()).toEqual({ id: 'u1', name: 'Ana', email_verified_at: t });
  });

  it('GROUP_CONCAT with a separator, and numbered ?1 ?2 parameters', async () => {
    const g = await DB.prepare("SELECT GROUP_CONCAT(u.email, ', ') AS people FROM group_members gm JOIN users u ON u.id = gm.user_id WHERE gm.group_id = ?").bind('g1').first<{ people: string }>();
    expect(g!.people.split(', ').sort()).toEqual(['ana@acme.test', 'bo@acme.test']);
    const n = await DB.prepare('SELECT (SELECT COUNT(*) FROM users WHERE created_at = ?2) + (SELECT COUNT(*) FROM workspaces WHERE id = ?1) AS n').bind('w1', t).first('n');
    expect(n).toBe(3);
  });

  it('booleans bind as 1 and 0; undefined is refused like D1', async () => {
    expect(await DB.prepare('SELECT ? AS a, ? AS b').bind(true, false).first()).toEqual({ a: 1, b: 0 });
    expect(() => DB.prepare('SELECT ?').bind(undefined)).toThrow(/undefined/);
  });
});

describe('batch', () => {
  it('returns one result per statement, reads included', async () => {
    const [m, gs] = await DB.batch([
      DB.prepare('SELECT COUNT(*) AS n FROM users'),
      DB.prepare('SELECT name FROM groups WHERE workspace_id = ?').bind('w1'),
    ]);
    expect(m.results).toEqual([{ n: 2 }]);
    expect(gs.results).toEqual([{ name: 'finance' }]);
  });

  it('is all-or-nothing: a failing statement rolls back the ones before it', async () => {
    await expect(DB.batch([
      DB.prepare('INSERT INTO workspaces (id, slug, name, created_at) VALUES (?,?,?,?)').bind('w2', 'beta', 'Beta', t),
      DB.prepare('INSERT INTO workspaces (id, slug, name, created_at) VALUES (?,?,?,?)').bind('w3', 'acme', 'Duplicate slug', t),
    ])).rejects.toThrow(/UNIQUE/);
    expect(await DB.prepare('SELECT 1 FROM workspaces WHERE id = ?').bind('w2').first()).toBeNull();
  });

  it('AUTOINCREMENT ids and last_row_id', async () => {
    const a = await DB.prepare('INSERT INTO events (workspace_id, app_id, at, actor, action, detail) VALUES (?,?,?,?,?,?)').bind('w1', null, t, 'ana', 'test', '').run();
    expect(a.meta.last_row_id).toBeGreaterThan(0);
  });

  it('counts rate limits with an upsert that returns the count', async () => {
    const env = { DB } as unknown as Env;
    for (let i = 0; i < 2; i++) await rateLimit(env, 'test', '203.0.113.9', 2, 60_000, 'Slow down.');
    await expect(rateLimit(env, 'test', '203.0.113.9', 2, 60_000, 'Slow down.')).rejects.toMatchObject({ status: 429, code: 'rate_limited' });
    await rateLimit(env, 'test', '203.0.113.10', 2, 60_000, 'Slow down.');
  });
});

it('works on an in-memory database too', async () => {
  const mem = createClient({ url: ':memory:', intMode: 'number' });
  const db = libsqlD1(mem as unknown as SqlClient);
  await db.exec('CREATE TABLE t (n INTEGER)');
  await db.batch([db.prepare('INSERT INTO t VALUES (?)').bind(1), db.prepare('INSERT INTO t VALUES (?)').bind(2)]);
  expect(await db.prepare('SELECT SUM(n) AS s FROM t').first('s')).toBe(3);
  mem.close();
});
