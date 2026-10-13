// The access decision the gateway makes on every request, for every access mode and kind of person.
import { env } from 'cloudflare:workers';
import { beforeAll, describe, expect, it } from 'vitest';
import { Access, AppRow, User } from '../src/lib';
import { decide, whoCanOpen } from '../src/people';

const W = 'ws_access', t = Date.now();
const people = ['owner', 'admin', 'builder', 'member', 'guest', 'outsider', 'domainer'] as const;
type Who = (typeof people)[number] | 'anonymous';
const user = (w: (typeof people)[number]): User =>
  ({ id: `usr_${w}`, email: w === 'domainer' ? 'd@partner.test' : `${w}@acme.test`, name: w, email_verified_at: t });

beforeAll(async () => {
  const s = (sql: string, ...v: unknown[]) => env.DB.prepare(sql).bind(...v);
  await env.DB.batch([
    s('INSERT INTO workspaces (id, slug, name, created_at) VALUES (?,?,?,?)', W, 'acme-access', 'Acme', t),
    ...people.map(p => s('INSERT INTO users (id, email, name, email_verified_at, created_at) VALUES (?,?,?,?,?)', user(p).id, user(p).email, p, t, t)),
    ...(['owner', 'builder'] as const).map(p => s("INSERT INTO members (workspace_id, user_id, role, created_at) VALUES (?,?,'builder',?)", W, user(p).id, t)),
    s("INSERT INTO members (workspace_id, user_id, role, created_at) VALUES (?,?,'admin',?)", W, user('admin').id, t),
    s("INSERT INTO members (workspace_id, user_id, role, created_at) VALUES (?,?,'member',?)", W, user('member').id, t),
    s("INSERT INTO members (workspace_id, user_id, role, created_at) VALUES (?,?,'guest',?)", W, user('guest').id, t),
    s('INSERT INTO groups (id, workspace_id, name, created_at) VALUES (?,?,?,?)', 'grp_fin', W, 'finance', t),
    s('INSERT INTO group_members (group_id, user_id) VALUES (?,?)', 'grp_fin', user('member').id),
  ]);
});

let n = 0;
/** A fresh app with the given mode and grants (subject -> role). */
async function app(access: Access, grants: Record<string, string> = {}): Promise<AppRow> {
  const a: AppRow = {
    id: `app_${++n}`, workspace_id: W, owner_id: user('owner').id, slug: `access-${n}`, name: 'App', title: '', welcome: '',
    status: 'live', access, roles: '["owner","editor","viewer"]', live_version: 1, created_at: t,
  };
  await env.DB.batch([
    env.DB.prepare('INSERT INTO apps (id, workspace_id, owner_id, slug, name, access, roles, live_version, created_at) VALUES (?,?,?,?,?,?,?,?,?)')
      .bind(a.id, W, a.owner_id, a.slug, a.name, a.access, a.roles, 1, t),
    ...Object.entries(grants).map(([subject, role]) => env.DB.prepare('INSERT INTO grants (app_id, subject, role, created_at) VALUES (?,?,?,?)').bind(a.id, subject, role, t)),
  ]);
  return a;
}
/** The role each person gets, or "-" when refused. */
async function roles(a: AppRow): Promise<Record<Who, string>> {
  const out = {} as Record<Who, string>;
  for (const w of [...people, 'anonymous'] as Who[]) {
    const d = await decide(env, a, w === 'anonymous' ? null : user(w));
    out[w] = d.allowed ? d.role ?? 'anon' : d.signInNeeded ? 'sign-in' : '-';
  }
  return out;
}

describe('decide', () => {
  it('private: only the owner and workspace admins', async () => {
    expect(await roles(await app('private', { 'user:usr_member': 'editor' }))).toEqual({
      owner: 'owner', admin: 'owner', builder: '-', member: '-', guest: '-', outsider: '-', domainer: '-', anonymous: 'sign-in',
    });
  });
  it('people: only grants count, by person, group or email domain; the best role wins', async () => {
    expect(await roles(await app('people', { 'user:usr_member': 'viewer', 'group:grp_fin': 'editor', 'domain:partner.test': 'viewer', workspace: 'editor' }))).toEqual({
      owner: 'owner', admin: 'owner', builder: '-', member: 'editor', guest: '-', outsider: '-', domainer: 'viewer', anonymous: 'sign-in',
    });
  });
  it('workspace: insiders get the lowest role, guests only with a grant', async () => {
    expect(await roles(await app('workspace'))).toEqual({
      owner: 'owner', admin: 'owner', builder: 'viewer', member: 'viewer', guest: '-', outsider: '-', domainer: '-', anonymous: 'sign-in',
    });
    expect(await roles(await app('workspace', { 'user:usr_guest': 'editor', workspace: 'editor' }))).toMatchObject({ guest: 'editor', member: 'editor', outsider: '-' });
  });
  it('password: grants count as for named people; everyone else needs the password (the gateway checks it)', async () => {
    expect(await roles(await app('password', { 'group:grp_fin': 'editor', workspace: 'editor' }))).toEqual({
      owner: 'owner', admin: 'owner', builder: '-', member: 'editor', guest: '-', outsider: '-', domainer: '-', anonymous: 'sign-in',
    });
  });
  it('signed_in: anyone who signs in', async () => {
    expect(await roles(await app('signed_in', { 'group:grp_fin': 'editor' }))).toEqual({
      owner: 'owner', admin: 'owner', builder: 'viewer', member: 'editor', guest: 'viewer', outsider: 'viewer', domainer: 'viewer', anonymous: 'sign-in',
    });
  });
  it('public: anyone, without signing in', async () => {
    expect(await roles(await app('public'))).toMatchObject({ anonymous: 'anon', outsider: 'viewer', owner: 'owner' });
  });
  it('ignores grants for roles the app no longer declares', async () => {
    expect(await roles(await app('people', { 'user:usr_member': 'superuser' }))).toMatchObject({ member: '-' });
  });
});

describe('whoCanOpen', () => {
  const a = (access: Access) => ({ access } as AppRow);
  it('says who can open the app in one sentence', () => {
    expect(whoCanOpen(a('private'), [], 'Acme')).toMatch(/^Only you/);
    expect(whoCanOpen(a('people'), [{ group: 'finance' }, { email: 'x@y.z' }], 'Acme')).toBe('Only the finance group, x@y.z can open it, after signing in.');
    expect(whoCanOpen(a('workspace'), [], 'Acme')).toBe('Everyone in Acme can open it after signing in.');
    expect(whoCanOpen(a('public'), [], 'Acme')).toMatch(/without signing in/);
    expect(whoCanOpen(a('password'), [], 'Acme')).toBe('Anyone with the address and its password can open it, without signing in.');
    expect(whoCanOpen(a('password'), [{ group: 'finance' }], 'Acme')).toBe('Anyone with the address and its password can open it, without signing in; the finance group can also sign in.');
  });
});
