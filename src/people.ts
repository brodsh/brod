// The workspace layer: people, workspaces, groups, invites, per-app role grants, sessions,
// and the one access decision the gateway makes for every visitor request.
import { ABUSE, perDay, rateLimit } from './abuse';
import { sendEmail, devMode } from './email';
import {
  AppRow, Caller, Env, LIMITS, Problem, Role, User, Workspace, RESERVED_WORKSPACES, appUrl, isEmail, normEmail, now, plan, randomId, sha256, slugify,
} from './lib';

export const event = (env: Env, workspaceId: string, actor: string, appId: string | null, action: string, detail: string) =>
  env.DB.prepare('INSERT INTO events (workspace_id, app_id, at, actor, action, detail) VALUES (?,?,?,?,?,?)')
    .bind(workspaceId, appId, now(), actor, action, detail);

const RANK: Record<Role, number> = { admin: 3, builder: 2, member: 1, guest: 0 };
export function requireRole(c: Caller, least: Role, what: string) {
  if (RANK[c.role] < RANK[least]) throw new Problem(403, 'forbidden', `Only a workspace ${least}${least === 'admin' ? '' : ' or admin'} can ${what}. You are a ${c.role}.`);
}
const homeUrl = (env: Env, w: Workspace) => `${env.API_ORIGIN}/w/${w.slug}`;

// ---------- people ----------

export async function userByEmail(env: Env, email: string): Promise<User | null> {
  return env.DB.prepare('SELECT id, email, name, email_verified_at FROM users WHERE email = ?').bind(email).first<User>();
}
/** Find or create the person who just proved they own this email address. */
export async function verifiedUser(env: Env, email: string, name = ''): Promise<User> {
  const e = normEmail(email);
  const t = now();
  await env.DB.prepare(
    `INSERT INTO users (id, email, name, email_verified_at, created_at) VALUES (?,?,?,?,?)
     ON CONFLICT(email) DO UPDATE SET email_verified_at = COALESCE(users.email_verified_at, excluded.email_verified_at),
       name = CASE WHEN users.name = '' THEN excluded.name ELSE users.name END`,
  ).bind(randomId('usr_'), e, name.slice(0, 80), t, t).run();
  return (await userByEmail(env, e))!;
}

// ---------- sessions ----------

/** Make a session. A platform session has no app; an app session belongs to one app and to the platform session it came from. */
export async function createSession(env: Env, userId: string, appId: string | null = null, parent: string | null = null): Promise<string> {
  const token = randomId('', 24);
  await env.DB.prepare('INSERT INTO sessions (hash, user_id, app_id, parent, created_at, expires_at) VALUES (?,?,?,?,?,?)')
    .bind(await sha256(token), userId, appId, parent, now(), now() + LIMITS.sessionTtlMs).run();
  return token;
}
export async function sessionUser(env: Env, token: string, appId: string | null): Promise<{ user: User; hash: string; parent: string | null } | null> {
  if (!token || !/^[0-9a-f]{48}$/.test(token)) return null;
  const hash = await sha256(token);
  const row = await env.DB.prepare(
    `SELECT u.id, u.email, u.name, u.email_verified_at, s.parent FROM sessions s JOIN users u ON u.id = s.user_id
     LEFT JOIN sessions p ON p.hash = s.parent
     WHERE s.hash = ? AND s.revoked_at IS NULL AND s.expires_at > ? AND s.app_id IS ? AND (s.parent IS NULL OR (p.revoked_at IS NULL AND p.expires_at > ?))`,
  ).bind(hash, now(), appId, now()).first<User & { parent: string | null }>();
  if (!row) return null;
  return { user: { id: row.id, email: row.email, name: row.name, email_verified_at: row.email_verified_at }, hash, parent: row.parent };
}
/** Sign out everywhere: the platform session and every app session made from it. */
export async function revokeSession(env: Env, platformHash: string) {
  await env.DB.prepare('UPDATE sessions SET revoked_at = ? WHERE (hash = ? OR parent = ?) AND revoked_at IS NULL').bind(now(), platformHash, platformHash).run();
}

// ---------- workspaces ----------

export async function myWorkspaces(env: Env, user: User) {
  const r = await env.DB.prepare(
    'SELECT w.slug, w.name, w.plan, m.role FROM members m JOIN workspaces w ON w.id = m.workspace_id WHERE m.user_id = ? ORDER BY m.created_at',
  ).bind(user.id).all<{ slug: string; name: string; plan: string; role: Role }>();
  return r.results.map(w => ({ ...w, home: `${env.API_ORIGIN}/w/${w.slug}` }));
}

export async function membership(env: Env, user: User, workspace?: string): Promise<{ workspace: Workspace; role: Role } | null> {
  const r = await env.DB.prepare(
    `SELECT w.*, m.role AS mrole FROM members m JOIN workspaces w ON w.id = m.workspace_id
     WHERE m.user_id = ? AND (? IS NULL OR w.slug = ?) ORDER BY m.role = 'guest', m.created_at LIMIT 1`,
  ).bind(user.id, workspace ?? null, workspace ?? null).first<Workspace & { mrole: Role }>();
  if (!r) return null;
  const { mrole, ...w } = r;
  return { workspace: w, role: mrole };
}

export async function createWorkspace(env: Env, user: User, name: string, acceptTerms: boolean) {
  const clean = String(name ?? '').trim().slice(0, 60);
  if (!clean) throw new Problem(400, 'need_name', 'Give the workspace a name, for example your team or company.');
  if (!user.email_verified_at) throw new Problem(403, 'unverified', 'Confirm your email address first.');
  const t = now();
  if (!acceptTerms) {
    const u = await env.DB.prepare('SELECT terms_accepted_at FROM users WHERE id = ?').bind(user.id).first<{ terms_accepted_at: number | null }>();
    if (!u?.terms_accepted_at) throw new Problem(400, 'terms', 'Accept the terms of use and acceptable-use policy to create a workspace ("accept_terms": true).');
  }
  await rateLimit(env, 'workspaces', user.id, ABUSE.workspacesPerUserDay, perDay, `You can create ${ABUSE.workspacesPerUserDay} workspaces a day and have reached that; use one you already have.`);
  const base = slugify(clean, RESERVED_WORKSPACES, 'team');
  let slug = base;
  for (let i = 0; await env.DB.prepare('SELECT 1 FROM workspaces WHERE slug = ?').bind(slug).first(); i++) slug = `${base}-${randomId('', i < 5 ? 2 : 4)}`;
  const w: Workspace = { id: randomId('ws_'), slug, name: clean, plan: 'free', color: '#1f6f4a', icon: '', created_at: t };
  await env.DB.batch([
    env.DB.prepare('INSERT INTO workspaces (id, slug, name, plan, color, icon, created_at) VALUES (?,?,?,?,?,?,?)').bind(w.id, w.slug, w.name, w.plan, w.color, w.icon, t),
    env.DB.prepare("INSERT INTO members (workspace_id, user_id, role, created_at) VALUES (?,?,'admin',?)").bind(w.id, user.id, t),
    env.DB.prepare('UPDATE users SET terms_accepted_at = COALESCE(terms_accepted_at, ?) WHERE id = ?').bind(t, user.id),
    event(env, w.id, user.email, null, 'workspace_created', clean),
  ]);
  return { workspace: w.slug, name: w.name, home: homeUrl(env, w), role: 'admin' };
}

export async function updateWorkspace(env: Env, c: Caller, o: { name?: unknown; color?: unknown; icon?: unknown }) {
  requireRole(c, 'admin', 'change the workspace name or branding');
  const name = o.name === undefined ? c.workspace.name : String(o.name).trim().slice(0, 60);
  const color = o.color === undefined ? c.workspace.color : String(o.color);
  const icon = o.icon === undefined ? c.workspace.icon : [...String(o.icon)].slice(0, 2).join('');
  if (!name) throw new Problem(400, 'need_name', 'The workspace needs a name.');
  if (!/^#[0-9a-f]{6}$/i.test(color)) throw new Problem(400, 'bad_color', 'Colour is a hex value such as "#1f6f4a".');
  await env.DB.batch([
    env.DB.prepare('UPDATE workspaces SET name = ?, color = ?, icon = ? WHERE id = ?').bind(name, color, icon, c.workspace.id),
    event(env, c.workspace.id, c.actor, null, 'branding', `name "${name}", colour ${color}`),
  ]);
  return { ...c.workspace, name, color, icon };
}

async function memberCount(env: Env, w: Workspace) {
  const r = await env.DB.prepare(
    `SELECT (SELECT COUNT(*) FROM members WHERE workspace_id = ?1 AND role != 'guest') +
            (SELECT COUNT(*) FROM invites WHERE workspace_id = ?1 AND role != 'guest' AND used_at IS NULL AND revoked_at IS NULL AND expires_at > ?2) AS n`,
  ).bind(w.id, now()).first<{ n: number }>();
  return r?.n ?? 0;
}

/** What an agent needs to build an app that fits this workspace (get_workspace). */
export async function describeWorkspace(env: Env, c: Caller) {
  const groups = await env.DB.prepare(
    'SELECT g.name, COUNT(gm.user_id) AS members FROM groups g LEFT JOIN group_members gm ON gm.group_id = g.id WHERE g.workspace_id = ? GROUP BY g.id ORDER BY g.name',
  ).bind(c.workspace.id).all<{ name: string; members: number }>();
  const apps = await env.DB.prepare("SELECT COUNT(*) AS n FROM apps WHERE workspace_id = ? AND status = 'live'").bind(c.workspace.id).first<{ n: number }>();
  const p = plan(c.workspace);
  return {
    workspace: c.workspace.slug, name: c.workspace.name, home: homeUrl(env, c.workspace), your_role: c.role,
    plan: c.workspace.plan, running_apps: apps?.n ?? 0, app_limit: p.apps, members: await memberCount(env, c.workspace), member_limit: p.members,
    groups: groups.results,
    default_app_roles: ['owner', 'editor', 'viewer'],
    access_modes: {
      private: 'Only the app\'s owner (and workspace admins).',
      people: 'Only the people and groups granted a role on the app.',
      workspace: 'Everyone in the workspace. Guests only if granted.',
      password: 'Anyone with the address and the password, without signing in. Set it with set_access { "access": "password", "password": "..." }; share the address and the password separately. People granted a role can sign in instead.',
      signed_in: 'Anyone who signs in.',
      public: 'Anyone, without signing in.',
    },
    identity: {
      how: 'An app never keeps its own user table. The platform signs people in before a request reaches the app. In the browser, ' +
        'GET /_brod/me on the app\'s own address returns the signed-in person, or 401 if nobody is signed in (public apps).',
      shape: { user: { id: 'usr_…', email: 'ana@example.com', name: 'Ana' }, role: 'editor', groups: ['finance'], app: 'reading-list', workspace: c.workspace.slug, token: '<signed identity token>' },
      client_library: '<script src="/_brod/client.js"></script> then: const me = await Brod.me(); if (me?.role === "editor") { … }; Brod.signIn(); Brod.signOut();',
      roles: 'Check me.role against the roles the app declares (default owner, editor, viewer; most powerful first). Hide or disable what a role may not do.',
      server_apps: 'Server code (_worker.js) receives the signed-in person on every request as headers x-brod-user-id, x-brod-user-email, x-brod-user-name (URI-encoded), ' +
        'x-brod-role and x-brod-groups (comma-separated), plus x-brod-identity (the signed token). They are absent for anonymous visitors of public apps. The platform removes any x-brod-* header a visitor sends.',
      signed_token: 'me.token and x-brod-identity are base64url(JSON) + "." + an HMAC-SHA256 signature with a per-app key, valid 5 minutes, for passing identity on to another service.',
    },
  };
}

// ---------- people directory ----------

export async function listPeople(env: Env, c: Caller) {
  const r = await env.DB.prepare(
    `SELECT u.id, u.email, u.name, m.role, m.created_at,
       (SELECT GROUP_CONCAT(g.name, ', ') FROM group_members gm JOIN groups g ON g.id = gm.group_id WHERE gm.user_id = u.id AND g.workspace_id = m.workspace_id) AS groups
     FROM members m JOIN users u ON u.id = m.user_id WHERE m.workspace_id = ? ORDER BY m.created_at`,
  ).bind(c.workspace.id).all<{ id: string; email: string; name: string; role: Role; created_at: number; groups: string | null }>();
  return { people: r.results.map(p => ({ id: p.id, email: p.email, name: p.name, role: p.role, groups: p.groups ? p.groups.split(', ') : [] })) };
}

async function personInWorkspace(env: Env, c: Caller, who: string): Promise<{ id: string; email: string; role: Role }> {
  const key = who.includes('@') ? normEmail(who) : who;
  const p = await env.DB.prepare('SELECT u.id, u.email, m.role FROM members m JOIN users u ON u.id = m.user_id WHERE m.workspace_id = ? AND (u.id = ? OR u.email = ?)')
    .bind(c.workspace.id, key, key).first<{ id: string; email: string; role: Role }>();
  if (!p) throw new Problem(404, 'no_person', `${who} is not in this workspace. Invite them first.`);
  return p;
}

async function admins(env: Env, w: Workspace) {
  return (await env.DB.prepare("SELECT COUNT(*) AS n FROM members WHERE workspace_id = ? AND role = 'admin'").bind(w.id).first<{ n: number }>())?.n ?? 0;
}

export async function setPersonRole(env: Env, c: Caller, who: string, role: string) {
  requireRole(c, 'admin', 'change workspace roles');
  if (!['admin', 'builder', 'member', 'guest'].includes(role)) throw new Problem(400, 'bad_role', 'Workspace roles are admin, builder, member and guest.');
  const p = await personInWorkspace(env, c, who);
  if (p.role === 'admin' && role !== 'admin' && (await admins(env, c.workspace)) <= 1) throw new Problem(409, 'last_admin', 'A workspace needs at least one admin.');
  if (p.role === 'guest' && role !== 'guest' && (await memberCount(env, c.workspace)) >= plan(c.workspace).members) throw memberLimit(c);
  await env.DB.batch([
    env.DB.prepare('UPDATE members SET role = ? WHERE workspace_id = ? AND user_id = ?').bind(role, c.workspace.id, p.id),
    event(env, c.workspace.id, c.actor, null, 'role_changed', `${p.email}: ${p.role} to ${role}`),
  ]);
  return { id: p.id, email: p.email, role };
}

/** Remove a person: their access to every app in the workspace ends on their next request. */
export async function removePerson(env: Env, c: Caller, who: string) {
  requireRole(c, 'admin', 'remove people');
  const p = await personInWorkspace(env, c, who);
  if (p.role === 'admin' && (await admins(env, c.workspace)) <= 1) throw new Problem(409, 'last_admin', 'A workspace needs at least one admin.');
  await env.DB.batch([
    env.DB.prepare('DELETE FROM members WHERE workspace_id = ? AND user_id = ?').bind(c.workspace.id, p.id),
    env.DB.prepare('DELETE FROM group_members WHERE user_id = ? AND group_id IN (SELECT id FROM groups WHERE workspace_id = ?)').bind(p.id, c.workspace.id),
    env.DB.prepare('DELETE FROM grants WHERE subject = ? AND app_id IN (SELECT id FROM apps WHERE workspace_id = ?)').bind(`user:${p.id}`, c.workspace.id),
    env.DB.prepare('UPDATE tokens SET revoked_at = ? WHERE workspace_id = ? AND user_id = ? AND revoked_at IS NULL').bind(now(), c.workspace.id, p.id),
    event(env, c.workspace.id, c.actor, null, 'person_removed', p.email),
  ]);
  return { removed: p.email };
}

/** Giving someone a private app opens it to named people, or the grant would do nothing. */
const shareWithPeople = (env: Env, appId: string) => env.DB.prepare("UPDATE apps SET access = 'people' WHERE id = ? AND access = 'private'").bind(appId);

// ---------- invites ----------

const memberLimit = (c: Caller) => new Problem(402, 'member_limit',
  `Your ${c.workspace.plan} plan includes ${plan(c.workspace).members} members and all are in use or invited. Remove someone, invite them as a guest to named apps, or upgrade the plan.`,
  { member_limit: plan(c.workspace).members });

export interface InviteInput { email?: unknown; role?: unknown; app?: unknown; app_role?: unknown }

/** Check an invite without sending it, so an agent's request can be validated before it waits for a person to confirm. */
export async function checkInvite(env: Env, c: Caller, o: InviteInput, getApp: (slug: string) => Promise<AppRow>) {
  const email = normEmail(o.email);
  if (!isEmail(email)) throw new Problem(400, 'bad_email', 'That does not look like an email address.');
  const app = o.app ? await getApp(String(o.app)) : null;
  const role = String(o.role ?? (app ? 'guest' : 'member')) as Role;
  if (!['admin', 'builder', 'member', 'guest'].includes(role)) throw new Problem(400, 'bad_role', 'Invite as admin, builder, member, or guest.');
  if (role === 'guest' && !app) throw new Problem(400, 'need_app', 'A guest is invited to a named app. Give "app".');
  if (role === 'guest') requireRole(c, 'builder', 'invite guests to an app');
  else requireRole(c, 'admin', 'invite people into the workspace');
  let appRole: string | null = null;
  if (app) {
    const roles: string[] = JSON.parse(app.roles);
    appRole = String(o.app_role ?? roles[roles.length - 1]);
    if (!roles.includes(appRole)) throw new Problem(400, 'bad_role', `${app.slug} understands the roles ${roles.join(', ')}.`);
  }
  if (role !== 'guest' && (await memberCount(env, c.workspace)) >= plan(c.workspace).members) throw memberLimit(c);
  return { email, role, app, appRole };
}

export async function invite(env: Env, c: Caller, o: InviteInput, getApp: (slug: string) => Promise<AppRow>) {
  const { email, role, app, appRole } = await checkInvite(env, c, o, getApp);
  // Someone already in the workspace who is being given an app gets the grant straight away.
  const existing = await env.DB.prepare('SELECT u.id, m.role FROM users u JOIN members m ON m.user_id = u.id AND m.workspace_id = ? WHERE u.email = ?')
    .bind(c.workspace.id, email).first<{ id: string; role: Role }>();
  if (existing && !app) throw new Problem(409, 'already_member', `${email} is already in this workspace as a ${existing.role}.`);
  if (existing && app) {
    await env.DB.batch([
      env.DB.prepare('INSERT INTO grants (app_id, subject, role, created_at) VALUES (?,?,?,?) ON CONFLICT(app_id, subject) DO UPDATE SET role = excluded.role')
        .bind(app.id, `user:${existing.id}`, appRole, now()),
      shareWithPeople(env, app.id),
      event(env, c.workspace.id, c.actor, app.id, 'grant', `${email} as ${appRole}`),
    ]);
    return { email, granted: { app: app.slug, role: appRole }, url: appUrl(env, c.workspace.slug, app.slug) };
  }
  const token = randomId('', 24), id = randomId('inv_', 8);
  await env.DB.batch([
    env.DB.prepare('INSERT INTO invites (id, workspace_id, email, role, app_id, app_role, hash, invited_by, created_at, expires_at) VALUES (?,?,?,?,?,?,?,?,?,?)')
      .bind(id, c.workspace.id, email, role, app?.id ?? null, appRole, await sha256(token), c.actor, now(), now() + LIMITS.inviteTtlMs),
    event(env, c.workspace.id, c.actor, app?.id ?? null, 'invite', `${email} as ${role}${app ? ` to ${app.slug} (${appRole})` : ''}`),
  ]);
  const link = `${env.API_ORIGIN}/auth/invite?token=${token}`;
  const what = app ? `the app "${app.title || app.name}"` : `the ${c.workspace.name} workspace`;
  await sendEmail(env, email, `You're invited to ${what}`,
    `${c.user.email} invited you to ${what} on Brod.\n\nOpen this link to accept. It works once and expires in 7 days:\n${link}\n\nIf you were not expecting this, ignore this email.`);
  return { invite: id, email, role, ...(app ? { app: app.slug, app_role: appRole } : {}), expires_in_days: 7, ...(devMode(env) ? { dev_link: link } : {}) };
}

export async function listInvites(env: Env, c: Caller) {
  requireRole(c, 'builder', 'see invites');
  const r = await env.DB.prepare(
    `SELECT i.id, i.email, i.role, a.slug AS app, i.app_role, i.invited_by, i.created_at, i.expires_at FROM invites i LEFT JOIN apps a ON a.id = i.app_id
     WHERE i.workspace_id = ? AND i.used_at IS NULL AND i.revoked_at IS NULL AND i.expires_at > ? ORDER BY i.created_at DESC`,
  ).bind(c.workspace.id, now()).all();
  return { pending: r.results };
}
export async function revokeInvite(env: Env, c: Caller, id: string) {
  requireRole(c, 'builder', 'revoke invites');
  const r = await env.DB.prepare('UPDATE invites SET revoked_at = ? WHERE id = ? AND workspace_id = ? AND used_at IS NULL AND revoked_at IS NULL').bind(now(), id, c.workspace.id).run();
  if (!r.meta.changes) throw new Problem(404, 'not_found', 'No pending invite with that id.');
  await event(env, c.workspace.id, c.actor, null, 'invite_revoked', id).run();
  return { revoked: id };
}

/** Accept an invite. The emailed link proves the address, so it also signs the person in. */
export async function acceptInvite(env: Env, token: string): Promise<{ user: User; appRef?: string; workspaceSlug: string }> {
  const hash = await sha256(token);
  const inv = await env.DB.prepare('SELECT i.*, w.slug AS wslug FROM invites i JOIN workspaces w ON w.id = i.workspace_id WHERE i.hash = ?')
    .bind(hash).first<{ id: string; workspace_id: string; email: string; role: Role; app_id: string | null; app_role: string | null; expires_at: number; used_at: number | null; revoked_at: number | null; wslug: string }>();
  if (!inv || inv.used_at || inv.revoked_at || inv.expires_at < now()) throw new Problem(410, 'invite_gone', 'This invitation has expired, was already used, or was withdrawn. Ask for a new one.');
  const claimed = await env.DB.prepare('UPDATE invites SET used_at = ? WHERE id = ? AND used_at IS NULL').bind(now(), inv.id).run();
  if (!claimed.meta.changes) throw new Problem(410, 'invite_gone', 'This invitation was already used.');
  const user = await verifiedUser(env, inv.email);
  const stmts = [
    // Keep a higher role if they already have one.
    env.DB.prepare(
      `INSERT INTO members (workspace_id, user_id, role, created_at) VALUES (?,?,?,?) ON CONFLICT(workspace_id, user_id) DO UPDATE SET role =
       CASE WHEN (CASE members.role WHEN 'admin' THEN 3 WHEN 'builder' THEN 2 WHEN 'member' THEN 1 ELSE 0 END) >=
                 (CASE excluded.role WHEN 'admin' THEN 3 WHEN 'builder' THEN 2 WHEN 'member' THEN 1 ELSE 0 END) THEN members.role ELSE excluded.role END`,
    ).bind(inv.workspace_id, user.id, inv.role, now()),
    event(env, inv.workspace_id, user.email, inv.app_id, 'invite_accepted', `${user.email} as ${inv.role}`),
  ];
  if (inv.app_id) stmts.push(env.DB.prepare('INSERT INTO grants (app_id, subject, role, created_at) VALUES (?,?,?,?) ON CONFLICT(app_id, subject) DO UPDATE SET role = excluded.role')
    .bind(inv.app_id, `user:${user.id}`, inv.app_role, now()), shareWithPeople(env, inv.app_id));
  await env.DB.batch(stmts);
  const app = inv.app_id ? await env.DB.prepare('SELECT slug FROM apps WHERE id = ?').bind(inv.app_id).first<{ slug: string }>() : null;
  return { user, appRef: app ? `${app.slug}.${inv.wslug}` : undefined, workspaceSlug: inv.wslug };
}

// ---------- groups ----------

export async function listGroups(env: Env, c: Caller) {
  const r = await env.DB.prepare(
    `SELECT g.id, g.name, (SELECT GROUP_CONCAT(u.email, ', ') FROM group_members gm JOIN users u ON u.id = gm.user_id WHERE gm.group_id = g.id) AS people
     FROM groups g WHERE g.workspace_id = ? ORDER BY g.name`,
  ).bind(c.workspace.id).all<{ id: string; name: string; people: string | null }>();
  return { groups: r.results.map(g => ({ id: g.id, name: g.name, people: g.people ? g.people.split(', ') : [] })) };
}
async function groupByName(env: Env, c: Caller, name: string) {
  const g = await env.DB.prepare('SELECT id, name FROM groups WHERE workspace_id = ? AND (id = ? OR name = ?)').bind(c.workspace.id, name, name.trim().toLowerCase())
    .first<{ id: string; name: string }>();
  if (!g) throw new Problem(404, 'no_group', `There is no group "${name}". Use list_groups or GET /v1/groups to see them.`);
  return g;
}
export async function createGroup(env: Env, c: Caller, name: string) {
  requireRole(c, 'admin', 'define groups');
  const clean = String(name ?? '').trim().toLowerCase().slice(0, 40);
  if (!/^[a-z0-9][a-z0-9 _-]*$/.test(clean)) throw new Problem(400, 'bad_name', 'A group name uses letters, numbers, spaces, - and _, for example "finance".');
  if (await env.DB.prepare('SELECT 1 FROM groups WHERE workspace_id = ? AND name = ?').bind(c.workspace.id, clean).first()) throw new Problem(409, 'exists', `There is already a group called "${clean}".`);
  const id = randomId('grp_', 8);
  await env.DB.batch([
    env.DB.prepare('INSERT INTO groups (id, workspace_id, name, created_at) VALUES (?,?,?,?)').bind(id, c.workspace.id, clean, now()),
    event(env, c.workspace.id, c.actor, null, 'group_created', clean),
  ]);
  return { id, name: clean, people: [] };
}
export async function deleteGroup(env: Env, c: Caller, name: string) {
  requireRole(c, 'admin', 'delete groups');
  const g = await groupByName(env, c, name);
  await env.DB.batch([
    env.DB.prepare('DELETE FROM group_members WHERE group_id = ?').bind(g.id),
    env.DB.prepare('DELETE FROM grants WHERE subject = ?').bind(`group:${g.id}`),
    env.DB.prepare('DELETE FROM groups WHERE id = ?').bind(g.id),
    event(env, c.workspace.id, c.actor, null, 'group_deleted', g.name),
  ]);
  return { deleted: g.name };
}
export async function setGroupMember(env: Env, c: Caller, group: string, who: string, add: boolean) {
  requireRole(c, 'admin', 'change group membership');
  const g = await groupByName(env, c, group);
  const p = await personInWorkspace(env, c, who);
  await env.DB.batch([
    add ? env.DB.prepare('INSERT OR IGNORE INTO group_members (group_id, user_id) VALUES (?,?)').bind(g.id, p.id)
      : env.DB.prepare('DELETE FROM group_members WHERE group_id = ? AND user_id = ?').bind(g.id, p.id),
    event(env, c.workspace.id, c.actor, null, add ? 'group_add' : 'group_remove', `${p.email} ${add ? 'to' : 'from'} ${g.name}`),
  ]);
  return listGroups(env, c).then(r => r.groups.find(x => x.id === g.id));
}

// ---------- app role grants ----------

/** One grant, as given by a person or agent: exactly one of email, group, domain, or everyone ("workspace" or "signed_in"). */
export interface GrantInput { email?: string; group?: string; domain?: string; everyone?: string; role?: string }

export async function resolveSubject(env: Env, c: Caller, g: GrantInput): Promise<{ subject: string; label: string }> {
  if (g.email) { const p = await personInWorkspace(env, c, g.email); return { subject: `user:${p.id}`, label: p.email }; }
  if (g.group) { const x = await groupByName(env, c, g.group); return { subject: `group:${x.id}`, label: `group ${x.name}` }; }
  if (g.domain) {
    const d = String(g.domain).trim().toLowerCase().replace(/^@/, '');
    if (!/^[a-z0-9.-]+\.[a-z]{2,}$/.test(d)) throw new Problem(400, 'bad_domain', 'A domain looks like "example.com".');
    return { subject: `domain:${d}`, label: `anyone @${d}` };
  }
  if (g.everyone === 'workspace' || g.everyone === 'signed_in') return { subject: g.everyone, label: g.everyone === 'workspace' ? 'everyone in the workspace' : 'anyone signed in' };
  throw new Problem(400, 'bad_grant', 'Each grant names one of "email", "group", "domain", or "everyone" ("workspace" or "signed_in"), plus a "role".');
}

export async function listGrants(env: Env, app: AppRow) {
  const r = await env.DB.prepare(
    `SELECT g.subject, g.role, u.email, gr.name AS gname FROM grants g
     LEFT JOIN users u ON g.subject = 'user:' || u.id LEFT JOIN groups gr ON g.subject = 'group:' || gr.id
     WHERE g.app_id = ? ORDER BY g.created_at`,
  ).bind(app.id).all<{ subject: string; role: string; email: string | null; gname: string | null }>();
  return r.results.map(g => ({
    role: g.role,
    ...(g.email ? { email: g.email } : g.gname ? { group: g.gname } : g.subject.startsWith('domain:') ? { domain: g.subject.slice(7) } : { everyone: g.subject }),
  }));
}

// ---------- the access decision ----------

export interface Decision { allowed: boolean; signInNeeded: boolean; role: string | null; groups: string[]; member: Role | null }

/**
 * Decide whether a person (or an anonymous visitor) may open an app, and with which app role.
 * The app's owner and workspace admins get the top role. Otherwise the best matching grant wins,
 * and modes that let a person in without a grant give the app's lowest role.
 */
export async function decide(env: Env, app: AppRow, user: User | null): Promise<Decision> {
  const roles: string[] = JSON.parse(app.roles);
  const lowest = roles[roles.length - 1];
  if (!user) return app.access === 'public' ? { allowed: true, signInNeeded: false, role: null, groups: [], member: null }
    : { allowed: false, signInNeeded: true, role: null, groups: [], member: null };
  const [m, gs, grants] = await env.DB.batch([
    env.DB.prepare('SELECT role FROM members WHERE workspace_id = ? AND user_id = ?').bind(app.workspace_id, user.id),
    env.DB.prepare('SELECT g.id, g.name FROM group_members gm JOIN groups g ON g.id = gm.group_id WHERE gm.user_id = ? AND g.workspace_id = ?').bind(user.id, app.workspace_id),
    env.DB.prepare('SELECT subject, role FROM grants WHERE app_id = ?').bind(app.id),
  ]);
  const member = (m.results[0] as { role: Role } | undefined)?.role ?? null;
  const groups = gs.results as { id: string; name: string }[];
  const insider = member !== null && member !== 'guest';
  const subjects = new Set([`user:${user.id}`, `domain:${user.email.split('@')[1]}`, ...groups.map(g => `group:${g.id}`), 'signed_in', ...(insider ? ['workspace'] : [])]);
  const matched = (grants.results as { subject: string; role: string }[]).filter(g => subjects.has(g.subject) && roles.includes(g.role));
  const best = matched.length ? roles[Math.min(...matched.map(g => roles.indexOf(g.role)))] : null;
  const names = groups.map(g => g.name);
  const yes = (role: string) => ({ allowed: true, signInNeeded: false, role, groups: names, member });
  if (app.owner_id === user.id || member === 'admin') return yes(roles[0]);
  // A grant to everyone in the workspace or everyone signed in only counts when the mode lets those people in.
  const direct = matched.filter(g => g.subject !== 'workspace' && g.subject !== 'signed_in');
  switch (app.access) {
    case 'private': break;
    case 'people': case 'password': if (direct.length) return yes(roles[Math.min(...direct.map(g => roles.indexOf(g.role)))]); break;
    case 'workspace': if (insider || direct.length) return yes(insider ? best ?? lowest : roles[Math.min(...direct.map(g => roles.indexOf(g.role)))]); break;
    case 'signed_in': case 'public': return yes(best ?? lowest);
  }
  return { allowed: false, signInNeeded: false, role: null, groups: names, member };
}

/** One sentence that says who can open an app (the share sheet). */
export function whoCanOpen(app: AppRow, grants: { email?: string; group?: string; domain?: string; everyone?: string }[], workspaceName: string): string {
  const named = grants.flatMap(g => (g.email ? [g.email] : g.group ? [`the ${g.group} group`] : g.domain ? [`anyone @${g.domain}`] : []));
  const list = named.length > 3 ? `${named.slice(0, 3).join(', ')} and ${named.length - 3} more` : named.join(', ');
  switch (app.access) {
    case 'private': return 'Only you (the owner) and workspace admins can open it.';
    case 'people': return named.length ? `Only ${list} can open it, after signing in.` : 'Nobody but you and workspace admins yet: add people or groups to share it.';
    case 'workspace': return `Everyone in ${workspaceName} can open it after signing in${named.length ? `, plus ${list}` : ''}.`;
    case 'password': return `Anyone with the address and its password can open it, without signing in${named.length ? `; ${list} can also sign in` : ''}.`;
    case 'signed_in': return 'Anyone who signs in with an email address can open it.';
    case 'public': return 'Anyone with the address can open it, without signing in.';
  }
}
