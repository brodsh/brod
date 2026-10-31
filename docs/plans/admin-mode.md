# Plan: Server admin mode (operator console, settings, limits)

Written against `main` at `9bd383f` (2026-10-31).

Goal: one place where the person running a Brod server can configure it from a browser (no `.env` edit plus restart),
see every workspace and app, and set limits such as the total number of apps allowed.

## 0. What exists today

| Area | Today | Where |
|---|---|---|
| Workspace admin page | `/w/<ws>/admin`, for a **workspace's** admins and builders: apps, marketplace, people, groups, billing. It does not cover the whole server. | `server/src/admin.rs`, `admin.html` |
| Operator API | `/v1/admin/...`, `Authorization: Bearer <ADMIN_SECRET>` only. Report queue, app takedown and restore, workspace suspend and trust. No UI and no session login. | `abuse.rs::serve` (from `api.rs:73`) |
| Who the operator is | No concept of one. `BROD_ADMIN_EMAIL` only decides who may create the **first** workspace. | `config.rs`, `people.rs::may_create_workspace`, `setup.rs` |
| Limits | Hard-coded `Plan { apps, members, storage, analytics_days }`. Hosted: `free`/`solo`/`team`. Self-hosted: `UNLIMITED` for everything. No per-workspace override. | `model.rs:148-201` |
| App limit | Counts **running** (`status = 'live'`) apps only. Paused apps are not counted. Checked in `control.rs::plan_full` (402 `plan_limit`). | `control.rs:676` |
| Member limit | `people.rs:327,344,441`. Guests are not counted. | `people.rs` |
| Storage limit | `usage.rs::check_storage` and app database fill. | `usage.rs:176-235` |
| Other limits | Constants: `DEPLOYS_PER_HOUR`, `CALLS_PER_MINUTE`, `WORKSPACES_PER_USER_DAY`, `NEW_WORKSPACE_MS`, and others. | `limits.rs`, `abuse.rs:20-30` |
| Server config | Read from env once at boot (`Config::from_env`). Toggles such as `BROD_MARKETPLACE` and `BROD_ABUSE_CHECKS` need a restart to change. | `config.rs` |

The limit checks have one weakness: `plan(&Workspace)` is a pure function with no database access, so a value stored
in the database cannot reach it. Every caller already holds a `Connection`, so the fix is mechanical.

## 1. Design

### 1.1 Who is an admin: "operator"

- New flag `users.operator_at INTEGER NULL`. It is separate from the workspace `admin` role, because a workspace admin
  is not a server admin.
- Bootstrap: at boot, the user whose email matches `BROD_ADMIN_EMAIL` becomes an operator. A self-hosted server that
  has no `BROD_ADMIN_EMAIL` instead promotes the admin of the first workspace, matching today's first-run flow.
- Operators can add or remove other operators in the UI. The last operator cannot be removed.
- `ADMIN_SECRET` bearer keeps working for scripts. Both paths go into one `Operator` caller. The audit log names the
  operator's email instead of the generic `"Brod operator"`.

### 1.2 Instance settings: changed at runtime, stored in the database

New table `instance_settings(key TEXT PRIMARY KEY, value TEXT /*json*/, updated_by TEXT, updated_at INTEGER)`.
Changes are added to both `migrations/` and `migrations-pg/`.

A typed registry in a new `server/src/instance.rs`:

```rust
pub struct Setting { key: &'static str, kind: Kind /* Int, Bool, Enum, StrList */, default: fn(&Config) -> Value, env: Option<&'static str> }
```

- The value used is: database value, else the env-derived value, else the built-in default.
- If an env var is set **explicitly**, that wins and the UI shows the setting as "locked by BROD_X" (read-only). This
  keeps infrastructure-as-code deployments predictable.
- Values are cached in `State` (`ArcSwap<Settings>`). A write refreshes the cache. With several replicas on Postgres,
  the cache also reloads on a 15 s TTL.
- **Secrets stay in env.** `ADMIN_SECRET`, `IDENTITY_SECRET`, `SECRETS_KEY`, Stripe keys, SMTP and S3 credentials are
  never editable or shown in the UI.

Settings in the first version:

| Group | Key | Default |
|---|---|---|
| Limits (defaults per workspace) | `limits.max_running_apps` (only live apps count; paused/stored apps are unlimited) | self-hosted: unlimited |
| | `limits.max_members` | unlimited |
| | `limits.max_storage_mb` | unlimited |
| | `limits.analytics_days` | `SELF_HOSTED_ANALYTICS_DAYS` |
| Server-wide caps | `server.max_workspaces` | unlimited |
| | `server.max_users` | unlimited |
| Sign-up / workspaces | `workspaces.creation`: `operators` \| `workspace_admins` (today's behaviour) \| `anyone_verified` | `workspace_admins` |
| | `signin.allowed_email_domains` (empty = any) | `[]` |
| Features | `features.marketplace`, `features.abuse_checks` | from env |
| Rate limits | `rate.deploys_per_hour`, `rate.calls_per_minute`, `rate.workspaces_per_user_day` | current constants |

### 1.3 Per-workspace overrides

New table `workspace_limits(workspace_id PK, max_running_apps, max_members, max_storage_mb, analytics_days,
note, updated_by, updated_at)`. A NULL column means "inherit".

Order used to resolve a limit:
**workspace override, else plan (hosted) or instance default (self-hosted), else built-in.**
**Decided:** overrides apply in hosted mode too, so an operator can give a customer more (or less) than their paid plan allows.

### 1.4 How limits are enforced

Replace `model::plan(&Workspace) -> Plan` with `limits::effective(conn, &Settings, &Workspace) -> Limits`, where
`Limits` has the same fields, now resolved from the database. Call sites:

| Check | Where | New behaviour |
|---|---|---|
| New app / unpause / marketplace install | `control.rs::plan_full`, `market.rs` install | Refuse when live apps ≥ `max_running_apps` (today's meaning, kept). Workspaces may store any number of paused apps. Error stays `402 plan_limit` with counts. |
| Members | `people.rs:327,344,441` | Use `effective().max_members`. |
| Storage | `usage.rs:176-235` | Use `effective().max_storage_mb`. |
| Create workspace | `people.rs::may_create_workspace`, `create_workspace` | Apply the `workspaces.creation` policy and `server.max_workspaces`. |
| Sign in / sign up | `auth` sign-in link handler | Apply `signin.allowed_email_domains` to **new** users only. Existing users are never locked out. |
| Rate limits | `control.rs::check_rate`, `CallLimiter`, `abuse::rate_limit` | Read from settings instead of constants. |
| Display | `billing.rs:172`, `people.rs:246` | Show effective limits, so the workspace admin page agrees with what is enforced. |

Lowering a limit below current usage never deletes or pauses anything. Existing apps keep running. Only new
deploys, installs and unpauses are refused, which matches today's `plan_limit` message.

Concurrency: the count check and the insert must happen in one transaction (`tx`), so two parallel deploys cannot
both take the last slot. `deploy` already runs in a transaction, so the check moves inside it.

### 1.5 Operator console UI

A static page at `/admin` on the API host, built like `admin.html`: one document that calls `/v1/admin/*` with the
session cookie. It is reached by session plus `operator_at`, and it is not linked for anyone else.

Tabs:
1. **Overview**: counts of workspaces, users, apps (live, paused, taken down), storage used, version, and config
   warnings (`cfg.warnings`).
2. **Settings**: the registry grouped as in §1.2. Env-locked keys are read-only. Every change records an event.
3. **Workspaces**: table with plan, members, running and total apps, and storage against effective limits.
   Row actions: edit limits override, suspend/unsuspend, trust, open the workspace admin page.
4. **Apps**: all apps on the server, with search. Takedown/restore (existing API).
5. **Reports**: the existing report queue (existing API).
6. **Nodes**: see §1.7.
7. **Operators**: list, add by email, remove.
8. **Audit**: operator events (`events` where actor is an operator).

### 1.6 API additions (`/v1/admin`, operator session or `ADMIN_SECRET`)

```
GET    /v1/admin/overview
GET    /v1/admin/settings                -> [{key, value, default, source: db|env|default, locked}]
PATCH  /v1/admin/settings                {key: value, ...}   (validated against the registry)
GET    /v1/admin/workspaces?q=&cursor=
GET    /v1/admin/workspaces/<ws>
PUT    /v1/admin/workspaces/<ws>/limits  {max_running_apps, max_members, max_storage_mb, analytics_days: n|null}
GET    /v1/admin/apps?q=&cursor=
GET    /v1/admin/operators  POST /v1/admin/operators {email}  DELETE /v1/admin/operators/<id>
```

Session writes go through `control::check_origin` (CSRF) just as `/v1/me` does. **No MCP tools:** server
administration stays out of agents' reach, in line with "agents can't widen access silently".

### 1.7 Nodes (needs vNext P1/P2)

On `evor/vnext-integration`, `nodes.rs::admin` already serves `/v1/admin/nodes` (ADMIN_SECRET only):
join tokens (15 min, one use, `brod-node join <origin> <token>`), list and get, `drain|disable|enable`, `DELETE`
(refused while connected unless disabled), and `tunnel/<path>`. The scheduler (`scheduler.rs`) places deployments on
online, connected nodes with room. Admin mode puts this behind the operator session and adds a UI:

| Action | API | Status |
|---|---|---|
| Add a node: mint a join token, show the copy-paste `brod-node join` command and the expiry, and wait until the node appears | `POST /v1/admin/nodes/join-tokens` | exists |
| List nodes: status, connected, version, address, last seen, CPU/memory capacity vs reserved, deployment count | `GET /v1/admin/nodes` | exists; add reserved and deployment counts |
| Node detail: its deployments (app, workspace, version, state) and recent heartbeats | `GET /v1/admin/nodes/<id>` | extend |
| Drain / disable / enable | `POST .../<id>/drain\|disable\|enable` | exists |
| Remove: guided flow disable → (move deployments) → delete, behind a confirm dialog | `DELETE /v1/admin/nodes/<id>` | exists |
| Rename | `PATCH /v1/admin/nodes/<id> {name}` | new |
| Evacuate: reschedule the node's live deployments onto other nodes, then drain | `POST .../<id>/evacuate` | new; check whether drain already reschedules |
| Revoke unused join tokens | `GET/DELETE /v1/admin/nodes/join-tokens` | new |

Node-related keys in the settings registry (§1.2): `nodes.join_token_minutes` (default 15) and
`nodes.memory_headroom_pct` (the scheduler keeps this much free). Only add them if P2 does not fix them first.

Safety: the UI never removes a node that still has live deployments unless they have been moved or the operator
types the node name to confirm. Every node action goes into the audit log with the operator's email.
`tunnel/<path>` stays API-only and is not exposed in the UI.

## 2. Phases

| Phase | Scope | Main files |
|---|---|---|
| A. Foundations | Migration (`users.operator_at`, `instance_settings`, `workspace_limits`); `instance.rs` registry, cache and env locking; operator bootstrap; `Operator` auth (session or secret) in `abuse::serve` | `migrations*/00NN_admin_mode.sql`, `instance.rs`, `state.rs`, `setup.rs`, `abuse.rs`, `api.rs` |
| B. Limits | `limits::effective`; move all enforcement points to it; move checks inside transactions; plus tests | `model.rs`, `control.rs`, `market.rs`, `people.rs`, `usage.rs`, `billing.rs` |
| C. Settings wiring | Workspace creation policy, email domain allowlist, feature toggles, rate limits read from settings | `people.rs`, `auth`, `limits.rs`, `abuse.rs`, `config.rs` |
| D. Admin API | Endpoints in §1.6, events and audit | new `operator.rs` (keep `abuse.rs` for abuse) |
| E. Console UI | `operator.html` + route `/admin` | `operator.rs`, `operator.html`, `http.rs` routes |
| G. Nodes | Operator auth on `nodes.rs::admin`; rename, evacuate, token list/revoke, per-node deployments; Nodes tab | `nodes.rs`, `scheduler.rs`, `operator.html` |
| F. Docs and e2e | `docs/configuration.md` (env vs UI and locking), `docs/security.md` (operator role), e2e: limit reached, override lifts it, locked env key, non-operator 403 | `docs/`, `test/` |

Phases A and B can ship without the UI; scripts can use `ADMIN_SECRET`.

## 3. Tests (minimum)

- Effective limit resolution: override, then plan or instance default, then built-in, for hosted and self-hosted.
- `max_running_apps` counts only live apps; a workspace at the limit can still hold any number of paused apps.
- Two concurrent deploys at limit − 1: exactly one succeeds.
- Lowering a limit below usage leaves existing apps live.
- An env-set key cannot be changed by PATCH (409 `locked`).
- Non-operator session gets 403 on `/admin` and `/v1/admin/*`; `ADMIN_SECRET` still works.
- Removing the last operator is refused.
- Email domain allowlist blocks new sign-ups only.

## 4. Coordination notes

- **Migration numbers:** vNext branches (#1–#5) already take `0020`–`0023`. Use the next free number at merge time.
  Do not reserve one now.
- `control.rs`, `api.rs` and `people.rs` are being changed heavily on `evor/vnext-integration`. Branch admin mode from
  the integration branch, or land Phase B after P2 merges, to avoid painful conflicts.
- **Decided:** admin mode branches from `evor/vnext-integration`, because nodes live there. Node management (phase
  G) depends on P1/P2 and lands after them.

## 5. Decisions (2026-10-31, rabin)

1. **App limit counts only running (live) apps.** A workspace may store any number of paused apps. There is no total
   app limit.
2. **Limits are per workspace.** They are set as instance defaults with a per-workspace override. There is no
   server-wide app cap.
3. **Operators may override plans in hosted mode too.** A workspace override beats the paid plan.
4. **Env vars win.** A key set in the environment is locked in the UI. The database only holds values for keys that
   are not set in the environment.
5. **Operators manage nodes** from the console: add (join token), list, drain, disable, enable, rename, evacuate and
   remove (§1.7).
