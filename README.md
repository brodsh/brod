# Brod

A cloud for small software. An agent deploys a web app over MCP and gets a live address back. A team's apps share one sign-in, one set of groups and roles, and one home page, so no app keeps its own user table.

This repository holds steps 1 to 3 of the build plan: **hosting** (deploy, versions, rollback, pause, plan allowance), the **workspace** (sign-up, one sign-in across every app, people, groups, role mapping, the identity contract, the home page, confirmations for agent actions, a report link, and [abuse protection](#abuse-protection)), and **server apps** (JavaScript server code per app with its own database, key-value store, files, secrets and logs).

One Worker does four jobs, split by hostname and path:

| Request | Handled by | File |
| --- | --- | --- |
| `<slug>.<workspace>.<APPS_DOMAIN>` | Gateway: signs people in, decides access, serves the live version from R2, and serves `/_brod/*` (identity, sign-out, report) | `src/gateway.ts` |
| a [custom domain](#custom-domains) a workspace has proven it owns | The same gateway | `src/domains.ts` |
| `POST /mcp` | MCP endpoint for agents (13 tools) | `src/mcp.ts` |
| `/v1/*` | REST control-plane API, for agents (token) and the dashboard (session) | `src/index.ts` |
| `/.well-known/oauth-*`, `/oauth/*`, `/w/<workspace>/connections` | Connecting agents: OAuth sign-in for MCP clients, and the connections page (make and disconnect tokens) | `src/connect.ts` |
| everything else | Sign-in, invitations, confirmations, workspace home pages | `src/auth.ts` |
| (inside the gateway) | Server apps: loads an app's server code, its database, files and log sink | `src/runtime.ts`, `src/secrets.ts` |

The MCP tools, the REST API and the confirmation pages all call the same functions in `src/control.ts` (apps, deploys, access) and `src/people.ts` (workspaces, people, groups, grants, sessions, and the access decision). Metadata lives in D1 (`migrations/0001_init.sql`); app files live in R2 under `<app id>/<version>/<path>`. A rollback, like publishing from staging, only moves a pointer in D1.

The same code also runs on **Vercel** (or any Node.js server) as one function, with Turso (libSQL) in place of D1 and an S3-compatible bucket in place of R2, for static apps. The adapters live in `src/platform/` and `src/node/`; see [Run it on Vercel](#run-it-on-vercel).

For your own server there is a third implementation: **a Rust server** in `server/` (binary `brod`), with the same HTTP behaviour as the Worker, SQLite in place of D1 (or Postgres, optionally), app files in a folder or an S3-compatible bucket, and server apps on [workerd](https://github.com/cloudflare/workerd), the open-source Workers runtime, as a sidecar. Docker Compose with Caddy runs all of it; see [Run it on your own server](#run-it-on-your-own-server). The TypeScript stays the specification: `scripts/e2e.mjs` runs unchanged against all three.

## Run it locally

```
npm install
npm run migrate               # create the local database
npm run dev                   # http://localhost:8787
```

If you ran step 1 locally, delete `.wrangler/state` first: the schema was replaced.

`.dev.vars` turns on `DEV_MODE`, so sign-in and invitation links are printed in the `wrangler dev` log and returned in API responses instead of being emailed.

Sign up and connect an agent:

1. Open `http://localhost:8787`, enter your email, and open the link from the log.
2. Create a workspace at `http://localhost:8787/new`.
3. Connect your agent. Either add the server and sign in with the browser when the client asks (OAuth; you pick the workspace on the consent page):
   ```
   claude mcp add --transport http brod http://localhost:8787/mcp
   ```
   or make a token on `http://localhost:8787/w/<workspace>/connections` and send it as `Authorization: Bearer brod_...`. On the Rust server the page lets you make it read-only and choose when it expires (30 days unless you pick otherwise):
   ```json
   { "mcpServers": { "brod": { "type": "http", "url": "http://localhost:8787/mcp", "headers": { "Authorization": "Bearer brod_..." } } } }
   ```

Then ask the agent to "deploy this to Brod". Locally, apps are at `http://<slug>.localhost:8787` and the workspace home page is at `http://localhost:8787/w/<workspace>`.

Builders and admins also have an admin page at `/w/<workspace>/admin` (the Rust server), and on the Rust server
`/w/<workspace>` takes them straight there; members and guests keep the plain app list, and builders can still open it
at `/w/<workspace>?view=apps` (the "App launcher" link in the admin page). The TypeScript Worker has no admin page, so
it shows everyone the app list. On the admin page builders can create an app or a new
version from a .zip of the built folder, roll back or delete old versions, change who can open an app, set secrets,
pause or delete apps, add and verify [custom domains](#custom-domains) (an app's Domains tab, or the Domains page for every domain and `*.` domains), see each app's visits and storage, read analytics for every app, group apps and people into spaces, invite and remove people,
manage groups, read the activity log, and (admins) change the plan and see invoices. Its Agents page links to the
connections page at `/w/<workspace>/connections`. Uploads accept .zip,
.tar or .tar.gz.

## Test, build and deploy

| Command | What it does |
| --- | --- |
| `npm run check` | Type checks the Worker, the Vercel/Node build and the tests. |
| `npm test` | Unit and integration tests (Vitest) inside the real Workers runtime, with in-memory D1 and R2. Covers slugs, signing, bundle clean-up, tar unpacking, the access decision for every mode and kind of person, and the HTTP and MCP flows end to end. No server needed. |
| `npm run build` | Bundles the Worker exactly as Cloudflare will run it, into `dist/`. |
| `npm run e2e:local` | Starts a fresh `wrangler dev` with its own database and runs `scripts/e2e.mjs`: 122 checks through the official MCP client and a cookie-keeping browser across the API and app hosts. |
| `npm run test:node` | Tests for the Vercel/Node build in plain Node.js: the D1 adapter on libSQL with the real migrations, the S3 and folder file stores (against a fake S3 that verifies every SigV4 signature, itself checked against AWS's published examples), the HTMLRewriter fallback, the Node adapter and the configuration checks. |
| `npm run build:vercel` | Bundles the Vercel function into `.vercel/output` (Build Output API). |
| `npm run e2e:node` | Serves that Vercel bundle with Node.js on a fresh libSQL file database, app files in a folder, and runs `scripts/e2e.mjs` with `E2E_SKIP_SERVER_APPS=1`: 117 checks (server apps are Cloudflare-only, so section 7 checks that they are refused and stops). |
| `npm run e2e:node:s3` | The same, with app files in a fake S3 server and uploads by presigned PUT, the way they work on Vercel. |
| `npm run test:rust` | The Rust server's unit tests (`cargo test`): the access decision for every mode and kind of person, tar unpacking and bundle limits, slugs, cookies, identity tokens, secrets sealed by `src/secrets.ts` (and `test-node/secrets-compat.test.ts` opens one sealed by Rust), bundle clean-up, the report link, SigV4 paths, the folder store and backups, and the SQL layer on both databases. With `BROD_TEST_DATABASE_URL=postgres://...` set, the same tests run on Postgres, plus the SQLite-to-Postgres copy. |
| `npm run e2e:rust` | Builds the release binary, starts it on a fresh data folder with `DEV_MODE=1` next to the workerd runtime (`deploy/runtime/`), and runs `scripts/e2e.mjs` (126 checks), then `scripts/e2e-billing.mjs` (41 checks: billing against the fake Stripe in `scripts/fake-stripe.mjs`, visits, analytics, storage and spaces), then `scripts/e2e-market.mjs` (79 checks: listing, previews Brod takes itself and uploaded ones, installing and updating through the marketplace, app settings, outside addresses, with `BROD_NETWORK=enforce` set to check refusing instead of recording; the previews are taken by `deploy/preview/` with Playwright's Chromium, and `E2E_SKIP_PREVIEWS=1` leaves them out), then `scripts/e2e-server-apps.mjs` (44 checks: the cases of `test/server.test.ts` over HTTP, an app filling its database until the plan's storage runs out, and apps stuck in a loop or using too much memory being cut off while the others keep serving; see [Limits for server apps](#limits-for-server-apps)). The runtime runs under its supervisor (`deploy/runtime/supervisor/`), built with cargo; `BROD_RUNTIME_BIN` skips that build. |
| `npm run e2e:rust:static` | The Rust server without a runtime: 121 checks, with server apps refused as `server_apps_unavailable`, then the 41 billing checks and the marketplace checks (75 without server apps). |
| `npm run e2e:rust:s3` | The Rust server with app files in the fake S3 server that checks every SigV4 signature. |
| `npm run e2e:rust:pg` | The same as `e2e:rust` with the database in Postgres: makes a fresh database with `psql` on the server at `E2E_DATABASE_URL` (default `postgres://postgres:pg@127.0.0.1:55432/postgres`, which `docker run -d --name brod-pg -e POSTGRES_PASSWORD=pg -p 55432:5432 postgres:17` gives you) and drops it afterwards. `pg` combines with `s3` and `static`. |
| `npm run e2e:tls` | The Rust server serving HTTPS itself (`BROD_TLS=acme`) against Pebble, Let's Encrypt's test CA: 11 checks, see [HTTPS without Caddy](#https-without-caddy). Downloads Pebble the first time. |
| `npm run verify` | Check, test (both runtimes) and build (both targets) in one go. Run this before pushing. |
| `npm run deploy` | Applies database migrations to the remote D1 database, then deploys. |

GitHub Actions:

- **CI** (`.github/workflows/ci.yml`) runs on every push and pull request: type check, tests, build, end-to-end suite, and keeps the built bundle as an artifact. A second job checks the Vercel build: Node tests, the Vercel bundle, and the end-to-end suite against it in both file-store modes. A third checks the Rust server: `cargo fmt --check`, `cargo clippy -D warnings`, `cargo test`, the three `e2e:rust` runs, and a build of both Docker images (never pushed). A fourth runs the Rust server's unit tests and end-to-end suite again with the database in Postgres, in a Postgres service container.

## How sign-in works

- **People** sign in once, with an emailed link (or Google, if configured). The platform session cookie lives only on the API host.
- **Apps** never see that cookie. When an app needs a person, the gateway sends them to `/auth/app`, which hands the app's host a one-time code; the app's host swaps it for its own session cookie. In production apps are on a separate domain, so an app cannot read the platform's cookies.
- **Signing out** of any app ends the platform session and every app session made from it. **Removing a person** from the workspace ends their access to every app on their next request.
- The emailed link opens a page with a Continue button, so mail scanners that open links do not use them up.

## The identity contract

An app reads the signed-in person from its own address:

```html
<script src="/_brod/client.js"></script>
<script>
  const me = await Brod.me();   // null when nobody is signed in (public apps)
  // { user: { id, email, name }, role: "editor", groups: ["finance"], app, workspace, token }
  if (me?.role === 'viewer') document.querySelector('#edit').hidden = true;
</script>
```

`Brod.signIn()` and `Brod.signOut()` send the person to sign in or out. `token` is the same identity signed with a per-app key (base64url JSON plus an HMAC-SHA256 signature, valid 5 minutes), for passing to a server. Server apps receive the same identity as request headers; see below.

## Server apps

A bundle with server code is a server app. Use the Cloudflare Pages layout that agents and build tools already know: a `_worker.js` ES module at the top of the bundle, or a `_worker/` folder with `index.js` and its other modules (`.js`, `.mjs`, `.cjs`, `.json`, `.wasm`, text). An `index.html` is optional.

```js
// _worker.js
export default {
  async fetch(request, env, ctx) {
    const email = request.headers.get('x-brod-user-email');       // the signed-in person (absent on public apps for anonymous visitors)
    await env.DB.run('CREATE TABLE IF NOT EXISTS notes (by TEXT, text TEXT)');
    if (request.method === 'POST') await env.DB.run('INSERT INTO notes VALUES (?, ?)', [email, await request.text()]);
    const notes = await env.DB.query('SELECT * FROM notes');       // rows as objects
    console.log('notes', notes.length);                            // shows in get_logs
    return Response.json({ notes, stripe: Boolean(env.STRIPE_KEY) });
  },
};
```

- **Routing.** A file that exists in the bundle is served directly. Every other request, with any method, goes to `fetch`. The server code itself is never served.
- **Identity.** Access is decided before the request reaches the app. The person arrives as `x-brod-user-id`, `x-brod-user-email`, `x-brod-user-name` (URI-encoded), `x-brod-role`, `x-brod-groups` (comma-separated) and `x-brod-identity` (the signed token). The gateway strips any `x-brod-*` header a visitor sends, and the platform's session cookie.
- **Storage, one set per app.** `env.DB` is the app's own SQLite database: `query(sql, params)` returns rows, `run(sql, params)` returns `{ changes }`, and `batch([{ sql, params }])` runs in one transaction. `env.KV` is a key-value store (`get`, `put`, `delete`, `list`; string values up to 128 KB). `env.FILES` is file storage (`put(key, body, contentType)`, `get(key)` returns a `Response` or `null`, `delete`, `list(prefix)`). No app can reach another app's storage. On the Rust server all three count toward the workspace's storage (see [Billing, visits, analytics, storage and spaces](#billing-visits-analytics-storage-and-spaces)).
- **Secrets.** `set_secret` (or `PUT /v1/apps/:slug/secrets/:NAME`) stores a value encrypted at rest (AES-GCM, key derived from `SECRETS_KEY`, bound to the app). The app reads it as `env.NAME` from its next request. Nobody can read a value back: the API lists names only.
- **Logs.** Each request's console output and exceptions are kept for 7 days. `get_logs` shows the last 50 and can search them.
- **Safe deploys.** A version whose server code throws while loading, or does not export `fetch`, is refused with the error, and the live version keeps serving. A request that throws gets a plain error page. The visitor never sees the exception; the owner sees it in the logs.
- **Limits per request:** 50 ms of CPU time and 50 outgoing requests. Outgoing `fetch` to the internet is allowed. On the Rust server, the limits are enforced differently: see [Limits for server apps](#limits-for-server-apps).

How it runs: the gateway loads the app's code from R2 into its own isolate with Cloudflare's [Worker Loader](https://developers.cloudflare.com/workers/runtime-apis/bindings/worker-loader/), keyed by app, version and secrets revision. So a rollback or a secret change takes effect on the next request, and nothing is uploaded to Cloudflare per deploy. The database is a SQLite Durable Object per app. Storage and logs reach the app as RPC stubs scoped to that app (`ctx.exports` with `props`). Idle apps cost nothing.

## Staging

Once an app is live, an update can go to its **staging address** first, `<slug>--staging.<workspace>.<APPS_DOMAIN>`, so
someone can try it before visitors see it. Staging serves one version (the app's `staging_version`) next to the live
one; publishing moves it live and empties staging, and nothing is rebuilt.

- **Where a deploy goes.** `deploy_app` and `POST /v1/deploys` take `"environment": "staging"` or `"production"`. Without
  it, an **agent** updating an app that already has a live version deploys to **staging**; a new app's first version,
  and a person deploying from the dashboard, go live. The admin page's deploy form offers "Staging first" or "Live now",
  and picks staging for an app that is already live. An upload address remembers the environment it was made for.
- **What the agent is told.** The tool descriptions and the MCP instructions ask the agent to check with the person
  before changing a live app, and a staging deploy answers with `staging_url` and a `next_step` that says to hand the
  person that address and call `publish_staging` only once they say it is ready.
- **Who can open staging.** The app's owner, workspace admins and builders (they try it with the app's top role), and
  anyone granted the app's top role. Never anonymous visitors or the app's password, whatever its access mode, and
  custom domains never serve staging. Visits on staging are not counted.
- **Publishing.** `publish_staging` (or `POST /v1/apps/:slug/publish`, or "Publish to live" on the admin page) makes the
  staging version live. `publish_staging` with `"discard": true` (or `DELETE /v1/apps/:slug/staging`) takes it off
  staging and keeps the version, so `rollback` can still serve it. A version on staging cannot be deleted.
- **Shared data.** Staging runs the new code against the app's own database, key-value store, files and secrets, the
  same ones the live version uses. What you change while testing is real.
- `get_status`, `list_apps` and every app result carry `staging` (`{ version, url }`, or `null`), and each version in
  `get_status` says whether it is `live` or on `staging`. The admin page shows the staging address on the app's page and
  in "Needs you" while a version waits there.

## Several people on one app

Each person's agent edits its own copy of an app's files and deploys the whole bundle. Without a check, a deploy built
from an older version silently undoes whatever someone else deployed since. So a deploy can say which version its files
started from, and Brod refuses it when the app has moved on.

- **`base_version`.** `deploy_app` and `POST /v1/deploys` take `"base_version": <n>`, the version the files started
  from (the `version` the agent's last deploy returned, or `current_version` from `get_status` when it began). An upload
  address remembers it. The app's **current version** is the one waiting on staging, or else the live one; every app
  result carries it as `current_version`.
- **Refused, not merged.** If the current version is no longer `base_version`, nothing is deployed: `409 stale_base`
  with `your_base`, `current_version`, `current_environment` (`staging` or `live`) and `since`, the versions deployed
  after the base with who deployed each and its note. The message tells the agent to tell the person, then get the
  current files with `get_files`, add its changes and deploy again with the new base, or replace the other work only if
  the person says so. Brod never merges bundles itself: they are build output, not source.
- **Getting the files back.** `get_files` (and `GET /v1/apps/:slug/files?version=`) returns a version's files, by
  default the current one, so an agent starts from what is deployed rather than its own older copy. Up to 1 MB and 200
  files they come inline, text as text and anything else as base64; a larger version comes as a `download_url`, a
  tar.gz that `curl | tar -xzf -` unpacks, which works without signing in for 15 minutes (`GET /v1/downloads/:id`,
  the address being its own credential, like an upload address). The result says to deploy with `base_version` set to
  the version returned. Only builders and admins can get files, the people who can deploy the app anyway; that includes
  server code, never secrets. The files are the built output as deployed, so for an app built from source with a build
  step they are a fallback, not the source. On Vercel a download over about 4.5 MB is cut off by the response limit.
- **Who else is working on it: a warning, never a lock.** Getting an app's files or deploying it records that the
  person is working on it (one row per app and person, in `editing`, with the agent connection they used and the
  version they started from). For two hours after someone's last such action, everyone else's `get_files`, deploy and
  `get_status` results carry `others_editing` (`by`, `via`, `base_version`, `since`, `last_active`) and a `warning` to
  pass on: who, through which agent, from which version, how long ago. Nothing is blocked. A person's own agents never
  warn them about themselves.
- **Checked when it counts.** The check runs before the upload and again in the same transaction that moves the
  pointer, so of two deploys from the same version exactly one goes through. A refused version's files are removed.
- **Straight to live.** A deploy with `base_version` and `"environment": "production"` builds on what was waiting on
  staging, so it also empties staging: publishing that version later would undo the new live one.
- **History.** Each version in `get_status` has `based_on` (`null` when the deploy did not say), and the deploy event
  in the activity log says `(from v<n>)`.
- **Version numbers.** A deploy takes its number from a counter on the app (`apps.last_version`) in one statement,
  before writing any files, so two deploys at once never share a number or a folder, and a deleted or refused version's
  number is never used again. Numbers can therefore skip.
- `base_version` is optional, so existing agents keep working; the `deploy_app` description and the server's MCP
  instructions ask agents to pass it whenever they update an app.

## Access

Each app has one of five access modes, changeable at any time without a redeploy:

| Mode | Who can open it |
| --- | --- |
| `private` | The app's owner and workspace admins |
| `people` | Only the people, groups and email domains granted a role |
| `workspace` | Everyone in the workspace (guests only if granted) |
| `password` | Anyone with the address and the app's password, without an account. People granted a role can sign in instead. |
| `signed_in` | Anyone who signs in |
| `public` | Anyone, without signing in. Pages carry a small "Report" link. |

Giving someone a role on a `private` app (through `set_access` or an invite) switches it to `people`, since a grant on a private app would do nothing.

Someone signed in whom an app is not shared with gets the same "App not found" page (404) as an address with no app
at all, so an address says nothing about whether an app lives there. The refusal still goes to the activity log, and
the admin page's "Needs you" list shows it for three days or until it is dismissed.

**Sharing with a password.** `set_access` with `{ "access": "password", "password": "..." }` (or the Access tab) lets
anyone with the address and the password in, without an account: they see a password page, and a correct password
earns a cookie on the app's own address for 30 days. Brod keeps only a salted PBKDF2-SHA256 hash, so it cannot show
the password again. A new password signs out everyone who used the old one, moving the app to another mode forgets
it, and after 30 wrong passwords in 15 minutes the app asks visitors to wait. Visitors who came in with the password
are anonymous to the app (`/_brod/me` answers 401), as on a public app. From an agent, setting a password is
widening access, so it waits for the owner's confirmation; the confirmation stores the hash, not the password.

Each app declares its roles, most powerful first (default `owner`, `editor`, `viewer`). Grants map a person, a group, an email domain, or everyone to one of those roles. Grants are stored as conditions (`user:`, `group:`, `domain:`, `workspace`, `signed_in`), so conditions such as "has installed" can be added later. The owner and workspace admins get the top role. Anyone else let in without a grant gets the lowest.

Workspace roles: **admin** (people, groups, branding), **builder** (deploy and manage apps, connect agents), **member** (use apps), **guest** (only the apps they were given).

## Abuse protection

The same rules on all three servers: `src/abuse.ts` and `src/scan.ts`, `server/src/abuse.rs` and `server/src/scan.rs`.

- **Takedown.** The platform operator can take one app down. Every address of the app, its `/_brod/` pages included, answers `410` with a neutral "This app has been taken down" page that gives no reason. While it is down, its owner and their agents cannot resume, deploy, upload, roll back, delete it (or its versions), or widen its access; narrowing still works. `get_status` and `list_apps` show `taken_down` with the reason and an explanation an agent can relay. Taking an app down resolves its open reports.
- **Suspension.** The operator can suspend a whole workspace. All its apps answer `410`, it cannot deploy new apps, and its existing apps are held as if taken down (`workspace_suspended` in `get_status` and `list_apps`).
- **New workspaces stay inside for a day.** For its first 24 hours (`ABUSE.newWorkspaceMs` / `NEW_WORKSPACE_MS`), a free workspace cannot set an app to `password`, `signed_in` or `public`. Sharing inside it (`workspace`, or `people` with named people and groups) works from the start. A paid plan, or the operator's `trust` call, lifts it at once. The refusal is `403 workspace_too_new`, with the time it lifts and what the agent can do now.
- **Rate limits**, counted in fixed windows in the `rate_limits` table, answering `429 rate_limited` with `retry_after_seconds`:

  | What | Limit |
  | --- | --- |
  | Sign-in links | 20 an hour per client address, on top of 5 an hour per email address |
  | OAuth client registrations (`/oauth/register`) | 10 an hour per client address, on top of 100 an hour across the server |
  | New workspaces | 3 a day per person |
  | Abuse reports | 10 an hour per client address |
  | Deploys (as before) | 30 an hour per workspace |

  The client address is `cf-connecting-ip` on Cloudflare; on Vercel and plain Node, the Node listener sets it from Vercel's `x-forwarded-for` or the socket. The Rust server uses the connection's address, or the first `X-Forwarded-For` hop when `BROD_TRUST_PROXY=1` (Caddy, as configured in `deploy/`, replaces whatever the visitor sent, so that hop is the real one; a proxy that appends instead would let visitors pick their address). IPv6 addresses count per /64. Where no address is known (the Workers test runtime), only the per-email, per-person and per-workspace limits apply.
- **Deploy-time phishing check.** Every deploy's HTML and JavaScript (up to 8 MB a bundle) is scored with plain string matching, no outside service. A version is flagged when it asks for a password or card number **and** scores 3 or more on impersonation signals: a known brand in the title, a heading, a label or a logo file name (2); sign-in words next to a brand, such as "sign in to your &lt;brand&gt; account" (3), or a brand account name (2); a brand in the page text (1); phrases such as "verify your account" (1 each, at most 2); a form that posts to another site (2); code that posts to a Telegram bot or Discord webhook (3); an IP lookup (1). A seed-phrase prompt, a "connect your wallet to claim" prompt, or a page that writes itself from an encoded string is flagged on its own. A flagged version still deploys, but the app stays `private` or `people` (an app that was open wider is narrowed to `people`), widening it is refused with `403 flagged` and the reasons, an automatic report goes to the queue, and `get_status` shows `flagged`. Rolling back to a flagged version does the same, and neither a flagged nor a taken-down app can publish a marketplace release (installs are deployed like any other version, so they are checked too). The operator clears the flag with `clear`.

  What it misses and what it may catch wrongly: it only sees the files in the bundle, so a page that loads its form from elsewhere, renders it from server code at request time, or uses an image of a logo with a neutral file name gets through; the brand list is short and English. A legitimate app can be flagged when its own login form posts to an outside identity service and its text says "sign in to continue", or when it really is a company's own portal named after that company; the cost of a false flag is that the app stays private or shared with named people until the operator clears it.

### The operator's API

Every call needs `Authorization: Bearer $ADMIN_SECRET`. Each action is recorded in the workspace's audit log (`GET /v1/events`) as by `Brod operator`.

| Route | |
| --- | --- |
| `GET /v1/admin/reports?status=open\|resolved\|dismissed` | The report queue, newest first (visitor reports and the phishing check's `automatic` ones), with each app's workspace and whether it is down |
| `POST /v1/admin/reports/:id` `{status: "resolved"\|"dismissed", note}` | Close a report |
| `POST /v1/admin/apps/:workspace/:app/takedown` `{reason}` | Take an app down (the reason is required; its owner sees it) |
| `POST /v1/admin/apps/:workspace/:app/restore` `{note?}` | Bring it back |
| `POST /v1/admin/apps/:workspace/:app/clear` `{note?}` | Clear the phishing check's flag on the app's versions |
| `POST /v1/admin/workspaces/:workspace/suspend` `{reason}`, `/unsuspend` `{note?}` | Suspend a workspace, or lift it |
| `POST /v1/admin/workspaces/:workspace/trust` `{note?}` | Let a new workspace open apps to everyone before it is a day old |

```sh
A="Authorization: Bearer $ADMIN_SECRET"
curl -sS -H "$A" "https://brod.sh/v1/admin/reports?status=open"
curl -sS -H "$A" -H 'content-type: application/json' -d '{"reason":"Credential phishing"}' https://brod.sh/v1/admin/apps/acme/login/takedown
curl -sS -H "$A" -X POST https://brod.sh/v1/admin/apps/acme/login/restore
curl -sS -H "$A" -H 'content-type: application/json' -d '{"status":"dismissed","note":"Not abuse"}' https://brod.sh/v1/admin/reports/rep_0123456789abcdef
curl -sS -H "$A" -H 'content-type: application/json' -d '{"reason":"Spam"}' https://brod.sh/v1/admin/workspaces/acme/suspend
curl -sS -H "$A" -X POST https://brod.sh/v1/admin/workspaces/acme/trust
```

## Billing, visits, analytics, storage and spaces

These are in the Rust server (`server/src/billing.rs`, `usage.rs`, `analytics.rs`, `spaces.rs`); the Worker and the Vercel host enforce the plan allowances but have none of the rest.

**Plans.** Each workspace is on `free`, `solo` or `team`:

| Plan | Running apps | People (guests free) | Storage | Analytics kept |
| --- | --- | --- | --- | --- |
| free | 10 | 10 | 250 MB | 30 days |
| solo | 15 | 1 | 5 GB | 1 year |
| team | 50 | 25 | 25 GB | 2 years |

**Billing with Stripe.** The paid plans are Stripe subscriptions to two recurring prices you create in Stripe; their amounts and currency are read from Stripe and shown on the Billing page. An admin picks a plan there: the first upgrade goes through Stripe Checkout, a switch between paid plans updates the subscription in place (prorated), and moving back to free cancels at the end of the paid period. The card, receipts and cancelling are in Stripe's customer portal (the Manage billing button). Stripe's webhooks are what change the plan, so allowances follow payment: an active, trialing or past-due subscription gives its plan; a canceled or unpaid one drops the workspace to free. Apps over the free allowance keep running, but no more can start until the plan is upgraded or some are paused. Every plan change is in the activity log.

To turn it on: create the two prices, add a webhook endpoint at `<API_ORIGIN>/stripe/webhook` for `checkout.session.completed` and `customer.subscription.created`, `.updated` and `.deleted`, turn on the customer portal in Stripe's settings, and set `STRIPE_SECRET_KEY`, `STRIPE_WEBHOOK_SECRET`, `STRIPE_PRICE_SOLO` and `STRIPE_PRICE_TEAM`. Webhooks are checked against their signature (and refused when older than five minutes), and each event is applied once. Without these variables the Billing page says billing is off and plans change only by hand in the database.

**Visits.** The gateway counts page views (`Sec-Fetch-Dest: document`, or a page path for browsers that do not send it; not scripts, styles or images) and distinct visitors per app per day. A visitor is a salted hash of their user id, or of their address and browser when they are not signed in, and that day; nothing that identifies them is stored, and the hashes are dropped after 35 days, leaving the daily totals. Counts are kept in memory and written every 10 seconds.

**Analytics.** The Analytics page (`/w/<workspace>/admin#analytics`, or `#analytics/<app>` for one app; `GET /v1/analytics`) shows, for every app or one, over 24 hours to 2 years (as far as the plan keeps): visitors, page views, visits (sessions: a visitor's pages with no gap over 30 minutes), pages per visit, bounce rate, visit length and time on page, each against the period before; visitors right now; a chart per hour or per day in the viewer's time zone; top, entry, exit and not-found pages; referrers and campaign tags (`utm_source` or `ref`, `utm_medium`, `utm_campaign`); countries and languages; devices, browsers, operating systems, screens and resolutions; visit depth; signed-in share; a weekday-by-hour heatmap; requests, bandwidth, status classes, response-time percentiles and a histogram, server-error rate and crawler traffic; Core Web Vitals (LCP, INP, CLS, FCP, TTFB at the 75th percentile, with good/needs improvement/poor shares); custom events; clicks to other sites; and JavaScript errors.

Where it comes from:

- **The gateway** records every page view with its path (never the query string), the host of an outside referrer, campaign tags, country (from `CF-IPCountry`, `X-Vercel-IP-Country`, `CloudFront-Viewer-Country`, `X-Country-Code` or `X-Geo-Country` when `BROD_TRUST_PROXY=1`, else the region of the browser's first language), language, browser, OS and device (from the User-Agent), whether the visitor is signed in, the status and the server time. The visitor is the same salted daily hash as for visits. Crawlers, link previews, uptime checks and command-line clients are counted as requests but never as page views or visitors. Every request an app answers is also folded into per-app hourly counters (status classes, bytes, crawlers, a server-time histogram).
- **The insights script** (`/_brod/insights.js`, about 3 KB, no cookies or storage) is added to every HTML page of a static app before `</body>`. It reports Core Web Vitals, time the page was visible, screen class and size, JavaScript errors and unhandled rejections, clicks on links to other sites, navigations inside single-page apps (`history.pushState`, which count as page views), and custom events: `brod.track('signup', { value: 1, label: 'pro' })`. Server apps add `<script src="/_brod/insights.js" defer></script>` to their own pages. A page with `<meta name="brod-insights" content="off">`, or that already loads the script, is left alone. Reports go to `POST /_brod/insights` on the app's own address, are taken only from people who may open the app, and are capped at 30 items per request.

Everything is collected in memory and written every 10 seconds in one transaction with multi-row inserts (`page_views`, `app_events`, `request_stats`; migration `0012_analytics.sql`). A report reads each table with one indexed range scan, streamed (`Sql::each`, rows from Postgres arrive as they are read) and aggregated in a single pass in Rust: sessions, entries and exits, every breakdown and the comparison come from the same read. On Postgres the tables are indexed `(app_id, at)` and `(workspace_id, at)` for the page's reads, with a BRIN index on `at` for the retention sweep, packed full (`fillfactor = 100`) since rows are only appended, and vacuumed sooner than the default. Every hour, rows older than the workspace's plan keeps are deleted (a workspace that is deleted or moves to a smaller plan loses the older rows on the next sweep), and deleting an app deletes its analytics.

**Storage.** Every kept version's bundle counts, plus what server apps keep in `env.FILES`, `env.DB` and `env.KV`. A deploy or a file write that would go over the plan is refused (`storage_limit`); deleting an old version frees its space. An app's database and key-value store (one SQLite file in the runtime) report their size to Brod after writes, at most every 5 seconds unless they grew by 256 KB, and Brod also asks the runtime for every server app's size every 10 minutes. While the workspace is out of storage, database statements that can grow it (anything but `SELECT`, `EXPLAIN`, `DELETE` and `DROP`) and `KV.put` throw `This app's workspace is out of storage...`; reads and deletes keep working, and deleting frees the space at once. Because sizes are reported in steps, an app can go a little over (about 256 KB per app, plus its last statement) before writes stop.

**Spaces.** A space groups related apps and the people who use them. An app is in at most one space. Everyone in a space can open its apps wherever named people count (the `people` and `workspace` modes), with their space role when the app has that role and the app's lowest role otherwise; private apps stay private. Admins create spaces and choose who is in them; builders move apps between spaces.

## Marketplace

In the Rust server (`server/src/market.rs`), like billing and spaces. A builder lists one of the workspace's apps; every workspace on the same server can then install its own copy and host it there, with its own address, sign-in, access, guests, secrets and data. Every listing is free for now.

- **Listing.** The app's live version (or a version you name) becomes release 1. A release is a frozen copy of that version's files, kept under `<listing id>/<n>/` in the file store, so the publisher can keep deploying, roll back and delete versions without changing what installers get. Releases count toward the publisher's storage. Only a person can list an app or list it again: an agent gets `people_only`, because listing shows the code (server code included) to every workspace on the server. Secrets and data are never copied; a listing names the secrets its server code reads (names only), so installers know what to set.
- **Finding and deploying.** Everything listed shows on the admin page's **Deploy an app** page, under "From the marketplace", and on the Marketplace page: search by name, what it does or who made it, press Deploy, name your copy, and it is deployed to your workspace.
- **Previews Brod takes itself.** With the preview service running (`BROD_PREVIEW_URL`, below), every release a publisher puts out is run and filmed automatically, a minute or so after publishing: a desktop screenshot (1280×800), a short screencast that scrolls through the page, and a phone screenshot (390×844). Nobody has to make them. They are taken of an **empty sandbox copy** of the release, never the publisher's live app: the release's own files and server code with a fresh, empty database and files and none of its secrets, so they show what an installer gets on day one and cannot leak the publisher's data into a picture every workspace sees. The sandbox is wiped before and after. The capturing browser opens it at `http://<token>.brod-preview.internal` on Brod's internal listener only; the token is random, names one release, lasts two minutes and is gone when the capture ends, and Brod's public HTTPS listener never serves such names. The previewed page may reach its sandbox and the public internet and nothing else: requests to private addresses and internal names are blocked (`deploy/preview/guard.mjs`). New previews replace the old automatic ones; the publisher can take them again at any time (Take them again on the Marketplace page, or `POST /v1/listings/:listing/previews`), and remove any of them.
- **Screenshots and screencasts.** A publisher can also add their own (up to 6 previews in all) to a listing (10 MB each): PNG, JPEG, WebP or GIF screenshots and MP4, MOV or WebM screencasts, each with a caption. The first one is shown on the listing's card and the rest as thumbnails, so people see the app before deploying it. A file's type is read from its first bytes, never from what the uploader says, so markup such as HTML or SVG is refused; previews are served with that type, `nosniff` and a sandboxing CSP. They count toward the publisher's storage and are never copied into installs.
- **Installing** makes a new private app in the installing workspace from the latest release, inside its plan allowance and storage like any deploy, with the release's app roles. The app stays **linked** to the listing.
- **Updates are offered, never deployed on their own.** When the publisher publishes a new release, every linked app shows "update available" (in `get_status`, `list_apps`, the admin page's overview and Marketplace page) with the release notes. Nothing changes until a builder in the installing workspace deploys it (`POST /v1/apps/:slug/marketplace/update`, or the button on the app's page). The update becomes the app's next version, so its access, secrets and data stay, and a rollback undoes it. A new version of the publisher's own app changes nothing for installers until it is published as a release.
- **Unlisting** hides the listing and stops new installs; installed copies stay linked and still get releases. **Deleting** a listing removes its releases and unlinks installed copies, which keep running as ordinary apps. An installed app can also stop following its listing. Deleting the app a listing came from keeps the releases already published, still installable.
- **Paid listings later.** Each listing stores a price (`price_cents`, `currency`), always 0 for now: listing with a price is refused (`paid_not_yet`), and installing or updating from a listing with a price is refused (`paid_listing`) until payment for apps exists.
- The publisher sees how many copies are installed, never which workspaces installed them.
- **Where it sends data.** A listing shows the outside hosts its app [declares](#outside-addresses) (or "no outside services"), and whether this server enforces that. Installing an app that declares hosts needs a person to tick that they allow them (`accept_network: true`; an agent gets `network_needs_a_person`), and so does deploying a release that adds a host: the app's page lists the new hosts before the update.
- **Settings.** A listing shows the [settings](#app-settings) its app declares, and the install form asks for them with the publisher's defaults filled in, so each workspace can deploy the app under its own name, logo and colours.

## App settings

In the Rust server (`server/src/settings.rs`). The people who make an app decide what the people who use it can change without touching its code: a name, a logo, colours, wording, a contact address, a number of tables. Brod imposes none. The app declares them in a `brod.json` at the top of its bundle:

```json
{ "settings": [
  { "key": "name",   "label": "Shop name",     "type": "text",  "default": "My shop" },
  { "key": "logo",   "label": "Logo",          "type": "image", "default": "logo.png" },
  { "key": "accent", "label": "Accent colour", "type": "color", "default": "#1f6f4a" },
  { "key": "theme",  "label": "Theme",         "type": "select", "options": ["light", "dark"], "default": "light", "help": "Shown to visitors" }
] }
```

- **Types:** `text` (200 characters), `textarea` (4000), `color` (`#rrggbb`), `image`, `url` (http or https), `email`, `number` (optional `min`, `max`), `boolean` and `select` (with `options`). A key is lowercase letters, digits and `_`. At most 30 settings. An image's default is a picture in the bundle; every other default is a value of its type.
- **Checked at deploy.** The declaration is read on every deploy and kept with the version, so it changes with versions, staging and rollbacks, and goes into marketplace releases. A `brod.json` Brod cannot use refuses the deploy (`bad_settings`) with what is wrong, so the mistake shows to the maker, not to someone installing.
- **Changing them.** On the admin page's **Customize** tab, when installing from the marketplace (`settings` in the install body), or with `PATCH /v1/apps/:slug/settings` `{ "name": "Cy's Coffee", "theme": null }` (null goes back to the default). Images are uploaded with `PUT /v1/apps/:slug/settings/:key` (PNG, JPEG, WebP or GIF, up to 1 MB, typed by their bytes, counted in the workspace's storage). No redeploy: changes show on the next request, and are in the activity log as `settings_changed`. Values are per app, so every installed copy has its own and updates from the marketplace keep them.
- **Reading them.** In the browser, `await Brod.settings()` (or `GET /_brod/settings` on the app's address) returns `{ "name": "...", "logo": "/_brod/settings/logo?v=...", "accent": "#1f6f4a", "theme": "light" }`: every declared key, with its default when nobody set it, and an image as an address to put in `<img src>`. Server code gets the same object as `env.SETTINGS`. Like the app itself, the settings are only served to people who may open it.

## Outside addresses

In the Rust server (`server/src/network.rs`). Nobody can prove by reading code that it does not leak data, so Brod does not try: an app may only send data to its own address and the outside hosts it declares, and Brod enforces that where the app's code runs. The app declares them in its `brod.json`:

```json
{ "network": ["api.stripe.com", "cdn.jsdelivr.net", "*.googleapis.com"] }
```

Host names only (no `https://`, port or path); `*.` covers subdomains, not the name itself. At most 30. Without a list, the app may only talk to its own address. The list is checked at deploy (`bad_network`), kept with the version, and goes into marketplace releases.

- **Server code.** Every `fetch` an app makes passes the runtime's outbound gate (`AppOutbound` in `deploy/runtime/host.js`), which lets declared hosts through. There is no other way out: no sockets, and the app's database, key-value store and files are not reached over the network.
- **The browser.** Every response from the app carries a `Content-Security-Policy` built from the list: its pages may load scripts, styles, fonts and pictures, fetch, open WebSockets, frame pages and post forms only to their own address and the declared hosts. Inline scripts still run; the policy is about where data goes. Browsers report what it stops to `/_brod/csp`. One gap no header closes: a script can still send the visitor's browser to another address with data in it (`location = ...`); the review and reporting of the marketplace cover that.
- **Log first, then enforce.** `BROD_NETWORK` sets what happens to an undeclared request. `log`, the default, lets it through and records it, and pages carry the policy as `Content-Security-Policy-Report-Only`, so existing apps keep working while their makers complete their lists. `enforce` refuses it (server code gets a 403 with `x-brod-network: refused`) and records it, and the policy is enforced. `off` does neither.
- **What people see.** Each app's **Network** tab (and `network` in `get_status`) shows the declared hosts, this server's policy, and every undeclared host the app reached or tried to, from its server code or a browser, with counts and whether it was blocked. Only the app's own workspace sees this. Installers see the declared list on the listing and approve it, as above.

| Tool | What it does |
| --- | --- |
| `deploy_app` | New app (`name`) or new version (`app`), static or with server code. Small apps pass `files` inline (up to 1 MB). Without `files` it returns a one-time upload address and a `tar \| curl` command for the build folder (up to 25 MB). `environment`: `staging` or `production`; an update to a live app goes to [staging](#staging) by default. `base_version`: the version the files started from; refused with `stale_base` if someone deployed since ([several people](#several-people-on-one-app)). |
| `get_files` | One version's files, the current one by default: inline when small, else a short-lived tar.gz `download_url`. Marks the caller as working on the app; carries a `warning` when someone else is ([several people](#several-people-on-one-app)). |
| `list_apps` | Apps with address, status, who can open each, live version, and plan slots in use. |
| `get_status` | One app: versions, roles, grants, and a one-sentence "who can open it". |
| `get_logs` | An app's recent activity (with the connection or person behind each), and for server apps its last 50 requests with console output and exceptions. `search` filters them. |
| `set_secret` | Store, replace or remove (`remove: true`) a secret for an app's server code. Values are write-only. |
| `publish_staging` | Make the version on the app's [staging address](#staging) live, or take it off staging (`discard: true`). |
| `rollback` | Serve an earlier version. Takes effect on the next request. |
| `set_access` | Change the access mode and add or remove role grants. |
| `set_paused` | Pause (frees a plan slot) or resume. |
| `invite` | Invite someone into the workspace, or as a guest to one app. |
| `set_domain` | Serve an app at a domain the workspace owns, or every app under `*.<domain>`; call again to verify the DNS records, or `remove: true`. See [Custom domains](#custom-domains). |
| `get_workspace` | Groups, default roles, access modes, plan slots, and how an app reads the signed-in person. |

**Confirmations:** deploying, reading status and reading logs need no confirmation. When an agent widens access (a more open mode or new grants), invites someone, or deletes an app, nothing changes yet. The tool returns a `confirm_url`, and a person in the workspace opens it and confirms or declines. Narrowing access applies at once.

Errors come back as tool results the agent can act on, for example `plan_limit` with the running count, the apps that could be paused, and an upgrade link.

## REST API

Agents send `Authorization: Bearer brod_...`. The dashboard sends the session cookie, an `Origin` of `API_ORIGIN` on changes, and picks a workspace with `X-Brod-Workspace` or `?workspace=` (default: the person's first).

| Route | |
| --- | --- |
| `GET /v1/me`, `POST /v1/workspaces` `{name, accept_terms}` | The signed-in person; create a workspace |
| `GET` / `PATCH /v1/workspace` `{name, color, icon}` | Workspace details and branding |
| `GET /v1/people`, `PATCH` / `DELETE /v1/people/:email-or-id` `{role}` | People directory |
| `GET` / `POST /v1/invites` `{email, role, app?, app_role?}`, `DELETE /v1/invites/:id` | Invitations |
| `GET` / `POST /v1/groups` `{name}`, `DELETE /v1/groups/:name`, `POST /v1/groups/:name/members` `{email}`, `DELETE /v1/groups/:name/members/:email` | Groups |
| `GET` / `POST /v1/tokens` `{name, scope?, expires_in_days?}`, `DELETE /v1/tokens/:id` | Agent connections. On the Rust server, `scope` is `manage` (the default) or `read`, and `expires_in_days` is 1 to 365 (default: never). |
| `GET /v1/events?app=&action=&limit=` | One audit log for the workspace |
| `POST /v1/deploys` | Same as `deploy_app` |
| `GET /v1/apps/:slug/files?version=`, `GET /v1/downloads/:id` | Same as `get_files`; the download address needs no sign-in until it expires |
| `GET /v1/apps`, `GET` / `PATCH` / `DELETE /v1/apps/:slug` `{title, welcome, roles}`, `GET /v1/apps/:slug/logs?search=` | Apps |
| `GET /v1/apps/:slug/secrets`, `PUT` / `DELETE /v1/apps/:slug/secrets/:NAME` `{value}` | Secrets (names only on read) |
| `GET` / `POST /v1/apps/:slug/access` `{access, add, remove}`, `POST /v1/apps/:slug/rollback` `{version}`, `/publish`, `/pause`, `/resume`, `DELETE /v1/apps/:slug/staging` | Changing an app ([staging](#staging): publish or discard) |
| `GET /v1/apps/:slug/usage?days=`, `DELETE /v1/apps/:slug/versions/:n`, `POST /v1/apps/:slug/space` `{space}` | An app's visits and storage, deleting an old version, its space (Rust server) |
| `GET /v1/usage?days=` | Visits and storage for every app (Rust server) |
| `GET /v1/analytics?days=&app=&tz=` | Analytics for every app, or one; `days` is cut to what the plan keeps, `tz` is the viewer's offset in minutes east of UTC (Rust server) |
| `GET` / `POST /v1/spaces` `{name, note}`, `DELETE /v1/spaces/:name`, `POST /v1/spaces/:name/members` `{email, role}`, `DELETE /v1/spaces/:name/members/:email` | Spaces (Rust server) |
| `GET /v1/marketplace?search=`, `GET /v1/marketplace/:listing`, `POST /v1/marketplace/:listing/install` `{name?, settings?}` | Browse the marketplace, one listing with its releases, install a copy (Rust server) |
| `GET` / `POST /v1/listings` `{app, name?, summary, description, version?, note?}`, `PATCH` / `DELETE /v1/listings/:listing` `{name, summary, description, status}`, `POST /v1/listings/:listing/releases` `{note, version?}` | The workspace's own listings: list an app, change or unlist it, publish a release (Rust server) |
| `POST /v1/listings/:listing/previews` | Take a listing's automatic previews again, now (Rust server with the preview service) |
| `POST /v1/listings/:listing/media?caption=` (the file as the body), `DELETE /v1/listings/:listing/media/:id`, `GET /v1/marketplace/:listing/media/:id` | A listing's screenshots and screencasts: add, remove, view (Rust server) |
| `POST /v1/apps/:slug/marketplace/update` `{release?}`, `DELETE /v1/apps/:slug/marketplace` | Deploy a newer release to an installed app; stop following its listing (Rust server) |
| `GET` / `PATCH /v1/apps/:slug/settings` `{key: value}`, `PUT` / `GET` / `DELETE /v1/apps/:slug/settings/:key` (an image as the body) | An app's [settings](#app-settings): read and change them; upload, view or remove an image (Rust server) |
| `GET /v1/billing`, `POST /v1/billing/checkout` `{plan}`, `POST /v1/billing/portal` | Plan, usage and invoices; change plan (answers a Checkout `url`, or the change); customer portal `url`. Admins (Rust server) |
| `POST /stripe/webhook` | Stripe's signed webhooks (Rust server) |
| `GET` / `POST /v1/domains` `{domain, app?}`, `POST /v1/domains/:domain/verify`, `DELETE /v1/domains/:domain` | [Custom domains](#custom-domains) |
| `/v1/admin/*` (admin secret) | The operator's API: report queue, takedowns, suspensions, trust (see [The operator's API](#the-operators-api)) |

## Custom domains

A workspace can serve its apps at domains it owns, in two ways:

- **One app, one domain:** `shop.example.com` serves the app `shop`. Builders and admins can add these (`set_domain` with `app`, `POST /v1/domains` `{domain, app}`, or the app's Domains tab in the admin page).
- **A whole domain for the workspace:** `*.apps.example.com` serves every app in the workspace at `<app>.apps.example.com`, and `apps.example.com` opens the workspace home page. Admins only (`domain: "*.apps.example.com"`, no `app`).

Adding a domain answers two DNS records to create:

| Record | Name | Value | Why |
| --- | --- | --- | --- |
| `TXT` | `_brod.shop.example.com` | `brod-verify=<token>` | Proves the workspace owns the domain. Keep it. |
| `CNAME` | `shop.example.com` (or `*.apps.example.com`) | the API host, or `CUSTOM_DOMAIN_TARGET` | Sends visitors to Brod. A bare domain (`example.com`) cannot have a CNAME: use the DNS provider's ALIAS, ANAME or CNAME flattening, or `A`/`AAAA` records to the server. |

Then verify: call `set_domain` again with the same domain, or `POST /v1/domains/<domain>/verify`. Brod looks up the TXT record over DNS-over-HTTPS (`DNS_RESOLVER_URL`, default Cloudflare's `https://cloudflare-dns.com/dns-query`). Until it is verified nothing is served there. Several workspaces may claim the same name while it is pending, so nobody can squat on it, but only the one holding the TXT record can verify it, and then no other can. `get_status` lists an app's domains with their status; removing a domain (or deleting the app) stops serving it at once. A workspace can have 50 domains.

Everything else works as on the app's own address: the access decision, roles, `/_brod/me`, server apps (which see the custom domain in `request.url`). Signing in still happens on the API host. The gateway sends the visitor to `/auth/app?app=<app>.<workspace>&host=<custom domain>`, and Brod hands the one-time code to that host only when it is a verified domain of that same app; anything else is refused, so a code can never be sent elsewhere. The custom domain then gets its own `__Host-` session cookie.

**HTTPS for custom domains** depends on where Brod runs:

- **Your own server:** handled. Caddy's on-demand TLS asks `/_caddy/ask`, which now also approves verified custom domains (the `https://` block at the end of `deploy/Caddyfile`). Or let Brod do HTTPS itself: [HTTPS without Caddy](#https-without-caddy).
- **Cloudflare:** the Worker routes custom domains already, but Cloudflare only sends it traffic for hostnames on your zone. Use [Cloudflare for SaaS](https://developers.cloudflare.com/cloudflare-for-platforms/cloudflare-for-saas/) custom hostnames (with the Worker as the fallback origin), and set `CUSTOM_DOMAIN_TARGET` to the fallback origin's name.
- **Vercel:** each custom domain must also be added to the Vercel project (Project Settings, Domains, or Vercel's API) before Vercel will issue a certificate and route it.

The e2e suites prove domains against `scripts/fake-dns.mjs`, a stand-in DNS-over-HTTPS resolver, on all three servers.

## Put it on Cloudflare

Not yet run against a live Cloudflare account; these are the standard steps.

1. Domains: `brod.sh` for the API, sign-in and home pages, and an apps domain set by `APPS_DOMAIN`, by default `apps.brod.sh`, so apps live at `<slug>.<workspace>.apps.brod.sh` (each workspace has its own app names, and `<workspace>.apps.brod.sh` opens its home page). Cloudflare's free certificate covers only one level (`*.brod.sh`), so these two-level names need an Advanced Certificate per workspace, or a server with on-demand TLS as in [Run it on your own server](#run-it-on-your-own-server).

   Apps under `apps.brod.sh` are the same site as `brod.sh`. Two things keep that safe: on HTTPS every Brod cookie uses the `__Host-` prefix, which browsers refuse to let another host set or overwrite; and every cookie-signed change must carry an `Origin` of exactly `API_ORIGIN`. Listing `apps.brod.sh` on the [Public Suffix List](https://publicsuffix.org/) later would make browsers treat each app as its own site, as GitHub does for `github.io`.
2. `npx wrangler d1 create brod` and put the returned id in `wrangler.jsonc`.
3. `npx wrangler r2 bucket create brod-bundles`
4. `npx wrangler d1 migrations apply brod --remote`
5. Secrets: `npx wrangler secret put ADMIN_SECRET`, `IDENTITY_SECRET`, `SECRETS_KEY` (long random values; changing `SECRETS_KEY` later makes stored app secrets unreadable) and `RESEND_API_KEY` (for sign-in emails; set `EMAIL_FROM` to a verified sender). For "Continue with Google", also set `GOOGLE_CLIENT_ID` and `GOOGLE_CLIENT_SECRET`, with `<API_ORIGIN>/auth/google/callback` as the redirect URI.
6. In `wrangler.jsonc`, set `APPS_DOMAIN` (`apps.brod.sh`) and `API_ORIGIN` (`https://brod.sh`), and uncomment `routes`. Add a proxied wildcard DNS record (`*.apps`) so every app address reaches the Worker.
7. `npm run deploy` from your machine, or push to `main` once the Deploy workflow is configured.

Do not set `DEV_MODE` on a deployed Worker.

## Run it on Vercel

Not yet run against live Vercel, Turso or R2 accounts. Everything below is checked locally: `npm run e2e:node:s3` serves the exact Vercel bundle with Node.js against a libSQL database and an S3 server that verifies request signatures.

Vercel runs code but keeps neither a database nor files, so Brod on Vercel needs two more services:

| Cloudflare | Vercel | Why |
| --- | --- | --- |
| Worker | One Vercel Function (Node.js runtime) answering every path on both domains | `src/node/handler.ts`, bundled by `scripts/build-vercel.mjs` |
| D1 | **Turso** (libSQL), on the Vercel Marketplace | libSQL is SQLite, so `migrations/*.sql` and every query run unchanged through a D1-shaped adapter (`src/platform/d1.ts`). `batch` is one write transaction, all-or-nothing as on D1. |
| R2 | **Any S3-compatible bucket**; Cloudflare R2's S3 endpoint recommended | `src/platform/s3.ts`, signed with `aws4fetch` (no AWS SDK). R2 has no egress fees and is reachable from anywhere; AWS S3 and MinIO work the same way. Vercel Blob was not chosen: its SDK and URLs are Vercel-only, and a standard S3 presigned PUT lets an agent upload with nothing but `curl`. |
| HTMLRewriter | A byte-level insert before the last `</body>` | `src/platform/html.ts`; only used for the Report link on public pages |
| Worker Loader, Durable Objects | None | Server apps are Cloudflare-only. A deploy with `_worker.js` or `_worker/` is refused with `server_apps_unavailable`; static apps work. |

### Limits on Vercel, and what Brod does about them

- **Request bodies are capped at 4.5 MB** for Vercel Functions, below Brod's 25 MB bundle limit. So on Vercel, `deploy_app` without files returns a presigned `upload_url` that goes straight to the bucket, plus a `finish_url`. The agent's one-line command uploads, then calls finish, which deploys from the bucket and deletes the staged archive. The address still works once and expires in 15 minutes, and a bad archive is refused without using it up. Inline `files` (up to 1 MB) still go through the API. On Cloudflare nothing changes: one `PUT` to `/v1/uploads/<id>`.
- **Responses** are streamed, so app files above 4.5 MB (up to the 10 MB per-file limit) are not held in memory.
- **Duration and memory:** the function is set to 60 s and 1024 MB (`scripts/build-vercel.mjs`). Finishing an upload reads up to 25 MB from the bucket, unpacks it and writes up to 2,000 files back.
- The Hobby plan is for non-commercial use; a business needs Vercel Pro.

### Steps

1. **Domains.** `brod.sh` for the API, sign-in and home pages, and `APPS_DOMAIN` for apps, by default `apps.brod.sh` (see "Put it on Cloudflare" for why that is safe).
2. **Database.** Create a Turso database: from the Vercel Marketplace (Storage, then Turso, which adds `TURSO_DATABASE_URL` and `TURSO_AUTH_TOKEN` to the project), or with the Turso CLI: `turso db create brod`, `turso db show brod --url`, `turso db tokens create brod`.
3. **Migrations.** From your machine, with those two values in `.env` (copy `.env.example`): `npm run migrate:libsql`. It applies `migrations/*.sql` in order, each in a transaction, and records them in `d1_migrations` like `wrangler d1 migrations apply`. Run it again after every new migration, before deploying.
4. **Bucket.** On Cloudflare: R2, Create bucket `brod-bundles`; then Manage API tokens, Create token with Object Read & Write on that bucket. Note the access key id, the secret, and the S3 endpoint `https://<ACCOUNT_ID>.r2.cloudflarestorage.com`. Keep the bucket private: Brod serves the files itself, after the access check.
5. **Project.** Import the repository in Vercel (Add New, Project). `vercel.json` sets the install and build commands. The build writes `.vercel/output` (Build Output API) with one function and a catch-all route, so there is no framework or output directory to choose.
6. **Environment variables** (Project Settings, Environment Variables): every name in `.env.example`: `APPS_DOMAIN=apps.brod.sh`, `API_ORIGIN=https://brod.sh`, `ADMIN_SECRET`, `IDENTITY_SECRET`, `RESEND_API_KEY`, `EMAIL_FROM`, optionally `GOOGLE_CLIENT_ID` and `GOOGLE_CLIENT_SECRET`, the two Turso values, and the `S3_*` values. Do not set `DEV_MODE`: Brod refuses to start with it in Production. Until everything is set, every request answers 503 naming the missing variables.
7. **Deploy.** Push to the connected branch (Vercel's Git integration deploys every push and gives pull requests preview deployments), or run `npx vercel --prod`.
8. **Add the domains** (Project Settings, Domains):
   - `brod.sh`: add it and create the DNS record Vercel shows.
   - `*.apps.brod.sh`: a wildcard domain. Vercel issues wildcard certificates only for domains on its own nameservers, so first point `brod.sh`'s nameservers at `ns1.vercel-dns.com` and `ns2.vercel-dns.com` at your registrar, then add `*.apps.brod.sh`.
9. For "Continue with Google", use `https://brod.sh/auth/google/callback` as the redirect URI.

There is no GitHub Actions workflow that deploys to Vercel: Vercel's Git integration does the same with less to configure, and CI still proves the Vercel build on every push.

To run the same build on any machine with Node.js 22: put the variables in `.env` (a `file:` database URL and `FILES_DIR` work locally), run `npm run migrate:libsql`, then `npm run start:node`.

## Run it on your own server

Brod also runs on one Linux machine (a VPS with 1 GB of memory is plenty to start) with Docker: the Rust server, the server-app runtime and Caddy for HTTPS, from `deploy/`. Checked locally end to end: `deploy/smoke-test.sh` runs the whole Compose stack over HTTPS with Caddy's local CA (certificates on demand, `__Host-` cookies, a server app through Caddy). Not yet run on a public server with Let's Encrypt.

| Service | What it is | Data |
| --- | --- | --- |
| `brod` | The Rust server (`server/`, image from `deploy/Dockerfile`): gateway, MCP, REST API and pages. SQLite in WAL mode with the same `migrations/*.sql` (applied at start, recorded in `d1_migrations`), or Postgres (see [Postgres instead of SQLite](#postgres-instead-of-sqlite)); app files in a folder or an S3-compatible bucket. | volume `brod-data` (`/data/brod.db`, `/data/files/`) |
| `postgres` | Optional, with `--profile postgres`: Postgres 17 for Brod's own database. | volume `postgres-data` |
| `runtime` | Server apps: workerd running `deploy/runtime/host.js`, which loads each app with the Worker Loader and gives it its own SQLite database (a Durable Object on disk). Brod decides access and forwards the request; the runtime fetches the code and secrets from Brod's internal `/_runtime/` endpoints and posts logs back. workerd runs under a supervisor (`deploy/runtime/supervisor/`) that restarts it when an app stalls it or runs it out of memory; see [Limits for server apps](#limits-for-server-apps). | volume `runtime-data` |
| `preview` | Optional, with `--profile previews`: headless Chromium (`deploy/preview/`, Playwright) that takes the marketplace's automatic previews. Brod asks it to open a release in an empty sandbox on Brod's internal address; it answers screenshots and a screencast. It holds no data and only `BROD_PREVIEW_SECRET`. | none |
| `caddy` | HTTPS. `brod.sh` gets a certificate as usual; each `<workspace>.<APPS_DOMAIN>` and `<slug>.<workspace>.<APPS_DOMAIN>` gets its own on its first visit (on-demand TLS), after Brod's `/_caddy/ask` confirms the address exists. | volumes `caddy-data`, `caddy-config` |

Only Caddy publishes ports (80 and 443). `/_caddy/ask` and `/_runtime/*` answer only on Brod's Docker address (a Host that is neither the API host, an app host nor a custom domain), never on Brod's own HTTPS listener, and Caddy refuses those paths on the public hosts as well. `/_caddy/ask` only says whether an app exists, which anyone can already learn by opening its address; `/_runtime/*` also needs `BROD_RUNTIME_SECRET`.

### Steps

1. **A server** with Docker Engine and the Compose plugin, and ports 80 and 443 open.
2. **DNS.** Point both names at the server, **DNS only** if the zone is on Cloudflare: an `A` record (and `AAAA` for IPv6) for `brod.sh`, and a wildcard `A`/`AAAA` record for `*.<APPS_DOMAIN>` (one wildcard covers every depth). Apps are served at `<slug>.<workspace>.<APPS_DOMAIN>`; workspace names the platform needs (`api`, `www`, `admin`, `mail`, ...) are reserved. That is safe on the same site as `brod.sh` for the reasons in [Put it on Cloudflare](#put-it-on-cloudflare): `__Host-` cookies and the exact-`Origin` check. Listing `apps.brod.sh` on the Public Suffix List later would separate the apps further.
3. **Configure.**
   ```
   git clone https://github.com/brodsh/brod && cd brod/deploy
   cp .env.example .env
   for k in ADMIN_SECRET IDENTITY_SECRET SECRETS_KEY BROD_RUNTIME_SECRET; do sed -i "s/^$k=$/$k=$(openssl rand -hex 32)/" .env; done
   ```
   Then edit `.env`: `API_ORIGIN=https://brod.sh`, `BROD_API_HOST=brod.sh`, `APPS_DOMAIN` (`brod.sh` puts apps at `<slug>.<workspace>.brod.sh`), `ACME_EMAIL`, and `RESEND_API_KEY` with `EMAIL_FROM` (a sender verified in Resend) so sign-in links can be emailed. Optionally `GOOGLE_CLIENT_ID` and `GOOGLE_CLIENT_SECRET` with `https://brod.sh/auth/google/callback` as the redirect URI, and the `S3_*` values to keep app files in R2 or another bucket (or `docker compose --profile minio up -d` for MinIO on the same machine). Never set `DEV_MODE` here. Keep `.env` private: it holds every secret.
4. **Start it:** `docker compose up -d` (the first run builds both images, a few minutes). `docker compose ps` should show `brod` healthy; `docker compose logs -f caddy` shows the certificate for `brod.sh` arriving.
5. **First sign-in.** Open `https://brod.sh`, enter your email, open the emailed link and press Continue, then create your workspace at `https://brod.sh/new`. You are its admin. Then `claude mcp add --transport http brod https://brod.sh/mcp` and sign in when asked, or make a token on the workspace's connections page, as in [Run it locally](#run-it-locally).

To serve static apps only, delete the `runtime` service and the `BROD_RUNTIME_URL` line from `docker-compose.yml`: deploys with server code are then refused with `server_apps_unavailable`, as on Vercel.

To have Brod take the marketplace's previews itself, set `BROD_PREVIEW_URL=http://preview:8790` and a long random `BROD_PREVIEW_SECRET` in `.env`, and start with `docker compose --profile previews up -d` (the first run builds the Chromium image, about 2 GB). Without it, listings show only the screenshots and screencasts publishers upload. Server apps are previewed only where the runtime runs too.

### HTTPS without Caddy

Brod can terminate HTTPS itself, with no proxy in front: `BROD_TLS=acme`. It then listens on 443 and 80 as well as `BROD_LISTEN`:

- **443:** the TLS handshake's server name picks the certificate. A name gets one on its first visit, from Let's Encrypt (or `ACME_DIRECTORY`), but only when Brod serves it: the API host, `www`, an existing workspace or app under `APPS_DOMAIN`, or a verified [custom domain](#custom-domains). The same check as `/_caddy/ask`, made in-process. HTTP/2 and HTTP/1.1. Requests over it are `https` to Brod and to apps.
- **80:** answers the CA's HTTP-01 challenges and redirects everything else to `https://`.
- Certificates, their keys and the ACME account are kept in `$BROD_DATA_DIR/certs/`. A background check every 12 hours renews certificates with a third of their lifetime left, and deletes those for names Brod no longer serves (a removed domain or app). A failed issuance is not retried for 10 minutes, to stay inside the CA's rate limits.
- `/_caddy/ask` and `/_runtime/*` never answer on the public listeners. Keep `BROD_LISTEN` private (the Docker network, or `127.0.0.1`): the runtime and the healthcheck use it.

With Compose, layer `deploy/compose.tls.yml` on `docker-compose.yml` instead of running Caddy: `docker compose -f docker-compose.yml -f compose.tls.yml up -d`. It maps the host's 443 and 80 to Brod and leaves Caddy off. Keep Caddy when the same server also hosts other sites behind it, as brod.sh does.

`npm run e2e:tls` checks all of this against [Pebble](https://github.com/letsencrypt/pebble), Let's Encrypt's test CA, with real HTTP-01 challenges (11 checks: certificates for the API host, an app and a verified custom domain; none for unknown names or a pending domain; HTTP/2; the port 80 redirect; internal endpoints refused). It downloads Pebble into `node_modules/.cache/pebble` the first time. `BROD_TLS=local` issues from a local CA that Brod makes in `certs/local-ca.crt` instead, for trying it out without a public name.

### Backups

Everything lives in the Docker volumes. Back up the database with SQLite's online backup (safe while Brod runs), and copy the app files and the server-app databases:

```
docker compose exec brod brod backup /data/backup.db        # or stop brod and copy /data/brod.db with its -wal file
docker run --rm -v brod_brod-data:/data -v brod_runtime-data:/runtime -v "$PWD":/out busybox \
  tar -czf /out/brod-$(date +%F).tar.gz /data /runtime
```

With the database in Postgres, `brod backup` refuses and says so; use `pg_dump` instead (also safe while Brod runs), and keep backing up the volumes above for the app files and server-app databases:

```
docker compose exec -T postgres pg_dump -U brod --format=custom brod > brod-$(date +%F).dump
# restore into an empty database: pg_restore -U brod -d brod --no-owner < brod-2026-01-01.dump
```

Keep `.env` with the backup: without the same `SECRETS_KEY`, stored app secrets cannot be decrypted. To restore, stop the stack, unpack the archive into the volumes, and start it again. With app files in S3, back up the bucket with your provider's tools.

### Upgrading

```
cd brod && git pull && cd deploy
docker compose build && docker compose up -d
```

New migrations apply when Brod starts. Back up first. `docker image prune` removes old images afterwards.

### Postgres instead of SQLite

Brod's own database (workspaces, people, apps, versions, sessions, the audit log; not the apps' files or their own `env.DB`) is a SQLite file by default. Set `BROD_DATABASE_URL=postgres://user:password@host:5432/dbname` and it lives in Postgres instead; unset, Brod uses SQLite exactly as before. The schema is the same: `migrations-pg/` holds the same migrations as `migrations/` in Postgres's dialect, applied at start and recorded under the same names in `d1_migrations`.

Stay on SQLite unless you need what Postgres gives. SQLite is one file on the same disk, with nothing else to run, and the fastest of the two for a single server. Postgres helps when you want the database on a managed service with its own backups and point-in-time recovery, or kept apart from the machine that runs Brod. It costs a second service to run and back up, and a network round trip per query. It does not yet make Brod scale out: app files can be in S3, but server apps' own databases are still on the runtime's disk, and Brod still assumes one instance (see [Differences](#differences-from-the-cloudflare-version)).

What differs between the two:

- Brod connects without TLS, so keep Postgres on the same machine or a private network (the Compose `postgres` service, or a managed database reached privately). A managed database that requires TLS needs a TLS-terminating proxy for now.
- Each write transaction takes one Postgres advisory lock, so writes go one at a time, as with SQLite's single writer. Reads run in parallel on both.
- Searching app logs ignores case for all letters on Postgres (`ILIKE`), and only for ASCII letters on SQLite.
- Backups: `pg_dump`, not `brod backup` (see [Backups](#backups)).

**A new server on Postgres:** `docker compose --profile postgres up -d` with `POSTGRES_PASSWORD` and `BROD_DATABASE_URL=postgres://brod:<that password>@postgres:5432/brod` in `.env`. Brod waits up to 30 seconds for Postgres at start and creates the tables.

**Moving an existing server from SQLite:** `brod migrate-to-postgres <sqlite-file> <postgres-url>` copies every row into a fresh Postgres database in one transaction, keeping every id and carrying the audit-log and app-log id sequences on. It only reads the SQLite file, refuses a database that already has Brod data, and keeps nothing if anything fails. With Compose:

```
cd deploy
docker compose exec brod brod backup /data/before-postgres.db     # a copy to fall back on
# add POSTGRES_PASSWORD to .env, then:
docker compose --profile postgres up -d postgres
docker compose stop brod runtime                                  # no writes during the copy
docker compose run --rm --no-deps brod migrate-to-postgres /data/brod.db postgres://brod:<password>@postgres:5432/brod
# add BROD_DATABASE_URL=postgres://brod:<password>@postgres:5432/brod to .env, then:
docker compose --profile postgres up -d
```

Going back: remove `BROD_DATABASE_URL` and restart; Brod opens `/data/brod.db` again, without what was written while it ran on Postgres.

### Configuration reference

The Rust server reads the same variables as the Worker (`APPS_DOMAIN`, `API_ORIGIN`, `ADMIN_SECRET`, `IDENTITY_SECRET`, `SECRETS_KEY`, `DEV_MODE`, `RESEND_API_KEY`, `EMAIL_FROM`, `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`), from the environment or a `.env` file in its working folder, plus:

| Variable | Default | |
| --- | --- | --- |
| `BROD_LISTEN` | `0.0.0.0:8080` | Address to listen on |
| `BROD_DATA_DIR` | `data` | Folder for `brod.db` (and `files/` when app files are kept locally) |
| `FILES_DIR` | `$BROD_DATA_DIR/files` | Where app files go without S3 |
| `S3_ENDPOINT`, `S3_BUCKET`, `S3_ACCESS_KEY_ID`, `S3_SECRET_ACCESS_KEY`, `S3_REGION`, `S3_VIRTUAL_HOSTED` | | App files in an S3-compatible bucket (`S3_REGION` defaults to `auto`) |
| `BROD_TRUST_PROXY` | off | `1`: take the scheme from `X-Forwarded-Proto` and the client address for rate limits from the first `X-Forwarded-For` hop (set by Compose, since Caddy terminates HTTPS) |
| `BROD_RUNTIME_URL`, `BROD_RUNTIME_SECRET` | | The workerd runtime for server apps and the secret both sides share (16 characters or more) |
| `BROD_NETWORK` | `log` | What happens when an app reaches an outside host its `brod.json` does not declare: `log` records it and lets it through, `enforce` refuses and records it, `off` does neither. See [Outside addresses](#outside-addresses) |
| `BROD_PREVIEW_URL`, `BROD_PREVIEW_SECRET` | | The preview service that takes the marketplace's automatic previews (`http://preview:8790` in Compose, with `--profile previews`) and the secret both sides share (16 characters or more). Unset: listings show only the previews people upload |
| `BROD_DATABASE_URL` | | `postgres://...`: Brod's database in Postgres instead of `$BROD_DATA_DIR/brod.db` (see [Postgres instead of SQLite](#postgres-instead-of-sqlite)) |
| `BROD_DB_CONNECTIONS` | `8` | Database connections in the pool |
| `STRIPE_SECRET_KEY`, `STRIPE_WEBHOOK_SECRET` | | Billing: the Stripe API key and the signing secret of the `/stripe/webhook` endpoint |
| `STRIPE_PRICE_SOLO`, `STRIPE_PRICE_TEAM` | | The recurring Stripe prices of the paid plans (at least one) |
| `STRIPE_API_BASE` | `https://api.stripe.com` | Only for tests against `scripts/fake-stripe.mjs` |
| `DEV_FREE_STORAGE_MB` | | With `DEV_MODE=1` only: a smaller free plan storage, so tests can fill it |
| `DNS_RESOLVER_URL` | `https://cloudflare-dns.com/dns-query` | DNS-over-HTTPS (JSON) resolver that checks custom domains' TXT records (the Worker and Node read it too) |
| `CUSTOM_DOMAIN_TARGET` | the API host | The name custom domains are told to point their CNAME at (the Worker and Node read it too) |
| `BROD_TLS` | off | `acme`: Brod serves HTTPS itself with certificates on demand; `local`: the same from a local test CA. See [HTTPS without Caddy](#https-without-caddy). Needs an `https://` `API_ORIGIN` |
| `BROD_HTTPS_LISTEN`, `BROD_HTTP_LISTEN` | `0.0.0.0:443`, `0.0.0.0:80` | Where Brod's own HTTPS and HTTP listeners go, with `BROD_TLS` |
| `ACME_DIRECTORY` | Let's Encrypt | The ACME CA's directory URL, with `BROD_TLS=acme` |
| `ACME_EMAIL` | | Contact for the ACME account (expiry and policy notices) |
| `ACME_CA_ROOT` | | A PEM root to trust for the ACME server itself; only for a test CA such as Pebble |

To run the binary without Docker: `cargo build --release --manifest-path server/Cargo.toml`, then `server/target/release/brod` with the variables set. For server apps, also run workerd under its supervisor: `cargo build --release --manifest-path deploy/runtime/supervisor/Cargo.toml`, then `BROD_RUNTIME_SECRET=... BROD_INTERNAL_URL=http://127.0.0.1:8080 deploy/runtime/supervisor/target/release/brod-runtime node_modules/workerd/bin/workerd serve deploy/runtime/config.capnp --experimental -e brod=127.0.0.1:8080` (workerd comes with `npm ci`).

### Limits for server apps

Open-source workerd runs every app's isolate on one thread and does not enforce the CPU limit that Brod passes to the Worker Loader. Left alone, one app stuck in a loop (`for (;;) {}`) stops **every** server app on the host, for good. An app that passes V8's heap limit aborts the whole process. So the runtime container runs workerd under a supervisor, `brod-runtime` (`deploy/runtime/supervisor/`, std and libc only), and Brod does the blaming (`server/src/watchdog.rs`):

- **Stalls.** The supervisor asks workerd's `/_runtime/health` every half second. When workerd has not answered for `RUNTIME_STALL_MS` (default 5000), it tells Brod (`POST /_runtime/stopped`), kills workerd with SIGKILL and starts it again. A wedged workerd does not respond to SIGTERM.
- **Memory.** When workerd's resident memory passes `RUNTIME_MEMORY_MB` (default 1536; 0 turns it off), the supervisor does the same. When workerd exits on its own, it restarts it and tells Brod afterwards. Compose also sets a kernel ceiling on the container, `mem_limit` (`RUNTIME_MEM_LIMIT`, default 2g).
- **Blame.** workerd takes requests in order on one thread. So the request that stalled it is the first one Brod sent after workerd's last answer; requests sent later only queued behind it. Requests sent earlier were waiting on I/O and might have resumed and stalled it, so they are suspects too.
- **Stopping.** When one app is the only suspect, its server code is stopped at once. Visitors get a 503 page with `Retry-After` for 1 minute, then 5, then 30 if it keeps doing it within an hour. Its static files keep serving. When several apps were in flight, each gets a strike, and an app is stopped after 3 strikes in 10 minutes. The record is kept in memory, so restarting Brod clears it.
- **What people see.** The request that stalled the runtime gets a 503 "This app was stopped" page. The app's logs get an entry with outcome `exceededCpu` or `exceededMemory` that says what happened and for how long the app is stopped, so `get_logs` tells the agent what to fix. Requests without a body that only queued, or that came while workerd was restarting, are sent again once it is back (within 10 seconds). They get their normal answer, at most a few seconds late.
- **Deploys.** Server code whose top-level code never finishes stalls the deploy-time check in the same way. That deploy is refused with `server_failed`, and the live version keeps serving.

What this does not do: a loop holds every server app on the host until it is cut off (5 seconds by default), and a restart drops the other requests that were in flight with a body (such as POSTs). Apps are not yet split across several workerd processes.

### Differences from the Cloudflare version

- Server apps' CPU limit is not enforced per request as Cloudflare does it. Instead, an app that holds the runtime for seconds or uses too much memory is cut off and stopped for a while (see [Limits for server apps](#limits-for-server-apps)). Apps' own `fetch` reaches the public internet only, never Brod's private network.
- One machine: the runtime's Durable Objects (server apps' own databases) live on local disk, and so does Brod's database unless it is in Postgres. Brod runs as one instance and does not scale out across machines. A single server handles a lot of small apps; see the benchmark below.
- Form posts to the sign-in pages and the report form are read as `application/x-www-form-urlencoded` (what the pages send); `multipart/form-data` is not parsed.

### Performance

`node scripts/bench.mjs` starts the Node build of the TypeScript server (`scripts/serve-node.mjs`, libSQL file database, files in a folder) and the Rust server side by side, gives each the same public app, and loads them with [oha](https://github.com/hatoo/oha) (`cargo install oha`). Measured in this repository's 4-core Linux sandbox, with oha on the same machine, 10 seconds per test at 50 connections, every response 200:

| Test | Node (TypeScript) | Rust |
| --- | --- | --- |
| Static file (40 KB JavaScript) | 909 req/s, p50 52.9 ms, p99 92.8 ms | 6,984 req/s, p50 7.0 ms, p99 13.6 ms |
| HTML page with the report link added | 974 req/s, p50 49.5 ms, p99 77.7 ms | 6,530 req/s, p50 7.4 ms, p99 14.8 ms |
| `GET /v1/apps` with an agent token | 391 req/s, p50 124 ms, p99 174 ms | 9,260 req/s, p50 5.1 ms, p99 12.8 ms |

Each app request still reads the app, the session and the access decision from the database (SQLite here) and the file from storage, with no caching between requests, so a rollback or an access change shows on the very next request, as on Cloudflare.

## Limits and what is not here yet

- Server apps run JavaScript (and WebAssembly) only. Containers and other languages are not supported.
- Server apps need Cloudflare's Worker Loader binding on the account. Check it is available to you before relying on server apps in production. On your own server they run on workerd instead.
- On Cloudflare and Vercel the only dashboard pages are the workspace home page and its connections page; the admin page, billing, visit counts, analytics, spaces, the marketplace and storage accounting are in the Rust server only. The API covers every other action, and agents use it through MCP.
- Plan allowances are enforced everywhere (running apps, people, and on the Rust server storage); only the Rust server takes payment, through Stripe. There are no usage-based charges, coupons beyond Stripe's promotion codes, or tax settings in Brod itself (set those up in Stripe).
- The marketplace is free only, has no MCP tools yet (agents use the REST routes, and cannot list apps), and is shared by the workspaces of one server; there is no marketplace across servers, ratings or reviews.
- Abuse: a report link, the operator's review queue, takedown, workspace suspension, per-address rate limits, a day-long hold on new workspaces opening apps to everyone, and a heuristic deploy-time phishing check exist (see [Abuse protection](#abuse-protection)). Still missing before a wide public launch: a dashboard page for the operator (the admin API is curl only), notifying the owner by email of a takedown, checking URLs against a blocklist such as Google Safe Browsing, scanning what server code renders at request time, CAPTCHA or proof of work on sign-up, disposable-email blocking, rate limits per agent connection on API calls other than deploys, and an appeal flow. Open sign-up with someone watching the report queue.
- MCP clients sign in with OAuth (PKCE, dynamic client registration) or use a token from the connections page. Either way the agent gets one connection for one workspace. On the Rust server:
  - **Expiry.** An OAuth access token lives an hour. The client renews it at `/oauth/token` with `grant_type=refresh_token`. Each refresh returns a new refresh token and retires the old one. If a retired refresh token is sent again, someone has a copy, so the whole connection is disconnected. A refresh token lapses after 30 days without use. A token made on the connections page or with `POST /v1/tokens` can be given an expiry.
  - **Scopes.** A connection can be read-only: the OAuth scope `brod:read`, or `scope: "read"` for a token. A read-only agent sees only `list_apps`, `get_files`, `get_status`, `get_logs` and `get_workspace` (getting files does not count it as working on the app). Any other tool call, and any REST request other than `GET`, is refused with `read_only`. A refresh may narrow a connection to read-only, never widen it.
  - **The connections page** shows each connection's rights, when it was last used, and when it expires or lapses.

  On Cloudflare and Vercel, tokens do not expire until disconnected, and there are no refresh tokens or scopes.
- Blocking paths by role, company sign-in (SAML/OIDC) and deploy-before-sign-up are later releases.
- A verified custom domain stays verified: Brod does not re-check its TXT record later. Removing the domain in Brod is what stops it being served.
- Brod's own HTTPS (`BROD_TLS`) issues certificates over HTTP-01 only, so there are no wildcard certificates: each app under a wildcard custom domain gets its own certificate on its first visit.
- 30 deploys an hour per workspace, 5 sign-in links an hour per email (and 20 per client address), 3 new workspaces a day per person, 2,000 files and 60 MB unpacked per bundle, 10 MB per file.
- Old versions are kept until someone deletes them (they count toward storage); there is no clean-up job.
