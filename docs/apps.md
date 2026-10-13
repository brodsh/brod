# Building apps on Brod

This page is for people and agents who build apps on Brod. It covers how people sign in, how an app reads who they
are, server code, staging, working on one app with others, access, custom domains, settings, outside addresses and
limits. Agents do all of this through MCP tools; see [mcp.md](mcp.md). The REST routes are in [api.md](api.md).

Every app lives at `<slug>.<workspace>.<APPS_DOMAIN>`.

- [How sign-in works](#how-sign-in-works)
- [The identity contract](#the-identity-contract)
- [Server apps](#server-apps)
- [Limits for server apps](#limits-for-server-apps)
- [Staging](#staging)
- [Several people on one app](#several-people-on-one-app)
- [Access](#access)
- [Custom domains](#custom-domains)
- [App settings](#app-settings)
- [Outside addresses](#outside-addresses)
- [Limits](#limits)

## How sign-in works

- **People** sign in once, with an emailed link (or Google, if the server has it set up). The platform session cookie
  lives only on the API host (`BROD_PUBLIC_URL`).
- **Apps** never see that cookie. When an app needs a person, the gateway sends them to `/auth/app` on the API host.
  It hands the app's host a one-time code, and the app's host swaps it for its own session cookie. Apps live under
  `APPS_DOMAIN`, a different domain from the API host, so an app cannot read the platform's cookies.
- **Signing out** of any app ends the platform session and every app session made from it. **Removing a person** from
  the workspace ends their access to every app on their next request.
- The emailed link opens a page with a Continue button. Mail scanners that open links do not use them up.

## The identity contract

An app reads the signed-in person from its own address:

```html
<script src="/_brod/client.js"></script>
<script type="module">
  const me = await Brod.me();   // null when nobody is signed in (public apps)
  // { user: { id, email, name }, role: "editor", groups: ["finance"], app, workspace, token }
  if (me?.role === 'viewer') document.querySelector('#edit').hidden = true;
</script>
```

- `Brod.me()` reads `GET /_brod/me`. Without a signed-in person it answers `401` with the error code `signed_out`, and
  `Brod.me()` returns `null`.
- `Brod.signIn()` and `Brod.signOut()` send the person to sign in or out (`/_brod/signin`, `/_brod/signout`).
- `token` is the same identity signed with a key for this app: base64url JSON, a dot, and an HMAC-SHA256 signature.
  It is valid for 5 minutes. Pass it to a server that needs proof of who the person is.
- Server apps get the same identity as request headers. See [Server apps](#server-apps).

Do not build a login page or a user table. Brod signs people in and decides who may open the app.

## Server apps

A bundle with server code is a server app. It uses the Cloudflare Pages layout that agents and build tools already
know: a `_worker.js` ES module at the top of the bundle, or a `_worker/` folder with `index.js` (or `index.mjs`) and its
other modules (`.js`, `.mjs`, `.cjs`, `.json`, `.wasm`, text). An `index.html` is optional.

```js
// _worker.js
export default {
  async fetch(request, env, ctx) {
    const email = request.headers.get('x-brod-user-email');       // the signed-in person (absent for anonymous visitors)
    await env.DB.run('CREATE TABLE IF NOT EXISTS notes (by TEXT, text TEXT)');
    if (request.method === 'POST') await env.DB.run('INSERT INTO notes VALUES (?, ?)', [email, await request.text()]);
    const notes = await env.DB.query('SELECT * FROM notes');       // rows as objects
    console.log('notes', notes.length);                            // shows in get_logs
    return Response.json({ notes, stripe: Boolean(env.STRIPE_KEY) });
  },
};
```

How it runs: Brod does not run JavaScript itself. It hands server code to a sidecar that runs
[workerd](https://github.com/cloudflare/workerd), the open-source Workers runtime (`deploy/runtime/`). The sidecar
loads each app into its own isolate, keyed by app, version and secrets revision. A rollback or a secret change takes
effect on the next request. Each app gets its own SQLite database on the sidecar's disk. Without the sidecar
(`BROD_RUNTIME_URL` not set), a deploy with server code is refused with `server_apps_unavailable`. See
[architecture.md](architecture.md).

- **Routing.** A file that exists in the bundle is served as is. Every other request, with any method, goes to `fetch`.
  The server code itself is never served. A path must name the file exactly: `/` and folder paths go to `fetch`, not to
  an `index.html`. Serve the page from `fetch`, or import it from a `_worker/` folder as text
  (`import page from './page.html'`), as [examples/hello-team](../examples/hello-team) does. Files in `_worker/` with
  the extensions `.html`, `.css`, `.txt`, `.md`, `.sql`, `.svg` and `.csv` import as strings.
- **Identity.** Access is decided before the request reaches the app. The person arrives as `x-brod-user-id`,
  `x-brod-user-email`, `x-brod-user-name` (URI-encoded), `x-brod-role`, `x-brod-groups` (comma-separated) and
  `x-brod-identity` (the signed token). The gateway strips any `x-brod-*` header a visitor sends, and the app's session
  cookie.
- **Storage, one set per app.** No app can reach another app's storage.
  - `env.DB` is the app's own SQLite database. `query(sql, params)` returns rows, `run(sql, params)` returns
    `{ changes }`, and `batch([{ sql, params }])` runs the statements in one transaction.
  - `env.KV` is a key-value store in the same database: `get`, `put`, `delete`, `list(prefix, limit)`. Values are
    strings up to 128 KB.
  - `env.FILES` is file storage: `put(key, body, contentType)`, `get(key)` (a `Response`, or `null`), `delete(key)`,
    `list(prefix)`. A key is 1 to 512 characters, without `..`. Brod keeps these files in its own file store, a folder
    or an S3-compatible bucket.
  - `env.SETTINGS` holds the app's [settings](#app-settings).
- **Storage counts.** On a hosted server, `env.DB`, `env.KV` and `env.FILES` count toward the workspace's plan storage.
  While the workspace is out of storage, database statements that can grow it (anything but `SELECT`, `EXPLAIN`,
  `DELETE` and `DROP`) and `KV.put` throw. Reads and deletes keep working. A self-hosted server has no storage limit.
- **Secrets.** `set_secret` (or `PUT /v1/apps/:slug/secrets/:NAME`) stores a value encrypted at rest (AES-GCM, with a
  key derived from `SECRETS_KEY` and bound to the app). The app reads it as `env.NAME` from its next request. Nobody can
  read a value back. The API lists names only.
- **Logs.** Each request's console output and exceptions are kept for 7 days. `get_logs` shows the last 50 requests and
  can search them.
- **Safe deploys.** Before a version goes live, the sidecar imports its main module and checks that it exports `fetch`.
  A version whose code throws while loading, or does not export `fetch`, is refused with `server_failed`, and the live
  version keeps serving. A request that throws gets a plain error page. The visitor never sees the exception. The owner
  sees it in the logs.
- **Outgoing requests.** `fetch` to the public internet is allowed, subject to the app's
  [outside addresses](#outside-addresses). Apps cannot reach Brod's private network.

### Limits for server apps

Open-source workerd runs every app's isolate on one thread and does not enforce a CPU limit per request. One app stuck
in a loop (`for (;;) {}`) would stop every server app on the host. An app that passes V8's heap limit would end the
whole process. So the sidecar runs workerd under a supervisor, `brod-runtime` (`deploy/runtime/supervisor/`), and Brod
decides which app to blame (`server/src/watchdog.rs`).

- **Stalls.** The supervisor asks workerd's `/_runtime/health` every half second. When workerd has not answered for
  `RUNTIME_STALL_MS` (default 5000), the supervisor tells Brod, kills workerd and starts it again.
- **Memory.** When workerd's resident memory passes `RUNTIME_MEMORY_MB` (default 1536; 0 turns it off), the
  supervisor does the same. Docker Compose also sets a kernel limit on the container, `RUNTIME_MEM_LIMIT` (default
  `2g`).
- **Blame.** workerd takes requests in order on one thread. The request that stalled it is the first one Brod sent
  after workerd's last answer. Requests sent earlier were waiting on I/O and might have resumed and stalled it, so they
  are suspects too.
- **Stopping.** When one app is the only suspect, its server code is stopped at once. Visitors get a `503` page with
  `Retry-After`, for 1 minute, then 5, then 30 if it happens again within an hour. Its static files keep serving. When
  several apps were in flight, each gets a strike, and an app is stopped after 3 strikes in 10 minutes. Brod keeps this
  record in memory, so a restart of Brod clears it.
- **What people see.** The request that stalled the runtime gets a `503` "This app was stopped" page. The app's logs
  get an entry with outcome `exceededCpu` or `exceededMemory` that says what happened and for how long the app is
  stopped, so `get_logs` tells the agent what to fix. Requests without a body that only queued, or that came while
  workerd was restarting, are sent again once it is back (within 10 seconds).
- **Deploys.** Server code whose top-level code never finishes stalls the deploy-time check in the same way. That deploy
  is refused with `server_failed`, and the live version keeps serving.

What this does not do: a loop holds every server app on the host until it is cut off (5 seconds by default), and a
restart drops the other requests that were in flight with a body (such as POSTs). Apps are not split across several
workerd processes.

## Staging

Once an app is live, an update can go to its **staging address** first, `<slug>--staging.<workspace>.<APPS_DOMAIN>`,
so someone can try it before visitors see it. Staging serves one version (the app's `staging_version`) next to the live
one. Publishing moves it live and empties staging. Nothing is rebuilt.

- **Where a deploy goes.** `deploy_app` and `POST /v1/deploys` take `"environment": "staging"` or `"production"`.
  Without it, an **agent** updating an app that already has a live version deploys to **staging**. A new app's first
  version, and a person deploying from the dashboard, go live. An upload address remembers the environment it was made
  for.
- **What the agent is told.** A staging deploy answers with `staging_url` and a `next_step` that says to give the
  person that address and call `publish_staging` only once they say it is ready.
- **Who can open staging.** The app's owner, workspace admins and builders (they get the app's top role), and anyone
  granted the app's top role. Never anonymous visitors, and never visitors with the app's password, whatever its access
  mode. Custom domains never serve staging. Visits on staging are not counted.
- **Publishing.** `publish_staging` (or `POST /v1/apps/:slug/publish`) makes the staging version live.
  `publish_staging` with `"discard": true` (or `DELETE /v1/apps/:slug/staging`) takes it off staging and keeps the
  version, so `rollback` can still serve it. A version on staging cannot be deleted (`409 staging_version`).
- **Shared data.** Staging runs the new code against the app's own database, key-value store, files and secrets, the
  same ones the live version uses. What you change while testing is real.
- `get_status`, `list_apps` and every app result carry `staging` (`{ version, url }`, or `null`).

## Several people on one app

Each person's agent edits its own copy of an app's files and deploys the whole bundle. Without a check, a deploy built
from an older version would undo whatever someone else deployed since. So a deploy can say which version its files
started from, and Brod refuses it when the app has moved on.

- **`base_version`.** `deploy_app` and `POST /v1/deploys` take `"base_version": <n>`, the version the files started
  from (the `version` the agent's last deploy returned, or `current_version` from `get_status`). An upload address
  remembers it. The app's **current version** is the one waiting on staging, or else the live one. Every app result
  carries it as `current_version`.
- **Refused, not merged.** If the current version is no longer `base_version`, nothing is deployed. The answer is
  `409 stale_base` with `your_base`, `current_version`, `current_environment` (`staging` or `live`) and `since`: the
  versions deployed after the base, with who deployed each and its note. The message tells the agent to tell the
  person, then get the current files with `get_files`, add its changes and deploy again with the new base. Brod never
  merges bundles itself: they are build output, not source.
- **Getting the files back.** `get_files` (and `GET /v1/apps/:slug/files?version=`) returns a version's files, by
  default the current one. Up to 1 MB and 200 files they come inline, text as text and anything else as base64. A
  larger version comes as a `download_url`, a tar.gz that `curl -sS "<download_url>" | tar -xzf -` unpacks. That
  address works without signing in for 15 minutes (`GET /v1/downloads/:id`). Only builders and admins can get files.
  That includes server code, never secrets. For an app built from source with a build step, the files are the build
  output, not the source.
- **Who else is working on it: a warning, never a lock.** Getting an app's files or deploying it records that the
  person is working on it. For two hours after someone's last such action, everyone else's `get_files`, deploy and
  `get_status` results carry `others_editing` (`by`, `via`, `base_version`, `since`, `last_active`) and a `warning` to
  pass on. Nothing is blocked. A person's own agents never warn them about themselves.
- **Checked when it counts.** The check runs before the upload and again in the same transaction that makes the
  version current. Of two deploys from the same version, exactly one goes through.
- **Straight to live.** A deploy with `base_version` and `"environment": "production"` builds on what was waiting on
  staging, so it also empties staging.
- **History.** Each version in `get_status` has `based_on` (`null` when the deploy did not say).
- **Version numbers.** Each deploy takes the next number from a counter on the app, so two deploys at once never share
  a number, and a deleted or refused version's number is never used again. Numbers can skip.
- `base_version` is optional, but agents should pass it whenever they update an app.

## Access

Each app has one of six access modes. You can change it at any time without a redeploy.

| Mode | Who can open it |
| --- | --- |
| `private` | The app's owner and workspace admins |
| `people` | Only the people, groups and email domains granted a role |
| `workspace` | Everyone in the workspace (guests only if granted) |
| `password` | Anyone with the address and the app's password, without an account. People granted a role can sign in instead. |
| `signed_in` | Anyone who signs in |
| `public` | Anyone, without signing in |

On a server with `BROD_ABUSE_CHECKS=true` (the default when hosted), pages of `public` apps carry a small "Report" link.

Giving someone a role on a `private` app (through `set_access` or an invite) switches it to `people`, since a grant on
a private app would do nothing.

Someone signed in whom an app is not shared with gets the same "App not found" page (404) as an address with no app at
all. An address says nothing about whether an app lives there. The refusal still goes to the activity log.

**Roles.** Each app declares its roles, the one with the most rights first (default `owner`, `editor`, `viewer`). Grants map a
person (`email`), a group (`group`), an email domain (`domain`), or everyone (`everyone`: `workspace` or `signed_in`)
to one of those roles:

```json
{ "access": "people", "add": [{ "group": "finance", "role": "editor" }, { "domain": "acme.test", "role": "viewer" }] }
```

The owner and workspace admins get the top role. Anyone else let in without a grant gets the lowest. If the app is in
a space, everyone in the space counts as named on it: they get their space role when the app has that role, and the
app's lowest role otherwise.

**Workspace roles.** **admin** (people, groups, branding), **builder** (deploy and manage apps, connect agents),
**member** (use apps), **guest** (only the apps they were given).

**Sharing with a password.** `set_access` with `{ "access": "password", "password": "..." }` lets anyone with the
address and the password in, without an account. The password is 6 to 128 characters.

- Visitors see a password page. A correct password earns a cookie on the app's own address for 30 days.
- Brod keeps only a salted PBKDF2-SHA256 hash, so it cannot show the password again.
- A new password signs out everyone who used the old one. Moving the app to another mode forgets it.
- After 30 wrong passwords in 15 minutes the app asks visitors to wait (`429`).
- Visitors who came in with the password and are not signed in are anonymous to the app: `/_brod/me` answers `401`.
  A signed-in visitor who came in with the password gets the app's lowest role.

**Agents and confirmations.** When an agent widens access (a more open mode, new grants or a new password), nothing
changes yet. The tool returns a `confirm_url`, and a person in the workspace opens it and confirms or declines.
Narrowing access applies at once. See [mcp.md](mcp.md).

**New workspaces.** With `BROD_ABUSE_CHECKS=true`, a workspace on the free plan cannot set an app to `password`,
`signed_in` or `public` for its first 24 hours. The refusal is `403 workspace_too_new` with `available_at`. Sharing
inside the workspace (`workspace`, or `people` with named people and groups) works from the start. A self-hosted
server has this hold off by default. See [security.md](security.md).

## Custom domains

A workspace can serve its apps at domains it owns, in two ways:

- **One app, one domain.** `shop.example.com` serves the app `shop`. Builders and admins can add these (`set_domain`
  with `app`, `POST /v1/domains` with `{ "domain": "shop.example.com", "app": "shop" }`, or the app's Domains tab).
- **A whole domain for the workspace.** `*.apps.example.com` serves every app in the workspace at
  `<slug>.apps.example.com`, and `apps.example.com` opens the workspace home page. Admins only (`domain` set to
  `*.apps.example.com`, no `app`).

Adding a domain answers with two DNS records to create:

| Record | Name | Value | Why |
| --- | --- | --- | --- |
| `TXT` | `_brod.shop.example.com` | `brod-verify=<token>` | Proves the workspace owns the domain. Keep it. |
| `CNAME` | `shop.example.com` (or `*.apps.example.com`) | the API host, or `CUSTOM_DOMAIN_TARGET` | Sends visitors to Brod. A bare domain (`example.com`) cannot have a CNAME: use your DNS provider's ALIAS, ANAME or CNAME flattening, or `A`/`AAAA` records to the server. |

Then verify: call `set_domain` again with the same domain, or `POST /v1/domains/<domain>/verify`. Brod looks up the TXT
record over DNS-over-HTTPS (`DNS_RESOLVER_URL`, default `https://cloudflare-dns.com/dns-query`). If the lookup fails,
the answer is `502 dns_unavailable`.

- Nothing is served at a domain until it is verified.
- Several workspaces may claim the same name while it is pending, so nobody can squat on it. Only the one holding the
  TXT record can verify it, and then no other can (`409 domain_taken`).
- `get_status` lists an app's domains with their status.
- Removing a domain (or deleting the app) stops serving it at once.
- A workspace can have 50 domains.
- A verified domain stays verified. Brod does not check its TXT record again later.

Everything else works as on the app's own address: the access decision, roles, `/_brod/me`, and server apps (which see
the custom domain in `request.url`). Signing in still happens on the API host. The gateway sends the visitor to
`/auth/app?app=<slug>.<workspace>&host=<custom domain>`, and Brod hands the one-time code to that host only when it is a
verified domain of that same app. The custom domain then gets its own session cookie.

**HTTPS.** Caddy's on-demand TLS asks Brod's `/_caddy/ask` before it gets a certificate, and Brod approves verified
custom domains (see the `https://` block at the end of `deploy/Caddyfile`). Or let Brod do HTTPS itself with
`BROD_TLS`. That issues certificates over HTTP-01 only, so there are no wildcard certificates: each app under a
wildcard custom domain gets its own certificate on its first visit. See [configuration.md](configuration.md).

## App settings

The people who make an app decide what the people who use it can change without touching its code: a name, a logo,
colours, wording, a contact address. Brod imposes none. The app declares them in a `brod.json` at the top of its
bundle:

```json
{ "settings": [
  { "key": "name",   "label": "Shop name",     "type": "text",  "default": "My shop" },
  { "key": "logo",   "label": "Logo",          "type": "image", "default": "logo.png" },
  { "key": "accent", "label": "Accent colour", "type": "color", "default": "#1f6f4a" },
  { "key": "theme",  "label": "Theme",         "type": "select", "options": ["light", "dark"], "default": "light", "help": "Shown to visitors" }
] }
```

- **Types.** `text` (up to 200 characters), `textarea` (4000), `color` (`#rrggbb`), `image`, `url` (http or https),
  `email`, `number` (optional `min`, `max`), `boolean` and `select` (with `options`). A key starts with a lowercase
  letter and has up to 40 lowercase letters, digits and `_`. At most 30 settings. An image's default is a picture in
  the bundle. Every other default is a value of its type.
- **Checked at deploy.** The declaration is read on every deploy and kept with the version, so it follows versions,
  staging and rollbacks. A `brod.json` Brod cannot use refuses the deploy with `400 bad_settings` and what is wrong.
- **Changing them.** On the admin page's **Customize** tab, or with `PATCH /v1/apps/:slug/settings`:

  ```json
  { "name": "Ada's Coffee", "theme": null }
  ```

  `null` goes back to the default. A value of the wrong type is refused with `400 bad_setting`, and an unknown key
  with `400 unknown_setting`. Images are uploaded with `PUT /v1/apps/:slug/settings/:key`, the picture as the body:
  PNG, JPEG, WebP or GIF, up to 1 MB, typed by their bytes. No redeploy: changes show on the next request and appear in
  the activity log as `settings_changed`. Values belong to the app, so each copy of an app has its own.
- **Reading them.** In the browser, `await Brod.settings()` (or `GET /_brod/settings` on the app's address) returns
  every declared key, with its default when nobody set it, and an image as an address to put in `<img src>`:

  ```json
  { "name": "My shop", "logo": "/_brod/settings/logo?v=...", "accent": "#1f6f4a", "theme": "light" }
  ```

  Server code gets the same object as `env.SETTINGS`. Settings are only served to people who may open the app.

## Outside addresses

Nobody can prove by reading code that it does not leak data, so Brod does not try. Instead, an app may only send data
to its own address and the outside hosts it declares, and Brod enforces that where the app's code runs
(`server/src/network.rs`). The app declares them in its `brod.json`:

```json
{ "network": ["api.stripe.com", "cdn.jsdelivr.net", "*.googleapis.com"] }
```

Host names only (no `https://`, port or path). `*.` covers subdomains, not the name itself. At most 30. Without a list,
the app may only talk to its own address. The list is checked at deploy (`400 bad_network`) and kept with the version.

- **Server code.** Every `fetch` an app makes passes the sidecar's outbound gate (`AppOutbound` in
  `deploy/runtime/host.js`), which lets declared hosts through. There is no other way out: no sockets, and the app's
  database, key-value store and files are not reached over the network.
- **The browser.** Every response from the app carries a `Content-Security-Policy` built from the list. Its pages may
  load scripts, styles, fonts and pictures, fetch, open WebSockets, frame pages and post forms only to their own address
  and the declared hosts. Inline scripts still run: the policy is about where data goes. Browsers report what it stops
  to `/_brod/csp`. One gap no header closes: a script can still send the visitor's browser to another address with data
  in it (`location = ...`).
- **Log first, then enforce.** `BROD_NETWORK` sets what happens to an undeclared request.
  - `log` (the default) lets it through and records it. Pages carry the policy as
    `Content-Security-Policy-Report-Only`, so existing apps keep working while their makers complete their lists.
  - `enforce` refuses it and records it. Server code gets a `403` with `x-brod-network: refused`, and the policy is
    enforced in the browser.
  - `off` does neither.
- **What people see.** Each app's **Network** tab (and `network` in `get_status`) shows the declared hosts, the
  server's policy, and every undeclared host the app reached or tried to, from its server code or a browser, with
  counts and whether it was blocked. Only the app's own workspace sees this.

## Limits

| What | Limit |
| --- | --- |
| Files passed inline to `deploy_app` or `POST /v1/deploys` | 1 MB in all |
| An uploaded bundle (tar.gz) | 25 MB |
| A bundle, unpacked | 60 MB, 2,000 files |
| One file | 10 MB |
| Upload and download addresses | valid for 15 minutes |
| Deploys | 30 an hour per workspace (`429 rate_limited`) |
| `env.KV` value | 128 KB |
| Server app logs | kept 7 days; `get_logs` shows the last 50 requests |
| Settings | 30 per app; images up to 1 MB |
| Outside hosts | 30 per app |
| Custom domains | 50 per workspace |

Plans differ by mode. On a self-hosted server there are no plans: no limit on running apps, people or storage. On a
hosted server each workspace's plan sets how many apps can run, how many people it can have, and its storage. A deploy
or file write over the storage allowance is refused with `storage_limit`.

What is not here yet:

- Server apps run JavaScript (and WebAssembly) only. Containers and other languages are not supported.
- Old versions are kept until someone deletes them (`DELETE /v1/apps/:slug/versions/:n`). They count toward storage.
  There is no clean-up job.
- Blocking paths by role, company sign-in (SAML/OIDC) and deploy-before-sign-up are not built yet.
