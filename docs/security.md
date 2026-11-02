# Security

This page says what Brod protects against, what it does not, and what an operator must do. To report a vulnerability,
see [SECURITY.md](../SECURITY.md).

- [The model in one paragraph](#the-model-in-one-paragraph)
- [What Brod protects against](#what-brod-protects-against)
- [What Brod does not protect against](#what-brod-does-not-protect-against)
- [What the operator must do](#what-the-operator-must-do)
- [Dependencies and audits](#dependencies-and-audits)

## The model in one paragraph

Brod runs apps that people in your organisation, or their agents, wrote. It decides who may open each app, signs
people in once for all of them, and keeps one app's data apart from another's. It assumes the people who deploy apps
are trusted members of the team. **It is not a sandbox for hostile code.** Server apps run inside the runtime
container on your network, and a determined author of a server app can affect other apps on the same server.

## What Brod protects against

**People who should not see an app.** Access is decided in Brod's gateway before a request reaches an app, for every
request ([docs/apps.md](apps.md#access)). Someone an app is not shared with gets the same 404 as an address with no
app. Removing a person from a workspace ends their access on their next request.

**Apps stealing or planting sign-in cookies.** The platform session cookie lives only on Brod's own host. Apps never
see it. On HTTPS every cookie is `__Host-`-prefixed, `Secure`, `HttpOnly` and `SameSite=Lax`, so an app on a sibling
host can neither read nor set it. Each app gets its own session cookie on its own host, made through a one-time code.
The gateway strips the platform cookie and any `x-brod-*` header a visitor sends before forwarding to an app.

**Cross-site requests to the platform.** Every state-changing request authenticated by a cookie must carry an `Origin`
header equal to `BROD_PUBLIC_URL`. Platform pages send `X-Frame-Options: DENY`.

**Leaked credentials at rest.**

| Kept | How |
| --- | --- |
| Agent tokens (`brod_…`), OAuth access and refresh tokens, sessions, sign-in and invitation links | SHA-256 of a 24-byte random value; the value itself is never stored |
| App passwords (`password` access) | Argon2id (19 MiB, 2 passes), per-password salt. Older PBKDF2-SHA256 hashes still verify. |
| App secrets (`set_secret`) | AES-256-GCM under a key derived from `SECRETS_KEY` with HKDF, bound to the app. Write-only through the API. |
| Container apps' database passwords | Stored as the app's `DATABASE_URL` secret, as above. Never shown by `get_status`. |
| Database backups | AES-256-GCM in 1 MiB chunks under a key derived from `SECRETS_KEY` with HKDF (`brod db backups v1`), each chunk bound to its database, position and whether it is the last. No plaintext dump is written to disk. |
| User passwords | None exist. Sign-in is an emailed link (or Google). |

Agent tokens can expire and can be read-only. OAuth access tokens last an hour; refresh tokens rotate on each use,
and reusing the previous one disconnects the client.

**Agents acting beyond what a person intended.** An agent can deploy and narrow access on its own. Five things wait
until a person opens a confirmation link: widening access, inviting someone, deleting an app, opening paths that
skip sign-in, and restoring an app's database from a backup ([docs/mcp.md](mcp.md#what-needs-a-person)). They are one list in the code (`control::NEEDS_A_PERSON`).
An agent deploy that declares new open paths still goes live, with those paths closed until a person confirms.
Updates to a live app go to a staging address first unless the agent is told otherwise.

**One app reaching another's database.** Apps' databases live in `apps-postgres`, which has no network: neither apps
nor nodes can reach it. An app reaches `brod-db.internal`, a listener its node opens on that app's own bridge only;
the node passes each connection to Brod over its own connection, saying which app it came from, and Brod accepts it
only if that app has a database and a deployment on that node, and only if the client asks for that app's database
as that app's role. Postgres then checks the role's password. Each role owns only its database, cannot create roles or
databases, and `CONNECT` on every app database is revoked from everyone else, so even a leaked password works only
for its own database and only through its own app's node.

**Forged identities.** Apps learn who a visitor is from the `x-brod-*` headers, which the gateway sets after stripping
any a visitor sent, and from an Ed25519-signed JWT (`x-brod-identity`, `/_brod/me`) that names one app as its
audience and lasts five minutes. Anything can verify it against `/.well-known/jwks.json`; only the holder of
`IDENTITY_SIGNING_KEY` can make one.

**Open paths used as a way around sign-in.** Paths an app opens ([docs/apps.md](apps.md#open-paths)) are exact or a
`/*` prefix, never `/` or everything. Requests with encoded slashes, dot segments or double encoding never match, and
the app receives the same normalised path that matched, so `/api/mcp/../admin` cannot reach `/admin`. Open-path
requests carry no identity, no session cookie and no `x-brod-*` header.

**Guessing and flooding.** Rate limits, kept in the database:

| What | Limit |
| --- | --- |
| REST API and MCP calls | 600 a minute per agent connection or person (kept in memory) |
| Sign-in links | 5 an hour per email address, 20 an hour per client address |
| App passwords | 30 tries in 15 minutes per app |
| OAuth client registration | 10 an hour per client address, 100 an hour in total |
| Deploys | 30 an hour per workspace |
| New workspaces | 3 a day per person |
| Abuse reports (hosted) | 10 an hour per client address |
| Requests to apps | 1,200 a minute per client address (the shield, below; kept in memory) |

**Bots and scanners on apps.** Every request to an app is classified `human`, `suspicious` or `bot` from its user
agent, its headers (`Accept-Language`, `Accept`, HTTP/1.0), probe paths such as `/wp-login.php`, `/.env` or `/.git/`,
its address's recent burst rate and share of 4xx answers, and whether the client proved it runs a browser
([docs/api.md](api.md#traffic-classes)). Analytics show people only unless asked. With the shield on (`BROD_SHIELD`,
the default), the gateway also:

- refuses (403, after a short tarpit) an address that asked for `BROD_SHIELD_SCANNER_PROBES` (8) probe paths within ten
  minutes, for `BROD_SHIELD_BLOCK_MINUTES` (60);
- answers 429 to an address over `BROD_SHIELD_REQUESTS_PER_MINUTE` (1,200) requests a minute;
- puts a proof-of-work check in front of page loads that are suspicious, or whose address made more than
  `BROD_SHIELD_CHALLENGE_PER_MINUTE` (300) requests this minute. The page's script finds a SHA-256 hash with
  `BROD_SHIELD_CHALLENGE_BITS` (16) leading zero bits (well under a second in a browser) for a token signed with
  `IDENTITY_SECRET`, bound to the address and valid for 10 minutes; the answer earns a signed, `HttpOnly` cookie bound
  to the address for `BROD_SHIELD_PASS_HOURS` (24). No third-party service sees the visitor. Clients without
  JavaScript cannot pass it.

Never checked or blocked: people signed in to the app, open paths (webhooks), anything but a page load, Brod's own
`/_brod/` endpoints, bots that say what they are, and loopback and private-network addresses. Those addresses are not
tracked either, because everyone behind a LAN or an untrusted proxy shares one; behind a proxy, set
`BROD_TRUST_PROXY=1` so the shield sees visitors' addresses. Blocks and counters live in memory and are lost on a
restart. Off (`BROD_SHIELD=false`, or in the admin console), traffic is still classified for analytics.

**Bad uploads.** Bundles are unpacked with checks on path traversal (`..`, absolute paths), file count (2,000), file
size (10 MB) and total size (60 MB unpacked). Files are served with a `Content-Type` from their extension and
`X-Content-Type-Options: nosniff`.

**Git mirror and inbound sync.** The push token is sealed with `SECRETS_KEY` (bound to the app), is only decrypted for a push, and
is never returned by any API, tool, log or export. It goes out as HTTP Basic auth (`x-access-token`) and is dropped on a redirect to
another host. Only the app's owner or an admin can set it. The remote must be https and every request, including the poller's, goes
through the same outbound guard as `import_app` (no loopback, private or metadata addresses, DNS pinned, redirects checked);
loopback is allowed only with `DEV_MODE=1` and `DEV_ALLOW_LOOPBACK_GIT=1`. Pushes are fast-forward only: Brod never sends a
forced update, never moves a tag, and marks a branch it cannot fast-forward as `diverged`. The webhook endpoint has no session:
it accepts a request only when the GitHub HMAC-SHA256 signature (`X-Hub-Signature-256`) or the GitLab token matches the app's
webhook secret, compared in constant time over the raw body; the secret is random, sealed and shown once. The endpoint has a body
cap (5 MB) and a rate limit per address and per app, and bad signatures get the same 401 whether or not the app exists. Inbound
changes only ever land on staging (never live) and conflicts create no version. Commits Brod pushed itself are recorded and
ignored when they come back, so a mirror and a webhook cannot loop.

**Weak configuration.** In hosted mode Brod refuses to start without `SECRETS_KEY` or `IDENTITY_SIGNING_KEY`, or with a
secret shorter than 32 characters or one of the example values from its own docs. In self-hosted mode it generates any secret that is not set
and warns about weak ones.

**The sidecars.** The runtime sees only its own secret, from a volume that holds nothing else, and compares it in
constant time. The marketplace's preview browser loads only its sandbox and public addresses, and checks what a host
name resolves to before letting a page load from it.

## What Brod does not protect against

Be clear about these before you put Brod in front of people:

- **Hostile server code.** All server apps run in one workerd process, each in its own V8 isolate with its own
  storage. Isolates separate memory, not CPU: open-source workerd does not enforce a per-request CPU limit. An app in a
  busy loop stalls every server app until the supervisor restarts workerd (after `RUNTIME_STALL_MS`, 5 s by default)
  and pauses the app it blames. One app can also use memory up to the runtime's ceiling. A V8 escape would reach the
  runtime container. Treat everyone who can deploy as able to disrupt other server apps.
- **Apps attacking each other's users.** Every app lives under `APPS_DOMAIN`, so browsers treat all apps as the same
  site. `SameSite=Lax` therefore does not stop a page in app A from sending a form to app B with the visitor's session
  for B. Apps that change data on `POST` should check the `Origin` header or use their own CSRF token. Adding
  `APPS_DOMAIN` to the [Public Suffix List](https://publicsuffix.org/) would make each workspace its own site; that is
  on the [roadmap](roadmap.md).
- **Framing.** App pages carry no `frame-ancestors` policy, so another site can frame them. Apps that need protection
  from clickjacking should send their own `Content-Security-Policy: frame-ancestors 'self'`.
- **Data leaving through server apps.** Outbound requests from server apps are checked against the hosts an app
  declares in `brod.json`, but the default `BROD_NETWORK=log` only records them. Set `BROD_NETWORK=enforce` to refuse
  them. The browser-side Content-Security-Policy is report-only under `log`.
- **Staging data.** An app's staging version uses the same database, files and secrets as its live version. What you
  change while testing is real.
- **Plain HTTP.** Without HTTPS, cookies have no `__Host-` prefix or `Secure` flag, and anything on the network can
  read sessions. The quickstart binds to `127.0.0.1` for that reason. Use HTTPS for anything else
  ([docs/deploy-production.md](deploy-production.md#https)).
- **Git import and export.** `import_app` with a `url` makes the server fetch an address a person gave it, so the fetch
  goes through an outbound guard: http(s) only, every resolved address must be public (no loopback, private,
  link-local or metadata ranges, also for redirects, each of which is checked again), the connection uses the address
  that was checked (no DNS rebinding), 10 s to connect, 120 s in all and a size cap (`BROD_GIT_MAX_IMPORT_MB`).
  Imports refuse symbolic links, submodules, Git LFS pointers, `.git` folders, `..` and absolute paths and files over
  the deploy limits, and then go through the normal deploy checks. Exports never contain secrets or app data, and
  authors are `<user id>@users.noreply.<apps domain>` unless `BROD_GIT_REAL_EMAILS` is set. The git endpoint is
  read-only (`git-receive-pack` is refused) and takes the same tokens and rate limits as the API.
- **The operator.** Whoever runs Brod can read every app's files and database, and with `SECRETS_KEY` every app secret.
- **Third-party requests from pages.** Brod's own pages load fonts from Google Fonts, so visitors' browsers contact
  Google. Self-hosting the fonts is on the [roadmap](roadmap.md).

## What the operator must do

1. Run Brod behind HTTPS before anyone else uses it.
2. Back up `secrets.env` with the database ([backups](deploy-production.md#backups)). Losing `SECRETS_KEY` loses every
   app secret. Losing `IDENTITY_SIGNING_KEY` changes the JWKS, so services that cached it must fetch it again.
3. Keep the `brod-data` volume and `.env` readable only by you.
4. Upgrade when a release has a security fix. Watch the repository's releases.
5. Give the builder role only to people you would let run code on your network.
6. Consider `BROD_NETWORK=enforce` once your apps declare the hosts they call.

## Dependencies and audits

CI runs on every change:

- `cargo deny check`: licenses compatible with AGPL-3.0, no crate with a known advisory, no yanked crate, crates.io
  only ([deny.toml](../deny.toml));
- `cargo audit` for both Rust crates, and `npm audit` for the test tooling;
- gitleaks on the full history.

There are no ignored advisories. Any advisory we decide to accept will be listed here with the reason. Dependabot
proposes updates weekly. Every release attaches an SPDX software bill of materials for each image.

Base images are pinned by digest. Both images run as a non-root user (uid 65532) on a distroless base, with no shell.
