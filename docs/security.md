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
| App passwords (`password` access) | PBKDF2-SHA256, 100,000 iterations, per-app salt |
| App secrets (`set_secret`) | AES-256-GCM under a key derived from `SECRETS_KEY` with HKDF, bound to the app. Write-only through the API. |
| User passwords | None exist. Sign-in is an emailed link (or Google). |

Agent tokens can expire and can be read-only. OAuth access tokens last an hour; refresh tokens rotate on each use,
and reusing the previous one disconnects the client.

**Agents acting beyond what a person intended.** An agent can deploy and narrow access on its own. Widening access,
inviting someone and deleting an app wait until a person opens a confirmation link ([docs/mcp.md](mcp.md#what-needs-a-person)).
Updates to a live app go to a staging address first unless the agent is told otherwise.

**Guessing and flooding.** Rate limits, kept in the database:

| What | Limit |
| --- | --- |
| Sign-in links | 5 an hour per email address, 20 an hour per client address |
| App passwords | 30 tries in 15 minutes per app |
| OAuth client registration | 10 an hour per client address, 100 an hour in total |
| Deploys | 30 an hour per workspace |
| New workspaces | 3 a day per person |
| Abuse reports (hosted) | 10 an hour per client address |

**Bad uploads.** Bundles are unpacked with checks on path traversal (`..`, absolute paths), file count (2,000), file
size (10 MB) and total size (60 MB unpacked). Files are served with a `Content-Type` from their extension and
`X-Content-Type-Options: nosniff`.

**Weak configuration.** In hosted mode Brod refuses to start with a secret shorter than 32 characters or one of the
example values from its own docs. In self-hosted mode it generates any secret that is not set and warns about weak ones.

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
- **The operator.** Whoever runs Brod can read every app's files and database, and with `SECRETS_KEY` every app secret.
- **Third-party requests from pages.** Brod's own pages load fonts from Google Fonts, so visitors' browsers contact
  Google. Self-hosting the fonts is on the [roadmap](roadmap.md).

## What the operator must do

1. Run Brod behind HTTPS before anyone else uses it.
2. Back up `secrets.env` with the database ([backups](deploy-production.md#backups)). Losing `SECRETS_KEY` loses every
   app secret.
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
