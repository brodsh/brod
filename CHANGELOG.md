# Changelog

All notable changes to Brod. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and Brod uses
[Semantic Versioning](https://semver.org/) (0.x: minor versions may change behaviour). Release notes on GitHub are
generated from conventional commits.

## 0.2.0 (2026-10-31)

Container apps on nodes, managed Postgres, signed identity tokens and app MCP.

### Added

- Signed identity: apps get an Ed25519-signed JWT in `x-brod-identity` (5 minutes), verifiable against
  `/.well-known/jwks.json`; apps get `BROD_ISSUER`, `BROD_APP_ID` and `BROD_IDENTITY_JWKS`. `@brod/auth` (MIT, `sdk/js`)
  verifies it in JavaScript; docs/apps.md has recipes for Python, Go and Rust.
- Open paths: up to 10 paths per app that skip sign-in (`set_open_paths`), live and staging. Opening paths, widening
  access, invites and deletes need a person to confirm.
- Nodes: `brod-node` joins with a one-time token and dials Brod over a reversed HTTP/2 tunnel; no inbound ports.
  Admin API at `/v1/admin/nodes`. New image `ghcr.io/brodsh/brod-node`.
- Container apps: a source folder with a Dockerfile is built on a node, stored in Brod's own registry and run hardened
  (read-only root, no capabilities, non-root, limits, a network per app). Health-checked switch, rollback without a
  rebuild, staging. Controlled by `BROD_CONTAINERS`.
- Managed Postgres for container apps (`request_database`): a role and database per app in `apps-postgres`, reached at
  `brod-db.internal` through the node; `migrate` before the switch; encrypted nightly backups, person-confirmed
  restore, weekly restore drill.
- App MCP: an app declares `"mcp": "/api/mcp"` in `brod.json`; MCP clients sign in with Brod (OAuth, tokens bound to
  that app's address) and the app reads the caller with `currentUser()`.

### Fixed

- Staging addresses (`<app>--staging.<workspace>`) get TLS certificates again.

### Upgrading

- Migrations 0020–0024 run at start.
- `docker-compose.yml` adds `apps-postgres`, `registry` and `node`, and gives `brod` `BROD_REGISTRY_URL` and
  `BROD_APPS_DATABASE_URL`. Self-hosted: nothing to set, the keys are generated.
- Hosted mode (`BROD_MODE=hosted`): set `IDENTITY_SIGNING_KEY` (`openssl rand -hex 32`) before upgrading, or Brod will
  not start. Without containers, also set `BROD_REGISTRY_URL=` and `BROD_APPS_DATABASE_URL=` (empty) for `brod` and
  leave out `apps-postgres`, `registry` and `node` (for example with a Compose profile); with them, also set
  `REGISTRY_SIGNING_KEY` and `APPS_DATABASE_PASSWORD`.

## 0.1.0 (2026-10-14)

The first open-source release.

### Added

- Self-hosted mode, the default (`BROD_MODE=self-hosted`): no plans or billing, no public landing page, and only
  workspace admins create workspaces.
- First start with nothing but `BROD_ADMIN_EMAIL`: Brod generates its secrets, makes a "Default" workspace, and logs a
  one-time sign-in link and the command that connects Claude Code. `brod setup-link` prints a fresh link.
- Email through any SMTP server (`SMTP_URL`). Without email, a self-hosted Brod logs sign-in links.
- `docker-compose.yml` with Brod, Postgres (over a shared socket, no password) and the server-app runtime.
- Multi-arch images (linux/amd64, linux/arm64) on a distroless base.
- `BROD_AUTO_MIGRATE` and `brod migrate`.
- Documentation: configuration, MCP, production, architecture, security, apps and API references.
- `examples/hello-team`.

### Changed

- `BROD_PUBLIC_URL` replaces `API_ORIGIN`, which still works.
- Licensed under AGPL-3.0-only.

### Removed

- The Cloudflare Workers and Vercel builds. Brod is the Rust server.

### Security

- App passwords are hashed with Argon2id. Existing PBKDF2 hashes keep working.
- REST and MCP calls are limited to 600 a minute per connection or person.
- Hosted mode requires `SECRETS_KEY`.
- The runtime container no longer mounts Brod's data volume, and checks its shared secret in constant time.
- The preview browser refuses host names that resolve to private addresses.

### Fixed

- Analytics reports left out what was recorded in the same millisecond as the report was asked for, and could read
  before a periodic flush had finished writing.
