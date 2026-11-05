# Changelog

All notable changes to Brod. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and Brod uses
[Semantic Versioning](https://semver.org/) (0.x: minor versions may change behaviour). Release notes on GitHub are
generated from conventional commits.

## 0.2.1 (2026-11-02)

### Fixed

- Hosted mode (`BROD_MODE=hosted`) now generates `REGISTRY_SIGNING_KEY` and `APPS_DATABASE_PASSWORD` into
  `<data>/secrets.env` when they are unset, like self-hosted does. Before, the shipped `docker-compose.yml` would not
  start in hosted mode without them.
- The image now gives `/run/brod-registry` to Brod's user, so a new `registry-cert` volume is writable and Brod can
  write the registry's token certificate.
- The error for a bad `REGISTRY_SIGNING_KEY` says it must be PKCS#8 (not SEC1) and shows how to make one.
- `deploy/upgrade.sh` rollback recreates the containers and ignores a `BROD_VERSION` set in the caller's environment,
  so a failed upgrade really goes back to the previous version.

## 0.2.0 (2026-11-01)

Container apps on nodes, managed Postgres for apps, admin mode, and git-backed app versions.

### Added

- Container apps: `brod deploy` builds an app from source on a node, pushes the image to Brod's registry and runs it as
  a hardened container, with health-checked deploys and rollback.
- Nodes (`brod-node`): a machine joins Brod, dials it over a reversed HTTP/2 tunnel and runs container apps. Compose
  starts a local node by default.
- Managed Postgres for container apps (`apps-postgres` service): a database per app, reached as
  `brod-db.internal` through the tunnel, with migrations and backups.
- Open paths: apps declare paths that skip sign-in; a person approves them. MCP `set_open_paths` and
  `get_auth_integration`.
- `@brodsh/auth`, the identity SDK for JavaScript.
- Admin mode: operators, instance settings, workspace limits and overrides, an audit log and the operator console
  (including node management).
- Git-backed app versions: files are stored once by content hash (`blobs/<sha256>`) and each version is a manifest.
  Old versions are converted lazily, with no downtime.
- Patch deploys: `deploy_app` and `POST /v1/deploys` take `base_version` plus changed and deleted files. A stale base
  is merged three-way; conflicts return 409 `merge_conflict`. `get_files` takes `since`; new `diff_versions` tool.
- Git export and import: clone an app read-only over smart HTTP or download a bundle (`export_app`); import a URL or
  bundle into staging (`import_app`), merged at the common ancestor.
- Git mirror and sync (`set_git_mirror`, `get_git_mirror`): fast-forward pushes to GitHub/GitLab, and signed webhooks
  or polling bring remote pushes into staging.

### Changed

- `docker-compose.yml` adds the `apps-postgres`, `registry` and `node` services; the Caddyfile passes `/_node/connect`
  through as HTTP/1.1 Upgrade. Existing installs must update both files before upgrading.
- Migrations 0025-0027 add the version store, git commit map and git mirror tables.

### Fixed

- Certificates for staging addresses, gzip archives padded with zeros or split in members, Postgres copies of
  admin-mode tables, and restore/drill scratch databases created outside a transaction.

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
