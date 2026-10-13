# Changelog

All notable changes to Brod. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and Brod uses
[Semantic Versioning](https://semver.org/) (0.x: minor versions may change behaviour). Release notes on GitHub are
generated from conventional commits.

## 0.1.0 (unreleased)

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
