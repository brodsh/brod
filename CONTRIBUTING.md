# Contributing to Brod

Thanks for helping. This page covers setting up, testing and sending a change.

## Before you start

For anything bigger than a small fix, open an issue first and say what you plan to do. Check
[docs/roadmap.md](docs/roadmap.md): some features were left out on purpose, and the issue is the place to argue for
them.

Read [docs/architecture.md](docs/architecture.md) for how the pieces fit together.

## Set up

You need:

- Rust (the version in `rust-toolchain.toml`; rustup installs it on first use) and a C compiler (`build-essential` on
  Debian and Ubuntu, Xcode's command-line tools on macOS);
- Node.js 22, for the end-to-end tests;
- Docker, for the development database and the images.

```sh
git clone https://github.com/brodsh/brod && cd brod
make dev
```

`make dev` starts Postgres from `compose.dev.yml` and runs Brod with `cargo run` at `http://localhost:8080`, with
`DEV_MODE=1`: sign-in links appear in the log and in API responses. The first start prints a sign-in link for
`dev@example.com`. Stop the database with `make db-stop`.

**Server apps.** To run apps' server code locally, start the runtime in a second terminal with `make dev-runtime`, and
start Brod with `BROD_RUNTIME_URL=http://127.0.0.1:8081 make dev`.

**The admin UI** is `server/src/admin.html`, plain HTML and JavaScript. In `make dev` Brod reads it from disk on every
request (`BROD_DEV_ASSETS`), so a change needs only a browser reload. Other pages are compiled in and need a restart.

`make help` lists every command.

## Test

| Command | What it runs |
| --- | --- |
| `make check` | Formatting, clippy with warnings as errors, unit tests, Node tests, and whether `docs/configuration.md` matches `.env.example`. Run this before every push. |
| `make test` | Rust unit tests. Set `BROD_TEST_DATABASE_URL=postgres://brod@127.0.0.1:5432/brod` (after `make db`) to run the database tests on Postgres too. |
| `make e2e` | The end-to-end suites against a release build: about 360 checks in hosted mode, and the self-hosted first start. |
| `npm run e2e:rust -- static`, `-- s3`, `-- pg` | The hosted suite without the runtime, with app files in a fake S3, or on Postgres. |
| `deploy/smoke-test.sh` | The production stack with Caddy and HTTPS (needs port 443 free). |

CI runs all of these, plus `cargo deny`, `cargo audit`, gitleaks and the Docker builds
([.github/workflows/ci.yml](.github/workflows/ci.yml)).

## Code

- Rust, formatted with `cargo fmt` (`server/rustfmt.toml`: 140 columns). Avoid `unwrap()` and `expect()` outside tests
  and start-up: a request must not be able to panic the server.
- Errors that reach a client are a `Problem` (`server/src/problem.rs`): a status, a stable `code`, and a message a
  person can act on. Internal details go to the log, never to the client.
- Comments say why, not what. Keep them short and keep them true when the code changes.
- A new setting goes in `.env.example` with a one-line comment; then run `make config-docs`.
- Every source file starts with `// SPDX-License-Identifier: AGPL-3.0-only`.

## Commits and pull requests

Commit messages follow [Conventional Commits](https://www.conventionalcommits.org/): `feat:`, `fix:`, `docs:`,
`refactor:`, `test:`, `build:`, `ci:`, `chore:`, with an optional scope (`fix(email): ...`). Release notes are made from
them, so write the subject for a reader of the changelog. Mark breaking changes with `!` and a `BREAKING CHANGE:` line.

A pull request should:

- do one thing, with a description of what and why;
- pass CI;
- add a test for new behaviour, or say why there is none;
- update the docs it affects.

## License

Brod is licensed under [AGPL-3.0-only](LICENSE). By sending a contribution you agree that it is licensed the same
way.
