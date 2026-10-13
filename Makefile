# Everyday commands for working on Brod. Run `make help` for the list.
# Needs: Rust (rust-toolchain.toml picks the version), a C compiler, Node 22, Docker.

SERVER := --manifest-path server/Cargo.toml
SUPERVISOR := --manifest-path deploy/runtime/supervisor/Cargo.toml
# The admin page is read from here on every request in `make dev`, so editing it needs only a browser reload.
BROD_DEV_ASSETS ?= server/src
DEV_ENV := BROD_DATABASE_URL=postgres://brod@127.0.0.1:5432/brod BROD_ADMIN_EMAIL=dev@example.com \
	BROD_DATA_DIR=data DEV_MODE=1 BROD_DEV_ASSETS=$(BROD_DEV_ASSETS)

.PHONY: help dev dev-runtime db db-stop fmt lint test test-node e2e check docker-build config-docs licenses

help: ## List the commands
	@grep -E '^[a-z-]+:.*## ' $(MAKEFILE_LIST) | awk -F ':.*## ' '{printf "  make %-14s %s\n", $$1, $$2}'

db: ## Start Postgres for development (compose.dev.yml)
	docker compose -f compose.dev.yml up -d --wait

db-stop: ## Stop it (the data stays in the postgres-dev volume)
	docker compose -f compose.dev.yml down

dev: db ## Run Brod at http://localhost:8080 against the dev Postgres, with DEV_MODE on
	$(DEV_ENV) cargo run $(SERVER)

dev-runtime: ## Run the server-app runtime next to `make dev` (in a second terminal), then start dev with BROD_RUNTIME_URL
	npm ci --silent
	cargo build $(SUPERVISOR)
	mkdir -p data/runtime
	BROD_RUNTIME_SECRET_FILE=data/runtime-secret BROD_INTERNAL_URL=http://127.0.0.1:8080 RUNTIME_PORT=8081 \
		deploy/runtime/supervisor/target/debug/brod-runtime node_modules/workerd/bin/workerd serve \
		deploy/runtime/config.capnp --experimental -s http=127.0.0.1:8081 -e brod=127.0.0.1:8080 -d data=data/runtime

fmt: ## Format the Rust code
	cargo fmt $(SERVER)
	cargo fmt $(SUPERVISOR)

lint: ## Check formatting and run clippy with warnings as errors
	cargo fmt $(SERVER) --check
	cargo fmt $(SUPERVISOR) --check
	cargo clippy $(SERVER) --all-targets --locked -- -D warnings
	cargo clippy $(SUPERVISOR) --all-targets --locked -- -D warnings

test: ## Rust unit tests (set BROD_TEST_DATABASE_URL to run them on Postgres too)
	cargo test $(SERVER) --locked
	cargo test $(SUPERVISOR) --locked

test-node: ## Node unit tests
	npm ci --silent
	npm test

e2e: ## The end-to-end suites against a release build
	npm ci --silent
	npm run e2e:rust
	npm run e2e:self-hosted

check: lint test test-node ## What CI checks first: lint, unit tests, Node tests, docs in sync
	node scripts/config-docs.mjs --check

docker-build: ## Build both images for this machine
	docker compose build

config-docs: ## Regenerate docs/configuration.md from .env.example
	node scripts/config-docs.mjs

licenses: ## Check dependency licenses and advisories (needs cargo-deny)
	cargo deny $(SERVER) --config deny.toml check
	cargo deny $(SUPERVISOR) --config deny.toml check
