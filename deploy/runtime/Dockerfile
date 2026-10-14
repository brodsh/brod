# syntax=docker/dockerfile:1.7
# SPDX-License-Identifier: AGPL-3.0-only
# Brod's server-app runtime: workerd (the open-source Workers runtime) running deploy/runtime/host.js, under the
# supervisor in deploy/runtime/supervisor/, which restarts it when an app stalls it or runs it out of memory.
# Build from the repository root:
#   docker build -f deploy/runtime/Dockerfile -t brod-runtime .
# Both build stages run on the build machine and fetch or cross-compile for the target, so no emulation is needed.

# workerd ships as an npm package with a prebuilt binary per platform. Keep this in step with package.json.
FROM --platform=$BUILDPLATFORM node:26-bookworm-slim@sha256:86f07bc9c5dce4578cf37e5a418b7bfc7f817cda25cde66e2b66e95ed86c4567 AS fetch
ARG WORKERD_VERSION=1.20261006.1
ARG TARGETARCH
ARG BUILDARCH
WORKDIR /w
RUN set -eu; \
    case "$TARGETARCH" in amd64) cpu=x64 pkg=64 ;; arm64) cpu=arm64 pkg=arm64 ;; *) echo "unsupported architecture: $TARGETARCH" >&2; exit 1 ;; esac; \
    npm install --no-save --os=linux --cpu="$cpu" "workerd@${WORKERD_VERSION}"; \
    cp "/w/node_modules/@cloudflare/workerd-linux-$pkg/bin/workerd" /workerd; \
    if [ "$TARGETARCH" = "$BUILDARCH" ]; then /workerd --version; fi; \
    mkdir /data

# The supervisor: one small binary, std and libc only.
FROM --platform=$BUILDPLATFORM rust:1.97-bookworm@sha256:0e2bcaef56d041a486784e54104a81aebe0da44bd03019bd70bc0401e42e4a97 AS supervisor
ARG TARGETARCH
ARG BUILDARCH
RUN set -eu; \
    case "$TARGETARCH" in \
      amd64) triple=x86_64-unknown-linux-gnu; cross="gcc-x86-64-linux-gnu libc6-dev-amd64-cross" ;; \
      arm64) triple=aarch64-unknown-linux-gnu; cross="gcc-aarch64-linux-gnu libc6-dev-arm64-cross" ;; \
      *) echo "unsupported architecture: $TARGETARCH" >&2; exit 1 ;; \
    esac; \
    if [ "$TARGETARCH" != "$BUILDARCH" ]; then \
      apt-get update && apt-get install -y --no-install-recommends $cross && rm -rf /var/lib/apt/lists/*; \
      echo "CARGO_TARGET_$(echo "$triple" | tr 'a-z-' 'A-Z_')_LINKER=$(echo "$triple" | sed 's/-unknown//')-gcc" > /cross.env; \
    else \
      : > /cross.env; \
    fi; \
    rustup target add "$triple"; \
    echo "$triple" > /triple
WORKDIR /src
COPY deploy/runtime/supervisor/Cargo.toml deploy/runtime/supervisor/Cargo.lock ./
COPY deploy/runtime/supervisor/src src
RUN set -eu; \
    if [ -s /cross.env ]; then export "$(cat /cross.env)"; fi; \
    cargo build --release --locked --target "$(cat /triple)"; \
    cp "target/$(cat /triple)/release/brod-runtime" /brod-runtime

# workerd needs only glibc; distroless also brings the CA certificates apps need for outgoing HTTPS.
FROM gcr.io/distroless/cc-debian12:nonroot@sha256:9dac0a79194e45a7da0158a9c6da57b217585af0786db3845d1f0ec1a0dd182f
LABEL org.opencontainers.image.title="Brod runtime" \
      org.opencontainers.image.description="Runs Brod's server apps on workerd." \
      org.opencontainers.image.source="https://github.com/brodsh/brod" \
      org.opencontainers.image.licenses="AGPL-3.0-only"
COPY --from=fetch /workerd /usr/local/bin/workerd
COPY --from=supervisor /brod-runtime /usr/local/bin/brod-runtime
COPY --from=fetch --chown=65532:65532 /data /data
COPY deploy/runtime/config.capnp deploy/runtime/host.js /etc/brod-runtime/
VOLUME /data
EXPOSE 8081
USER nonroot
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 CMD ["/usr/local/bin/brod-runtime", "healthcheck"]
# Brod is expected at brod:8080 (override workerd's with -e brod=<host:port>, and the supervisor's with
# BROD_INTERNAL_URL). The secret comes from BROD_RUNTIME_SECRET or BROD_RUNTIME_SECRET_FILE.
ENTRYPOINT ["/usr/local/bin/brod-runtime", "/usr/local/bin/workerd", "serve", "/etc/brod-runtime/config.capnp", "--experimental"]
