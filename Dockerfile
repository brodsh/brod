# syntax=docker/dockerfile:1.7
# SPDX-License-Identifier: AGPL-3.0-only
# The Brod server. One static-ish binary with the UI, migrations and assets compiled in, on a distroless base.
#   docker build -t brod .
#   docker buildx build --platform linux/amd64,linux/arm64 -t brod .
# The Rust stage runs on the build machine and cross-compiles, so an arm64 image does not need emulation.

FROM --platform=$BUILDPLATFORM rust:1.97-bookworm@sha256:0e2bcaef56d041a486784e54104a81aebe0da44bd03019bd70bc0401e42e4a97 AS build
ARG TARGETARCH
ARG BUILDARCH
# A C cross-compiler for the target, for the parts of SQLite and ring written in C.
RUN set -eu; \
    case "$TARGETARCH" in \
      amd64) triple=x86_64-unknown-linux-gnu; cross="gcc-x86-64-linux-gnu libc6-dev-amd64-cross" ;; \
      arm64) triple=aarch64-unknown-linux-gnu; cross="gcc-aarch64-linux-gnu libc6-dev-arm64-cross" ;; \
      *) echo "unsupported architecture: $TARGETARCH" >&2; exit 1 ;; \
    esac; \
    if [ "$TARGETARCH" != "$BUILDARCH" ]; then \
      apt-get update && apt-get install -y --no-install-recommends $cross && rm -rf /var/lib/apt/lists/*; \
    fi; \
    rustup target add "$triple"; \
    echo "$triple" > /triple
ENV CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc \
    CC_aarch64_unknown_linux_gnu=aarch64-linux-gnu-gcc \
    CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=x86_64-linux-gnu-gcc \
    CC_x86_64_unknown_linux_gnu=x86_64-linux-gnu-gcc
WORKDIR /src
COPY migrations migrations
COPY migrations-pg migrations-pg
COPY server/Cargo.toml server/Cargo.lock server/rustfmt.toml server/
COPY server/src server/src
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/server/target,id=brod-target-$TARGETARCH \
    set -eu; \
    if [ "$TARGETARCH" = "$BUILDARCH" ]; then unset CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER CC_x86_64_unknown_linux_gnu CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER CC_aarch64_unknown_linux_gnu; fi; \
    cargo build --release --locked --manifest-path server/Cargo.toml --target "$(cat /triple)"; \
    cp "server/target/$(cat /triple)/release/brod" /brod; \
    mkdir /data

# glibc and libgcc only: no shell, no package manager.
FROM gcr.io/distroless/cc-debian12:nonroot@sha256:9dac0a79194e45a7da0158a9c6da57b217585af0786db3845d1f0ec1a0dd182f
LABEL org.opencontainers.image.title="Brod" \
      org.opencontainers.image.description="The self-hosted cloud your AI agent deploys team tools to, over MCP." \
      org.opencontainers.image.source="https://github.com/brodsh/brod" \
      org.opencontainers.image.licenses="AGPL-3.0-only"
COPY --from=build /brod /usr/local/bin/brod
COPY --from=build --chown=65532:65532 /data /data
ENV BROD_LISTEN=0.0.0.0:8080 \
    BROD_DATA_DIR=/data
VOLUME /data
EXPOSE 8080
USER nonroot
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 CMD ["/usr/local/bin/brod", "healthcheck"]
ENTRYPOINT ["/usr/local/bin/brod"]
