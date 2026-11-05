# syntax=docker/dockerfile:1.7
# SPDX-License-Identifier: AGPL-3.0-only
# brod-node (node/): a machine that runs workloads for Brod. It dials Brod, so it needs no open port. Its own image,
# not a second binary in Brod's, because it runs on machines that have no Brod (a second server, a customer's box) and
# is the only service that gets the Docker socket.
# Build from the repository root:
#   docker build -f deploy/node/Dockerfile -t brod-node .
# The Rust stage runs on the build machine and cross-compiles, so an arm64 image does not need emulation.

FROM --platform=$BUILDPLATFORM rust:1.98-bookworm@sha256:93ce27a88655056a51dbdd8f5f2d7ddc071c7b0070fb288a37b5a285fc83971e AS build
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
    fi; \
    rustup target add "$triple"; \
    echo "$triple" > /triple
# ring is partly C: cross-compiling needs the target's C compiler and linker.
ENV CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc \
    CC_aarch64_unknown_linux_gnu=aarch64-linux-gnu-gcc \
    CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=x86_64-linux-gnu-gcc \
    CC_x86_64_unknown_linux_gnu=x86_64-linux-gnu-gcc
WORKDIR /src
COPY node/Cargo.toml node/Cargo.lock ./
COPY node/src src
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/src/target,id=brod-node-target-$TARGETARCH \
    set -eu; \
    if [ "$TARGETARCH" = "$BUILDARCH" ]; then unset CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER CC_x86_64_unknown_linux_gnu CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER CC_aarch64_unknown_linux_gnu; fi; \
    cargo build --release --locked --target "$(cat /triple)"; \
    cp "target/$(cat /triple)/release/brod-node" /brod-node; \
    mkdir -p /state

# The docker CLI and its buildx plugin: the node builds app images with buildx (node/src/work.rs). Both are static Go
# binaries, copied from the official image.
FROM docker:29-cli@sha256:5e6baf67325a79f64ed3bed6863954d5e05d0f3d4e57cbdb14809346814bbfdb AS docker

# Debian slim rather than distroless: the node runs iptables to keep app containers off private networks and the cloud
# metadata service (node/src/firewall.rs).
FROM debian:bookworm-slim@sha256:99c0b25c46d0214d5a2091092e7908907dcaecd6a962cde0ac700acee222b6f3
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates iptables && rm -rf /var/lib/apt/lists/*
LABEL org.opencontainers.image.title="Brod node" \
      org.opencontainers.image.description="Runs workloads for Brod. Dials Brod; needs no open port." \
      org.opencontainers.image.source="https://github.com/brodsh/brod" \
      org.opencontainers.image.licenses="AGPL-3.0-only"
COPY --from=docker /usr/local/bin/docker /usr/local/bin/docker
COPY --from=docker /usr/local/libexec/docker/cli-plugins/docker-buildx /usr/local/libexec/docker/cli-plugins/docker-buildx
COPY --from=build /brod-node /usr/local/bin/brod-node
COPY --from=build /state /var/lib/brod-node
ENV BROD_NODE_DIR=/var/lib/brod-node
VOLUME /var/lib/brod-node
# Root: the Docker socket it is given is root's, and iptables needs it. App containers never run as root
# (docs/apps.md, Container apps).
USER root
ENTRYPOINT ["/usr/local/bin/brod-node"]
CMD ["run"]
