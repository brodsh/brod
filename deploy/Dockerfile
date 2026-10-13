# The Brod server (Rust). Build from the repository root:
#   docker build -f deploy/Dockerfile -t brod .
# Runs as a non-root user; the SQLite database and app files live in the /data volume.

FROM rust:1.97-bookworm AS build
WORKDIR /src
COPY migrations migrations
COPY migrations-pg migrations-pg
COPY server/Cargo.toml server/Cargo.lock server/rustfmt.toml server/
COPY server/src server/src
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/server/target \
    cargo build --release --locked --manifest-path server/Cargo.toml \
 && cp server/target/release/brod /brod \
 && mkdir /data

# glibc and libgcc only; no shell, no package manager.
FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=build /brod /usr/local/bin/brod
COPY --from=build --chown=65532:65532 /data /data
ENV BROD_LISTEN=0.0.0.0:8080 \
    BROD_DATA_DIR=/data
VOLUME /data
EXPOSE 8080
USER nonroot
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 CMD ["/usr/local/bin/brod", "healthcheck"]
ENTRYPOINT ["/usr/local/bin/brod"]
