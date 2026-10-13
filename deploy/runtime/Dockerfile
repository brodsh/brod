# Brod's server-app runtime: workerd (the open-source Workers runtime) running deploy/runtime/host.js, under the
# supervisor in deploy/runtime/supervisor/, which restarts it when an app stalls it or runs it out of memory.
# Build from the repository root:
#   docker build -f deploy/runtime/Dockerfile -t brod-runtime .

# workerd ships as an npm package with a prebuilt binary per platform. Keep this in step with package-lock.json.
FROM node:22-bookworm-slim AS fetch
ARG WORKERD_VERSION=1.20261006.1
WORKDIR /w
RUN npm install --no-save workerd@${WORKERD_VERSION} \
 && cp "$(find /w/node_modules/@cloudflare -path '*workerd-linux-*/bin/workerd' | head -n1)" /workerd \
 && /workerd --version \
 && mkdir /data

# The supervisor: one small binary, std and libc only.
FROM rust:1.97-bookworm AS supervisor
WORKDIR /src
COPY deploy/runtime/supervisor/Cargo.toml deploy/runtime/supervisor/Cargo.lock ./
COPY deploy/runtime/supervisor/src src
RUN cargo build --release --locked && cp target/release/brod-runtime /brod-runtime

# workerd needs only glibc; distroless also brings the CA certificates apps need for outgoing HTTPS.
FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=fetch /workerd /usr/local/bin/workerd
COPY --from=supervisor /brod-runtime /usr/local/bin/brod-runtime
COPY --from=fetch --chown=65532:65532 /data /data
COPY deploy/runtime/config.capnp deploy/runtime/host.js /etc/brod-runtime/
VOLUME /data
EXPOSE 8081
USER nonroot
# BROD_RUNTIME_SECRET must be set; Brod is expected at brod:8080 (override workerd's with -e brod=<host:port>, and the
# supervisor's with BROD_INTERNAL_URL). RUNTIME_STALL_MS and RUNTIME_MEMORY_MB tune when workerd is restarted.
ENTRYPOINT ["/usr/local/bin/brod-runtime", "/usr/local/bin/workerd", "serve", "/etc/brod-runtime/config.capnp", "--experimental"]
