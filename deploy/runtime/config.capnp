# workerd configuration for Brod's server-app runtime (the "runtime" service in docker-compose.yml).
# Run: workerd serve config.capnp --experimental
# Local overrides: -s http=127.0.0.1:8789 -e brod=127.0.0.1:8787 -d data=/tmp/brod-runtime
using Workerd = import "/workerd/workerd.capnp";

const config :Workerd.Config = (
  services = [
    (name = "host", worker = .host),
    # The Rust server, for code, secrets, files and logs. Reached only through the BROD binding.
    (name = "brod", external = (address = "brod:8080", http = ())),
    # Where each app's database (one SQLite Durable Object per app) is kept.
    (name = "data", disk = (path = "/data", writable = true)),
    # Apps' own outgoing fetch: the public internet only, never the private network Brod and the runtime are on.
    (name = "internet", network = (allow = ["public"], deny = ["private", "local"])),
  ],
  sockets = [ (name = "http", address = "0.0.0.0:8081", http = (), service = "host") ],
);

const host :Workerd.Worker = (
  modules = [ (name = "host.js", esModule = embed "host.js") ],
  compatibilityDate = "2025-09-01",
  compatibilityFlags = ["nodejs_compat", "enable_ctx_exports"],
  bindings = [
    (name = "LOADER", workerLoader = (id = "brod-apps")),
    (name = "APP_DATA", durableObjectNamespace = "AppData"),
    (name = "BROD", service = "brod"),
    (name = "BROD_RUNTIME_SECRET", fromEnvironment = "BROD_RUNTIME_SECRET"),
  ],
  durableObjectNamespaces = [ (className = "AppData", uniqueKey = "brod-app-data", enableSql = true) ],
  durableObjectStorage = (localDisk = "data"),
  globalOutbound = "internet",
);
