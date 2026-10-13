// Stands in for the `cloudflare:workers` module in the Node/Vercel bundle (aliased by scripts/build-vercel.mjs).
// src/runtime.ts defines its server-app classes on these bases; off Cloudflare those classes are exported but never
// instantiated, because deploys with server code are refused there.
export class DurableObject<E = unknown> {
  constructor(readonly ctx: unknown, readonly env: E) {}
}
export class WorkerEntrypoint<E = unknown, P = unknown> {
  constructor(readonly ctx: { props: P }, readonly env: E) {}
}
