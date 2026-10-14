# MCP

Brod is an MCP server. Any agent that speaks MCP over HTTP can deploy and manage apps in a workspace. The endpoint is
`<BROD_PUBLIC_URL>/mcp`, for example `http://localhost:8080/mcp`.

- [Connect an agent](#connect-an-agent)
- [Tools](#tools)
- [A worked example](#a-worked-example)
- [What needs a person](#what-needs-a-person)
- [Tokens and OAuth](#tokens-and-oauth)

## Connect an agent

Make a token first: open `<BROD_PUBLIC_URL>/w/<workspace>/connections` and press **Make a token**. It starts with
`brod_` and is shown once. The first sign-in link Brod prints opens this page for you.

In the examples below, replace `brod_...` with the token and `http://localhost:8080` with your `BROD_PUBLIC_URL`.

### Claude Code

```sh
claude mcp add --transport http brod http://localhost:8080/mcp --header "Authorization: Bearer brod_..."
```

Without `--header`, Claude Code signs in with OAuth instead. Run `/mcp` in Claude Code and pick the workspace in the
browser.

### Claude Desktop

Claude Desktop's config file starts local servers, so it reaches Brod through
[mcp-remote](https://www.npmjs.com/package/mcp-remote), which needs Node.js. Open **Settings → Developer → Edit
Config** and add:

```json
{
  "mcpServers": {
    "brod": {
      "command": "npx",
      "args": ["-y", "mcp-remote@0.14.3", "http://localhost:8080/mcp", "--header", "Authorization:Bearer ${BROD_TOKEN}"],
      "env": { "BROD_TOKEN": "brod_..." }
    }
  }
}
```

Restart Claude Desktop. If Brod has a public HTTPS address, you can add it under **Settings → Connectors → Add custom
connector** instead, and sign in with OAuth.

### Cursor

Add to `~/.cursor/mcp.json` (or `.cursor/mcp.json` in a project):

```json
{
  "mcpServers": {
    "brod": {
      "url": "http://localhost:8080/mcp",
      "headers": { "Authorization": "Bearer brod_..." }
    }
  }
}
```

### Anything else

Use the Streamable HTTP transport at `/mcp` with the header `Authorization: Bearer brod_...`, or OAuth 2.1 (see
[Tokens and OAuth](#tokens-and-oauth)).

## Tools

| Tool | What it does |
| --- | --- |
| `deploy_app` | Deploy a new app or a new version: files inline (up to 1 MB), or a one-time upload address for a bigger build. Returns the address. |
| `list_apps` | The workspace's apps: address, status, who can open each, live version. |
| `get_files` | The files of an app's current version (or a named one), to change them. |
| `get_status` | One app: access, roles, who it is shared with, versions, what is on staging, custom domains, secret names. |
| `get_logs` | An app's activity (deploys, access changes, refusals) and, for server apps, recent requests with console output and errors. |
| `set_secret` | Store or remove an encrypted secret the app's server code reads as `env.NAME`. Values cannot be read back. |
| `publish_staging` | Make the version on staging live, or discard it. |
| `rollback` | Serve an earlier version. Takes effect on the next request. |
| `set_access` | Change who can open an app: `private`, `people`, `workspace`, `password`, `signed_in` or `public`, and grants by person, group or email domain. |
| `set_paused` | Pause or resume an app. |
| `invite` | Invite someone into the workspace, or as a guest to one app. |
| `set_domain` | Serve an app (or every app, with `*.`) at a custom domain, and check its DNS records. |
| `get_workspace` | The workspace's groups, default roles and access modes, and how an app reads the signed-in person. |

A read-only connection (OAuth scope `brod:read`, or a token made read-only) sees only `list_apps`, `get_files`,
`get_status`, `get_logs` and `get_workspace`.

The server also sends instructions with `initialize`. They tell the agent to ask before changing a live app, to deploy
updates to staging first, and to pass `base_version` so it never overwrites someone else's work.

## A worked example

What follows is one conversation with real results from a Brod server, shortened only where marked `…`.

**You:** Put our on-call rota online. It needs to call PagerDuty, so store the key too.

The agent writes the app and calls `deploy_app`:

```json
{ "name": "On-call rota", "files": [
    { "path": "index.html", "content": "<h1>On-call rota</h1>" },
    { "path": "_worker.js", "content": "export default { async fetch(r, env) { return Response.json({ pager: Boolean(env.PAGER_KEY) }); } }" } ] }
```

```json
{
  "app": "on-call-rota",
  "url": "http://on-call-rota.default.localhost:8080",
  "status": "live",
  "access": "private",
  "who_can_open": "Only you (the owner) and workspace admins can open it.",
  "version": 1,
  "kind": "server",
  …
}
```

Then `set_secret` with `{ "app": "on-call-rota", "name": "PAGER_KEY", "value": "…" }`:

```json
{
  "app": "on-call-rota",
  "secret": "PAGER_KEY",
  "set": true,
  "note": "The value is stored encrypted and is never shown again. The app sees it as env.PAGER_KEY from its next request.",
  …
}
```

**You:** Add next week to it.

The app is live, so the agent asks whether to try the change on staging first. You say yes. It deploys with
`{ "app": "on-call-rota", "base_version": 1, "note": "Add next week", "files": [ … ] }`:

```json
{
  "app": "on-call-rota",
  "version": 2,
  "environment": "staging",
  "staging": { "version": 2, "url": "http://on-call-rota--staging.default.localhost:8080" },
  "live_version": 1,
  "next_step": "v2 is on staging, not live: visitors still get v1. Give the person the staging address http://on-call-rota--staging.default.localhost:8080 to try it (only the app's builders can open it). When they say it is ready, call publish_staging to make v2 live."
}
```

**You:** Looks good, publish it. And let Bo see it.

`publish_staging` with `{ "app": "on-call-rota" }` returns `{ "live_version": 2, "staging": null, … }`. Then `invite`
with `{ "email": "bo@acme.test", "app": "on-call-rota", "app_role": "viewer" }`:

```json
{
  "needs_confirmation": true,
  "summary": "Invite bo@acme.test to on-call-rota as viewer",
  "confirm_url": "http://localhost:8080/confirm/cf_…",
  "message": "Nothing has changed yet. Invite bo@acme.test to on-call-rota as viewer needs the owner's confirmation: give them this link to open and confirm. It expires in 24 hours."
}
```

The agent gives you the link. You open it and confirm, and Bo gets an invitation email (or, with no email set up, the
invitation link appears in Brod's log).

**You:** The new version breaks on Mondays. Go back.

`rollback` with `{ "app": "on-call-rota", "version": 1 }` returns `{ "live_version": 1, "status": "live", … }`. The
next request gets version 1. Nothing is rebuilt.

## What needs a person

An agent can deploy, roll back, pause, read logs and narrow access on its own. Three kinds of change wait for a person
to open a `confirm_url` and confirm:

- widening access: a more open mode, new grants, or a new password;
- inviting someone;
- deleting an app (REST only; there is no MCP tool for it).

The link expires after 24 hours. Until it is confirmed, nothing changes.

## Tokens and OAuth

**Tokens.** Made on the connections page, or with `POST /v1/tokens`. They act with the role of the person who made
them, in one workspace. They can be read-only. On the connections page a token expires after 30 days unless you pick
another period or "never"; through the API it expires only if you give `expires_in_days`. Brod stores only their
SHA-256 hash. The connections page lists every connection with when it was last used, and disconnects one at a
time.

**OAuth 2.1.** For clients that sign in in a browser. Brod publishes its metadata at
`/.well-known/oauth-authorization-server` and `/.well-known/oauth-protected-resource`, and supports dynamic client
registration, PKCE (S256 only) and refresh tokens. The person picks the workspace on the consent page. Access tokens
last one hour. Refresh tokens rotate on every use, and reusing an old one disconnects the client. The scope
`brod:read` makes a read-only connection.

A request without a valid token gets `401` with a `WWW-Authenticate` header that points the client at the metadata, as
the MCP specification describes.
