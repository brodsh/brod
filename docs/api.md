# REST API

Brod's control plane is a JSON API under `/v1/` on the API host (`BROD_PUBLIC_URL`). Agents usually reach the same
actions through MCP tools at `/mcp`; see [mcp.md](mcp.md). For what the app-side features do, see
[apps.md](apps.md).

The examples use `https://brod.example.com` as the API host.

## Signing requests

- **Agents** send `Authorization: Bearer brod_...`. A token belongs to one workspace. Make one on the workspace's
  connections page (`/w/<workspace>/connections`), with `POST /v1/tokens`, or through OAuth (below).
- **The dashboard** sends the platform session cookie. Every change (any method other than `GET` and `HEAD`) must carry
  an `Origin` equal to `BROD_PUBLIC_URL`, or it is refused with `403 bad_origin`. It picks a workspace with
  `X-Brod-Workspace: <workspace>` or `?workspace=<workspace>` (default: the person's first workspace).
- A **read-only** connection (token scope `read`, or OAuth scope `brod:read`) may only send `GET`. Anything else is
  refused with `read_only`.

```sh
curl -sS -H "Authorization: Bearer $BROD_TOKEN" https://brod.example.com/v1/apps
```

## Errors

An error answers with an HTTP status and a body like this:

```json
{ "error": { "code": "stale_base", "message": "..." } }
```

`code` is stable. `message` is written for a person or an agent to read. Some errors add fields next to them, such as
`retry_after_seconds` on `429 rate_limited`. Common ones:

| Status | Code | When |
| --- | --- | --- |
| 401 | `unauthorized` | No valid token or session |
| 401 | `token_expired` | The token is past its expiry |
| 403 | `bad_origin` | A cookie request changed something without the right `Origin` |
| 403 | `read_only` | A read-only connection tried to change something |
| 404 | `not_found` | No such route, or nothing with that name |
| 409 | `stale_base` | A deploy's `base_version` is no longer the app's current version |
| 429 | `rate_limited` | Too many requests in the window; see `retry_after_seconds` |

## Routes

Routes marked *hosted* exist only with `BROD_MODE=hosted`. Routes marked *marketplace* exist only when the marketplace
is on (`BROD_MARKETPLACE=true`, the default when hosted, off when self-hosted). Elsewhere they answer
`404 not_found`.

### You and your workspace

| Route | |
| --- | --- |
| `GET /v1/me` | The signed-in person and their workspaces. Session cookie only. |
| `POST /v1/workspaces` `{name, accept_terms}` | Create a workspace. Session cookie only. `accept_terms` is needed only when hosted. Self-hosted, only workspace admins can create workspaces. |
| `GET /v1/workspace`, `PATCH /v1/workspace` `{name, color, icon}` | Workspace details and branding |
| `GET /v1/people`, `PATCH /v1/people/:email-or-id` `{role}`, `DELETE /v1/people/:email-or-id` | The people directory. Changing roles and removing people needs an admin. |
| `GET /v1/invites`, `POST /v1/invites` `{email, role, app?, app_role?}`, `DELETE /v1/invites/:id` | Invitations, to the workspace or as a guest to one app |
| `GET /v1/groups`, `POST /v1/groups` `{name}`, `DELETE /v1/groups/:name` | Groups |
| `POST /v1/groups/:name/members` `{email}`, `DELETE /v1/groups/:name/members/:email` | Group members |
| `GET /v1/tokens`, `POST /v1/tokens` `{name, scope?, expires_in_days?}`, `DELETE /v1/tokens/:id` | Agent connections. `scope` is `manage` (the default) or `read`. `expires_in_days` is 1 to 365, or left out for never. |
| `GET /v1/events?app=&action=&limit=` | The workspace's audit log |

### Deploying

| Route | |
| --- | --- |
| `POST /v1/deploys` `{name?, app?, note?, environment?, base_version?, files?}` | Same as `deploy_app`. `name` makes a new app, `app` deploys a new version of one. With `files` (up to 1 MB in all) it deploys at once. Without `files` it answers with a one-time `upload_url` and a `tar \| curl` command. |
| `PUT /v1/uploads/:id` (a tar.gz as the body) | Upload a bundle to an upload address and deploy it. Up to 25 MB. The address is its own credential and lasts 15 minutes. |
| `GET /v1/apps/:slug/files?version=` | Same as `get_files`: a version's files inline, or a `download_url` |
| `GET /v1/downloads/:id` | A version's files as a tar.gz. The address is its own credential and lasts 15 minutes. |

`environment` is `staging` or `production`. `base_version` is the version the files started from. See
[Staging](apps.md#staging) and [Several people on one app](apps.md#several-people-on-one-app).

```sh
# Ask for an upload address, then send the build folder to it.
curl -sS -H "Authorization: Bearer $BROD_TOKEN" -H 'content-type: application/json' \
  -d '{"app":"notes","base_version":3}' https://brod.example.com/v1/deploys
tar -czf - -C dist . | curl -sS -X PUT --data-binary @- "<upload_url>"
```

### Apps

| Route | |
| --- | --- |
| `GET /v1/apps` | Every app, like `list_apps` |
| `GET /v1/apps/:slug` | One app, like `get_status` |
| `PATCH /v1/apps/:slug` `{title, welcome, roles}` | Change an app's title, welcome text or roles |
| `DELETE /v1/apps/:slug` | Delete an app. From an agent, this waits for a person to confirm. |
| `GET /v1/apps/:slug/logs?search=` | Recent activity and, for server apps, the last 50 requests |
| `GET /v1/apps/:slug/secrets` | Secret names (never values) |
| `PUT /v1/apps/:slug/secrets/:NAME` `{value}`, `DELETE /v1/apps/:slug/secrets/:NAME` | Set or remove a secret |
| `GET /v1/apps/:slug/access` | The access mode and who it is shared with (`access`, `shared_with`) |
| `POST /v1/apps/:slug/access` `{access, password?, add?, remove?}` | Change access and role grants. See [Access](apps.md#access). |
| `POST /v1/apps/:slug/rollback` `{version}` | Serve an earlier version |
| `POST /v1/apps/:slug/publish` | Make the staging version live |
| `DELETE /v1/apps/:slug/staging` | Take the version off staging and keep it |
| `POST /v1/apps/:slug/pause`, `POST /v1/apps/:slug/resume` | Pause or resume an app |
| `DELETE /v1/apps/:slug/versions/:n` | Delete an old version. Refused for the live version (`409 live_version`) and the staging version (`409 staging_version`). |
| `POST /v1/apps/:slug/space` `{space}` | Move an app into a space |
| `GET /v1/apps/:slug/usage?days=` | One app's visits and storage |
| `GET /v1/apps/:slug/settings`, `PATCH /v1/apps/:slug/settings` `{key: value}` | Read and change an app's [settings](apps.md#app-settings) |
| `PUT /v1/apps/:slug/settings/:key` (the image as the body), `GET` and `DELETE` on the same route | Upload, view or remove an image setting |

```sh
curl -sS -H "Authorization: Bearer $BROD_TOKEN" -H 'content-type: application/json' \
  -d '{"access":"people","add":[{"email":"bo@acme.test","role":"editor"}]}' \
  https://brod.example.com/v1/apps/notes/access
```

### Domains, spaces, usage and analytics

| Route | |
| --- | --- |
| `GET /v1/domains`, `POST /v1/domains` `{domain, app?}` | List or add [custom domains](apps.md#custom-domains). Without `app`, the domain (`*.apps.example.com`) is for the whole workspace and needs an admin. |
| `POST /v1/domains/:domain/verify`, `DELETE /v1/domains/:domain` | Check the DNS records, or remove a domain |
| `GET /v1/spaces`, `POST /v1/spaces` `{name, note}`, `DELETE /v1/spaces/:name` | Spaces |
| `POST /v1/spaces/:name/members` `{email, role}`, `DELETE /v1/spaces/:name/members/:email` | Space members |
| `GET /v1/usage?days=` | Visits and storage for every app |
| `GET /v1/analytics?days=&app=&tz=` | Analytics for every app, or one. `days` is cut to what the workspace keeps (365 days self-hosted; the plan's allowance when hosted). `tz` is the viewer's offset in minutes east of UTC. |

### Marketplace (*marketplace*)

| Route | |
| --- | --- |
| `GET /v1/marketplace?search=` | Browse listings |
| `GET /v1/marketplace/:listing` | One listing with its releases |
| `GET /v1/marketplace/:listing/media/:id` | One screenshot or screencast |
| `POST /v1/marketplace/:listing/install` `{name?, settings?, accept_network?}` | Install a copy into this workspace |
| `GET /v1/listings`, `POST /v1/listings` `{app, name?, summary, description, version?, note?}` | The workspace's own listings; list an app. People only: an agent gets `people_only`. |
| `PATCH /v1/listings/:listing` `{name, summary, description, status}`, `DELETE /v1/listings/:listing` | Change, unlist (`status`: `listed` or `unlisted`) or delete a listing |
| `POST /v1/listings/:listing/releases` `{note, version?}` | Publish a new release. People only. |
| `POST /v1/listings/:listing/previews` | Take the listing's automatic previews again (needs the preview service) |
| `POST /v1/listings/:listing/media?caption=` (the file as the body), `DELETE /v1/listings/:listing/media/:id` | Add or remove a screenshot or screencast |
| `POST /v1/apps/:slug/marketplace/update` `{release?}` | Deploy a newer release to an installed app |
| `DELETE /v1/apps/:slug/marketplace` | Stop following the listing |

Listings are free only: a price is refused with `paid_not_yet`. Installing or updating to a release that adds outside
hosts needs `accept_network: true` from a person; an agent gets `network_needs_a_person`.

### Billing (*hosted*)

| Route | |
| --- | --- |
| `GET /v1/billing` | Plan, usage and invoices. Admins. |
| `POST /v1/billing/checkout` `{plan}` | Change plan. Answers a Stripe Checkout `url`, or the change. |
| `POST /v1/billing/portal` | A Stripe customer portal `url` |
| `POST /stripe/webhook` | Stripe's signed webhooks (not under `/v1/`) |

A self-hosted server has no plans or billing.

## Other routes on the API host

| Route | |
| --- | --- |
| `POST /mcp` | The MCP endpoint for agents. See [mcp.md](mcp.md). |
| `GET /healthz` | `{ "service": "brod", "ok": true, "mcp": "...", "api": "..." }` |
| `GET /.well-known/oauth-protected-resource`, `GET /.well-known/oauth-protected-resource/mcp` | OAuth resource metadata for MCP clients |
| `GET /.well-known/oauth-authorization-server` | OAuth server metadata |
| `POST /oauth/register` | Dynamic client registration |
| `GET /oauth/authorize`, `POST /oauth/authorize` | The person picks a workspace and approves the agent |
| `POST /oauth/token` | Swap a code for tokens (`grant_type=authorization_code`), or renew them (`grant_type=refresh_token`) |

OAuth needs PKCE with `S256`. Scopes are `brod` (deploy and manage) and `brod:read` (read only). An access token lasts
an hour. Each refresh returns a new refresh token and retires the old one. If a retired refresh token is sent again,
the whole connection is disconnected. A refresh token lapses after 30 days without use.

## The operator's API

The person who runs the Brod server has a small API under `/v1/admin/`. Every call needs
`Authorization: Bearer $ADMIN_SECRET`; without it, or when `ADMIN_SECRET` is empty, the answer is `401 unauthorized`.
Each action is recorded in the workspace's audit log (`GET /v1/events`) as by `Brod operator`.

| Route | |
| --- | --- |
| `GET /v1/admin/reports?status=open\|resolved\|dismissed` | The report queue, newest first, at most 200: visitor reports and the phishing check's `automatic` ones, with each app's workspace and whether it is down |
| `POST /v1/admin/reports/:id` `{status, note?}` | Close a report. `status` is `resolved` (the default) or `dismissed`. |
| `POST /v1/admin/apps/:workspace/:app/takedown` `{reason}` | Take an app down. `reason` is required (`400 need_reason`); the owner sees it. This also resolves the app's open reports. |
| `POST /v1/admin/apps/:workspace/:app/restore` `{note?}` | Bring it back |
| `POST /v1/admin/apps/:workspace/:app/clear` `{note?}` | Clear the phishing check's flag on the app's versions |
| `POST /v1/admin/workspaces/:workspace/suspend` `{reason}` | Suspend a workspace. `reason` is required. |
| `POST /v1/admin/workspaces/:workspace/unsuspend` `{note?}` | Lift a suspension |
| `POST /v1/admin/workspaces/:workspace/trust` `{note?}` | Let a new workspace open apps to everyone before it is a day old |

```sh
A="Authorization: Bearer $ADMIN_SECRET"
curl -sS -H "$A" "https://brod.example.com/v1/admin/reports?status=open"
curl -sS -H "$A" -H 'content-type: application/json' -d '{"reason":"Credential phishing"}' https://brod.example.com/v1/admin/apps/acme/login/takedown
curl -sS -H "$A" -X POST https://brod.example.com/v1/admin/apps/acme/login/restore
curl -sS -H "$A" -H 'content-type: application/json' -d '{"status":"dismissed","note":"Not abuse"}' https://brod.example.com/v1/admin/reports/rep_0123456789abcdef
curl -sS -H "$A" -H 'content-type: application/json' -d '{"reason":"Spam"}' https://brod.example.com/v1/admin/workspaces/acme/suspend
curl -sS -H "$A" -X POST https://brod.example.com/v1/admin/workspaces/acme/trust
```

A taken-down app answers `410` with a neutral "This app has been taken down" page on every address. Its owner cannot
resume, deploy, roll back, delete or widen it until it is restored (`403 taken_down`). A suspended workspace's apps
answer `410` too, and it cannot deploy new ones (`403 workspace_suspended`).

The takedown and suspension routes work in both modes. Visitor reports, the phishing check and `trust` only matter when
`BROD_ABUSE_CHECKS=true` (the default when hosted, off when self-hosted). See [security.md](security.md).
