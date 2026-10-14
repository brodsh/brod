# Roadmap

What Brod does not do yet, and what was left out on purpose. Nothing here has a date. If one of these matters to you,
say so in an issue: it helps decide the order.

## Left out of 0.1 on purpose

| Item | Why it is not here |
| --- | --- |
| Company sign-in: SAML, OIDC with your identity provider, SCIM | Large, and every provider differs. Email links and Google work today. |
| LDAP | Same as above. |
| Helm chart and Kubernetes manifests | Brod is one binary and a database; Compose covers one machine well. |
| Several Brod servers behind a load balancer | Analytics and visit counts are buffered in memory, and custom-domain certificates live on one disk. |
| A backup page in the admin UI | `pg_dump` and two volume copies do the job ([backups](deploy-production.md#backups)). |

## Isolation and security

- **Process-level isolation for server apps**: several workerd processes, so one app in a loop does not hold the
  others for `RUNTIME_STALL_MS`, and real per-request CPU limits.
- **Separate data for staging**: today staging shares the live app's database, files and secrets.
- **`APPS_DOMAIN` on the Public Suffix List** (for brod.sh), and documentation for operators who want the same, so
  browsers treat each workspace as its own site.
- **A default `frame-ancestors` policy** on app pages.
- **Self-hosted fonts** for Brod's own pages, so no request goes to Google.
- **`BROD_NETWORK=enforce` by default**, once apps commonly declare their hosts.
- **Blocking paths by app role**, for example `/admin` only for an app's editors.

## Running Brod

- Structured logs (`tracing`) with a JSON option.
- Clean-up of old versions, which count toward storage until someone deletes them.
- Re-checking custom domains' DNS records after they are verified, and wildcard certificates with DNS-01.
- An operator page for reports, takedowns and suspensions (today: the `/v1/admin` API).

## Building apps

- Python and container apps. Server code is JavaScript and WebAssembly today.
- Scheduled jobs, background queues, sending email from an app, WebSockets.
- Deploying from a GitHub repository.
- MCP tools for the marketplace.

## Hosted service only

- Usage-based billing and tax handling.
- An appeal flow for takedowns, and email to the owner when one happens.
