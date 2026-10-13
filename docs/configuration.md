# Configuration

Brod reads its settings from environment variables, and from a `.env` file in its working directory. With Docker
Compose, put them in `.env` next to `docker-compose.yml`. Start from [`.env.example`](../.env.example).

A self-hosted Brod needs only `BROD_ADMIN_EMAIL`. Everything else has a working default. A hosted Brod
(`BROD_MODE=hosted`) must also set `BROD_PUBLIC_URL`, `APPS_DOMAIN` and every secret.

This page is generated from `.env.example` by `node scripts/config-docs.mjs`. Edit that file, not this one.

## Start here

| Variable | Example or default | What it does |
| --- | --- | --- |
| `BROD_ADMIN_EMAIL` | `you@example.com` | The first admin: on an empty database, Brod makes them admin of a "Default" workspace and logs a one-time sign-in link. |
| `BROD_PUBLIC_URL` | `http://localhost:8080` | Where people and agents reach Brod. Apps get addresses under the same host: http://&lt;app&gt;.&lt;workspace&gt;.localhost:8080. |

## Addresses

| Variable | Example or default | What it does |
| --- | --- | --- |
| `APPS_DOMAIN` | `apps.example.com` | The host apps are served under, when it is not BROD_PUBLIC_URL's host. Needs a wildcard DNS record. |
| `BROD_LISTEN` | `0.0.0.0:8080` | The address Brod listens on inside its container. |
| `BROD_TRUST_PROXY` | `0` | 1 behind a proxy you control (Caddy, nginx): take the scheme and client address from X-Forwarded-* headers. |
| `API_ORIGIN` |  | The older name of BROD_PUBLIC_URL, still read when BROD_PUBLIC_URL is not set. |

## Secrets

| Variable | Example or default | What it does |
| --- | --- | --- |
| `ADMIN_SECRET` |  | The bearer token for the operator API (/v1/admin). Generated into &lt;BROD_DATA_DIR&gt;/secrets.env on first start if not set. |
| `IDENTITY_SECRET` |  | Keys the identity tokens apps receive, password-app cookies and visitor counts. Generated on first start if not set. |
| `SECRETS_KEY` |  | Encrypts app secrets at rest; changing it makes stored app secrets unreadable. Generated on first start if not set. |
| `BROD_RUNTIME_SECRET` |  | Shared with the runtime sidecar. Generated on first start if not set. |
| `BROD_RUNTIME_SECRET_FILE` |  | Where Brod writes BROD_RUNTIME_SECRET for the runtime to read. Default: &lt;BROD_DATA_DIR&gt;/runtime-secret. Compose sets this. |

## Data

| Variable | Example or default | What it does |
| --- | --- | --- |
| `BROD_DATA_DIR` | `data` | Brod's own folder: the SQLite database (without BROD_DATABASE_URL), app files and generated secrets. |
| `BROD_DATABASE_URL` | `postgres://brod:password@postgres:5432/brod` | Keep Brod's database in Postgres instead of SQLite. Compose sets this for you. |
| `BROD_AUTO_MIGRATE` | `true` | Apply new database migrations at start. false: refuse to start until `brod migrate` has run. |
| `BROD_DB_CONNECTIONS` | `8` | How many database connections Brod keeps open. |
| `FILES_DIR` |  | Keep app files in this folder instead of &lt;BROD_DATA_DIR&gt;/files. |
| `S3_ENDPOINT` | `https://s3.eu-central-1.amazonaws.com` | Keep app files in an S3-compatible bucket (AWS S3, Cloudflare R2, MinIO) instead: its endpoint. Set all four S3_* or none. |
| `S3_BUCKET` | `brod-bundles` | The bucket for app files. |
| `S3_ACCESS_KEY_ID` |  | The bucket's access key id. |
| `S3_SECRET_ACCESS_KEY` |  | The bucket's secret access key. |
| `S3_REGION` | `auto` | The bucket's region; "auto" works for R2. |
| `S3_VIRTUAL_HOSTED` | `0` | 1 to address the bucket as &lt;bucket&gt;.&lt;endpoint host&gt;, for services that need it. |

## Email

| Variable | Example or default | What it does |
| --- | --- | --- |
| `SMTP_URL` | `smtps://user:password@smtp.example.com:465` | Send sign-in links and invitations through this SMTP server (smtps:// for TLS, smtp:// for STARTTLS). |
| `RESEND_API_KEY` |  | Send them through Resend (https://resend.com) instead. With neither, a self-hosted Brod prints each email to its log. |
| `EMAIL_FROM` | `Brod <brod@example.com>` | The sender address. Required with SMTP_URL or RESEND_API_KEY. |
| `GOOGLE_CLIENT_ID` |  | Offer "Continue with Google" on the sign-in page. Redirect URI: &lt;BROD_PUBLIC_URL&gt;/auth/google/callback. |
| `GOOGLE_CLIENT_SECRET` |  | The Google OAuth client's secret. |

## Server apps

| Variable | Example or default | What it does |
| --- | --- | --- |
| `BROD_RUNTIME_URL` | `http://runtime:8081` | Where Brod reaches the runtime sidecar that runs apps' server code. Unset: static apps only. Compose sets this. |
| `RUNTIME_STALL_MS` | `5000` | Runtime container: restart workerd when it has not answered for this many milliseconds (an app stuck in a loop). |
| `RUNTIME_MEMORY_MB` | `1536` | Runtime container: restart workerd when it uses more memory than this, in MB. |
| `RUNTIME_MEM_LIMIT` | `2g` | Runtime container: the hard memory ceiling Docker enforces. Keep it above RUNTIME_MEMORY_MB. |
| `BROD_NETWORK` | `log` | Where apps may send data: log (record undeclared hosts), enforce (refuse them) or off. |
| `BROD_VERSION` | `latest` | The image version Compose runs. |

## HTTPS with Caddy

| Variable | Example or default | What it does |
| --- | --- | --- |
| `BROD_API_HOST` | `brod.example.com` | BROD_PUBLIC_URL's host, for Caddy's certificate (docker compose -f docker-compose.yml -f deploy/compose.caddy.yml). |

## HTTPS without a proxy

| Variable | Example or default | What it does |
| --- | --- | --- |
| `BROD_TLS` | `acme` | Serve HTTPS from Brod itself: acme (Let's Encrypt or ACME_DIRECTORY) or local (a test CA). Needs an https BROD_PUBLIC_URL. |
| `ACME_EMAIL` | `you@example.com` | The email address Let's Encrypt (or Caddy) sends certificate expiry notices to. |
| `ACME_DIRECTORY` | `https://acme-v02.api.letsencrypt.org/directory` | Another ACME certificate authority's directory URL. |
| `ACME_CA_ROOT` |  | A root certificate (PEM file) to trust for that authority, for test CAs. |
| `BROD_HTTPS_LISTEN` | `0.0.0.0:443` | Where Brod listens for HTTPS when BROD_TLS is set. |
| `BROD_HTTP_LISTEN` | `0.0.0.0:80` | Where Brod listens for plain HTTP (redirects and ACME challenges) when BROD_TLS is set. |

## Custom domains

| Variable | Example or default | What it does |
| --- | --- | --- |
| `DNS_RESOLVER_URL` | `https://cloudflare-dns.com/dns-query` | The DNS-over-HTTPS resolver that checks a custom domain's TXT record. Default: Cloudflare's. |
| `CUSTOM_DOMAIN_TARGET` |  | The name custom domains point their CNAME at. Default: BROD_PUBLIC_URL's host. |

## Features

| Variable | Example or default | What it does |
| --- | --- | --- |
| `BROD_MODE` | `self-hosted` | self-hosted (one organisation's Brod) or hosted (a public service with plans and billing, such as brod.sh). |
| `BROD_MARKETPLACE` | `false` | The app marketplace shared by the workspaces on this server. Default: off self-hosted, on hosted. |
| `BROD_ABUSE_CHECKS` | `false` | Phishing scan at deploy, a "Report" link on public apps, a one-day hold on new free workspaces. Default: off self-hosted, on hosted. |
| `BROD_PREVIEW_URL` | `http://preview:8790` | Where Brod reaches the preview sidecar that screenshots marketplace listings (deploy/compose.preview.yml). |
| `BROD_PREVIEW_SECRET` |  | Shared with the preview sidecar; at least 16 random characters. |

## Hosted only

| Variable | Example or default | What it does |
| --- | --- | --- |
| `STRIPE_SECRET_KEY` |  | Stripe secret key, for billing (BROD_MODE=hosted). Webhook endpoint: &lt;BROD_PUBLIC_URL&gt;/stripe/webhook. |
| `STRIPE_WEBHOOK_SECRET` |  | The signing secret of that Stripe webhook endpoint. |
| `STRIPE_PRICE_SOLO` |  | The Stripe price id of the Solo plan. |
| `STRIPE_PRICE_TEAM` |  | The Stripe price id of the Team plan. |
| `BROD_GA_ID` |  | A Google Analytics 4 measurement ID for the hosted landing page. Unset: no Google tag anywhere. |

## Development and tests only

| Variable | Example or default | What it does |
| --- | --- | --- |
| `DEV_MODE` | `0` | Never on a reachable server: returns sign-in links in API responses. |
| `DEV_FREE_STORAGE_MB` |  | With DEV_MODE: a smaller free-plan storage limit in MB, so tests can fill it. |
| `STRIPE_API_BASE` | `https://api.stripe.com` | A stand-in for Stripe's API, for tests. |
| `BROD_TEST_DATABASE_URL` |  | A Postgres database for `cargo test` to run its database tests against. |
