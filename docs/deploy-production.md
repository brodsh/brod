# Running Brod in production

The [quickstart](../README.md#quickstart) runs Brod on `http://localhost:8080` for one machine. For a team, Brod needs a
name, HTTPS, email and backups. This page covers each.

- [What you need](#what-you-need)
- [DNS](#dns)
- [HTTPS](#https): [Caddy](#with-caddy-recommended), [nginx](#with-nginx), [Brod's own](#with-brods-own-https)
- [Email](#email)
- [Backups](#backups)
- [Upgrades](#upgrades)
- [Resources](#resources)
- [Monitoring](#monitoring)

## What you need

- A Linux server with Docker Engine and the Compose plugin. amd64 and arm64 both work.
- Ports 80 and 443 open to the people who will use Brod.
- A domain you control, for example `example.com`.
- An SMTP server or a [Resend](https://resend.com) account, so sign-in links and invitations reach people's inboxes.

## DNS

Brod needs two names: one for itself and one, with a wildcard, for apps. In these examples:

| Name | Points at | Serves |
| --- | --- | --- |
| `brod.example.com` | the server (A, and AAAA for IPv6) | sign-in, the admin pages, MCP, the API |
| `*.apps.example.com` | the server | apps, at `<app>.<workspace>.apps.example.com` |

A wildcard record covers every depth, so `*.apps.example.com` also answers for `rota.default.apps.example.com`. If the
zone is on Cloudflare, set both records to **DNS only**: Cloudflare's proxy certificate covers one level only.

You can also put apps under Brod's own name (`APPS_DOMAIN=brod.example.com`, with a wildcard record
`*.brod.example.com`). Apps are then at `<app>.<workspace>.brod.example.com`.

## HTTPS

Brod sets its cookies with the `__Host-` prefix and the `Secure` flag when its address is `https://`. That keeps an
app from reading or planting the sign-in cookie. Run it behind HTTPS before anyone else uses it.

Start from the same `.env` as the quickstart, and set:

```sh
BROD_ADMIN_EMAIL=you@example.com
BROD_PUBLIC_URL=https://brod.example.com
APPS_DOMAIN=apps.example.com
```

### With Caddy (recommended)

Caddy gets a certificate for `brod.example.com`, and one for each app's host on its first visit. Before it asks for a
certificate, Caddy checks with Brod that the app exists, so nobody can make it request certificates for made-up names.

Add to `.env`:

```sh
BROD_API_HOST=brod.example.com
ACME_EMAIL=you@example.com
```

Start Brod with the Caddy file layered on:

```sh
docker compose -f docker-compose.yml -f deploy/compose.caddy.yml up -d
docker compose logs brod
```

`deploy/compose.caddy.yml` takes Brod off `127.0.0.1:8080`, so only Caddy reaches it, and sets `BROD_TRUST_PROXY=1`.
Custom domains that workspaces add (`set_domain`) get certificates the same way, once Brod has verified them.

### With nginx

nginx cannot get certificates on demand, so it needs certificates that cover every app host. App hosts are two levels
below `APPS_DOMAIN` (`<app>.<workspace>.apps.example.com`), and a wildcard certificate covers one level. You need one
wildcard certificate per workspace (`*.default.apps.example.com`), from a DNS-01 challenge (for example certbot with
your DNS provider's plugin). Use Caddy unless you already run nginx.

Set `BROD_TRUST_PROXY=1` in `.env`, keep Brod on `127.0.0.1:8080`, and add a site:

```nginx
server {
    listen 80;
    server_name brod.example.com .apps.example.com;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl;
    http2 on;
    server_name brod.example.com .apps.example.com;

    ssl_certificate     /etc/nginx/certs/fullchain.pem;
    ssl_certificate_key /etc/nginx/certs/privkey.pem;

    # Uploads of built apps are up to 25 MB.
    client_max_body_size 30m;

    # Brod's internal endpoints answer only on its internal address; refuse them here as well.
    location ~ ^/_(caddy|runtime)/ { return 404; }

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Host $host;
        proxy_read_timeout 120s;
    }
}
```

`Host` and `X-Forwarded-Proto` matter: Brod picks the app from the host name, and checks that sign-in forms come from
`BROD_PUBLIC_URL`.

### With Brod's own HTTPS

Brod can get Let's Encrypt certificates itself, with no proxy. It uses HTTP-01 challenges, so each host gets its own
certificate on its first visit. Add `ACME_EMAIL` to `.env`, then:

```sh
docker compose -f docker-compose.yml -f deploy/compose.tls.yml up -d
```

Certificates are kept in the `brod-data` volume.

## Email

Without email, a self-hosted Brod prints sign-in links and invitations to its log. That is fine for one person. For a
team, set one of these in `.env`:

```sh
# any SMTP server: smtps:// for TLS (usually port 465), smtp:// for STARTTLS (usually 587)
SMTP_URL=smtps://brod%40example.com:app-password@smtp.example.com:465
EMAIL_FROM=Brod <brod@example.com>
```

```sh
# or Resend
RESEND_API_KEY=re_...
EMAIL_FROM=Brod <brod@example.com>
```

Characters such as `@` in the SMTP user name or password must be percent-encoded (`%40`). The first log line after a
restart says which one Brod uses.

## Backups

Three things hold state. Back up all of them, and keep the copies off the server.

| What | Where | Holds |
| --- | --- | --- |
| The database | the `postgres` service | workspaces, people, apps, versions, access, audit log |
| `brod-data` volume | `/data` in the `brod` container | app files, **`secrets.env`** (without it, stored app secrets cannot be read and every session ends) |
| `runtime-data` volume | `/data` in the `runtime` container | each server app's own SQLite database, key-value store and files |

The `runtime-secret` volume needs no backup: Brod writes it again from `secrets.env` at every start.

Run these from the folder with `docker-compose.yml`. Compose names the volumes after the folder (`brod` here), so
check yours with `docker volume ls`.

```sh
docker compose exec -T postgres pg_dump -U brod -Fc brod > brod-$(date +%F).dump
docker run --rm -v brod_brod-data:/data:ro -v "$PWD":/backup alpine:3.22 tar czf /backup/brod-data-$(date +%F).tgz -C /data .
docker run --rm -v brod_runtime-data:/data:ro -v "$PWD":/backup alpine:3.22 tar czf /backup/runtime-data-$(date +%F).tgz -C /data .
```

The database copy is consistent while Brod runs. The volume copies are consistent for files that are not being written
at that moment; for a fully consistent copy of server apps' data, run `docker compose stop runtime` first and
`docker compose start runtime` after.

To restore onto an empty server (with the same `docker-compose.yml` and `.env`):

```sh
docker volume create brod_brod-data
docker volume create brod_runtime-data
docker run --rm -v brod_brod-data:/data -v "$PWD":/backup:ro alpine:3.22 tar xzf /backup/brod-data-2026-01-31.tgz -C /data
docker run --rm -v brod_runtime-data:/data -v "$PWD":/backup:ro alpine:3.22 tar xzf /backup/runtime-data-2026-01-31.tgz -C /data
docker compose up -d --wait postgres
docker compose exec -T postgres pg_restore -U brod -d brod --clean --if-exists --no-owner < brod-2026-01-31.dump
docker compose up -d
```

## Upgrades

```sh
docker compose pull
docker compose up -d
```

Brod applies new database migrations when it starts and logs one line about them. To review migrations first, set
`BROD_AUTO_MIGRATE=false`: Brod then refuses to start while migrations are waiting, and names them. Back up, then run
`docker compose run --rm brod migrate` and start it again.

`BROD_VERSION` in `.env` pins the image version (`BROD_VERSION=0.1.0`). Without it, Compose runs `latest`. Read the
[changelog](../CHANGELOG.md) before moving to a new minor version.

## Resources

Measured on an idle server with one workspace:

| Container | Memory |
| --- | --- |
| `brod` | about 2 MB, plus about 1 MB per active request |
| `runtime` | about 13 MB, plus what server apps use (capped at `RUNTIME_MEM_LIMIT`, 2 GB by default) |
| `postgres` | about 40 MB |

A server with 1 vCPU and 2 GB of memory is enough for a team using a handful of apps. Server apps share one runtime
process, so give it more memory (and raise `RUNTIME_MEMORY_MB` and `RUNTIME_MEM_LIMIT`) before you add apps with heavy
server code. Disk use is the apps' files (every kept version counts) plus their databases.

## Monitoring

- `GET /healthz` answers `200` when Brod is up. The `brod` image has a Docker health check that uses it.
- `docker compose logs brod` shows start-up, email and errors. `docker compose logs runtime` shows when an app stalled
  or ran the runtime out of memory, and which app was paused for it.
- Each app's own activity and server logs are in the admin page and in `get_logs`.
