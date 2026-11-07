# @brodsh/auth

Read the person [Brod](https://github.com/brodsh/brod) signed in, in your app's server code.

Brod signs people in and decides who may open an app before a request reaches it. It then adds the person to the
request as `x-brod-identity`, a JWT signed with Brod's Ed25519 key. This package checks that token (signature, issuer,
audience, expiry) and gives you the person:

```ts
import { currentUser } from '@brodsh/auth';

const user = await currentUser(request);
// { id, email, name, workspace: { id, slug }, role, groups, app, claims } or null
```

It works in Node 20+, Next.js (App Router, including middleware on the edge runtime) and Workers (workerd), with one
dependency, [`jose`](https://github.com/panva/jose).

- [Install](#install)
- [Next.js App Router](#nextjs-app-router)
- [Node: http and Express](#node-http-and-express)
- [Workers (workerd)](#workers-workerd)
- [Your own users table: the 403 pattern](#your-own-users-table-the-403-pattern)
- [App users and tenants](#app-users-and-tenants)
- [Your own login page](#your-own-login-page)
- [API](#api)
- [Local development: BROD_DEV_USER](#local-development-brod_dev_user)
- [Other languages](#other-languages)

## Install

```sh
npm install @brodsh/auth
```

Brod gives every app what verification needs in its environment, so there is nothing to configure:

| Variable | Value |
| --- | --- |
| `BROD_ISSUER` | Brod's public URL: the token's `iss` |
| `BROD_APP_ID` | The app's id: the token's `aud` is `brod:app:<BROD_APP_ID>` |
| `BROD_IDENTITY_JWKS` | Brod's public keys as a JWK set (JSON), so verification needs no network call |

Without `BROD_IDENTITY_JWKS` the keys are fetched from `<BROD_ISSUER>/.well-known/jwks.json` and cached.

## Next.js App Router

Server components, route handlers and server actions read the current request's headers with `@brodsh/auth/next`:

```tsx
// app/page.tsx
import { currentUserFromHeaders } from '@brodsh/auth/next';

export default async function Page() {
  const user = await currentUserFromHeaders();
  return <p>Hello {user?.name ?? 'stranger'}</p>;
}
```

```ts
// app/api/notes/route.ts
import { BrodAuthError } from '@brodsh/auth';
import { requireUserFromHeaders } from '@brodsh/auth/next';

export async function GET() {
  try {
    const user = await requireUserFromHeaders(); // throws a 401 BrodAuthError when nobody is signed in
    return Response.json(await notesOf(user.id));
  } catch (e) {
    if (e instanceof BrodAuthError) return Response.json({ error: e.code }, { status: e.status });
    throw e;
  }
}
```

A route handler can also pass its `Request`: `await currentUser(request)` from `@brodsh/auth`.

Middleware gets the request itself. Brod has already decided who may open the app, so use middleware for checks of
your own, such as a role:

```ts
// middleware.ts (proxy.ts, with the function named proxy, in Next.js 16)
import { NextResponse, type NextRequest } from 'next/server';
import { currentUser } from '@brodsh/auth';

export async function middleware(request: NextRequest) {
  const user = await currentUser(request).catch(() => null); // an invalid token counts as nobody here
  if (request.nextUrl.pathname.startsWith('/admin') && user?.role !== 'admin') {
    return new NextResponse('Admins only', { status: 403 });
  }
  return NextResponse.next();
}

export const config = { matcher: ['/((?!_next/static|_next/image|favicon.ico).*)'] };
```

`@brodsh/auth` uses only Web APIs, so this runs on the edge runtime as well as on Node. Middleware reads
`process.env` at request time when you run `next start` (a container on Brod); in other hosts, pass the values as
options.

## Node: http and Express

`currentUser` takes anything with `headers`: a Node `IncomingMessage`, an Express or Fastify request, a `Request`, a
`Headers`, or the token string.

```js
import http from 'node:http';
import { currentUser } from '@brodsh/auth';

http.createServer(async (req, res) => {
  try {
    const user = await currentUser(req);
    res.end(`Hello ${user?.name ?? 'stranger'}`);
  } catch (e) {
    res.writeHead(e.status ?? 500).end(e.code ?? 'error'); // a token that does not verify: 401
  }
}).listen(process.env.PORT ?? 3000);
```

```js
import express from 'express';
import { requireUser } from '@brodsh/auth';

const app = express();

// Every route below needs a signed-in person.
app.use(async (req, res, next) => {
  try {
    req.user = await requireUser(req);
    next();
  } catch (e) {
    res.status(e.status ?? 500).json({ error: e.code ?? 'error' });
  }
});

app.get('/api/me', (req, res) => res.json(req.user));
app.listen(process.env.PORT ?? 3000);
```

CommonJS works too: `const { currentUser } = require('@brodsh/auth')`.

## Workers (workerd)

A Brod server app (`_worker.js`) has no `process.env`: pass the Worker's `env`.

```js
import { currentUser } from '@brodsh/auth';

export default {
  async fetch(request, env) {
    const user = await currentUser(request, { env });
    return Response.json({ hello: user?.name ?? 'stranger' });
  },
};
```

Brod runs `_worker.js` as one file, so bundle it:
`npx esbuild src/worker.js --bundle --format=esm --outfile=_worker.js`.

Inside a Brod server app the gateway is the only way in and replaces any `x-brod-*` header a visitor sends, so the
plain `x-brod-user-email` and `x-brod-role` headers can be trusted too. Verify the token when identity must hold
beyond that, for example when you pass it on to another service.

## Your own users table: the 403 pattern

Brod decides who may open the app. Your app may still keep its own users, with data Brod does not know about (an
employee record, a disabled flag, an app-specific role). Map the Brod person to your row, and answer **403** when
there is none:

```ts
// lib/user.ts
import { requireUser } from '@brodsh/auth';

/** Your row for the signed-in person, or null when this app has none for them. */
export async function appUser(request: Request) {
  const brod = await requireUser(request); // throws a 401 BrodAuthError: nobody signed in, or a bad token
  // Match on the stable Brod id; the first time, find the row by email and remember the id.
  const known = await db.user.findUnique({ where: { brodId: brod.id } });
  if (known) return known.disabled ? null : known;
  const byEmail = await db.user.findUnique({ where: { email: brod.email.toLowerCase() } });
  if (!byEmail || byEmail.disabled) return null;
  return db.user.update({ where: { id: byEmail.id }, data: { brodId: brod.id } });
}
```

```ts
// app/api/ledger/route.ts
import { BrodAuthError } from '@brodsh/auth';
import { appUser } from '@/lib/user';

export async function GET(request: Request) {
  try {
    const user = await appUser(request);
    if (!user) return Response.json({ error: 'no_account', message: 'Ask an admin to add you to this app.' }, { status: 403 });
    return Response.json(await ledgerFor(user));
  } catch (e) {
    if (e instanceof BrodAuthError) return Response.json({ error: e.code }, { status: e.status });
    throw e;
  }
}
```

401 means "not signed in"; 403 means "signed in, but not allowed here". Never create a row on the fly for anyone who
gets through unless the app is meant to be open to the whole workspace, and never keep passwords: Brod signs people
in.

## App users and tenants

A person's grant on an app can carry filters besides a role, such as a tenant. Brod passes them on; your code applies them:

```ts
import { filterValues, requireUser } from '@brodsh/auth';

const user = await requireUser(request);
const [tenant] = filterValues(user, 'tenant'); // user.filters is { tenant: 'acme' }
if (!tenant) return new Response('No access', { status: 403 });
const rows = await env.DB.query('SELECT * FROM jobs WHERE tenant = ?', [tenant]);
```

See [App users and filters](https://github.com/brodsh/brod/blob/main/docs/apps.md#app-users-and-filters).

## Your own login page

Build the page in your app's design. Brod sends the code, checks it and sets the session, so your code never handles
a password or a session token. Name the page in `brod.json` as an open path with `"sign_in_page": true`, along with the
files it loads, and pass on the `confirm_url` from the deploy. See
[the docs](https://github.com/brodsh/brod/blob/main/docs/apps.md#your-own-login-page).

```ts
import { methods, sendCode, verifyCode, google, signOut, BrodSignInError } from '@brodsh/auth/client';

const how = await methods(); // { email, google, app: { name }, return }
await sendCode(email);
try {
  const r = await verifyCode(email, code);
  if (r.allowed) location.href = r.return;
  else showNoAccess();
} catch (e) {
  if (e instanceof BrodSignInError) showError(e.message); // e.code: bad_code, rate_limited, ...
}
```

`@brodsh/auth/client` runs in the browser and has no dependencies. Without a bundler, `<script src="/_brod/client.js">`
gives the same functions as `Brod.auth`.

## API

### `currentUser(input, options?) => Promise<BrodUser | null>`

The person, or `null` when the request has no `x-brod-identity` header: an open path (a webhook), or a public app
with nobody signed in. Treat those requests as anonymous.

When a token is present but does not verify it **throws** a `BrodAuthError`. Do not treat that as anonymous.

`input` is a `Request`, a `Headers`, a header record, anything with a `headers` property, or the token string.

### `requireUser(input, options?) => Promise<BrodUser>`

Like `currentUser`, but throws a `BrodAuthError` with `code: 'unauthenticated'` and `status: 401` when there is no
token.

### `verifyIdentityToken(token, options?) => Promise<BrodUser>`

Verifies one token. Only `EdDSA` is accepted; the key is picked by the token's `kid`.

### `BrodUser`

| Field | |
| --- | --- |
| `id` | Brod's user id (`sub`). Stable: store it. |
| `email`, `name` | The person |
| `workspace` | `{ id, slug }` |
| `role` | Their role in this app, or `null` when the app gives them none (a public app) |
| `groups` | Their workspace groups |
| `app` | The app id the token was made for |
| `claims` | The verified claims as they came (`iss`, `aud`, `iat`, `exp`, `jti`, ...) |

### Options

| Option | Default |
| --- | --- |
| `issuer` | `BROD_ISSUER` |
| `appId` | `BROD_APP_ID` |
| `audience` | `brod:app:<appId>` |
| `jwks` | `BROD_IDENTITY_JWKS`. A JWK set object, its JSON text, or a `jose` key resolver. |
| `jwksUrl` | `<issuer>/.well-known/jwks.json`, used when there is no inline key set. Fetched once and cached; fetched again when a token names an unknown key. |
| `clockTolerance` | `30` seconds |
| `env` | `process.env`. Where the variables above are read; pass the Worker's `env` on workerd. |

### `BrodAuthError`

`code` is one of `unauthenticated`, `invalid_token`, `bad_signature`, `unknown_key`, `alg_not_allowed`, `expired`,
`not_yet_valid`, `wrong_issuer`, `wrong_audience`, `invalid_claims` (all `status` 401), `jwks_unavailable` (503: the
key set could not be fetched) and `misconfigured` (500: no issuer or app id, or an unreadable key set). Answer with
`e.status`.

## Local development: BROD_DEV_USER

Outside Brod there is no gateway and no token. Set `BROD_DEV_USER` and requests without a token get that person:

```sh
BROD_DEV_USER=me@example.com npm run dev
BROD_DEV_USER='{"email":"me@example.com","name":"Me","role":"admin","groups":["finance"]}' npm run dev
```

The default role is `owner`. The dev person's `claims.brod_dev` is `true`.

It only applies when `NODE_ENV` is not `production`, and only when the request has no token: a token is always
verified, and one that fails still throws. Brod never sets `BROD_DEV_USER`.

## Other languages

The token is a standard JWT; any JWT library that supports EdDSA verifies it. See
[Verifying the identity token](https://github.com/brodsh/brod/blob/main/docs/apps.md#verifying-the-identity-token)
for recipes in Python (PyJWT), Go (golang-jwt) and Rust (jsonwebtoken).

## License

MIT
