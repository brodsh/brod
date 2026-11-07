# Building apps on Brod

This page is for people and agents who build apps on Brod. It covers how people sign in, how an app reads who they
are, server code, staging, working on one app with others, access, custom domains, settings, outside addresses and
limits. Agents do all of this through MCP tools; see [mcp.md](mcp.md). The REST routes are in [api.md](api.md).

Every app lives at `<slug>.<workspace>.<APPS_DOMAIN>`.

- [How sign-in works](#how-sign-in-works)
- [The identity contract](#the-identity-contract)
- [Server apps](#server-apps)
- [Limits for server apps](#limits-for-server-apps)
- [Staging](#staging)
- [Several people on one app](#several-people-on-one-app)
- [Access](#access)
- [Custom domains](#custom-domains)
- [App settings](#app-settings)
- [Outside addresses](#outside-addresses)
- [Limits](#limits)

## How sign-in works

- **People** sign in once, with an emailed link (or Google, if the server has it set up). The platform session cookie
  lives only on the API host (`BROD_PUBLIC_URL`).
- **Apps** never see that cookie. When an app needs a person, the gateway sends them to `/auth/app` on the API host.
  It hands the app's host a one-time code, and the app's host swaps it for its own session cookie. Apps live under
  `APPS_DOMAIN`, a different domain from the API host, so an app cannot read the platform's cookies.
- **Signing out** of any app ends the platform session and every app session made from it. **Removing a person** from
  the workspace ends their access to every app on their next request.
- The emailed link opens a page with a Continue button. Mail scanners that open links do not use them up.
- An app can have [its own login page](#your-own-login-page). Brod still does the work behind it.

### Your own login page

Brod's sign-in page carries the app's icon, name and colour. For anything more, build the page in the app's own design
and let Brod do the rest: Brod sends the code, checks it and sets the session, on the app's own address, including a
custom domain. The app never handles a password or a session token.

Name the page in `brod.json`, with every file it loads:

```json
{
  "open_paths": [
    { "path": "/login", "sign_in_page": true },
    "/assets/*"
  ]
}
```

These are [open paths](#open-paths), so a person approves them, and anyone can read them. Until then, visitors see Brod's page
and the routes below answer `404 no_sign_in_page`. Afterwards, signed-out visitors go to `/login?return=<where they were
going>`, and `Brod.signIn()` goes there too. A live version that stops naming the page goes back to Brod's.

```html
<script src="/_brod/client.js"></script>
<script type="module">
  const how = await Brod.auth.methods();            // { email, google, app: { name }, return }
  await Brod.auth.sendCode(email);                  // emails a 6-digit code
  const r = await Brod.auth.verifyCode(email, code); // throws an Error with .code and .message
  if (r.allowed) location.href = r.return; else showNoAccess();
  if (how.google) Brod.auth.google();               // a redirect, and back signed in
  await Brod.auth.signOut();
</script>
```

In a bundled app, `@brodsh/auth/client` has the same functions.

| Route, on the app's address | |
| --- | --- |
| `GET /_brod/auth/methods` | How people can sign in here |
| `POST /_brod/auth/start` `{email}` | Email a code |
| `POST /_brod/auth/verify` `{email, code, return}` | Swap the code for the session cookie: `{ok, allowed, return}` |
| `GET /_brod/auth/google?return=` | Sign in with Google, if the server has it |
| `POST /_brod/auth/signout` | End the session |

- **One app only.** A session from a code works on that app, and nowhere else: not on the platform, not on another
  app. Google sign-in goes through the API host, so it is the ordinary single sign-in, and signing out of it signs out
  of every app.
- **Access is unchanged.** `verify` answers `allowed: false` when the app is not shared with the person, so the page can say so.
- **Limits.** A code lasts 10 minutes and allows 5 tries. Per hour: 5 codes for one address across all apps, 20 from
  one network, and 100 from one app. POSTs must come from the app's own origin, with a JSON body.
- **The email** names the app and its address and comes from the server's sender (`EMAIL_FROM`).

## The identity contract

An app reads the signed-in person from its own address:

```html
<script src="/_brod/client.js"></script>
<script type="module">
  const me = await Brod.me();   // null when nobody is signed in (public apps)
  // { user: { id, email, name }, role: "editor", groups: ["finance"], app, workspace, token }
  if (me?.role === 'viewer') document.querySelector('#edit').hidden = true;
</script>
```

- `Brod.me()` reads `GET /_brod/me`. Without a signed-in person it answers `401` with the error code `signed_out`, and
  `Brod.me()` returns `null`.
- `Brod.signIn()` and `Brod.signOut()` send the person to sign in or out (`/_brod/signin`, `/_brod/signout`).
- `token` is the same identity as a signed JWT for this app, valid for 5 minutes. Pass it to a server that needs proof
  of who the person is. See [Verifying the identity token](#verifying-the-identity-token).
- Server apps get the same identity as request headers. See [Server apps](#server-apps).

Do not build a login page or a user table. Brod signs people in and decides who may open the app.

### Verifying the identity token

The token in `/_brod/me` and in the `x-brod-identity` header is a compact JWT signed with Ed25519
(`server/src/identity.rs`). Anything can verify it with the server's public keys; nothing but Brod can make one.

- **Header.** `{ "alg": "EdDSA", "typ": "JWT", "kid": "<key id>" }`. The key id is the key's RFC 7638 thumbprint.
- **Claims.**

  | Claim | Value |
  | --- | --- |
  | `iss` | The server's public address (`BROD_PUBLIC_URL`), e.g. `https://brod.example.com` |
  | `aud` | `brod:app:<app id>`. A token for one app is refused by another. |
  | `sub` | The person's user id |
  | `email`, `name` | The person |
  | `workspace` | `{ "id", "slug" }` |
  | `role`, `groups` | The person's role in this app and their groups |
  | `iat`, `exp` | Issued at and expiry, in seconds. `exp` is `iat + 300`. |
  | `jti` | A random id, different on every token |

- **Keys.** `GET <issuer>/.well-known/jwks.json` answers a JWKS with one `OKP` / `Ed25519` key. Fetch it once and
  cache it; refetch when a token names a `kid` you do not have.
- **Server code learns the values from its environment.** Server apps get `env.BROD_ISSUER`, `env.BROD_APP_ID` and
  `env.BROD_IDENTITY_JWKS` (the JWKS as a JSON string), so they can verify without a network call. The audience is
  `brod:app:` followed by `env.BROD_APP_ID`.

To verify one: split it on `.`, base64url-decode the header and check `alg` is `EdDSA`, find the key with that `kid`
in the JWKS, verify the Ed25519 signature over `<header>.<payload>` with the key's `x` (32 bytes, base64url), then
check `iss`, `aud` and `exp`. With `jose` in Node:

```js
import { createRemoteJWKSet, jwtVerify } from 'jose';
const jwks = createRemoteJWKSet(new URL('https://brod.example.com/.well-known/jwks.json'));
const { payload } = await jwtVerify(token, jwks, {
  issuer: 'https://brod.example.com',
  audience: 'brod:app:app_…',
  algorithms: ['EdDSA'],
});
```

#### In JavaScript: `@brodsh/auth`

[`@brodsh/auth`](../sdk/js/README.md) does all of this in one call, in Node, Next.js (server components, route handlers,
middleware) and Workers. It reads `BROD_ISSUER`, `BROD_APP_ID` and `BROD_IDENTITY_JWKS` from the environment, accepts
only `EdDSA`, allows 30 seconds of clock skew, and fetches and caches the JWKS when there is no inline copy:

```js
import { currentUser } from '@brodsh/auth';

const user = await currentUser(request); // a Request, Headers, or a Node / Express request
// null: anonymous (an open path, or a public app with nobody signed in)
// otherwise { id, email, name, workspace: { id, slug }, role, groups, app, claims }
// A token that does not verify throws a BrodAuthError with status 401.
```

In Next.js, `currentUserFromHeaders()` from `@brodsh/auth/next` reads the current request in server components and
route handlers. On workerd, pass the Worker's env: `currentUser(request, { env })`. The
[README](../sdk/js/README.md) has examples for each, and the 403 pattern for an app that keeps its own users table.

#### In other languages

Any JWT library with EdDSA (Ed25519) support verifies the token. In each, allow only `EdDSA`, pick the key by `kid`,
and check `iss`, `aud` and `exp`.

Python, with [PyJWT](https://pyjwt.readthedocs.io/) (`pip install "pyjwt[crypto]"`):

```python
import json, os
import jwt

ISSUER = os.environ["BROD_ISSUER"]
AUDIENCE = "brod:app:" + os.environ["BROD_APP_ID"]
KEYS = {k["kid"]: jwt.PyJWK(k).key for k in json.loads(os.environ["BROD_IDENTITY_JWKS"])["keys"]}
# Without BROD_IDENTITY_JWKS: jwt.PyJWKClient(ISSUER + "/.well-known/jwks.json").get_signing_key_from_jwt(token).key

def brod_user(token):
    """The verified claims, or None for an anonymous request. Raises jwt.InvalidTokenError for a bad token."""
    if not token:
        return None
    key = KEYS.get(jwt.get_unverified_header(token).get("kid"))
    if key is None:
        raise jwt.InvalidTokenError("unknown key")
    return jwt.decode(token, key, algorithms=["EdDSA"], audience=AUDIENCE, issuer=ISSUER,
                      leeway=30, options={"require": ["exp", "iat", "sub"]})

# Flask: brod_user(request.headers.get("x-brod-identity"))
```

Go, with [golang-jwt](https://github.com/golang-jwt/jwt) (`go get github.com/golang-jwt/jwt/v5`):

```go
package brod

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Keys reads BROD_IDENTITY_JWKS (or the body of <BROD_ISSUER>/.well-known/jwks.json): key id to Ed25519 public key.
func Keys(jwks []byte) (map[string]ed25519.PublicKey, error) {
	var set struct {
		Keys []struct{ Kty, Crv, Kid, X string }
	}
	if err := json.Unmarshal(jwks, &set); err != nil {
		return nil, err
	}
	keys := map[string]ed25519.PublicKey{}
	for _, k := range set.Keys {
		if k.Kty != "OKP" || k.Crv != "Ed25519" {
			continue
		}
		x, err := base64.RawURLEncoding.DecodeString(k.X)
		if err != nil || len(x) != ed25519.PublicKeySize {
			return nil, errors.New("bad Ed25519 key")
		}
		keys[k.Kid] = ed25519.PublicKey(x)
	}
	return keys, nil
}

// User returns the verified claims, or nil for an anonymous request (an open path, or a public app).
func User(r *http.Request, keys map[string]ed25519.PublicKey) (jwt.MapClaims, error) {
	token := r.Header.Get("X-Brod-Identity")
	if token == "" {
		return nil, nil
	}
	claims := jwt.MapClaims{}
	_, err := jwt.ParseWithClaims(token, claims, func(t *jwt.Token) (any, error) {
		kid, _ := t.Header["kid"].(string)
		if k, ok := keys[kid]; ok {
			return k, nil
		}
		return nil, errors.New("unknown key")
	},
		jwt.WithValidMethods([]string{"EdDSA"}),
		jwt.WithIssuer(os.Getenv("BROD_ISSUER")),
		jwt.WithAudience("brod:app:"+os.Getenv("BROD_APP_ID")),
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
		jwt.WithLeeway(30*time.Second))
	if err != nil {
		return nil, err
	}
	return claims, nil
}
```

Rust, with [jsonwebtoken](https://crates.io/crates/jsonwebtoken) (`cargo add jsonwebtoken --features rust_crypto`
and `cargo add serde_json`; from version 10 on, jsonwebtoken needs a crypto backend feature, `rust_crypto` or
`aws_lc_rs`):

```rust
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header, jwk::JwkSet};

/// The verified claims, or None for an anonymous request (an open path, or a public app).
/// `jwks` is BROD_IDENTITY_JWKS parsed once with serde_json (or the body of <BROD_ISSUER>/.well-known/jwks.json).
pub fn brod_user(token: Option<&str>, jwks: &JwkSet) -> Result<Option<serde_json::Value>, Box<dyn std::error::Error>> {
    let Some(token) = token.filter(|t| !t.is_empty()) else { return Ok(None) };
    let kid = decode_header(token)?.kid.ok_or("no kid")?;
    let jwk = jwks.find(&kid).ok_or("unknown key")?;
    let mut v = Validation::new(Algorithm::EdDSA);
    v.set_issuer(&[std::env::var("BROD_ISSUER")?]);
    v.set_audience(&[format!("brod:app:{}", std::env::var("BROD_APP_ID")?)]);
    v.set_required_spec_claims(&["exp", "iss", "aud", "sub"]);
    v.leeway = 30;
    Ok(Some(decode::<serde_json::Value>(token, &DecodingKey::from_jwk(jwk)?, &v)?.claims))
}
```

These three were checked against a token signed the way Brod signs (PyJWT 2.15, golang-jwt 5.3, jsonwebtoken 11.1):
a valid token verifies, a missing one is anonymous, and another app's audience is refused.

Agents can ask the `get_auth_integration` tool for this contract and ready-made snippets for Next.js, Node, Python,
Go, Rust and workerd. The Next.js, Node and workerd ones use `@brodsh/auth`, with the plain `jose` code beside them.

The signing key is `IDENTITY_SIGNING_KEY`. A self-hosted server generates one on first start; a hosted server refuses
to start without one. Changing it invalidates tokens already handed out, which matters little at five minutes.

## Server apps

A bundle with server code is a server app. It uses the Cloudflare Pages layout that agents and build tools already
know: a `_worker.js` ES module at the top of the bundle, or a `_worker/` folder with `index.js` (or `index.mjs`) and its
other modules (`.js`, `.mjs`, `.cjs`, `.json`, `.wasm`, text). An `index.html` is optional.

```js
// _worker.js
export default {
  async fetch(request, env, ctx) {
    const email = request.headers.get('x-brod-user-email');       // the signed-in person (absent for anonymous visitors)
    await env.DB.run('CREATE TABLE IF NOT EXISTS notes (by TEXT, text TEXT)');
    if (request.method === 'POST') await env.DB.run('INSERT INTO notes VALUES (?, ?)', [email, await request.text()]);
    const notes = await env.DB.query('SELECT * FROM notes');       // rows as objects
    console.log('notes', notes.length);                            // shows in get_logs
    return Response.json({ notes, stripe: Boolean(env.STRIPE_KEY) });
  },
};
```

How it runs: Brod does not run JavaScript itself. It hands server code to a sidecar that runs
[workerd](https://github.com/cloudflare/workerd), the open-source Workers runtime (`deploy/runtime/`). The sidecar
loads each app into its own isolate, keyed by app, version and secrets revision. A rollback or a secret change takes
effect on the next request. Each app gets its own SQLite database on the sidecar's disk. Without the sidecar
(`BROD_RUNTIME_URL` not set), a deploy with server code is refused with `server_apps_unavailable`. See
[architecture.md](architecture.md).

- **Routing.** A file that exists in the bundle is served as is, and `/` and folder paths serve the folder's
  `index.html` when the bundle has one. Every other request, with any method, goes to `fetch`, so there is no
  single-page-app fallback: a path with no file behind it is the server code's to answer. The server code itself is
  never served. A page can also come from `fetch`, imported from a `_worker/` folder as text
  (`import page from './page.html'`), as [examples/hello-team](../examples/hello-team) does. Files in `_worker/` with
  the extensions `.html`, `.css`, `.txt`, `.md`, `.sql`, `.svg` and `.csv` import as strings.
- **Identity.** Access is decided before the request reaches the app. The person arrives as `x-brod-user-id`,
  `x-brod-user-email`, `x-brod-user-name` (URI-encoded), `x-brod-role`, `x-brod-groups` (comma-separated) and
  `x-brod-identity` (the signed JWT, see [Verifying the identity token](#verifying-the-identity-token)). The gateway
  strips any `x-brod-*` header a visitor sends, and the app's session cookie. Requests to an
  [open path](#open-paths) carry none of these.
- **Storage, one set per app.** No app can reach another app's storage.
  - `env.DB` is the app's own SQLite database. `query(sql, params)` returns rows, `run(sql, params)` returns
    `{ changes }`, and `batch([{ sql, params }])` runs the statements in one transaction.
  - `env.KV` is a key-value store in the same database: `get`, `put`, `delete`, `list(prefix, limit)`. Values are
    strings up to 128 KB.
  - `env.FILES` is file storage: `put(key, body, contentType)`, `get(key)` (a `Response`, or `null`), `delete(key)`,
    `list(prefix)`. A key is 1 to 512 characters, without `..`. Brod keeps these files in its own file store, a folder
    or an S3-compatible bucket.
  - `env.SETTINGS` holds the app's [settings](#app-settings).
- **Storage counts.** On a hosted server, `env.DB`, `env.KV` and `env.FILES` count toward the workspace's plan storage.
  While the workspace is out of storage, database statements that can grow it (anything but `SELECT`, `EXPLAIN`,
  `DELETE` and `DROP`) and `KV.put` throw. Reads and deletes keep working. A self-hosted server has no storage limit.
- **Secrets.** `set_secret` (or `PUT /v1/apps/:slug/secrets/:NAME`) stores a value encrypted at rest (AES-GCM, with a
  key derived from `SECRETS_KEY` and bound to the app). The app reads it as `env.NAME` from its next request. Nobody can
  read a value back. The API lists names only.
- **Logs.** Each request's console output and exceptions are kept for 7 days. `get_logs` shows the last 50 requests and
  can search them.
- **Safe deploys.** Before a version goes live, the sidecar imports its main module and checks that it exports `fetch`.
  A version whose code throws while loading, or does not export `fetch`, is refused with `server_failed`, and the live
  version keeps serving. A request that throws gets a plain error page. The visitor never sees the exception. The owner
  sees it in the logs.
- **Outgoing requests.** `fetch` to the public internet over HTTP and HTTPS is allowed, subject to the app's
  [outside addresses](#outside-addresses). HTTPS certificates are checked against the CAs browsers trust. Apps cannot
  reach Brod's private network: private, loopback and link-local addresses (including cloud metadata at
  `169.254.169.254`), internal names such as `brod` or `*.internal`, and public names that resolve to any of these. A
  fetch that fails throws `Brod could not reach <origin>: <reason>`, and that message shows in the app's logs.

### Limits for server apps

Open-source workerd runs every app's isolate on one thread and does not enforce a CPU limit per request. One app stuck
in a loop (`for (;;) {}`) would stop every server app on the host. An app that passes V8's heap limit would end the
whole process. So the sidecar runs workerd under a supervisor, `brod-runtime` (`deploy/runtime/supervisor/`), and Brod
decides which app to blame (`server/src/watchdog.rs`).

- **Stalls.** The supervisor asks workerd's `/_runtime/health` every half second. When workerd has not answered for
  `RUNTIME_STALL_MS` (default 5000), the supervisor tells Brod, kills workerd and starts it again.
- **Memory.** When workerd's resident memory passes `RUNTIME_MEMORY_MB` (default 1536; 0 turns it off), the
  supervisor does the same. Docker Compose also sets a kernel limit on the container, `RUNTIME_MEM_LIMIT` (default
  `2g`).
- **Blame.** workerd takes requests in order on one thread. The request that stalled it is the first one Brod sent
  after workerd's last answer. Requests sent earlier were waiting on I/O and might have resumed and stalled it, so they
  are suspects too.
- **Stopping.** When one app is the only suspect, its server code is stopped at once. Visitors get a `503` page with
  `Retry-After`, for 1 minute, then 5, then 30 if it happens again within an hour. Its static files keep serving. When
  several apps were in flight, each gets a strike, and an app is stopped after 3 strikes in 10 minutes. Brod keeps this
  record in memory, so a restart of Brod clears it.
- **What people see.** The request that stalled the runtime gets a `503` "This app was stopped" page. The app's logs
  get an entry with outcome `exceededCpu` or `exceededMemory` that says what happened and for how long the app is
  stopped, so `get_logs` tells the agent what to fix. Requests without a body that only queued, or that came while
  workerd was restarting, are sent again once it is back (within 10 seconds).
- **Deploys.** Server code whose top-level code never finishes stalls the deploy-time check in the same way. That deploy
  is refused with `server_failed`, and the live version keeps serving.

What this does not do: a loop holds every server app on the host until it is cut off (5 seconds by default), and a
restart drops the other requests that were in flight with a body (such as POSTs). Apps are not split across several
workerd processes.

## Staging

Once an app is live, an update can go to its **staging address** first, `<slug>--staging.<workspace>.<APPS_DOMAIN>`,
so someone can try it before visitors see it. Staging serves one version (the app's `staging_version`) next to the live
one. Publishing moves it live and empties staging. Nothing is rebuilt.

- **Where a deploy goes.** `deploy_app` and `POST /v1/deploys` take `"environment": "staging"` or `"production"`.
  Without it, an **agent** updating an app that already has a live version deploys to **staging**. A new app's first
  version, and a person deploying from the dashboard, go live. An upload address remembers the environment it was made
  for.
- **What the agent is told.** A staging deploy answers with `staging_url` and a `next_step` that says to give the
  person that address and call `publish_staging` only once they say it is ready.
- **Who can open staging.** The app's owner, workspace admins and builders (they get the app's top role), and anyone
  granted the app's top role. Never anonymous visitors, and never visitors with the app's password, whatever its access
  mode. Custom domains never serve staging. Visits on staging are not counted.
- **Publishing.** `publish_staging` (or `POST /v1/apps/:slug/publish`) makes the staging version live.
  `publish_staging` with `"discard": true` (or `DELETE /v1/apps/:slug/staging`) takes it off staging and keeps the
  version, so `rollback` can still serve it. A version on staging cannot be deleted (`409 staging_version`).
- **Shared data.** Staging runs the new code against the app's own database, key-value store, files and secrets, the
  same ones the live version uses. What you change while testing is real.
- `get_status`, `list_apps` and every app result carry `staging` (`{ version, url }`, or `null`).

## Several people on one app

Each person's agent edits its own copy of an app's files and deploys the whole bundle. Without a check, a deploy built
from an older version would undo whatever someone else deployed since. So a deploy can say which version its files
started from, and Brod refuses it when the app has moved on.

- **`base_version`.** `deploy_app` and `POST /v1/deploys` take `"base_version": <n>`, the version the files started
  from (the `version` the agent's last deploy returned, or `current_version` from `get_status`). An upload address
  remembers it. The app's **current version** is the one waiting on staging, or else the live one. Every app result
  carries it as `current_version`.
- **Refused, not merged.** If the current version is no longer `base_version`, nothing is deployed. The answer is
  `409 stale_base` with `your_base`, `current_version`, `current_environment` (`staging` or `live`) and `since`: the
  versions deployed after the base, with who deployed each and its note. The message tells the agent to tell the
  person, then get the current files with `get_files`, add its changes and deploy again with the new base. Brod never
  merges bundles itself: they are build output, not source.
- **Getting the files back.** `get_files` (and `GET /v1/apps/:slug/files?version=`) returns a version's files, by
  default the current one. Up to 1 MB and 200 files they come inline, text as text and anything else as base64. A
  larger version comes as a `download_url`, a tar.gz that `curl -sS "<download_url>" | tar -xzf -` unpacks. That
  address works without signing in for 15 minutes (`GET /v1/downloads/:id`). Only builders and admins can get files.
  That includes server code, never secrets. For an app built from source with a build step, the files are the build
  output, not the source.
- **Who else is working on it: a warning, never a lock.** Getting an app's files or deploying it records that the
  person is working on it. For two hours after someone's last such action, everyone else's `get_files`, deploy and
  `get_status` results carry `others_editing` (`by`, `via`, `base_version`, `since`, `last_active`) and a `warning` to
  pass on. Nothing is blocked. A person's own agents never warn them about themselves.
- **Checked when it counts.** The check runs before the upload and again in the same transaction that makes the
  version current. Of two deploys from the same version, exactly one goes through.
- **Straight to live.** A deploy with `base_version` and `"environment": "production"` builds on what was waiting on
  staging, so it also empties staging.
- **History.** Each version in `get_status` has `based_on` (`null` when the deploy did not say).
- **Version numbers.** Each deploy takes the next number from a counter on the app, so two deploys at once never share
  a number, and a deleted or refused version's number is never used again. Numbers can skip.
- `base_version` is optional, but agents should pass it whenever they update an app.

### Patch deploys and merging

To change a few files, send only those. `deploy_app` and `POST /v1/deploys` take, instead of `files`, a patch:
`base_version` (required), `changes` (path -> exactly one of `{ "content" }`, `{ "content_base64" }` or `{ "sha256" }` of
content this app already has, as `get_files` lists it) and `deletes` (paths). Brod applies it to the base version and
runs the result through the same checks as a full upload (paths, size limits, abuse scan, storage allowance, staging).
A `sha256` the app does not have is refused with `422 unknown_blobs` and a `missing` list. A patch to an app or version
that has no files to patch (a container app, a deleted version) is a 404.

If the app moved on since `base_version`, Brod merges per file instead of refusing. A file only one side changed takes
that side. A text file both sides changed is merged by line (three-way, diff3); a binary file both changed, or a file
one side deleted and the other changed, is a conflict. Any conflict is `409 merge_conflict` with `conflicts`
(`path`, `kind` `text`, `binary` or `delete_modify`, and `hunks` of `base`, `current`, `incoming` text) and nothing is
deployed; fix those files against `current_version` and send the patch again. A merged deploy answers with a `patch`
object (`base_version`, `merged_onto`, `stale_base`, `changed`, `merged`). A full upload with a stale base keeps the
`stale_base` refusal above.

`get_files` with `since=<version>` lists only the files added, modified or deleted since that version (unchanged
ones are named, not sent). `diff_versions {app, from, to}` (`GET /v1/apps/:slug/diff?from=&to=`) returns the changed
paths and a unified diff, capped at 100 KB. Each version records its parent, its author and its note.

### How versions are stored

Files are stored once by content: a blob at `blobs/<sha256>` in storage, written only when it is missing. A version is
a manifest (path, sha256, size, mode, in path order) in the database (`version_manifests`, `manifest_entries`), so a
deploy that changes one file uploads one blob, and rollback, staging, serving and downloads only read manifests.
Download tarballs are built on demand and are deterministic. Versions deployed before this stored one object per
file; each is converted the first time it is read, and its old objects are deleted
only after the manifest is saved. Nothing is converted at start-up. Blobs no manifest refers to are removed hourly,
once they are more than an hour old (the grace period lets a deploy that is still being committed keep its blobs).
Marketplace releases and previews keep their own per-file layout.

Storage use counts the unique content of an app once: the same bytes in ten versions, or twice in one version, count
once for that app. The same bytes in two apps count once for each, so an app's usage never depends on another's.

## Git

An app's history is a git repository. `export_app {app}` (or `GET /v1/apps/:slug/export.bundle`) gives a git bundle;
`git clone https://x:TOKEN@your.brod/v1/apps/notes.git` clones it over read-only smart HTTP (any user name, a Brod token
as the password; a read-only token works). `main` is the live version, `staging` the version waiting on staging, and each
version is a commit tagged `v<N>` with its note as the message and a `Brod-Version: N` trailer. The commits are
deterministic: the same app exports the same ids. Authors are the person's name with
`<user id>@users.noreply.<apps domain>`; the instance setting `BROD_GIT_REAL_EMAILS` uses real addresses instead.
Secrets, databases and other app data are never exported. Pushing is refused (403): changes come back with import.

`import_app {app, url?, ref?, base_version?, history?, target?}` (`POST /v1/apps/:slug/import`, a JSON body or a raw
bundle) turns a commit into a new version, on staging unless `target` is `production`. Without `url` it gives an upload
address for a bundle (`git bundle create app.bundle --all`, then `curl -X PUT --data-binary @app.bundle`). With `url`
Brod fetches a public https repository itself, through an outbound guard that refuses private, loopback, link-local and
metadata addresses (also after redirects), with 10 s to connect and 120 s in all.

If the commit or an ancestor is one Brod exported (or imported before), that version is the merge base and the change is
merged like a [patch](#patch-deploys-and-merging). Otherwise every file is replaced and the result has a `warning`
("no common ancestor; replaced all files"). `history: "all"` makes one version per new first-parent commit, oldest first
(at most 50). Refused, with the path named: symbolic links, submodules, Git LFS pointers, `.git` folders, paths with `..`
or absolute paths, and files over the deploy limits. The pack may be up to `BROD_GIT_MAX_IMPORT_MB` (default 50).

### Git mirror and sync

An app can be mirrored to a repository on GitHub, GitLab or any git host, and can take pushes back.

**Push mirror.** `set_git_mirror` (or `PUT /v1/apps/:slug/git-mirror`) takes the repository `url` (https), a `token` that may push
(GitHub: a fine-grained token with Contents write, user name `x-access-token`) or `token_secret`, the name of one of the app's
secrets that holds it, and `enabled`. After every deploy, publish, rollback or staging change Brod pushes in the background:
the live version to `main`, the version on staging to `staging`, and every version as a tag `v<N>`. The `branches` setting
renames them. Pushes are batched: several changes in quick succession become one push, and a failing push is retried five
times with growing waits (10 s, 40 s, 160 s, up to 10 minutes) before the status becomes `error`. A deploy never waits for it.

Pushes only ever fast-forward. If a remote branch holds commits Brod does not know and that are not its ancestors, the branch is
left alone and the status is `diverged` with a message; nothing is forced. When the remote tip is a commit Brod imported or
knows from before (for example after a rollback), Brod adds a commit on top of it so the push still fast-forwards. A tag that
exists with another commit is never moved (its ref shows `skipped`).

`get_git_mirror` (read-only) and `get_status` show `git_mirror: {status, last_push_at, error}` with the status `idle`, `ok`,
`retrying`, `diverged`, `error` or `disabled`. The token is stored sealed and is never returned or exported. Only the app's owner
or a workspace admin can configure the mirror; builders can see it.

**Inbound sync.** With `sync_inbound: true`, a push to the remote branch (default: the one mapped to `main`) is imported into
staging with the same merge-base logic as `import_app`: it is merged with what is on staging, never onto live. Enabling it shows a
`webhook_secret` once (`rotate_webhook_secret` makes a new one) and the `webhook_url`. In the repository's webhook settings use
that address, content type `application/json`, the secret, and the push event. GitHub is verified by `X-Hub-Signature-256`,
GitLab by `X-Gitlab-Token`. Without a webhook Brod looks at the remote every `BROD_GIT_SYNC_POLL_MINUTES` (default 10, 0 = never)
and fetches only when the branch moved.

If the pushed changes clash with staging, no version is made; `get_git_mirror` shows `inbound.status: conflict` with the paths
and the owner gets an email. Commits Brod pushed itself are recognised and never imported again. Every inbound event is in
`recent_sync` with its result (`imported`, `conflict`, `ignored`, `unchanged`, `error`).

## Access

Each app has one of six access modes. You can change it at any time without a redeploy.

| Mode | Who can open it |
| --- | --- |
| `private` | The app's owner and workspace admins |
| `people` | Only the people, groups and email domains granted a role |
| `workspace` | Everyone in the workspace (guests only if granted) |
| `password` | Anyone with the address and the app's password, without an account. People granted a role can sign in instead. |
| `signed_in` | Anyone who signs in |
| `public` | Anyone, without signing in |

On a server with `BROD_ABUSE_CHECKS=true` (the default when hosted), pages of `public` apps carry a small "Report" link.

Giving someone a role on a `private` app (through `set_access` or an invite) switches it to `people`, since a grant on
a private app would do nothing.

Someone signed in whom an app is not shared with gets the same "App not found" page (404) as an address with no app at
all. An address says nothing about whether an app lives there. The refusal still goes to the activity log.

**Roles.** Each app declares its roles, the one with the most rights first (default `owner`, `editor`, `viewer`). Grants map a
person (`email`), a group (`group`), an email domain (`domain`), or everyone (`everyone`: `workspace` or `signed_in`)
to one of those roles:

```json
{ "access": "people", "add": [{ "group": "finance", "role": "editor" }, { "domain": "acme.test", "role": "viewer" }] }
```

The owner and workspace admins get the top role. Anyone else let in without a grant gets the lowest. If the app is in
a space, everyone in the space counts as named on it: they get their space role when the app has that role, and the
app's lowest role otherwise.

**Workspace roles.** **admin** (people, groups, branding), **builder** (deploy and manage apps, connect agents),
**member** (use apps), **guest** (only the apps they were given).

**Sharing with a password.** `set_access` with `{ "access": "password", "password": "..." }` lets anyone with the
address and the password in, without an account. The password is 6 to 128 characters.

- Visitors see a password page. A correct password earns a cookie on the app's own address for 30 days.
- Brod keeps only a salted PBKDF2-SHA256 hash, so it cannot show the password again.
- A new password signs out everyone who used the old one. Moving the app to another mode forgets it.
- After 30 wrong passwords in 15 minutes the app asks visitors to wait (`429`).
- Visitors who came in with the password and are not signed in are anonymous to the app: `/_brod/me` answers `401`.
  A signed-in visitor who came in with the password gets the app's lowest role.

**Agents and confirmations.** When an agent widens access (a more open mode, new grants or a new password), nothing
changes yet. The tool returns a `confirm_url`, and a person in the workspace opens it and confirms or declines.
Narrowing access applies at once. See [mcp.md](mcp.md).

**New workspaces.** With `BROD_ABUSE_CHECKS=true`, a workspace on the free plan cannot set an app to `password`,
`signed_in` or `public` for its first 24 hours. The refusal is `403 workspace_too_new` with `available_at`. Sharing
inside the workspace (`workspace`, or `people` with named people and groups) works from the start. A self-hosted
server has this hold off by default. See [security.md](security.md).

### App users and filters

An app user is someone who uses one app and nothing else, such as a customer's employee. They get no place in the
workspace and no invitation, and see nothing of Brod but the app. Name them, or a whole email domain, on the app:

```json
{
  "access": "people",
  "add": [
    { "app_user": "sam@acme.com", "role": "viewer", "filters": { "tenant": "acme" } },
    { "domain": "beta.example", "role": "viewer", "filters": { "tenant": ["beta", "beta-eu"] } }
  ]
}
```

`filters` is what a grant carries besides a role: up to 8 names, each a short string or a list. It works on any grant
except one to everyone, and on any kind of person, not just app users.

- **The app applies them.** Brod passes filters on and does nothing else with them. Scope every query by them, and
  refuse a person with none, unless the app means otherwise: no filter must never mean every tenant by accident.
- **Where they arrive.** `filters` in `/_brod/me` and in the identity token, `user.filters` from `@brodsh/auth`, and
  the `x-brod-filters` header in server code (URI-encoded JSON, absent when there are none).
- **Which apply.** The grant naming the person, else their groups' together, else their email domain's. They never add
  to each other, so someone given one tenant does not also get their domain's. Owners and workspace admins open every app, with
  whatever filters their own grants carry, so decide in the app what they see.
- **Changing them.** An agent's change waits for a person to confirm, and the confirmation shows the filters. Moving
  someone between tenants shows other data, so it counts as widening. Leaving `filters` out keeps what is there,
  and `{}` clears them. A change applies on the person's next request.

## Custom domains

A workspace can serve its apps at domains it owns, in two ways:

- **One app, one domain.** `shop.example.com` serves the app `shop`. Builders and admins can add these (`set_domain`
  with `app`, `POST /v1/domains` with `{ "domain": "shop.example.com", "app": "shop" }`, or the app's Domains tab).
- **A whole domain for the workspace.** `*.apps.example.com` serves every app in the workspace at
  `<slug>.apps.example.com`, and `apps.example.com` opens the workspace home page. Admins only (`domain` set to
  `*.apps.example.com`, no `app`).

Adding a domain answers with two DNS records to create:

| Record | Name | Value | Why |
| --- | --- | --- | --- |
| `TXT` | `_brod.shop.example.com` | `brod-verify=<token>` | Proves the workspace owns the domain. Keep it. |
| `CNAME` | `shop.example.com` (or `*.apps.example.com`) | the API host, or `CUSTOM_DOMAIN_TARGET` | Sends visitors to Brod. A bare domain (`example.com`) cannot have a CNAME: use your DNS provider's ALIAS, ANAME or CNAME flattening, or `A`/`AAAA` records to the server. |

Then verify: call `set_domain` again with the same domain, or `POST /v1/domains/<domain>/verify`. Brod looks up the TXT
record over DNS-over-HTTPS (`DNS_RESOLVER_URL`, default `https://cloudflare-dns.com/dns-query`). If the lookup fails,
the answer is `502 dns_unavailable`.

- Nothing is served at a domain until it is verified.
- Several workspaces may claim the same name while it is pending, so nobody can squat on it. Only the one holding the
  TXT record can verify it, and then no other can (`409 domain_taken`).
- `get_status` lists an app's domains with their status.
- Removing a domain (or deleting the app) stops serving it at once.
- A workspace can have 50 domains.
- A verified domain stays verified. Brod does not check its TXT record again later.

Everything else works as on the app's own address: the access decision, roles, `/_brod/me`, and server apps (which see
the custom domain in `request.url`). Signing in still happens on the API host. The gateway sends the visitor to
`/auth/app?app=<slug>.<workspace>&host=<custom domain>`, and Brod hands the one-time code to that host only when it is a
verified domain of that same app. The custom domain then gets its own session cookie.

**HTTPS.** Caddy's on-demand TLS asks Brod's `/_caddy/ask` before it gets a certificate, and Brod approves verified
custom domains (see the `https://` block at the end of `deploy/Caddyfile`). Or let Brod do HTTPS itself with
`BROD_TLS`. That issues certificates over HTTP-01 only, so there are no wildcard certificates: each app under a
wildcard custom domain gets its own certificate on its first visit. See [configuration.md](configuration.md).

## App settings

The people who make an app decide what the people who use it can change without touching its code: a name, a logo,
colours, wording, a contact address. Brod imposes none. The app declares them in a `brod.json` at the top of its
bundle:

```json
{ "settings": [
  { "key": "name",   "label": "Shop name",     "type": "text",  "default": "My shop" },
  { "key": "logo",   "label": "Logo",          "type": "image", "default": "logo.png" },
  { "key": "accent", "label": "Accent colour", "type": "color", "default": "#1f6f4a" },
  { "key": "theme",  "label": "Theme",         "type": "select", "options": ["light", "dark"], "default": "light", "help": "Shown to visitors" }
] }
```

- **Types.** `text` (up to 200 characters), `textarea` (4000), `color` (`#rrggbb`), `image`, `url` (http or https),
  `email`, `number` (optional `min`, `max`), `boolean` and `select` (with `options`). A key starts with a lowercase
  letter and has up to 40 lowercase letters, digits and `_`. At most 30 settings. An image's default is a picture in
  the bundle. Every other default is a value of its type.
- **Checked at deploy.** The declaration is read on every deploy and kept with the version, so it follows versions,
  staging and rollbacks. A `brod.json` Brod cannot use refuses the deploy with `400 bad_settings` and what is wrong.
- **Changing them.** On the admin page's **Customize** tab, or with `PATCH /v1/apps/:slug/settings`:

  ```json
  { "name": "Ada's Coffee", "theme": null }
  ```

  `null` goes back to the default. A value of the wrong type is refused with `400 bad_setting`, and an unknown key
  with `400 unknown_setting`. Images are uploaded with `PUT /v1/apps/:slug/settings/:key`, the picture as the body:
  PNG, JPEG, WebP or GIF, up to 1 MB, typed by their bytes. No redeploy: changes show on the next request and appear in
  the activity log as `settings_changed`. Values belong to the app, so each copy of an app has its own.
- **Reading them.** In the browser, `await Brod.settings()` (or `GET /_brod/settings` on the app's address) returns
  every declared key, with its default when nobody set it, and an image as an address to put in `<img src>`:

  ```json
  { "name": "My shop", "logo": "/_brod/settings/logo?v=...", "accent": "#1f6f4a", "theme": "light" }
  ```

  Server code gets the same object as `env.SETTINGS`. Settings are only served to people who may open the app.

## Outside addresses

Nobody can prove by reading code that it does not leak data, so Brod does not try. Instead, an app may only send data
to its own address and the outside hosts it declares, and Brod enforces that where the app's code runs
(`server/src/network.rs`). The app declares them in its `brod.json`:

```json
{ "network": ["api.stripe.com", "cdn.jsdelivr.net", "*.googleapis.com"] }
```

Host names only (no `https://`, port or path). `*.` covers subdomains, not the name itself. At most 30. Without a list,
the app may only talk to its own address. The list is checked at deploy (`400 bad_network`) and kept with the version.

- **Server code.** Every `fetch` an app makes passes the sidecar's outbound gate (`AppOutbound` in
  `deploy/runtime/host.js`), which lets declared hosts through. There is no other way out: no sockets, and the app's
  database, key-value store and files are not reached over the network.
- **The browser.** Every response from the app carries a `Content-Security-Policy` built from the list. Its pages may
  load scripts, styles, fonts and pictures, fetch, open WebSockets, frame pages and post forms only to their own address
  and the declared hosts. Inline scripts still run: the policy is about where data goes. Browsers report what it stops
  to `/_brod/csp`. One gap no header closes: a script can still send the visitor's browser to another address with data
  in it (`location = ...`).
- **Log first, then enforce.** `BROD_NETWORK` sets what happens to an undeclared request.
  - `log` (the default) lets it through and records it. Pages carry the policy as
    `Content-Security-Policy-Report-Only`, so existing apps keep working while their makers complete their lists.
  - `enforce` refuses it and records it. Server code gets a `403` with `x-brod-network: refused`, and the policy is
    enforced in the browser.
  - `off` does neither.
- **What people see.** Each app's **Network** tab (and `network` in `get_status`) shows the declared hosts, the
  server's policy, and every undeclared host the app reached or tried to, from its server code or a browser, with
  counts and whether it was blocked. Only the app's own workspace sees this.

## Open paths

Some routes must answer callers who cannot sign in: a payment provider's webhook, a health check. (For an MCP server
of the app's own, declare it as [app MCP](#app-mcp) instead: callers then sign in, and the app knows who they are.) An app lists them as `open_paths` in its `brod.json` (`server/src/open_paths.rs`):

```json
{
  "open_paths": [
    "/api/webhooks/*",
    { "path": "/api/mcp", "methods": ["POST"] }
  ]
}
```

- **Entries.** A string or `{ "path", "methods" }`. At most 10. A path is exact (`/api/mcp` matches only
  `/api/mcp`, not `/api/mcpx` or `/api/mcp/x`), or ends in `/*` to cover everything below it
  (`/api/webhooks/*` matches `/api/webhooks` and `/api/webhooks/stripe`, not `/api/webhooksx`). Paths are
  case-sensitive and up to 200 characters. `GET` also allows `HEAD`. Without `methods`, every method is open.
- **Refused patterns.** `/`, `/*`, a `*` anywhere but a trailing `/*`, `..` or `.` segments, `//`, `%` (no encoded
  characters), and anything under `/_brod`. A bad list refuses the deploy with `400 bad_open_paths`.
- **Matching.** The gateway decodes the request path once and refuses to match a path with an encoded slash or
  backslash, a `..` segment, or one that changes on a second decode. It collapses `//`. The app receives the same
  normalised path that matched. So `/api/mcp/../admin`, `/api%2fmcp` and `//api/mcp` never open `/admin` or
  `/api/mcp`.
- **What an open path skips.** Sign-in and the access mode. The request reaches the app with no identity: every
  `x-brod-*` header and the session cookie are stripped, and `/_brod/me` is not open. Takedowns, suspension and
  pausing still apply. Open paths work for static files and server code, on the app's address and on its staging
  address.

**Approval.** An open path makes part of an app public, so it needs a person ([mcp.md](mcp.md#what-needs-a-person)).

- When an agent deploys a `brod.json` with paths nobody approved, the deploy still goes live, but those paths stay
  closed: they get the app's usual access check, as every other path does. The result has `open_paths.pending` and a `confirm_url`. A person
  in the workspace opens it and confirms.
- When a person deploys (the dashboard, a CLI or REST call with their session), the declared paths are approved,
  unless the [new-workspace hold](#access) refuses making the app public yet.
- An approval is kept per app. A path is open when the served version declares it and an approved entry covers it,
  so removing a path from `brod.json` closes it at the next deploy, and a later version may declare it again without
  another confirmation.
- `set_open_paths` (or `PUT /v1/apps/<slug>/open-paths`) replaces the approved list. Removing entries applies at once;
  adding them asks for a confirmation when an agent does it.
- `get_status` shows `open_paths`: what is approved, what the live and staging versions declare, what is open and what
  waits for a confirmation.

## App MCP

An app can be an MCP server that agents use as the signed-in person: a client is given only its address, and Brod
does the sign-in. The app writes no OAuth, keeps no tokens and puts no secret in the URL (`server/src/app_mcp.rs`).

**Declare the path** in `brod.json`. One path per app; it covers its sub-paths too (`/api/mcp/messages`):

```json
{ "mcp": "/api/mcp" }
```

The path follows the open-path rules (no `/`, `*`, `..`, `%` or `/_brod`), without the trailing `/*`. It needs server
code (`_worker.js` or a container): a static bundle that declares it is refused with `400 bad_mcp`. The declaration
travels with the version, like open paths and settings, so a rollback brings it back and a version without it turns
the endpoint off. `get_status` (and every deploy result) shows `mcp.url`, the address to give a client, and
`mcp.staging_url` when the staging version declares one.

Declaring it needs no person to confirm, unlike [open paths](#open-paths): it lets in nobody who could not open the
app already, and each request reaches the app as the person who signed in, with the app's usual role for them.

**Handle the path** like any other route. The person arrives the usual way, so `currentUser()` from `@brodsh/auth` (or
the `x-brod-identity` token) tells the handler who is calling:

```js
// app/api/mcp/route.ts (Next.js), or the same in _worker.js
import { currentUser } from '@brodsh/auth/next';

export async function POST(request) {
  const user = await currentUser(request);
  if (!user) return new Response('Unauthorized', { status: 401 });
  return handleMcp(await request.json(), user); // your JSON-RPC handler; user.role is their role in this app
}
```

**Connect a client.** Add the address as a remote (HTTP) MCP server, for example
`claude mcp add --transport http notes https://notes.acme.brod.example/api/mcp`, or paste it into Claude's custom
connector. What happens:

1. The client calls the address without a token. The gateway answers `401` with
   `WWW-Authenticate: Bearer resource_metadata="https://<app host>/.well-known/oauth-protected-resource/api/mcp"`. It
   never redirects this path to the sign-in page.
2. That metadata (RFC 9728), served on the app's host without sign-in, names the address as the resource and Brod as
   the authorization server.
3. The client registers itself with Brod (RFC 7591) and sends the person to `/oauth/authorize` with
   `resource=https://<app host>/api/mcp` (RFC 8707) and PKCE. The consent page says
   "<client> wants to use <app> in <workspace> as you". Somebody who cannot open the app gets `403` instead.
4. The token endpoint issues an access token (an hour) and a rotating refresh token, both bound to that address.
5. On each call the gateway checks the token is for exactly this address, then checks that the person may still open
   the app (the same check as a browser visit), removes the `Authorization` header and forwards the request with the
   person's identity.

**What a token is good for.** Only the address it was issued for. Each host the app is served at is its own
resource: the live address, the staging address (which only the app's builders and top role can open, as in the
browser) and each custom domain. A token for Brod's own `/mcp`, for another app or for another address of this app
gets `401` with `error="invalid_token"`; an app token is refused by Brod's own `/mcp` and API. When the person loses
access to the app (unshared, removed from the workspace or group, the app made private), their next call gets `403`
with `error="insufficient_scope"` and the refresh token stops renewing. A browser that is signed in to the app and
may open it reaches the path as before.

**Tokens for automation.** A builder can make a token for one app's endpoint, for a script with no browser:
`POST /v1/tokens` with `{ "name": "nightly sync", "app": "notes", "expires_in_days": 30 }` (add `"staging": true` for
the staging address). It acts as that person, is checked the same way on every request, and works nowhere else. App
connections, sign-ins and tokens alike, show on the workspace's connections page and in `GET /v1/tokens` with
`"kind": "app"`, and are disconnected the same way.

## Container apps

An app in any language: a source folder with a `Dockerfile` at its top. Brod builds the image on a node, keeps it in
its own registry and runs it as a container behind the same gateway as every other app: the same sign-in, access
rules, [identity headers](#the-identity-contract), [open paths](#open-paths), staging and rollback. A working example
is in [`examples/container-app`](../examples/container-app).

**Deploying.** Upload the source like any bundle: `deploy_app` without `files` gives an upload address, and
`tar -czf - -C <source folder> . | curl -sS -X PUT --data-binary @- "<upload_url>"` sends it. Small sources can be
passed inline as `files`. A `Dockerfile` at the top is what makes it a container app; `"runtime": "container"` asks
for one explicitly and is refused without a Dockerfile.

- The source may be up to 200 MB (a tar.gz). `.dockerignore` is honoured when Brod writes the build context, and
  `node_modules/`, `.git/` and `.next/` are always left out: install dependencies in the Dockerfile.
- The deploy answers at once with a `deployment` (`scheduled`). Call `get_deployment` (or
  `GET /v1/apps/<slug>/deployments/<id>`) until its `state` is `serving` or `failed`. States: `scheduled`,
  `building`, `pulling`, `migrating` (only with a [`migrate`](#databases) command), `starting`, `healthy`, `serving`,
  then `draining` and `stopped` once another version replaces it.
- A failed deployment answers the problem `build_failed` (the image did not build), `migration_failed` (its
  [`migrate`](#databases) command failed) or `deployment_failed` (it built but did not start or pass its health
  check), with the last 50 lines of its log. Nothing changes for visitors: the
  version that was serving keeps serving.
- The build output and the container's output go to the app's logs (`get_logs`).

**Settings** come from `brod.json` at the top of the source, and `deploy_app`'s arguments of the same names override
them:

| Setting | Default | What |
| --- | --- | --- |
| `port` | `8080` | The port the app listens on. It also gets it as `$PORT`. |
| `health` | `/` | A path Brod requests after starting the container. Any answer below 500 within 60 s means healthy. |
| `cpu` | `0.5` | CPUs reserved for it, 0.1 to 16. |
| `memory_mb` | `512` | Memory, 64 to 65536 MB. It is the container's hard limit; there is no swap. |
| `migrate` | none | A shell command run once in the new image before it serves, such as `npx prisma migrate deploy`. See [Databases](#databases). |

**What the container gets.** The person, as headers on every request (`x-brod-identity` and the `x-brod-user-*`
headers, exactly as server apps get them; anything a client sends under those names is removed), plus
`x-forwarded-host`, `x-forwarded-proto` and `x-forwarded-for`. Its environment has `BROD_ISSUER`, `BROD_APP_ID` and
`BROD_IDENTITY_JWKS`, enough to verify `x-brod-identity` without calling Brod, and the app's secrets. A changed secret
reaches the container at its next deploy (or rollback).

**How it runs.** As the image's `USER`, or `10001:10001` when it sets none. An image that asks for root is refused
unless the workspace is trusted (`BROD_CONTAINERS=trusted`). With a read-only root file system and a writable `/tmp`, every Linux capability dropped,
no privilege escalation, at most 512 processes, and its own bridge network. On a Linux node with iptables, it can
reach the internet but not private addresses (10/8, 172.16/12, 192.168/16, 100.64/10), link-local ones (the cloud
metadata service at 169.254.169.254), other apps or the node itself. On macOS and Windows (Docker Desktop) there are
no such rules: a node there is for development only, and the deploy log says so.

**Requests** have the same rules as for server apps: at most 32 MB of body (`413` above that) and 60 s until the
answer starts. When the node that runs the app is offline, visitors get `503`.

**Updates and rollback.** A new version starts next to the one serving; the gateway switches once it is healthy, and
the old container drains for 30 s, then stops. `rollback` to an earlier container version starts it again from its
stored image, without a rebuild. Staging works as for any app: the staging version runs in its own container, and
`publish_staging` moves it to live without a rebuild. Brod keeps the images of the live and staging versions and the
last 5 others; older ones are deleted from the registry each night and cannot be rolled back to.

**Operating it.** `BROD_CONTAINERS` sets who may deploy container apps (`trusted` self-hosted by default, `off`
hosted; see [configuration.md](configuration.md)); with it off, or without a registry, a deploy is refused with
`containers_unavailable`. `docker-compose.yml` runs the registry (`registry:2`, no published port: only Brod talks to
it, with short-lived tokens scoped to one app's repository `apps/<app id>`) and a node with Docker access. Nodes get
images from Brod over their own connection, never from the registry. The nightly clean-up deletes manifests; to free
their disk space run
`docker compose exec registry registry garbage-collect --delete-untagged /etc/docker/registry/config.yml`
from time to time. A node builds with `docker buildx` (a `docker-container` builder, 15 minutes at most) and reads:

| Node variable | Default | What |
| --- | --- | --- |
| `BROD_NODE_DOCKER_SOCKET` | `/var/run/docker.sock` | The Docker Engine API. |
| `BROD_NODE_BUILDER` | `brod-builder` | The buildx builder it creates and builds with. |
| `BROD_NODE_BUILD_MEMORY` / `BROD_NODE_BUILD_CPUS` | `2g` / `2` | The builder's limits. |
| `BROD_NODE_BUILD_TIMEOUT` | `900` | Seconds a build may take. |
| `BROD_NODE_REACH` | by platform | How it reaches containers: `ip` (Linux host), `attach` (the node in a container joins each app's network) or `publish` (a port on 127.0.0.1; macOS and Windows). |

### Databases

A container app can have one Postgres database of its own. The MCP tool `request_database` creates it; an agent
needs no confirmation, and calling it again changes nothing.
The app's next deploy gets `DATABASE_URL`:

```
postgres://app_<id>:<password>@brod-db.internal:5432/app_<id>?sslmode=disable
```

Use it as it is. `brod-db.internal` is not a database server: it is the app's node, which carries the connection to
Brod over the node's own encrypted connection, and Brod to the database server. `sslmode=disable` is correct: that
link is the encryption. Nodes have no network access to the database server at all.

- **One app, one database.** The app's role (`app_<id>`) owns its database and nothing else. It cannot create roles
  or databases, and Postgres refuses it `CONNECT` on every other app's database. Brod also checks every connection
  before it reaches Postgres: through an app's `brod-db.internal`, only that app's database, as that app's role, is
  reachable, and only from a node that runs one of its deployments. At most 20 connections at a time.
- **`DATABASE_URL` is Brod's.** `set_secret` refuses to set or remove it while the database exists. An app that
  already has its own `DATABASE_URL` secret is refused a managed database (`database_url_set`) until that secret is
  removed. `get_status` shows the database (name, size, backups), never its password.
- **Migrations.** `migrate` in `brod.json` (or `deploy_app`'s `migrate`) is a shell command (`/bin/sh -c`) run once
  in a one-off container of the new image, with the app's environment and `DATABASE_URL`, before the new version
  starts. Its output goes to the deployment log. If it exits non-zero or runs longer than 10 minutes the deployment
  fails with `migration_failed` and the version that was serving keeps serving. One migration runs per app at a
  time. It runs only for a newly built image: a rollback, or `publish_staging`, does not run it again.

> **A rollback does not undo a migration.** Rolling back serves the old code against the database as the newer
> migration left it. Write migrations the old version can live with (add before you remove), or restore a backup.
>
> **Staging shares the live database.** A staging version gets the same `DATABASE_URL` as live, and its migration
> changes the live database the moment it is deployed to staging, before anyone publishes it.

**Backups.** Brod backs up every managed database once a day (`pg_dump`, custom format) and keeps the newest of each
of the last 7 days and of each of the last 4 weeks. Backups are encrypted (AES-256-GCM, with a key derived from
`SECRETS_KEY`) before they reach file storage, under `backups/<database id>/`. With folder storage they are on the
same machine as the database, and `backup_database` and `get_status` warn about it: use S3 storage to keep them
elsewhere. `backup_database` backs up now.

- **Restoring** replaces the app's database with a backup (`restore_database`, the latest by default). It needs a
  person: an agent gets a `confirm_url`, and nothing changes until it is confirmed. Brod restores into a new
  database, checks it, swaps it in, keeps the replaced one as `<name>_before_<time>` for 24 hours, and restarts the
  app's containers.
- **Restore drill.** Once a week Brod restores each database's latest backup into a scratch database, compares the
  row counts of every table with those taken at backup time, and drops it. `get_status` shows when a backup was last
  proved this way; a failed drill is logged loudly.
- **Deleting the app** takes a final backup, kept for 30 days, then drops the database and its role. If that backup
  fails the app is not deleted.

**Operating it.** `docker-compose.yml` runs `apps-postgres`, a Postgres 17 separate from Brod's own database, with no
network at all: Brod reaches it through a shared socket. Its admin password is generated into `secrets.env`
(`APPS_DATABASE_PASSWORD`). Brod's image carries `pg_dump` and `pg_restore` of the same major version. Without
`BROD_APPS_DATABASE_URL`, `request_database` answers `database_unavailable`. The admin can back up every database
now with `POST /v1/admin/backups/run` and run the drill with `POST /v1/admin/backups/drill`.

## Limits

| What | Limit |
| --- | --- |
| Files passed inline to `deploy_app` or `POST /v1/deploys` | 1 MB in all |
| An uploaded bundle (tar.gz) | 25 MB |
| A bundle, unpacked | 60 MB, 2,000 files |
| One file | 10 MB |
| A patch deploy | the same limits; inline `content` up to 1 MB in all |
| Upload and download addresses | valid for 15 minutes |
| Deploys | 30 an hour per workspace (`429 rate_limited`) |
| `env.KV` value | 128 KB |
| Server app logs | kept 7 days; `get_logs` shows the last 50 requests |
| Settings | 30 per app; images up to 1 MB |
| Outside hosts | 30 per app |
| Open paths | 10 per app, 200 characters each |
| Custom domains | 50 per workspace |

Plans differ by mode. On a self-hosted server there are no plans: no limit on running apps, people or storage. On a
hosted server each workspace's plan sets how many apps can run, how many people it can have, and its storage. A deploy
or file write over the storage allowance is refused with `storage_limit`.

What is not here yet:

- Container apps need a `Dockerfile`; projects without one are not detected and built automatically yet. Managed
  Postgres for container apps is not built yet.
- Old versions are kept until someone deletes them (`DELETE /v1/apps/:slug/versions/:n`). They count toward storage.
  There is no clean-up job.
- Blocking paths by role, company sign-in (SAML/OIDC) and deploy-before-sign-up are not built yet.
