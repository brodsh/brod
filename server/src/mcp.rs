// SPDX-License-Identifier: AGPL-3.0-only
// MCP endpoint (Streamable HTTP, stateless, JSON responses). Each tool is a thin wrapper over the control plane.
use axum::response::Response;
use base64::Engine;
use serde_json::{Map, Value, json};

use crate::control::{self, Credentials, DeployTarget};
use crate::http::{Req, empty, json_response};
use crate::model::{Caller, js_string, js_to_number, limits};
use crate::people;
use crate::problem::{Problem, Result};
use crate::state::State;
use crate::tar::BundleFile;

const VERSIONS: [&str; 3] = ["2025-06-18", "2025-03-26", "2024-11-05"];

fn s(description: &str) -> Value {
    json!({ "type": "string", "description": description })
}

pub fn tools() -> Value {
    let app_arg = || s("The app's short name (slug), as shown by list_apps.");
    let grant_item = json!({
        "type": "object",
        "description": "Exactly one of email, group, domain or everyone, plus a role.",
        "properties": {
            "email": s("A person already in the workspace."), "group": s("A workspace group name, for example \"finance\"."),
            "domain": s("An email domain, for example \"example.com\"."), "everyone": { "type": "string", "enum": ["workspace", "signed_in"] },
            "role": s("One of the app's roles (default owner, editor, viewer)."),
        },
    });
    json!([
        {
            "name": "deploy_app",
            "title": "Deploy an app",
            "description": concat!(
                "Put a web app online and get its address back, or publish a new version of an existing app. ",
                "For a small app (up to 1 MB total), pass its files directly in \"files\". ",
                "For anything larger, call this WITHOUT \"files\": you get a one-time upload address and a one-line command that uploads the built output folder (such as dist/ or build/). ",
                "Give \"name\" to create a new app, or \"app\" to add a version to an existing one. New apps start private to their owner; use set_access to share them (with people or groups, the workspace, or anyone who has a password). ",
                "Static files are served as they are. For server code, include \"_worker.js\" (or a \"_worker/\" folder with index.js): an ES module with ",
                "`export default { async fetch(request, env, ctx) { ... } }`. Files that exist in the bundle are served directly; every other request goes to fetch. ",
                "Inside fetch, env holds the app's secrets (set_secret) plus its own storage: env.DB (SQLite: await env.DB.query(sql, params) returns rows, await env.DB.run(sql, params), ",
                "await env.DB.batch([{sql, params}]) in one transaction), env.KV (get, put, delete, list; string values) and env.FILES (put(key, body, contentType), get(key) returns a Response or null, delete, list(prefix)). ",
                "The signed-in person arrives as request headers x-brod-user-id, x-brod-user-email, x-brod-role and x-brod-groups (the platform strips any a visitor sends), plus x-brod-identity, a signed JWT (get_auth_integration explains how to verify it). ",
                "Apps are private: paths that must work without sign-in (webhooks, an MCP endpoint with its own auth) go in the \"open_paths\" list of a brod.json at the top of the bundle; new ones stay closed until the owner opens the result's confirm_url. ",
                "Never build a login or user table. A version whose server code does not start is refused, and the live version stays. Use get_logs to see console output and errors. ",
                "STAGING: when you update an app that already has a live version, ask the person first whether to try it on staging before it goes live (recommended) or to publish straight away. ",
                "Updates to a live app go to staging unless \"environment\" is \"production\": the result's staging_url serves the new version to the app's builders only, while visitors keep the live one. ",
                "Give the person the staging_url to test, and call publish_staging only once they say it is ready. Staging and live share the app's data (env.DB, env.KV, env.FILES) and secrets. ",
                "SEVERAL PEOPLE: others may update the same app. When updating, pass \"base_version\": the version your files started from (the \"version\" your last deploy_app returned, or \"current_version\" from get_status when you began). ",
                "If someone deployed since, nothing is deployed and the error stale_base says who changed what: call get_files for the current version, add your changes to it, and deploy again; do not deploy over their work unless the person says to. ",
                "If the result has a \"warning\", someone else is also working on the app: tell the person. ",
                "CONTAINERS (when this Brod runs them): a source folder with a Dockerfile at its top is built into an image on a node and run as a container. Upload the SOURCE folder (not built output) with the upload command; ",
                ".dockerignore is honoured and node_modules/, .git/ and .next/ are left out. The app listens on \"port\" (default 8080, also in $PORT) and must answer \"health\" (default \"/\") below 500. ",
                "Its environment holds the app's secrets plus BROD_ISSUER, BROD_APP_ID and BROD_IDENTITY_JWKS; the signed-in person arrives in the same x-brod-* headers. It runs as a non-root user on a read-only file system (write to /tmp only). ",
                "The deploy returns at once with a \"deployment\": call get_deployment until it is \"serving\" or \"failed\"; what is live keeps serving until the new version is healthy. ",
                "PATCH: to change a few files of an existing app, send only what changed instead of every file: \"base_version\" (required: the version your edit started from), \"changes\" (path -> { content } or { content_base64 } or { sha256 } of a file get_files showed) and \"deletes\" (paths to remove). ",
                "The new version is the base plus your changes minus the deletes, and goes through the same checks as a full upload. If someone deployed since your base, Brod merges your changes onto their version file by file (line by line in text files) and the result says what it merged; ",
                "overlapping edits are refused with merge_conflict and the conflicting paths and hunks, and nothing is deployed: resolve those files and deploy again with the current \"base_version\". Do not send \"files\" together with \"changes\"."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "name": s("Name for a NEW app, for example \"Reading list\". The address is derived from it."),
                    "app": s("Slug of an EXISTING app to publish a new version of."),
                    "note": s("One line on what this version is or what changed."),
                    "environment": {
                        "type": "string", "enum": ["staging", "production"],
                        "description": "Where this version goes. \"staging\": only to the app's staging address for testing; the live version is unchanged. \"production\": live at once. Default: staging when updating an app that is already live, production for a new app.",
                    },
                    "base_version": {
                        "type": "integer", "minimum": 1,
                        "description": "For an update: the version your files started from. The deploy is refused (stale_base) if the app's current version (staging, else live) is no longer this one, so you never undo someone else's changes.",
                    },
                    "runtime": { "type": "string", "enum": ["container"], "description": "\"container\" to insist the bundle is a container app's source (a Dockerfile at its top is enough on its own)." },
                    "port": { "type": "integer", "minimum": 1, "maximum": 65535, "description": "Container apps: the port the app listens on. Default 8080, or \"port\" in brod.json." },
                    "health": s("Container apps: the path Brod checks before sending traffic, such as \"/healthz\" (healthy: any status below 500). Default \"/\"."),
                    "cpu": { "type": "number", "minimum": 0.1, "maximum": 16, "description": "Container apps: CPUs. Default 0.5." },
                    "memory_mb": { "type": "integer", "minimum": 64, "maximum": 65536, "description": "Container apps: memory in MB. Default 512." },
                    "migrate": s("Container apps: a shell command run once from the new image before it serves, such as \"npm run migrate\" (or \"migrate\" in brod.json). If it fails the deployment fails with migration_failed and what is live keeps serving. Schema changes are NOT undone by a rollback, and staging shares the live database."),
                    "changes": {
                        "type": "object",
                        "description": "Patch mode (needs \"app\" and \"base_version\"): path -> exactly one of { \"content\": text }, { \"content_base64\": base64 } or { \"sha256\": hash of a file of this app, as get_files lists it }. Instead of \"files\".",
                        "additionalProperties": { "type": "object", "properties": { "content": s("New text content."), "content_base64": s("New content, base64 encoded."), "sha256": s("The sha256 of content the app already has.") } },
                    },
                    "deletes": { "type": "array", "items": { "type": "string" }, "description": "Patch mode: paths to remove from the base version." },
                    "files": {
                        "type": "array", "description": "The app's files, for small apps. Must include index.html at the top level.",
                        "items": { "type": "object", "properties": { "path": s("Path inside the app, for example \"index.html\" or \"assets/app.js\"."), "content": s("File content."), "encoding": { "type": "string", "enum": ["utf8", "base64"], "description": "How content is encoded. Default utf8." } }, "required": ["path", "content"] },
                    },
                },
            },
            "annotations": { "readOnlyHint": false, "destructiveHint": false, "openWorldHint": true },
        },
        { "name": "list_apps", "title": "List apps", "description": "List the workspace's apps with address, status, who can open each, live version, plus how many plan slots are in use.", "inputSchema": { "type": "object", "properties": {} }, "annotations": { "readOnlyHint": true } },
        {
            "name": "get_files", "title": "Get an app's files",
            "description": concat!(
                "Get the files of an app's current version (the one on staging, else the live one), or of the \"version\" you name, to change them. ",
                "Call this before changing an app someone else may have changed, so you start from what is deployed rather than an older copy, then deploy_app with \"base_version\" set to the \"version\" returned. ",
                "Small apps come back inline in \"files\" (base64 when \"encoding\" says so); larger ones as a download_url with a one-line curl | tar command. ",
                "Each file has its sha256 and size; deploy_app can reuse a file by its sha256 when patching. Pass \"since\" (a version you already have) to get only what changed from that version to this one, plus the deleted paths. ",
                "The files are the built output as deployed. If the result has a \"warning\", someone else is working on the app too: tell the person."
            ),
            "inputSchema": { "type": "object", "properties": { "app": app_arg(), "version": { "type": "integer", "minimum": 1, "description": "A version number. Default: the current version." }, "since": { "type": "integer", "minimum": 1, "description": "Return only the files changed since this version (and the paths deleted since)." } }, "required": ["app"] },
            "annotations": { "readOnlyHint": true },
        },
        {
            "name": "diff_versions", "title": "Compare two versions",
            "description": "A unified diff between two versions of an app, to see what someone else changed. \"to\" defaults to the current version. Binary files only say that they differ; the diff is cut off at about 100 KB (\"truncated\" says so, and \"files\" still lists every changed path).",
            "inputSchema": { "type": "object", "properties": { "app": app_arg(), "from": { "type": "integer", "minimum": 1, "description": "The older version." }, "to": { "type": "integer", "minimum": 1, "description": "The newer version. Default: the current version." } }, "required": ["app", "from"] },
            "annotations": { "readOnlyHint": true },
        },
        {
            "name": "export_app", "title": "Export an app as git",
            "description": concat!(
                "Get an app's files and history as a git repository: a short-lived download address for a git bundle (one command clones it), plus a clone address for git over HTTP (user name anything, password a Brod token). ",
                "\"main\" is the live version, \"staging\" the version waiting on staging, and every version is a tag (v1, v2, ...); each version is a commit with its note as the message. ",
                "Secrets and the app's data are never included. Change the files with git, then bring the work back with import_app."
            ),
            "inputSchema": { "type": "object", "properties": { "app": app_arg(), "format": { "type": "string", "enum": ["git-bundle"], "description": "Only git-bundle for now." } }, "required": ["app"] },
            "annotations": { "readOnlyHint": true },
        },
        {
            "name": "import_app", "title": "Import git work into an app",
            "description": concat!(
                "Turn a git commit into a new version of an existing app. Give \"url\" of a public repository (https; Brod fetches it), or leave it out to get a one-time upload address for a git bundle (git bundle create ../app.bundle --all, then upload it with the one-line command). ",
                "\"ref\" picks the branch or tag (default HEAD, then main). The version lands on staging unless \"target\" is \"production\". ",
                "If the commit (or an ancestor) came from export_app or an earlier import, Brod merges your changes with whatever others deployed since, like a patch on base_version; otherwise all files are replaced and the result says so in \"warning\". ",
                "\"history\": \"all\" creates one version per new commit (up to 50) instead of one for the tip. ",
                "Symbolic links, submodules, Git LFS files, .git folders and files over the size limits are refused with the path named."
            ),
            "inputSchema": { "type": "object", "properties": {
                "app": app_arg(), "url": s("A public repository address, https://github.com/owner/repo.git. Omit to upload a bundle."),
                "ref": s("Branch or tag to import (default HEAD, then main)."),
                "base_version": { "type": "integer", "minimum": 1, "description": "Merge onto this version instead of the one the commit is known as." },
                "history": { "type": "string", "enum": ["tip", "all"], "description": "tip (default): one version for the commit; all: one per new commit." },
                "target": { "type": "string", "enum": ["staging", "production"], "description": "Default staging." },
                "note": s("The version's note (default: the commit's subject).")
            }, "required": ["app"] },
        },
        {
            "name": "set_git_mirror", "title": "Mirror an app to a git remote",
            "description": concat!(
                "Keep a git repository (GitHub, GitLab, Gitea, ...) in step with an app. After every deploy, publish, rollback or staging change Brod pushes in the background: the live version to the \"main\" branch, the version on staging to \"staging\", and every version as a tag vN. ",
                "Pushes only ever fast-forward: if the remote branch holds work Brod does not know, it is left alone and get_git_mirror / get_status show \"diverged\"; tags are created, never moved. ",
                "Give \"url\" (https) and an access token that can push: \"token\" (stored sealed, never shown again) or \"token_secret\", the name of one of the app's secrets. Fields left out keep their value. ",
                "With \"sync_inbound\": true a push to the remote branch (a webhook, or polling) lands on staging as a new version, merged with what is there; the answer then holds a one-time \"webhook_secret\" and the \"webhook_url\" to put in the repository's webhook settings. ",
                "Only the app's owner or a workspace admin can set this up."
            ),
            "inputSchema": { "type": "object", "properties": {
                "app": app_arg(),
                "url": s("The remote repository, https://github.com/owner/repo.git."),
                "token": s("An access token with permission to push (GitHub: a fine-grained token with Contents write). Stored sealed and never returned."),
                "token_secret": s("The name of an existing app secret that holds the token, instead of \"token\"."),
                "enabled": { "type": "boolean", "description": "Push on changes. Default true." },
                "branches": { "type": "object", "description": "Remote branch names: {\"main\": \"main\", \"staging\": \"staging\"}. An empty staging name stops pushing staging.", "properties": { "main": { "type": "string" }, "staging": { "type": "string" } } },
                "push_tags": { "type": "boolean", "description": "Push a tag vN for every version. Default true." },
                "sync_inbound": { "type": "boolean", "description": "Import pushes to the remote branch into staging. Default false." },
                "inbound_branch": s("The remote branch to import (default: the one mapped to main)."),
                "rotate_webhook_secret": { "type": "boolean", "description": "Make a new webhook secret (shown once)." }
            }, "required": ["app"] },
        },
        {
            "name": "get_git_mirror", "title": "Git mirror settings",
            "description": "Show how an app is mirrored to a git remote: address, branch mapping, the last push (time, status ok / retrying / diverged / error, and the error), each ref's state, and the recent inbound sync events with conflicts. The token and webhook secret are never shown.",
            "inputSchema": { "type": "object", "properties": { "app": app_arg() }, "required": ["app"] },
            "annotations": { "readOnlyHint": true },
        },
        { "name": "get_status", "title": "App status", "description": "Show one app: address, status, access, roles, who it is shared with, its versions with which one is live, and what is on staging (version and address).", "inputSchema": { "type": "object", "properties": { "app": app_arg() }, "required": ["app"] }, "annotations": { "readOnlyHint": true } },
        {
            "name": "get_logs", "title": "App activity and logs",
            "description": concat!("Show one app's recent activity (deploys, rollbacks, access changes, sign-in refusals, pauses, and which connection or person made each) ",
                "and, for server apps, its last 50 requests with their console output and exceptions (kept 7 days). Use \"search\" to find requests whose logs, errors or path contain some text."),
            "inputSchema": { "type": "object", "properties": { "app": app_arg(), "search": s("Only requests whose logs, exceptions or path contain this text.") }, "required": ["app"] },
            "annotations": { "readOnlyHint": true },
        },
        {
            "name": "get_deployment", "title": "Deployment status",
            "description": "Follow a container app's deployment (deploy_app or rollback returns its id): its state (scheduled, building, pulling, migrating, starting, healthy, serving; draining and stopped once replaced) and the last 50 lines of its log. A failed one returns the error build_failed, migration_failed or deployment_failed with the log lines that say why; what was live stays live.",
            "inputSchema": { "type": "object", "properties": { "app": app_arg(), "deployment": s("The deployment id. Default: the app's newest deployment.") }, "required": ["app"] },
            "annotations": { "readOnlyHint": true },
        },
        {
            "name": "set_secret", "title": "Set a secret",
            "description": concat!("Store a secret for an app's server code, such as an API key. The app reads it as env.NAME from its next request. Values are encrypted and write-only: ",
                "nobody, you included, can read one back. get_status lists the names. Give \"remove\": true instead of a value to delete one."),
            "inputSchema": {
                "type": "object",
                "properties": { "app": app_arg(), "name": s("UPPER_SNAKE_CASE name, for example \"STRIPE_KEY\"."), "value": s("The secret value, up to 5 KB."), "remove": { "type": "boolean", "description": "Delete this secret." } },
                "required": ["app", "name"],
            },
            "annotations": { "readOnlyHint": false, "destructiveHint": false, "idempotentHint": true },
        },
        {
            "name": "request_database", "title": "Add a Postgres database",
            "description": concat!("Give a container app its own Postgres database (when this Brod has managed databases). Safe to call again: it returns the database the app already has. ",
                "The app's containers get DATABASE_URL (postgres://...@brod-db.internal:5432/...) from their next deployment, so deploy the app after this. Only this app can reach its database. ",
                "DATABASE_URL is then managed by Brod and set_secret cannot change it. It is backed up nightly (backup_database takes one now); get_status shows its size and backups. ",
                "To change the schema on deploy, give deploy_app (or brod.json) a \"migrate\" command."),
            "inputSchema": { "type": "object", "properties": { "app": app_arg() }, "required": ["app"] },
            "annotations": { "readOnlyHint": false, "destructiveHint": false, "idempotentHint": true },
        },
        {
            "name": "backup_database", "title": "Back up a database",
            "description": "Back up an app's managed database now (encrypted, kept with the nightly ones). Returns the backup's id, which restore_database takes.",
            "inputSchema": { "type": "object", "properties": { "app": app_arg() }, "required": ["app"] },
            "annotations": { "readOnlyHint": false, "destructiveHint": false, "idempotentHint": false },
        },
        {
            "name": "restore_database", "title": "Restore a database",
            "description": concat!("Replace an app's managed database with a backup (the newest unless \"backup\" names one; get_status lists them). Everything written since that backup is replaced. ",
                "This needs a person: nothing changes until the owner opens the confirm_url you get back. Pass it on and tell them what will be replaced. ",
                "Once confirmed, the replaced data is kept for 24 hours and the app's containers restart."),
            "inputSchema": { "type": "object", "properties": { "app": app_arg(), "backup": s("A backup id from get_status. Default: the newest.") }, "required": ["app"] },
            "annotations": { "readOnlyHint": false, "destructiveHint": true, "idempotentHint": false },
        },
        {
            "name": "publish_staging", "title": "Publish staging",
            "description": concat!("Make the version on an app's staging address live, after the person has tried it there and said it is ready. Takes effect on the next request. ",
                "Give \"discard\": true instead to take it off staging without publishing (the version is kept; rollback can still serve it). get_status shows what is on staging."),
            "inputSchema": { "type": "object", "properties": { "app": app_arg(), "discard": { "type": "boolean", "description": "Take the version off staging instead of publishing it." } }, "required": ["app"] },
            "annotations": { "readOnlyHint": false, "destructiveHint": false, "idempotentHint": false },
        },
        { "name": "rollback", "title": "Roll back", "description": "Make an earlier version live again. Takes effect on the next request and rebuilds nothing. Use get_status to see version numbers.", "inputSchema": { "type": "object", "properties": { "app": app_arg(), "version": { "type": "integer", "description": "Version number to serve." } }, "required": ["app", "version"] }, "annotations": { "readOnlyHint": false, "destructiveHint": false, "idempotentHint": true } },
        {
            "name": "set_access", "title": "Change who can open an app",
            "description": concat!("Set an app's access mode and who holds which app role. Modes: \"private\" (owner and admins only), \"people\" (only granted people and groups), \"workspace\" (everyone in the workspace), ",
                "\"password\" (anyone with the address and the password, no sign-in or account needed: give \"password\" too), \"signed_in\" (anyone who signs in), \"public\" (anyone, no sign-in). ",
                "To share an app quietly with people outside the workspace, use \"password\": visitors see a password page, and the address plus the password is all they need. Brod keeps only a hash, so tell the owner the password you set; ",
                "setting a new one signs out everyone who used the old one, and moving the app to another mode removes it. Grants give a person (by email, must already be in the workspace), a group, an email domain, or everyone (\"workspace\"/\"signed_in\") one of the app's roles. ",
                "Narrowing access applies at once. Widening it (a more open mode, new grants or a new password) does NOT apply yet: the result has a confirm_url the owner must open and confirm. Give them that link."),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "app": app_arg(),
                    "access": { "type": "string", "enum": ["private", "people", "workspace", "password", "signed_in", "public"] },
                    "password": s("With \"access\": \"password\": the password to share the app with, 6 to 128 characters. Giving it alone switches the app to \"password\"."),
                    "add": { "type": "array", "description": "Grants to add or change.", "items": grant_item },
                    "remove": { "type": "array", "description": "Grants to remove (role is ignored).", "items": grant_item },
                },
                "required": ["app"],
            },
            "annotations": { "readOnlyHint": false, "destructiveHint": true, "idempotentHint": true },
        },
        { "name": "set_paused", "title": "Pause or resume", "description": "Pause an app (visitors see a \"paused\" page and its plan slot is freed) or resume it.", "inputSchema": { "type": "object", "properties": { "app": app_arg(), "paused": { "type": "boolean" } }, "required": ["app", "paused"] }, "annotations": { "readOnlyHint": false, "destructiveHint": false, "idempotentHint": true } },
        {
            "name": "invite", "title": "Invite someone",
            "description": concat!("Invite a person by email: into the workspace (role admin, builder or member), or as a guest to one app (give \"app\" and optionally \"app_role\"). Someone already in the workspace who is given an app just gets the role on it. ",
                "This needs the owner's confirmation: the result has a confirm_url to give them. The invitation email goes out once they confirm."),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "email": s("Their email address."),
                    "role": { "type": "string", "enum": ["admin", "builder", "member", "guest"], "description": "Workspace role. Default member, or guest when \"app\" is given." },
                    "app": s("Slug of an app to give them."),
                    "app_role": s("Their role on that app, one of the roles the app declares. Default its lowest role."),
                },
                "required": ["email"],
            },
            "annotations": { "readOnlyHint": false, "destructiveHint": false, "openWorldHint": true },
        },
        {
            "name": "set_domain", "title": "Custom domain",
            "description": concat!("Serve an app at a domain the workspace owns, such as \"shop.example.com\" (give \"app\"), or every app in the workspace under a domain, such as \"*.apps.example.com\" ",
                "(<app>.apps.example.com opens that app; admins only). The result lists two DNS records the owner must add: a TXT record that proves they own the domain, and a CNAME that sends visitors to Brod. ",
                "Call set_domain again with the same domain once the records are in to check them; the domain is served only after it is verified. Sign-in, roles and access work the same as on the app's own address. ",
                "Give \"remove\": true to stop serving a domain. get_status lists an app's domains."),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "domain": s("The domain, for example \"shop.example.com\", or \"*.apps.example.com\" for the whole workspace."),
                    "app": s("Slug of the app to serve there. Leave out for a \"*.\" domain."),
                    "remove": { "type": "boolean", "description": "Stop serving this domain." },
                },
                "required": ["domain"],
            },
            "annotations": { "readOnlyHint": false, "destructiveHint": false, "idempotentHint": true, "openWorldHint": true },
        },
        {
            "name": "set_open_paths", "title": "Open paths without sign-in",
            "description": concat!("Set which paths of an app anyone may reach without signing in, such as a webhook receiver or an MCP endpoint that does its own authentication. ",
                "Each entry is an exact path (\"/api/mcp\") or a prefix (\"/api/webhooks/*\"), optionally limited to methods: { \"path\": \"/api/mcp\", \"methods\": [\"POST\"] }. At most 10; \"/\" and \"/*\" are refused (use set_access for that). ",
                "A path is open only while the served version also declares it in the \"open_paths\" list of its brod.json, so deploying with open_paths is the usual way to ask; this tool changes the approved list. ",
                "Requests on an open path reach the app anonymously: no sign-in, no x-brod-identity, no x-brod-user-* headers. ",
                "Narrowing (removing entries, fewer methods) applies at once. Opening anything new does NOT apply yet: the result has a confirm_url the owner must open and confirm. Give them that link. get_status shows approved and pending open paths."),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "app": app_arg(),
                    "open_paths": {
                        "type": "array", "maxItems": 10, "description": "The full list of approved open paths after this call; [] closes them all.",
                        "items": { "anyOf": [
                            { "type": "string", "description": "\"/api/mcp\" or \"/api/webhooks/*\"." },
                            { "type": "object", "properties": { "path": s("\"/api/mcp\" or \"/api/webhooks/*\"."), "methods": { "type": "array", "items": { "type": "string", "enum": ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"] } } }, "required": ["path"] },
                        ] },
                    },
                },
                "required": ["app", "open_paths"],
            },
            "annotations": { "readOnlyHint": false, "destructiveHint": true, "idempotentHint": true },
        },
        {
            "name": "get_auth_integration", "title": "Identity and access for an app's code",
            "description": concat!("How an app's code learns who is signed in and how to trust it: the identity contract (the x-brod-identity JWT, its claims, the JWKS URL and env vars), ",
                "how access works (private by default, the gateway signs people in, open paths are anonymous), and a short verification snippet for a framework (the @brodsh/auth package for Next.js, Node and Workers). ",
                "Call this before writing code that reads the user, checks roles, or exposes a webhook. Never build a login or user table."),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "framework": { "type": "string", "enum": crate::identity::FRAMEWORKS, "description": "The app's framework. Default: snippets for all of them." },
                    "runtime": { "type": "string", "enum": ["workerd", "container"], "description": "Where the code runs: \"workerd\" for _worker.js server apps (the default)." },
                    "app": s("An existing app's slug, to get its exact token audience."),
                },
            },
            "annotations": { "readOnlyHint": true },
        },
        {
            "name": "get_workspace", "title": "Workspace and identity",
            "description": concat!("Read the workspace an app will live in: its groups, the default app roles, the access modes, plan slots, and how an app reads the signed-in person (the identity contract). ",
                "Call this before building an app that needs sign-in or roles: apps never keep their own user table."),
            "inputSchema": { "type": "object", "properties": {} }, "annotations": { "readOnlyHint": true },
        },
    ])
}

/// Files passed inline in a tool call (or in POST /v1/deploys when `strict` is false).
pub fn inline_files(raw: &Value, strict: bool, too_large: &str) -> Result<Vec<BundleFile>> {
    let Value::Array(list) = raw else {
        return Err(Problem::new(400, "bad_files", "\"files\" must be a list of { path, content }."));
    };
    let mut total = 0usize;
    let mut out = Vec::with_capacity(list.len());
    for f in list {
        let path = f.get("path");
        let content = f.get("content");
        if strict && !(matches!(path, Some(Value::String(_))) && matches!(content, Some(Value::String(_)))) {
            return Err(Problem::new(400, "bad_files", "Each file needs a \"path\" and a \"content\" string."));
        }
        let path = match path {
            None | Some(Value::Null) => String::new(),
            Some(v) => js_string(v),
        };
        let content = match content {
            None | Some(Value::Null) => String::new(),
            Some(v) => js_string(v),
        };
        let bytes = if f.get("encoding").and_then(|e| e.as_str()) == Some("base64") {
            atob(&content).ok_or_else(|| Problem::new(400, "bad_files", format!("{path} is not valid base64.")))?
        } else {
            content.into_bytes()
        };
        total += bytes.len();
        out.push(BundleFile { path, bytes });
    }
    if total > limits::INLINE_BYTES {
        return Err(Problem::new(413, "too_large", too_large));
    }
    Ok(out)
}

/// atob(): base64 with or without padding, ignoring ASCII whitespace.
fn atob(s: &str) -> Option<Vec<u8>> {
    let clean: String = s.chars().filter(|c| !matches!(c, ' ' | '\t' | '\n' | '\x0c' | '\r')).collect();
    let trimmed = clean.trim_end_matches('=');
    if clean.len() - trimmed.len() > 2 || (!clean.len().is_multiple_of(4) && clean.len() != trimmed.len()) || trimmed.len() % 4 == 1 {
        return None;
    }
    base64::engine::general_purpose::STANDARD_NO_PAD.decode(trimmed).ok()
}

/// The tools a read-only connection may call: they look and change nothing.
pub const READ_TOOLS: [&str; 10] = [
    "list_apps",
    "get_files",
    "diff_versions",
    "export_app",
    "get_git_mirror",
    "get_status",
    "get_logs",
    "get_deployment",
    "get_auth_integration",
    "get_workspace",
];

/// The tools this caller may use: all of them, or only the reading ones for a read-only connection.
fn tools_for(c: &Caller) -> Value {
    let mut all = tools();
    if c.read_only
        && let Value::Array(list) = &mut all
    {
        list.retain(|t| t["name"].as_str().is_some_and(|n| READ_TOOLS.contains(&n)));
    }
    all
}

async fn call(st: &State, c: &Caller, name: &str, a: &Map<String, Value>) -> Result<Value> {
    if !READ_TOOLS.contains(&name) && tools().as_array().is_some_and(|l| l.iter().any(|t| t["name"] == name)) {
        control::require_write(c, &format!("use {name}"))?;
    }
    let str_arg = |k: &str| match a.get(k) {
        None | Some(Value::Null) => String::new(),
        Some(v) => js_string(v),
    };
    let cfg = st.cfg.clone();
    let c2 = c.clone();
    match name {
        "deploy_app" => {
            let target = DeployTarget::from_json(a);
            if let Some(patch) = crate::patch::parse(a)? {
                return crate::patch::deploy_patch(st, c, target, patch).await;
            }
            match a.get("files") {
                None => st.db.call(move |conn| control::create_upload(conn, &cfg, &c2, &target)).await,
                Some(files) => {
                    let files = inline_files(
                        files,
                        true,
                        "Files passed inline can total 1 MB. Call deploy_app without \"files\" to get an upload address for larger apps.",
                    )?;
                    control::deploy(st, c, target, files).await
                }
            }
        }
        "list_apps" => st.db.call(move |conn| control::list_apps(conn, &cfg, &c2)).await,
        "get_files" => control::get_files(st, c, &str_arg("app"), a.get("version").cloned(), a.get("since").cloned()).await,
        "diff_versions" => crate::patch::diff_versions(st, c, &str_arg("app"), a.get("from"), a.get("to")).await,
        "export_app" => {
            let format = str_arg("format");
            if !format.is_empty() && format != "git-bundle" {
                return Err(Problem::new(400, "bad_format", "\"format\" is \"git-bundle\"."));
            }
            crate::git_export::export_app(st, c, &str_arg("app")).await
        }
        "import_app" => {
            use crate::git_import::{ImportRequest, Source};
            let app = str_arg("app");
            let url = str_arg("url");
            if url.trim().is_empty() {
                // No address: a one-time upload address for a bundle; the upload runs the import (api.rs deploy_upload).
                let mut options = Map::new();
                for k in ["ref", "history"] {
                    if a.get(k).is_some_and(|v| !v.is_null()) {
                        options.insert(k.into(), a[k].clone());
                    }
                }
                let target = DeployTarget {
                    app: Some(app),
                    note: Some(str_arg("note")).filter(|n| !n.is_empty()),
                    environment: Some(str_arg("target")).filter(|n| !n.is_empty()),
                    base_version: a.get("base_version").filter(|v| !v.is_null()).cloned(),
                    options: Some(options),
                    ..Default::default()
                };
                target.check_environment()?;
                let mut out = st.db.call(move |conn| control::create_upload(conn, &cfg, &c2, &target)).await?;
                if let Value::Object(m) = &mut out {
                    m.insert("kind".into(), json!("git-bundle"));
                    m.insert(
                        "next_step".into(),
                        json!("Create a bundle with `git bundle create app.bundle --all`, then upload it to upload_url: curl -sS --fail -X PUT --data-binary @app.bundle \"<upload_url>\". The upload imports it into staging."),
                    );
                }
                return Ok(out);
            }
            let r = ImportRequest::from_json(&app, a, Source::Url(url))?;
            crate::git_import::run(st, c, r).await
        }
        "set_git_mirror" => crate::git_mirror::set(st, c, &str_arg("app"), a).await,
        "get_git_mirror" => {
            let slug = str_arg("app");
            st.db.call(move |conn| crate::git_mirror::get(conn, &cfg, &c2, &slug)).await
        }
        "get_status" => {
            let slug = str_arg("app");
            st.db.call(move |conn| control::get_status(conn, &cfg, &c2, &slug).map(Value::Object)).await
        }
        "get_logs" => {
            let slug = str_arg("app");
            let search = if crate::model::truthy(a.get("search")) { Some(str_arg("search")) } else { None };
            st.db.call(move |conn| control::get_logs(conn, &c2, &slug, search.as_deref())).await
        }
        "get_deployment" => {
            let (slug, id) = (str_arg("app"), str_arg("deployment"));
            st.db.call(move |conn| crate::deployments::get_deployment(conn, &c2, &slug, Some(&id))).await
        }
        "set_secret" => {
            let remove = matches!(a.get("remove"), Some(Value::Bool(true)));
            let value = match a.get("value") {
                Some(Value::String(v)) => Some(v.clone()),
                _ if remove => None,
                _ => {
                    return Err(Problem::new(400, "bad_value", "Give \"value\", or \"remove\": true to delete the secret."));
                }
            };
            let (slug, name) = (str_arg("app"), str_arg("name"));
            let value = if remove { None } else { value };
            st.db.call(move |conn| control::set_secret(conn, &cfg, &c2, &slug, &name, value.as_deref())).await
        }
        "request_database" => crate::databases::request(st, c, &str_arg("app")).await,
        "backup_database" => crate::backups::backup_now(st, c, &str_arg("app")).await,
        "restore_database" => {
            let backup = str_arg("backup");
            crate::backups::restore(st, c, &str_arg("app"), Some(&backup)).await
        }
        "publish_staging" => {
            let slug = str_arg("app");
            if matches!(a.get("discard"), Some(Value::Bool(true))) {
                st.db.call(move |conn| control::discard_staging(conn, &cfg, &c2, &slug)).await
            } else {
                st.db.call(move |conn| control::publish_staging(conn, &cfg, &c2, &slug)).await
            }
        }
        "rollback" => {
            let slug = str_arg("app");
            let version = js_to_number(a.get("version"));
            crate::deployments::rollback(st, c, &slug, version).await
        }
        "set_access" => {
            let slug = str_arg("app");
            let mut o = Map::new();
            for k in ["access", "add", "remove", "password"] {
                if let Some(v) = a.get(k) {
                    o.insert(k.into(), v.clone());
                }
            }
            st.db.call(move |conn| control::set_access(conn, &cfg, &c2, &slug, &o, None)).await
        }
        "set_paused" => {
            let slug = str_arg("app");
            let paused = matches!(a.get("paused"), Some(Value::Bool(true)));
            st.db.call(move |conn| control::set_paused(conn, &cfg, &c2, &slug, paused)).await
        }
        "invite" => {
            let mut o = Map::new();
            for k in ["email", "role", "app", "app_role"] {
                if let Some(v) = a.get(k) {
                    o.insert(k.into(), v.clone());
                }
            }
            control::invite_from(st, c, o).await
        }
        "set_domain" => crate::domains::set_domain(st, c, a).await,
        "set_open_paths" => {
            let slug = str_arg("app");
            let list = a.get("open_paths").cloned().unwrap_or(Value::Null);
            st.db.call(move |conn| control::set_open_paths(conn, &cfg, &c2, &slug, &list)).await
        }
        "get_auth_integration" => {
            let framework = match a.get("framework") {
                None | Some(Value::Null) => None,
                Some(v) => {
                    let f = js_string(v).to_lowercase();
                    if !crate::identity::FRAMEWORKS.contains(&f.as_str()) {
                        return Err(Problem::new(
                            400,
                            "bad_framework",
                            format!("\"framework\" is one of {}.", crate::identity::FRAMEWORKS.join(", ")),
                        ));
                    }
                    Some(f)
                }
            };
            let runtime = if crate::model::truthy(a.get("runtime")) { Some(str_arg("runtime")) } else { None };
            let audience = match a.get("app") {
                None | Some(Value::Null) => None,
                Some(_) => {
                    let slug = str_arg("app");
                    Some(st.db.call(move |conn| control::get_app(conn, &c2, &slug)).await.map(|app| crate::identity::audience(&app.id))?)
                }
            };
            Ok(crate::identity::integration(&cfg, framework.as_deref(), runtime.as_deref(), audience))
        }
        "get_workspace" => st.db.call(move |conn| people::describe_workspace(conn, &cfg, &c2)).await,
        _ => Err(Problem::new(404, "unknown_tool", format!("There is no tool called \"{name}\"."))),
    }
}

fn text(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        _ => serde_json::to_string_pretty(v).unwrap_or_default(),
    }
}

async fn handle(st: &State, c: &Caller, m: &Value) -> Option<Value> {
    let id = m.get("id").filter(|v| !v.is_null())?.clone();
    let reply = |result: Value| json!({ "jsonrpc": "2.0", "id": id, "result": result });
    let method = m.get("method").and_then(|v| v.as_str()).unwrap_or("");
    let params = m.get("params");
    match method {
        "initialize" => {
            let asked = params.and_then(|p| p.get("protocolVersion")).and_then(|v| v.as_str());
            let version = asked.filter(|v| VERSIONS.contains(v)).unwrap_or(VERSIONS[0]);
            Some(reply(json!({
                "protocolVersion": version,
                "capabilities": { "tools": { "listChanged": false } },
                "serverInfo": { "name": "brod", "title": "Brod", "version": "0.2.0" },
                "instructions": concat!("Brod puts small web apps online inside a team workspace with one sign-in. Call get_workspace before building an app that needs to know who is using it: ",
                    "the platform signs people in and the app reads them from /_brod/me, so never build a login or user table. Use deploy_app to publish and return the address. ",
                    "Apps start private. To share one with people outside the workspace without accounts, set_access with \"access\": \"password\" and a password, then give them the address and the password. ",
                    "Sharing more widely and inviting people need the owner to confirm: pass on the confirm_url you get back. ",
                    "Once an app is live, ask before changing it whether to deploy to staging first: updates go to its staging address, the person tests there, and publish_staging makes it live. ",
                    "Other people may change the same app: before changing one, call get_files for its current version, and pass base_version (the version your files started from) to deploy_app, so a deploy never undoes someone else's. ",
                    "When a result has a \"warning\" that someone else is working on the app, tell the person. ",
                    "Before writing code that reads the signed-in person or must work without sign-in (a webhook), call get_auth_integration."),
            })))
        }
        "ping" => Some(reply(json!({}))),
        "tools/list" => Some(reply(json!({ "tools": tools_for(c) }))),
        "tools/call" => {
            let name =
                params.and_then(|p| p.get("name")).map(|v| if v.is_null() { String::new() } else { js_string(v) }).unwrap_or_default();
            let args = match params.and_then(|p| p.get("arguments")) {
                Some(Value::Object(a)) => a.clone(),
                _ => Map::new(),
            };
            Some(match call(st, c, &name, &args).await {
                Ok(result) => {
                    reply(json!({ "content": [{ "type": "text", "text": text(&result) }], "structuredContent": result, "isError": false }))
                }
                Err(e) if e.is_internal() => {
                    tracing::error!("{e}");
                    reply(
                        json!({ "content": [{ "type": "text", "text": "Something went wrong on our side. Try again." }], "isError": true }),
                    )
                }
                Err(e) => {
                    // Tool errors go back as results the agent can read and act on, not as protocol errors.
                    let mut body = Map::new();
                    body.insert("error".into(), json!(e.code));
                    body.insert("message".into(), json!(e.message));
                    body.extend(e.extra.iter().map(|(k, v)| (k.clone(), v.clone())));
                    reply(json!({ "content": [{ "type": "text", "text": text(&Value::Object(body)) }], "isError": true }))
                }
            })
        }
        _ => Some(json!({ "jsonrpc": "2.0", "id": id, "error": { "code": -32601, "message": format!("Method not found: {method}") } })),
    }
}

pub async fn serve(st: &State, mut req: Req) -> Result<Response> {
    if req.method != axum::http::Method::POST {
        return Ok(json_response(
            &json!({ "error": { "code": "method_not_allowed", "message": "This MCP endpoint takes POST requests only." } }),
            405,
            &[("allow", "POST".into())],
        ));
    }
    let caller = match control::authenticate_async(st, Credentials::of(&req)).await {
        Ok(c) => c,
        Err(e) if e.is_internal() => return Err(e),
        Err(e) => {
            return Ok(json_response(
                &json!({ "jsonrpc": "2.0", "id": null, "error": { "code": -32001, "message": e.message } }),
                401,
                &[(
                    "www-authenticate",
                    format!("Bearer realm=\"brod\", resource_metadata=\"{}\"", crate::connect::resource_metadata_url(&st.cfg)),
                )],
            ));
        }
    };
    if let Err(e) = st.calls.check(&caller, crate::instance::current(st).await.int("rate.calls_per_minute")) {
        return Ok(json_response(&json!({ "jsonrpc": "2.0", "id": null, "error": { "code": -32000, "message": e.message } }), 429, &[]));
    }
    let raw = req.bytes(crate::tar::BUNDLE_BYTES, "The request body").await?;
    let body: Value = match serde_json::from_slice(&raw) {
        Ok(v) => v,
        Err(_) => {
            return Ok(json_response(
                &json!({ "jsonrpc": "2.0", "id": null, "error": { "code": -32700, "message": "Parse error" } }),
                400,
                &[],
            ));
        }
    };
    if let Value::Array(list) = &body {
        let mut replies = Vec::new();
        for m in list {
            if let Some(r) = handle(st, &caller, m).await {
                replies.push(r);
            }
        }
        return Ok(if replies.is_empty() { empty(202) } else { json_response(&Value::Array(replies), 200, &[]) });
    }
    Ok(match handle(st, &caller, &body).await {
        Some(r) => json_response(&r, 200, &[]),
        None => empty(202),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lists_the_tools_in_order() {
        let names: Vec<String> = tools().as_array().unwrap().iter().map(|t| t["name"].as_str().unwrap().to_string()).collect();
        assert_eq!(
            names,
            [
                "deploy_app",
                "list_apps",
                "get_files",
                "diff_versions",
                "export_app",
                "import_app",
                "set_git_mirror",
                "get_git_mirror",
                "get_status",
                "get_logs",
                "get_deployment",
                "set_secret",
                "request_database",
                "backup_database",
                "restore_database",
                "publish_staging",
                "rollback",
                "set_access",
                "set_paused",
                "invite",
                "set_domain",
                "set_open_paths",
                "get_auth_integration",
                "get_workspace"
            ]
        );
    }

    #[test]
    fn read_only_connections_see_only_the_reading_tools() {
        let user = crate::model::User { id: "usr_a".into(), email: "a@a.test".into(), name: String::new(), email_verified_at: None };
        let workspace = crate::model::Workspace {
            id: "ws_a".into(),
            slug: "a".into(),
            name: "A".into(),
            plan: "free".into(),
            color: String::new(),
            icon: String::new(),
            created_at: 0,
        };
        let mut c = Caller { workspace, user, role: "builder".into(), actor: "agent".into(), agent: true, read_only: false };
        let all = tools_for(&c).as_array().unwrap().len();
        c.read_only = true;
        let names: Vec<String> = tools_for(&c).as_array().unwrap().iter().map(|t| t["name"].as_str().unwrap().to_string()).collect();
        assert_eq!(names, READ_TOOLS);
        assert_eq!(all, tools().as_array().unwrap().len());
        // Every reading tool says so in its annotations.
        for t in tools().as_array().unwrap() {
            assert_eq!(READ_TOOLS.contains(&t["name"].as_str().unwrap()), t["annotations"]["readOnlyHint"] == true, "{}", t["name"]);
        }
    }

    #[test]
    fn decodes_inline_files() {
        let files = inline_files(
            &json!([{ "path": "a.txt", "content": "aGk=", "encoding": "base64" }, { "path": "b.txt", "content": "x" }]),
            true,
            "big",
        )
        .unwrap();
        assert_eq!(files[0].bytes, b"hi");
        assert_eq!(
            inline_files(&json!([{ "path": "a", "content": "!!", "encoding": "base64" }]), true, "big").unwrap_err().code,
            "bad_files"
        );
        assert_eq!(inline_files(&json!([{ "path": 1, "content": "x" }]), true, "big").unwrap_err().code, "bad_files");
        assert_eq!(inline_files(&json!("x"), true, "big").unwrap_err().code, "bad_files");
        let big = "a".repeat(limits::INLINE_BYTES + 1);
        assert_eq!(inline_files(&json!([{ "path": "a", "content": big }]), true, "big").unwrap_err().code, "too_large");
    }
}
