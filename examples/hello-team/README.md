# hello-team: an on-call rota

A small app of the kind an agent builds for a team in a few minutes: who is on call each day for the next two weeks.

- `_worker/index.js` is the server code. It serves the page, `_worker/page.html`, and a small JSON API.
- Brod signs people in. The app reads who they are from the `x-brod-user-email`, `x-brod-user-name` and `x-brod-role`
  headers, and keeps no user table.
- The rota is stored in the app's own SQLite database (`env.DB`). Editors and the owner can change it; viewers can
  read it.

## Deploy it

With your agent connected to Brod ([docs/mcp.md](../../docs/mcp.md)), ask it from the repository's folder:

> Deploy examples/hello-team to Brod as "On-call rota".

The agent sends the two files in one `deploy_app` call and gives you the app's address. The app starts private: share it
with your team with `set_access` (for example "share the on-call rota with the whole workspace, as viewers, and make
Bo an editor").

Without an agent, upload a zip of this folder on the admin page (**Apps → Deploy**).
