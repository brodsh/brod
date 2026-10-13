# Security policy

## Reporting a vulnerability

Please do not open a public issue. Report it privately through GitHub: on the repository's **Security** tab, choose
**Report a vulnerability**. Include what you found, how to reproduce it, and which version or commit you used.

What to expect:

- an acknowledgement within 3 working days;
- an assessment, and a plan for a fix, within 10 working days;
- a fix released, and the advisory published with credit to you (unless you prefer otherwise), within 90 days of your
  report. If a fix takes longer, we agree a date with you.

Please give us that time before you publish details.

## Supported versions

Security fixes go into the latest minor release. Brod is at 0.x: upgrade to the latest release to receive them.

## Scope

In scope: the Brod server, the runtime sidecar and supervisor, the Docker images and Compose files in this repository,
and the hosted service at brod.sh.

What Brod does and does not protect against is described in [docs/security.md](docs/security.md). Reports about the
known limits listed there (for example, a server app that stalls other server apps) are welcome, but they are known.
