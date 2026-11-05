#!/bin/bash
# SSH forced command for the deploy key: the only thing the key can do is
#   ssh <server> 0.2.0        -> upgrade to 0.2.0
#   ssh <server> force 0.1.0  -> same, with BROD_FORCE=1 (downgrade / skip the compose-file hold)
# authorized_keys:
#   restrict,command="/opt/brod/upgrade-ssh.sh" ssh-ed25519 AAAA... github-deploy
set -eu -o pipefail
set -f  # split the command into words, no globbing
# shellcheck disable=SC2086
set -- ${SSH_ORIGINAL_COMMAND:-}
if [ "${1:-}" = force ]; then export BROD_FORCE=1; shift; fi
case "${1:-}" in
  [0-9]*.[0-9]*.[0-9]*) ;;
  *) echo "usage: <version> | force <version>" >&2; exit 2 ;;
esac
[ $# -eq 1 ] || { echo "usage: <version> | force <version>" >&2; exit 2; }
export BROD_DIR=/opt/brod
export BROD_BACKUP_CMD=/root/backup/brod-backup.sh
export BROD_HEALTH_URL=https://brod.sh/readyz
/opt/brod/upgrade.sh "$1" 2>&1 | tee -a /var/log/brod-upgrade.log
