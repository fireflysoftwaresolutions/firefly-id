#!/bin/bash
set -euo pipefail
# Keycloak has no generic *_FILE secret option. Read mounted files and use its
# supported raw environment source so special characters are preserved.
export KCRAW_DB_PASSWORD="$(cat /run/secrets/db-password)"
export KCRAW_BOOTSTRAP_ADMIN_PASSWORD="$(cat /run/secrets/admin-password)"
exec /opt/keycloak/bin/kc.sh "$@"
