#!/usr/bin/env bash
# Stops the stack. Without --purge the volumes stay: the registered device, the passkey and the log.
# --purge also removes the Keycloak realm record (deploy/local/.state/realm.sha256), and nothing
# else under .state, which `just web` uses.
#   tools/stack-down.sh [--purge]        (just down | just purge)
# Needs only the container engine: compose only reads the secrets to interpolate them, so when
# they are gone placeholders stand in and leftovers are still removed.
set -euo pipefail
# shellcheck source=stack-engine.sh
. "$(dirname "${BASH_SOURCE[0]}")/stack-engine.sh"
if [ -f "$LOCAL/.env.secrets" ]; then
  down() { compose --profile demo down "$@"; }
else
  export KC_BOOTSTRAP_ADMIN_PASSWORD=unused FIELDSEAL_SECRET_FACTORY_OIDC_CLIENT_SECRET=unused FIELDSEAL_SECRET_INTAKE_OIDC_CLIENT_SECRET=unused
  down() { "${COMPOSE[@]}" "${COMPOSE_FILES[@]}" --profile demo down "$@"; }
fi
if [ "${1:-}" = --purge ]; then
  down -v --remove-orphans
  rm -rf "$LOCAL/.out" "$LOCAL/.generated" "$LOCAL/.env.secrets" "$LOCAL/.state/realm.sha256"
  say "stopped, and removed the volumes, the generated files, the secrets and the realm record"
else
  down --remove-orphans
  say "stopped. The volumes are kept; \`just purge\` forgets everything."
fi
