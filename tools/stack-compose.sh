#!/usr/bin/env bash
# Runs compose for the stack with the chosen engine: tools/stack-compose.sh ps | logs -f | ...
set -euo pipefail
# shellcheck source=stack-engine.sh
. "$(dirname "${BASH_SOURCE[0]}")/stack-engine.sh"
[ -f "$LOCAL/.env.secrets" ] || die "the stack has not been started yet: just up"
compose "$@"
