#!/usr/bin/env bash
# Containers and endpoint health (just status).
set -euo pipefail
# shellcheck source=stack-engine.sh
. "$(dirname "${BASH_SOURCE[0]}")/stack-engine.sh"
if [ -f "$LOCAL/.env.secrets" ]; then compose ps; else say "(not started: no deploy/local/.env.secrets yet)"; fi
probe() { if curl -fsS -o /dev/null --max-time 3 "$2" 2>/dev/null; then printf '  %-18s up    %s\n' "$1" "$2"; else printf '  %-18s DOWN  %s\n' "$1" "$2"; fi; }
say; say "endpoints:"
probe "Keycloak (OIDC)" http://localhost:8180/realms/fieldseal/.well-known/openid-configuration
probe "factory" http://localhost:8080/readyz
probe "web app" http://127.0.0.1:8090/instruments
probe "intake uploads" http://localhost:8480/healthz
probe "intake portal" http://localhost:8481/
probe "transparency log" http://localhost:9001/checkpoint
