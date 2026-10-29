#!/usr/bin/env bash
# The opener the CLI runs in the demo container (FIELDSEAL_BROWSER=/opt/fieldseal/tools/stack-browser.sh)
# for an operator sign-in (`fieldseal roster issue` and `roster assign`). It receives the
# authorisation URL as its first argument and has tools/local-stack-passkey.py sign in at it as
# product-owner with a passkey (registering one first). Keycloak then redirects to the CLI's
# loopback listener; the listener and this browser share Keycloak's network namespace, so the
# redirect arrives. tools/dev-web.sh does not use it: under the development IdP the CLI runs with
# `--browser none`. Each run resets the user's passkeys (see local-stack-passkey.py).
set -euo pipefail

: "${1:?the authorisation URL}"
exec python3 -I /opt/fieldseal/tools/local-stack-passkey.py --open "$1"
