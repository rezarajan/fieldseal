#!/usr/bin/env bash
# The hook tools/local-stack-passkey.py runs once the portal has issued a registration token
# (in FIELDSEAL_TOKEN): the device in /device builds its sealed request against the stack's trust
# bundle and submits it to the factory (FIELDSEAL_FACTORY_URL). The LAST line it prints is the
# JSON {"words": "...", "tenancy": "..."} that the browser flow confirms in the portal.
set -euo pipefail

: "${FIELDSEAL_TOKEN:?the registration token}"
W=/tmp/demo
mkdir -p "$W"
req="$(fieldseal registration request --token "$FIELDSEAL_TOKEN" \
  --trust-bundle /authority/trust-bundle.bundle --device-dir /device --out "$W/device.request" --json)"
printf '%s\n' "$req" >&2
sub="$(fieldseal registration submit "$W/device.request" --json)"
printf '%s\n' "$sub" >&2
words="$(printf '%s' "$req" | jq -r '.words')"
tenancy="$(printf '%s' "$req" | jq -r '.tenancy')"
jq -cn --arg words "$words" --arg tenancy "$tenancy" '{words: $words, tenancy: $tenancy}'
