#!/usr/bin/env bash
# Opt-in smoke check of the local compose stack. NOT part of `cargo test`, and it refuses to
# run in CI (it needs a container engine, pulls the Keycloak image and builds images with nix).
#
#   tools/stack-smoke.sh [--no-up] [--keep] [--browser]    (just smoke)
#
#   --no-up     check a stack that is already running (do not start it)
#   --keep      leave the stack running afterwards (default: stop it, keeping its volumes)
#   --browser   also run the whole demo in the demo container (tools/stack-run.sh demo): headless
#               Chromium with a virtual authenticator registers a passkey, a device registers,
#               captures, uploads and verifies the receipts
#
# Checks: the log, the upload endpoint and the factory answer their probes; Keycloak serves
# OIDC discovery for the realm with the endpoints and the issuer the factory expects; the
# realm requires the passkey flow; the factory's sign-in redirects to Keycloak with PKCE and
# asks for acr=phr; Keycloak shows its username form.
set -euo pipefail

if [ -n "${CI:-}" ] || [ -n "${GITHUB_ACTIONS:-}" ] || [ -n "${GITLAB_CI:-}" ] || [ -n "${BUILDKITE:-}" ]; then
  echo "stack-smoke: refusing to run in CI (it is a local, opt-in check)" >&2
  exit 2
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
UP=1; KEEP=0; BROWSER=0
for a in "$@"; do
  case "$a" in
    --no-up) UP=0 ;; --keep) KEEP=1 ;; --browser) BROWSER=1 ;;
    *) echo "unknown option $a" >&2; exit 2 ;;
  esac
done

FAILS=0
ok() { printf '  ok    %s\n' "$*"; }
bad() { printf '  FAIL  %s\n' "$*"; FAILS=$((FAILS + 1)); }
# yes_no <what> <test...>: ok when the test succeeds, FAIL otherwise.
yes_no() { local what="$1"; shift; if "$@"; then ok "$what"; else bad "$what"; fi; }
check() { local what="$1"; shift; if "$@" >/dev/null 2>&1; then ok "$what"; else bad "$what"; fi; }

if [ "$UP" = 1 ]; then "$ROOT/tools/stack-up.sh"; fi
cleanup() { if [ "$KEEP" = 0 ] && [ "$UP" = 1 ]; then "$ROOT/tools/stack-down.sh"; fi; }
trap cleanup EXIT

ISSUER="http://localhost:8180/realms/fieldseal"
echo "== probes"
check "factory /healthz" curl -fsS --max-time 5 http://localhost:8080/healthz
check "factory /readyz" curl -fsS --max-time 5 http://localhost:8080/readyz
check "upload /healthz" curl -fsS --max-time 5 http://localhost:8480/healthz
check "transparency log /checkpoint" curl -fsS --max-time 5 http://localhost:9001/checkpoint
check "Keycloak ready" curl -fsS --max-time 5 "$ISSUER/.well-known/openid-configuration"

echo "== OIDC discovery"
DISC="$(curl -fsS --max-time 5 "$ISSUER/.well-known/openid-configuration" || true)"
field() { printf '%s' "$DISC" | sed -n "s/.*\"$1\":\"\\([^\"]*\\)\".*/\\1/p" | head -1; }
if [ "$(field issuer)" = "$ISSUER" ]; then ok "issuer is $ISSUER"; else bad "issuer is '$(field issuer)', expected $ISSUER"; fi
for f in authorization_endpoint token_endpoint jwks_uri; do
  case "$(field $f)" in http://localhost:8180/*) ok "$f is on localhost:8180" ;; *) bad "$f is '$(field $f)'" ;; esac
done
yes_no "PKCE S256 is advertised" grep -q '"S256"' <<<"$DISC"
check "JWKS is served" curl -fsS --max-time 5 "$(field jwks_uri)"

echo "== sign-in through the factory"
LOCATION="$(curl -sS --max-time 5 -o /dev/null -D - http://localhost:8080/sign-in | tr -d '\r' | sed -n 's/^[Ll]ocation: //p')"
case "$LOCATION" in "$ISSUER"/protocol/openid-connect/auth?*) ok "redirects to Keycloak's authorization endpoint" ;; *) bad "redirect was '$LOCATION'" ;; esac
case "$LOCATION" in *code_challenge_method=S256*) ok "uses PKCE (S256)" ;; *) bad "no PKCE" ;; esac
case "$LOCATION" in *acr_values=phr*) ok "asks for acr=phr" ;; *) bad "does not ask for acr=phr" ;; esac
JAR="$(mktemp)"; trap 'rm -f "$JAR"; cleanup' EXIT
FORM="$(curl -sS --max-time 10 -L -c "$JAR" -b "$JAR" "$LOCATION" || true)"
yes_no "Keycloak shows the username form (then the passkey step)" grep -q 'name="username"' <<<"$FORM"

echo "== realm"
PASS="$(sed -n 's/^KC_BOOTSTRAP_ADMIN_PASSWORD=//p' "$ROOT/deploy/local/.env.secrets")"
TOKEN="$(curl -sS --max-time 10 -d grant_type=password -d client_id=admin-cli -d username=admin --data-urlencode "password=$PASS" http://localhost:8180/realms/master/protocol/openid-connect/token | sed -n 's/.*"access_token":"\([^"]*\)".*/\1/p')"
if [ -n "$TOKEN" ]; then
  REALM="$(curl -sS --max-time 10 -H "Authorization: Bearer $TOKEN" http://localhost:8180/admin/realms/fieldseal)"
  yes_no "the realm's browser flow is the passkey flow" grep -q '"browserFlow":"fieldseal passkey browser"' <<<"$REALM"
  yes_no "the realm maps level 2 to acr phr" grep -q 'acr.loa.map' <<<"$REALM"
else
  bad "could not authenticate to the Keycloak admin API"
fi

if [ "$BROWSER" = 1 ]; then
  echo "== demo container (virtual authenticator, device registration, upload, receipts)"
  if "$ROOT/tools/stack-run.sh" demo; then ok "the end-to-end demo"; else bad "the end-to-end demo"; fi
fi

echo
if [ "$FAILS" = 0 ]; then echo "local stack: all checks passed"; else echo "local stack: $FAILS check(s) failed"; exit 1; fi
