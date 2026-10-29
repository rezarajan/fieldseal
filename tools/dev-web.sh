#!/usr/bin/env bash
# `just web`: the dev loop without containers. Runs the transparency log, the factory and the
# intake app and collector stand-in (fieldseal-web in stack mode) natively from a rendered deployment manifest,
# behind a development OIDC provider (fieldseal-dev-idp, in the place Keycloak takes in the stack),
# publishes the bundled examples and the publishing policy through the log, issues the example
# rosters and assigns their cohorts, one survey to each of the logins `presenter` and `collector1` (fieldseal roster issue and assign,
# signed in at the development IdP with no browser), has the factory build bundles for the
# devices that register (served at GET /v1/bundle), and re-reads the survey files on every
# request, so an edit shows at once. Ctrl-C stops everything.
#
#   tools/dev-web.sh            (normally: just web)
#   tools/dev-web.sh --check    start everything, wait for each service, run the checks (the
#                               development adapters each service reports against the manifest, the
#                               pages, the edit-and-reload check), stop everything; exit 0 when
#                               every check passes
#   tools/dev-web.sh --check --browser
#                               also run, in a headless browser, the cookie-scoping check
#                               (tools/browser-tests/cookies.sh) and the eight steps of the guided
#                               demo (tools/browser-tests/demo-e2e.sh) and the phone-fit check
#                               (tools/browser-tests/phone-fit.sh) and the survey picker test
#                               (tools/browser-tests/picker.sh); all need chromium and
#                               python3 with `websockets`, both in the dev shell
#
# State is in deploy/local/.state/dev-web/ (git-ignored): remove it to start over. `just web` and
# `just up` use the same ports, so they cannot run together. Environment: FIELDSEAL_BIN (a CLI to
# use instead of building one).
# shellcheck disable=SC2030,SC2031 # PATH and HOME are reset on purpose inside the subshells that start a process
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
STATE="$ROOT/deploy/local/.state/dev-web"
MANIFEST="examples/deployments/dev-web.yaml"
LOGS="$STATE/logs"
CHECK=0
BROWSER=0
for arg in "$@"; do
  case "$arg" in
    --check) CHECK=1 ;;
    --browser) BROWSER=1 ;;
    *) echo "usage: tools/dev-web.sh [--check [--browser]]" >&2; exit 2 ;;
  esac
done
[ "$BROWSER" = 0 ] || [ "$CHECK" = 1 ] || { echo "usage: tools/dev-web.sh [--check [--browser]]  (--browser belongs to --check)" >&2; exit 2; }

say() { printf '%s\n' "$*"; }
die() { printf 'web: %s\n' "$*" >&2; exit 1; }

# 1. The ports.
PORTS=("8080:the factory" "8090:the collector stand-in" "8180:the development IdP" "8480:the intake upload endpoint" "8481:the results reader" "9001:the transparency log")
for entry in "${PORTS[@]}"; do
  port="${entry%%:*}"
  if (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null; then
    die "port $port (${entry#*:}) is already in use, so nothing was started. Stop what holds it ('just down' stops the compose stack, which uses the same ports) and run again."
  fi
done

PIDS=()
BACKUP=""
BACKUP_PO=""
EDITED="$ROOT/examples/surveys/household-water-access/instrument.yaml"
EDITED_PO="$ROOT/examples/surveys/household-water-access/i18n/es.po"
# shellcheck disable=SC2329 # run by the traps
cleanup() {
  trap - EXIT INT TERM
  # An edit check interrupted half-way puts the survey files back.
  if [ -n "$BACKUP" ] && [ -f "$BACKUP" ]; then cat "$BACKUP" > "$EDITED"; rm -f "$BACKUP"; fi
  if [ -n "$BACKUP_PO" ] && [ -f "$BACKUP_PO" ]; then cat "$BACKUP_PO" > "$EDITED_PO"; rm -f "$BACKUP_PO"; fi
  local i
  for ((i = ${#PIDS[@]} - 1; i >= 0; i--)); do kill "${PIDS[i]}" 2>/dev/null || true; done
  for pid in "${PIDS[@]}"; do wait "$pid" 2>/dev/null || true; done
  [ "$CHECK" = 1 ] || say "stopped"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

mkdir -p "$STATE/authority" "$STATE/env" "$STATE/cli/registry" "$STATE/factory" "$STATE/log" "$STATE/logs" "$STATE/published" "$STATE/landing" "$STATE/submissions" "$STATE/bundles" "$STATE/issued"
# The factory refuses an issued-roster directory that group or others can reach (the files carry roster data); intake runs as the same user.
chmod 700 "$STATE/issued"
# The roster store holds display names and consent: owner-only, as the store requires.
mkdir -p "$STATE/rosters"; chmod 700 "$STATE/rosters"

# 2. The CLI, built once; tools/stack-init.sh and tools/dev-publish.sh use this binary.
FIELDSEAL_BIN="$("$ROOT/tools/stack-cli.sh")"
export FIELDSEAL_BIN
export FIELDSEAL_ENVIRONMENT=development

# The client secrets of the development IdP, made once (mode 0600, git-ignored with the rest of
# the state) as 48 hex digits each, as tools/stack-up.sh makes the stack's. The manifest names them
# `{ secretRef: ... }`; only the development IdP, the factory and the intake app get them in their
# environment.
rand_hex() { head -c "$1" /dev/urandom | od -An -vtx1 | tr -d ' \n'; }
if [ -f "$STATE/secrets" ]; then
  mode="$(stat -c %a "$STATE/secrets" 2>/dev/null || stat -f %Lp "$STATE/secrets")"
  [ "$mode" = 600 ] || die "$STATE/secrets has mode $mode, not 600. Run 'chmod 600 $STATE/secrets' (or remove the file to make new secrets) and run again."
else
  ( umask 077
    { echo "# Generated by tools/dev-web.sh. Local development only. Never commit."
      echo "FIELDSEAL_SECRET_FACTORY_OIDC_CLIENT_SECRET=$(rand_hex 24)"
      echo "FIELDSEAL_SECRET_INTAKE_OIDC_CLIENT_SECRET=$(rand_hex 24)"
    } > "$STATE/secrets" ) || die "could not write $STATE/secrets"
fi
mapfile -t SECRETS < <(grep -v '^[[:space:]]*\(#\|$\)' "$STATE/secrets")
# The factory and the intake app each get their own client secret and no other (the dev IdP keeps both).
mapfile -t FACTORY_SECRET < <(printf '%s\n' "${SECRETS[@]}" | grep '^FIELDSEAL_SECRET_FACTORY_OIDC_CLIENT_SECRET=')
mapfile -t INTAKE_SECRET < <(printf '%s\n' "${SECRETS[@]}" | grep '^FIELDSEAL_SECRET_INTAKE_OIDC_CLIENT_SECRET=')

# 3. The manifest. The rendered environment is the only configuration the services read (DEP-012).
VALIDATED="$("$FIELDSEAL_BIN" deployment validate "$MANIFEST" --json)" || die "the manifest does not validate: fieldseal deployment validate $MANIFEST"
find "$STATE/env" -maxdepth 1 -name '*.env' -delete
"$FIELDSEAL_BIN" deployment render "$MANIFEST" --environment development --out "$STATE/env" >/dev/null || die "could not render $MANIFEST"
say "rendered the environment of $(basename "$MANIFEST") to deploy/local/.state/dev-web/env"

# 4. The authority, made once.
FIELDSEAL_AUTHORITY_DIR="$STATE/authority" "$ROOT/tools/stack-init.sh" >"$LOGS/authority.log" 2>&1 || { tail -n 20 "$LOGS/authority.log" >&2; die "could not create the authority (deploy/local/.state/dev-web/logs/authority.log)"; }

say "building the services"
cargo build -q -p fieldseal-translog -p fieldseal-factory -p fieldseal-intake-app -p fieldseal-web -p fieldseal-dev-idp
TARGET="$(cargo metadata --format-version 1 --no-deps | jq -r .target_directory)/debug"

# The browser device is the format core compiled to WebAssembly (the Device page and the guided
# demo need it). Nix builds it; FIELDSEAL_WEB_WASM_DIR names a bundle you already have.
WASM_DIR="${FIELDSEAL_WEB_WASM_DIR:-}"
if [ -z "$WASM_DIR" ]; then
  WASM_DIR="$(nix build --no-link --print-out-paths "path:$ROOT#fieldseal-wasm" 2>"$LOGS/wasm.log")" || WASM_DIR=""
fi
if [ -n "$WASM_DIR" ] && [ -f "$WASM_DIR/fieldseal_wasm_bg.wasm" ]; then
  say "the browser device (WebAssembly): $WASM_DIR"
else
  WASM_DIR=""
  say "warning: no WebAssembly bundle, so the Device page cannot run (set FIELDSEAL_WEB_WASM_DIR, or install Nix: deploy/local/.state/dev-web/logs/wasm.log)"
fi

# start <name> <binary> <env file> [NAME=value...] [-- argument...]: the process gets the rendered
# environment and nothing else of ours (the log refuses unknown FIELDSEAL_TRANSLOG_ variables). The
# variables, secrets among them, are read inside a subshell that clears the environment and then
# execs the binary, so they never appear on a command line.
start() {
  local name="$1" bin="$2" envfile="$3"; shift 3
  local vars=() extra=() args=()
  [ -z "$envfile" ] || mapfile -t vars < <(grep -v '^[[:space:]]*\(#\|$\)' "$envfile")
  while [ "$#" -gt 0 ] && [ "$1" != "--" ]; do extra+=("$1"); shift; done
  [ "$#" -eq 0 ] || { shift; args=("$@"); }
  (
    keep_path="$PATH"; keep_home="$HOME"
    for v in $(compgen -e); do unset "$v"; done
    export PATH="$keep_path" HOME="$keep_home" FIELDSEAL_ENVIRONMENT=development
    # shellcheck disable=SC2163 # each item is NAME=value
    for kv in "${vars[@]}" "${extra[@]}"; do export "$kv"; done
    exec "$bin" "${args[@]}"
  ) >"$LOGS/$name.log" 2>&1 &
  PIDS+=("$!")
}

# wait_for <name> <url> <seconds>: the service answers, or the run stops with its log.
wait_for() {
  local name="$1" url="$2" i=0 pid="${PIDS[${#PIDS[@]} - 1]}"
  until curl -fsS -o /dev/null --max-time 2 "$url" 2>/dev/null; do
    kill -0 "$pid" 2>/dev/null || { tail -n 20 "$LOGS/$name.log" >&2; die "$name stopped (deploy/local/.state/dev-web/logs/$name.log)"; }
    i=$((i + 1)); [ "$i" -lt "$3" ] || die "$name did not answer at $url"
    sleep 1
  done
  say "ready: $name ($url)"
}

# 4b. The development IdP, before the services that sign in against it. It is a tool, not a
# component: it reads no rendered environment and takes the secrets of the clients it knows.
start dev-idp "$TARGET/fieldseal-dev-idp" "" "${SECRETS[@]}" -- --development-tool --config examples/deployments/dev-idp.yaml --bind localhost:8180
wait_for dev-idp http://localhost:8180/realms/fieldseal/.well-known/openid-configuration 60

# 5. The log, then the bundled examples and the policy, which later steps need.
start translog "$TARGET/fieldseal-translog" "$STATE/env/publishing.env"
wait_for translog http://127.0.0.1:9001/checkpoint 60
"$ROOT/tools/dev-publish.sh" --all >"$LOGS/publish.log" 2>&1 || { tail -n 20 "$LOGS/publish.log" >&2; die "could not publish the examples (deploy/local/.state/dev-web/logs/publish.log)"; }
say "published the bundled instruments, layouts and policy (deploy/local/.state/dev-web/logs/publish.log)"

# 6. The factory, signing in through the production OIDC adapter against the development IdP.
start factory "$TARGET/fieldseal-factory" "$STATE/env/factory.env" "${FACTORY_SECRET[@]}"
wait_for factory http://127.0.0.1:8080/healthz 60

# 6b. The rosters and the assignment, in the production order: publish (above), issue, assign. The
# factory refuses an assignment for a survey that is not published or a cohort with no roster. The
# CLI signs the operator in at the development IdP (`--browser none`: no human) as `presenter`,
# whose account the assignment names; it needs no secret, so it gets a cleared environment.
# Both commands are idempotent: a second run prints `unchanged`.
PRESENTER=00000000-0000-4000-8000-000000000001
# cli <fieldseal args...>: the CLI in an environment of PATH, HOME and the sign-in settings only.
cli() {
  env -i PATH="$PATH" HOME="$HOME" \
    FIELDSEAL_OIDC_ISSUER=http://localhost:8180/realms/fieldseal FIELDSEAL_OIDC_CLIENT_ID=fieldseal-cli \
    "$FIELDSEAL_BIN" "$@"
}
cli roster issue --factory-url http://localhost:8080 --browser none --login presenter \
  examples/rosters/village-a.yaml examples/rosters/cohort-a.yaml >"$LOGS/roster.log" 2>&1 \
  || { tail -n 20 "$LOGS/roster.log" >&2; die "could not issue the example rosters (deploy/local/.state/dev-web/logs/roster.log)"; }
# Each of these accounts gets one survey: the presenter the water survey, collector1 the
# school-meals survey. (`--check --browser` gives collector2 both, for the survey picker.)
COLLECTOR1=00000000-0000-4000-8000-000000000002
cli roster assign --factory-url http://localhost:8080 --browser none --login presenter --account "$PRESENTER" \
  --assign household-water-access=village-a >>"$LOGS/roster.log" 2>&1 \
  || { tail -n 20 "$LOGS/roster.log" >&2; die "could not assign the cohorts (deploy/local/.state/dev-web/logs/roster.log)"; }
cli roster assign --factory-url http://localhost:8080 --browser none --login presenter --account "$COLLECTOR1" \
  --assign school-meals-baseline=cohort-a >>"$LOGS/roster.log" 2>&1 \
  || { tail -n 20 "$LOGS/roster.log" >&2; die "could not assign the cohorts (deploy/local/.state/dev-web/logs/roster.log)"; }
say "issued the example rosters and assigned household-water-access to the presenter account and school-meals-baseline to collector1 (deploy/local/.state/dev-web/logs/roster.log)"

# 7. The intake app: the upload endpoint on :8480 and the results reader on :8481. It replays what
# it stored before it listens, so a restart keeps what has landed. The results reader signs in
# through the production OIDC adapter against the development IdP. The export key was made with
# the authority above; the app never creates it.
start intake "$TARGET/fieldseal-intake" "$STATE/env/intake.env" "${INTAKE_SECRET[@]}"
wait_for intake http://127.0.0.1:8480/healthz 60

# 8. The collector stand-in, on 127.0.0.1 while the services are on localhost, so cookies are not sent to it.
# Its device accepts the publishers the intake component's policy engine does: the same two lists, from the rendered environment.
env_value() { sed -n "s/^$2=//p" "$1" | head -n 1; }
start web "$TARGET/fieldseal-web" "" \
  FIELDSEAL_WEB_STACK=true FIELDSEAL_WEB_BIND=127.0.0.1:8090 \
  FIELDSEAL_WEB_ALLOWED_BUILDERS="$(env_value "$STATE/env/intake.env" FIELDSEAL_INTAKE_ALLOWED_BUILDERS)" \
  FIELDSEAL_WEB_ALLOWED_SOURCES="$(env_value "$STATE/env/intake.env" FIELDSEAL_INTAKE_ALLOWED_SOURCES)" \
  FIELDSEAL_WEB_EXAMPLES_DIR="$ROOT/examples" FIELDSEAL_WEB_WASM_DIR="$WASM_DIR" \
  FIELDSEAL_WEB_AUTHORITY_DIR="$STATE/authority" FIELDSEAL_WEB_PUBLISHED_DIR="$STATE/published" FIELDSEAL_WEB_REGISTRY_DIR="$STATE/cli/registry" \
  FIELDSEAL_WEB_ROSTER_DIR="$STATE/rosters" \
  FIELDSEAL_FACTORY_URL=http://localhost:8080 FIELDSEAL_UPLOAD_URL=http://localhost:8480 FIELDSEAL_LOG_URL=http://localhost:9001 FIELDSEAL_WEB_PUBLIC_URL=http://127.0.0.1:8090 \
  FIELDSEAL_WEB_RESULTS_URL=http://localhost:8481
wait_for web http://127.0.0.1:8090/healthz 60

# sign_in_as <login> <cookie jar> <base url> <path>: signs in to a service through the development
# IdP's login page without a browser, and prints the status of <path> afterwards. /sign-in redirects
# to the IdP and sets the pre-auth cookie (Path=/sign-in); the IdP's `login_hint` picks the login
# and approves at once; the callback then sets the session cookie. The jar carries both cookies.
sign_in_as() {
  local login="$1" jar="$2" base="$3" path="$4" to
  to="$(curl -sS -c "$jar" -b "$jar" -o /dev/null -w '%{redirect_url}' --max-time 10 "$base/sign-in")" || return 1
  [ -n "$to" ] || return 1
  curl -sS -L -c "$jar" -b "$jar" -o /dev/null --max-time 20 "$to&login_hint=$login" || return 1
  curl -s -c "$jar" -b "$jar" -o /dev/null -w '%{http_code}' --max-time 10 "$base$path"
}

# portal_devices <jar>: the factory portal's home page for the signed-in login.
portal_home() { curl -fsS -b "$1" --max-time 10 http://localhost:8080/; }
# portal_csrf <jar>: the CSRF token the portal's forms carry.
portal_csrf() { portal_home "$1" | sed -n 's/.*name="csrf" value="\([^"]*\)".*/\1/p' | head -n 1; }

# retire_devices <jar>: retires every live device of the signed-in login, so the cohort slot is
# free (one active tenancy per cohort) and a second run of the check starts clean.
retire_devices() {
  local jar="$1" csrf id
  csrf="$(portal_csrf "$jar")"
  while read -r id; do
    [ -n "$id" ] || continue
    curl -fsS -b "$jar" -o /dev/null --max-time 10 -d "csrf=$csrf" "http://localhost:8080/devices/$id/retire" || die "check: could not retire device $id"
  done < <(portal_home "$jar" | grep -o 'action="/devices/[^"/]*/retire"' | sed 's|action="/devices/\([^"/]*\)/retire"|\1|')
}

# The bundle check: a device registers with the CLI as `presenter` (portal token, request, words
# confirmed in the portal, as a person does), the factory builds its bundle, and
# `fieldseal bundle fetch` returns sequence 1. The factory's `bundle-built` event is the
# independent witness. The browser device's own fetch (the WebAssembly device asks through the
# stand-in's proxy with a token made in the page) needs a browser, so it is not driven here: the
# check below covers what the stand-in contributes (its provisioning, the proxy's pass-through of
# the token and the route that is gone), and the browser flow is `tools/stack-smoke.sh --browser`.
check_bundle() {
  local jar="$STATE/check-cookies" dev="$STATE/check-device" csrf page token req tenancy out i
  rm -rf "$dev" "$jar"; mkdir -p "$dev"
  [ "$(sign_in_as presenter "$jar" http://localhost:8080 /)" = 200 ] || die "check: the factory sign-in did not complete"
  retire_devices "$jar"
  csrf="$(portal_csrf "$jar")"
  page="$(curl -fsS -b "$jar" --max-time 10 -d "csrf=$csrf&route=online" http://localhost:8080/tokens)"
  token="$(sed -n 's|.*<p class="token">\([^<]*\)</p>.*|\1|p' <<<"$page" | head -n 1)"
  [ -n "$token" ] || die "check: the portal issued no registration token"
  req="$(cli registration request --token "$token" --trust-bundle "$STATE/authority/trust-bundle.bundle" --device-dir "$dev" --out "$dev/request" --json)" \
    || die "check: registration request failed"
  tenancy="$(jq -r .tenancy <<<"$req")"
  cli registration submit "$dev/request" --factory-url http://localhost:8080 --json >/dev/null || die "check: registration submit failed"
  curl -fsS -b "$jar" -o /dev/null --max-time 10 -d "csrf=$csrf" "http://localhost:8080/pending/$tenancy/confirm" || die "check: the portal did not confirm the device"
  cli registration wait "$tenancy" --device-dir "$dev" --factory-url http://localhost:8080 --trust-bundle "$STATE/authority/trust-bundle.bundle" --timeout 30 --json >/dev/null \
    || die "check: the device did not register"
  curl -fsS --max-time 10 "http://127.0.0.1:8090/registration?tenancy=$tenancy" | grep -q '<strong>registered</strong>' || die "check: the Registration page does not show the factory's state registered for the device"
  out=""
  for i in $(seq 1 30); do
    if out="$(cli bundle fetch --device-dir "$dev" --factory-url http://localhost:8080 --trust-bundle "$STATE/authority/trust-bundle.bundle" --out "$dev/bundle/" --json 2>"$LOGS/check-fetch.err")"; then break; fi
    grep -q 'no-bundle' "$LOGS/check-fetch.err" || die "check: bundle fetch failed: $out $(cat "$LOGS/check-fetch.err")"
    out=""; sleep 1
  done
  [ -n "$out" ] || die "check: the factory built no bundle in 30 seconds (deploy/local/.state/dev-web/logs/factory.log)"
  [ "$(jq -r .sequence <<<"$out")" = 1 ] || die "check: the first bundle is not sequence 1: $out"
  grep -q '"event":"bundle-built"' "$LOGS/factory.log" || die "check: the factory log has no bundle-built event"
  retire_devices "$jar"
  rm -f "$jar"
  say "check: a registered device fetched its bundle (sequence 1) and the factory logged bundle-built, and the Registration page shows the factory's state"
}

# The stand-in's part of the browser device's fetch: the provisioning names the factory itself
# (the token is bound to its URL) and the publishers the device accepts, the proxy hands the factory's
# answer back to a request that carries a token header (a made-up token is the factory's 400 or 401,
# not the 502 of an unreachable factory), and the removed route is gone.
check_device_fetch() {
  local prov code
  prov="$(curl -fsS --max-time 10 http://127.0.0.1:8090/device/provisioning)" || die "check: the stand-in gave no device provisioning"
  [ "$(jq -r .factoryUrl <<<"$prov")" = http://localhost:8080 ] || die "check: the provisioning does not name the factory: $prov"
  [ "$(jq -r '.allowedBuilders | length' <<<"$prov")" -ge 1 ] || die "check: the provisioning has no allowed builders"
  code="$(curl -s -o /dev/null -w '%{http_code}' -H 'Fieldseal-PoP: not-a-token' --max-time 10 http://127.0.0.1:8090/proxy/factory/v1/bundle)"
  case "$code" in 400 | 401) ;; *) die "check: the proxy did not hand back the factory's refusal of a bad token (got $code)" ;; esac
  [ "$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 "http://127.0.0.1:8090/device/bundle?tenancy=00")" = 404 ] || die "check: the removed bundle route still answers"
  say "check: the stand-in provisions the device with the factory's URL, passes its token to the factory and has no bundle route of its own"
}

# The development adapters check (DEP-076, Technical Plan 10.1): each service wrote one
# `development-adapters` event at start, and the ports and adapters in it are the ones the
# manifest binds to development adapters, as `fieldseal deployment validate` lists them.
check_adapters() {
  local component service log expected found events
  for entry in factory:fieldseal-factory:factory intake:fieldseal-intake:intake publishing:fieldseal-translog:translog; do
    IFS=: read -r component service log <<<"$entry"
    expected="$(jq -r --arg c "$component" '.developmentAdapters[$c] // {} | to_entries | map("\(.key)=\(.value)") | sort | join(",")' <<<"$VALIDATED")"
    events="$(grep -h '"event":"development-adapters"' "$LOGS/$log.log" | jq -c --arg s "$service" 'select(.service == $s)')"
    [ "$(wc -l <<<"$events")" = 1 ] && [ -n "$events" ] || die "check: $service did not write exactly one development-adapters event (deploy/local/.state/dev-web/logs/$log.log)"
    found="$(jq -r '.adapters | map("\(.port)=\(.adapter)") | sort | join(",")' <<<"$events")"
    [ "$found" = "$expected" ] || die "check: $service reports the development adapters [$found] but the manifest binds [$expected]"
  done
  say "check: each service reports the development adapters the manifest binds"
}

# The pages the collector stand-in serves from the real services: Publishing verifies the log and
# the published artefacts against the trust bundle (WEB-141), Registration reads the factory
# (WEB-150), the Device page is in stack mode, and there is no Intake page (WEB-154).
check_pages() {
  local base=http://127.0.0.1:8090 page code
  for path in /demo /demo/1 /demo/2 /demo/8 /instruments /instruments/school-meals-baseline /publishing /registration /device; do
    code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 15 "$base$path")"
    [ "$code" = 200 ] || die "check: $path answered $code"
  done
  page="$(curl -fsS --max-time 30 "$base/publishing")"
  grep -q '<span class="ok">verified</span>' <<<"$page" || die "check: the Publishing page verifies no artefact against the trust bundle"
  ! grep -q '<span class="bad">not verified' <<<"$page" || die "check: the Publishing page shows an artefact that does not verify"
  grep -q 'pinned log key</dt><dd><span class="ok">yes</span>' <<<"$page" || die "check: the log's checkpoint does not verify against the pinned log key"
  grep -q 'household-water-access' <<<"$page" || die "check: the Publishing page does not list the published survey"
  grep -q 'data-mode="stack"' < <(curl -fsS --max-time 10 "$base/device") || die "check: the Device page is not in stack mode"
  [ "$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 "$base/intake")" = 404 ] || die "check: /intake does not answer 404"
  ! curl -fsS --max-time 10 "$base/registration" | grep -q 'href="/intake' || die "check: a page links to /intake"
  curl -fsS --max-time 10 "$base/registration" | grep -q 'href="http://localhost:8481/"' || die "check: the pages do not link to the results reader"
  say "check: the Publishing page verifies the log and the artefacts, there is no Intake page, and the Instruments, Registration and Device pages answer"
}

# The edit-and-reload check: a changed label shows with no restart, and a broken file keeps the
# last good version and shows the resolver's error with file, line and column. The survey
# declares Spanish, so the label changes in the catalogue too (a changed English text with a stale
# Spanish one is an error, as the tutorial shows).
check_edit() {
  local page render
  BACKUP="$STATE/check-backup.yaml"; BACKUP_PO="$STATE/check-backup.po"
  cat "$EDITED" > "$BACKUP"; cat "$EDITED_PO" > "$BACKUP_PO"
  sed -i 's/label: Public standpipe$/label: Public standpipe (edited)/' "$EDITED"
  sed -i 's/^msgid "Public standpipe"$/msgid "Public standpipe (edited)"/' "$EDITED_PO"
  render="$(curl -fsS --max-time 10 http://127.0.0.1:8090/instruments/household-water-access/render)"
  grep -q 'Public standpipe (edited)' <<<"$render" || die "check: the edited label did not show without a restart"
  say "check: an edited label shows at once"
  sed -i 's/^language: en$/languag: en/' "$EDITED"
  page="$(curl -fsS --max-time 10 http://127.0.0.1:8090/instruments/household-water-access)"
  grep -q 'id="current-errors"' <<<"$page" || die "check: a broken file did not show its error"
  grep -Eq 'instrument\.yaml:[0-9]+:[0-9]+' <<<"$page" || die "check: the error has no file, line and column"
  render="$(curl -fsS --max-time 10 http://127.0.0.1:8090/instruments/household-water-access/render)"
  grep -q 'Public standpipe (edited)' <<<"$render" || die "check: the last good version was not kept"
  say "check: a broken file keeps the last good version and shows the error"
  cat "$BACKUP" > "$EDITED"; rm -f "$BACKUP"; BACKUP=""
  cat "$BACKUP_PO" > "$EDITED_PO"; rm -f "$BACKUP_PO"; BACKUP_PO=""
  page="$(curl -fsS --max-time 10 http://127.0.0.1:8090/instruments/household-water-access)"
  ! grep -q 'id="current-errors"' <<<"$page" || die "check: the error stayed after the file was restored"
  say "check: the file is restored"
}

if [ "$CHECK" = 1 ]; then
  [ "$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 http://localhost:8481/)" = 200 ] || die "check: the results reader's sign-in page does not answer"
  [ "$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 http://localhost:8481/results)" = 302 ] || die "check: the results reader shows results without a session"
  say "check: the results reader answers and asks for a sign-in"
  jar="$STATE/check-cookies"; rm -f "$jar"
  sign_in_as presenter "$jar" http://localhost:8481 /results >/dev/null || die "check: the sign-in through the development IdP did not reach the results page"
  curl -fsS -b "$jar" --max-time 10 http://localhost:8481/results | grep -q 'outside Fieldseal' || die "check: the results page did not show after the sign-in"
  mark="$(curl -fsS -b "$jar" --max-time 10 http://localhost:8481/results | sed -n 's|.*/results/exports/\([0-9]*\)/manifest.json.*|\1|p' | head -n 1)"
  [ -n "$mark" ] || die "check: the results page lists no export"
  curl -fsS -b "$jar" --max-time 10 "http://localhost:8481/results/exports/$mark/manifest.json" | grep -q '"landing_mark"' || die "check: the manifest did not download"
  rm -f "$jar"
  say "check: signing in as presenter through the development IdP reads the results and downloads the manifest"
  jar="$STATE/check-cookies"; rm -f "$jar"
  [ "$(sign_in_as presenter "$jar" http://localhost:8080 / )" = 200 ] || die "check: the factory sign-in through the development IdP did not complete"
  curl -fsS -b "$jar" --max-time 10 http://localhost:8080/ | grep -q 'href="/sign-in"' && die "check: the factory still asks for a sign-in after the development IdP's"
  rm -f "$jar"
  say "check: the factory signs in through the development IdP"
  curl -fsS --max-time 10 http://127.0.0.1:8090/publishing | grep -q 'household-water-access' || die "check: the Publishing page does not list the published examples"
  say "check: the Publishing page lists the published examples"
  curl -fsS --max-time 10 http://127.0.0.1:8090/instruments/school-meals-baseline/roster?cohort=cohort-a | grep -q '"cohort":"cohort-a"' || die "check: the roster page does not show the issued roster of cohort-a"
  say "check: the roster page reads the roster the factory stored"
  check_adapters
  check_pages
  check_bundle
  check_device_fetch
  check_edit
  if [ "$BROWSER" = 1 ]; then
    "$ROOT/tools/browser-tests/cookies.sh" --login presenter http://127.0.0.1:8090 http://localhost:8080 http://localhost:8481 || die "check: the cookie-scoping check failed"
    say "check: the browser sends no factory or results reader cookie to the collector stand-in"
    "$ROOT/tools/browser-tests/demo-e2e.sh" --state "$STATE" || die "check: the guided demo's eight steps did not pass in the browser"
    say "check: the eight steps of the guided demo ran end to end, each confirmation found at its own source"
    "$ROOT/tools/browser-tests/phone-fit.sh" --state "$STATE" || die "check: a device screen does not fit a phone without scrolling"
    say "check: every device screen (your surveys, the roster, each step of both examples, the review) fits 390x844 without scrolling"
    # The picker's own state: a roster for a cohort that both example surveys are assigned to, for an account of its own.
    COLLECTOR2=00000000-0000-4000-8000-000000000003
    cli roster issue --factory-url http://localhost:8080 --browser none --login presenter \
      "$ROOT/tools/browser-tests/fixtures/picker-a.yaml" >>"$LOGS/roster.log" 2>&1 \
      || { tail -n 20 "$LOGS/roster.log" >&2; die "check: could not issue the picker's roster"; }
    cli roster assign --factory-url http://localhost:8080 --browser none --login presenter --account "$COLLECTOR2" \
      --assign household-water-access=picker-a --assign school-meals-baseline=picker-a >>"$LOGS/roster.log" 2>&1 \
      || { tail -n 20 "$LOGS/roster.log" >&2; die "check: could not assign both surveys to the picker's cohort"; }
    "$ROOT/tools/browser-tests/picker.sh" --state "$STATE" || die "check: the survey picker did not work in the browser"
    say "check: a group of two surveys is chosen from, survey by survey, on the roster; a capture starts for a person and backs out"
  fi
  say "dev-web --check passed"
  exit 0
fi

cat <<MSG

just web is running (Ctrl-C stops everything). State: deploy/local/.state/dev-web/ (remove it to start over).
  Collector stand-in   http://127.0.0.1:8090   (edit a survey under examples/surveys/ and reload)
  Factory              http://localhost:8080
  Intake uploads       http://localhost:8480   (devices upload here)
  Results reader       http://localhost:8481   (signs you in as the development login presenter)
  Transparency log     http://localhost:9001/checkpoint
  Publish your survey  just publish <survey>   (then see the Publishing page)
  Rosters              issued; household-water-access assigned to presenter (subject 00000000-0000-4000-8000-000000000001), school-meals-baseline to collector1 (...0002):
                       fieldseal roster issue <file>... --factory-url http://localhost:8080 --browser none --login presenter
                       fieldseal roster assign --factory-url http://localhost:8080 --browser none --login presenter --account <subject> --assign <survey>=<cohort>
                       (set FIELDSEAL_OIDC_ISSUER=http://localhost:8180/realms/fieldseal and FIELDSEAL_OIDC_CLIENT_ID=fieldseal-cli first)
  Development IdP      http://localhost:8180/realms/fieldseal   (logins: presenter, collector1; no password)
Sign-in at the factory and the results reader goes through the development IdP: pick a login on its page.
Not for production: fieldseal-dev-idp refuses to run there. Logs: deploy/local/.state/dev-web/logs/
MSG
echo "Development adapters in use (production refuses every one; the manifest binds them, each service reports them):"
jq -r '.developmentAdapters | to_entries[] | .key as $c | .value | to_entries[] | "  \($c) \(.key): \(.value)"' <<<"$VALIDATED"
echo "The identity provider is the development IdP (no password, any login), in the place Keycloak takes in the stack."

# Stop when any service stops.
wait -n "${PIDS[@]}" || true
die "a service stopped; see deploy/local/.state/dev-web/logs/"
