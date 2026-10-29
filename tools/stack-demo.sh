#!/usr/bin/env bash
# The stack's end-to-end demo, run inside the `demo` compose service (fieldseal-demo:local):
#
#   demo     seed, issue and assign, then register a device through the browser flow, build its
#            bundle, capture, export, upload to the intake and verify the receipts
#   seed     publish the sample instruments, their layouts and the policy through the stack's log
#   issue    issue the example rosters at the factory (one operator sign-in); `unchanged` when
#            the factory already holds them
#   assign   assign the cohorts to the account of the stack's product-owner (one operator
#            sign-in); `unchanged` when they are already assigned
#   resume   after `just down` and `just up`: seed, issue and assign again (nothing changes), then
#            the device registered earlier is still registered and uploads the same export again
#            (changing nothing)
#
# Every command is printed as it runs; any failure ends the run with a non-zero status.
set -euo pipefail

EX=/opt/fieldseal/examples
TB=/authority/trust-bundle.bundle
W=/tmp/demo
export HOME="${HOME:-/tmp/home}"
export FIELDSEAL_ADAPTERS=files
# The CLI's registry of published artefacts persists in the clistate volume, which makes
# publishing idempotent (CLI-006) and lets the factory's artefact registry (read-only) see the publications.
export FIELDSEAL_STATE_DIR=/clistate
export FIELDSEAL_TRANSLOG_URL="${FIELDSEAL_TRANSLOG_URL:-http://translog:8080}"
export FIELDSEAL_LOG_ORIGIN="${FIELDSEAL_LOG_ORIGIN:-fieldseal.local/log}"
export FIELDSEAL_FACTORY_URL="${FIELDSEAL_FACTORY_URL:-http://localhost:8080}"
INTAKE="${FIELDSEAL_INTAKE_URL:-http://localhost:8480}"
# The survey the device collects: the school meals survey (the stack assigns its roster's cohort).
SURVEY="${FIELDSEAL_DEMO_SURVEY:-school-meals-baseline}"
SCENARIO="stack-capture-$SURVEY.yaml"
[ "$SURVEY" = household-water-access ] && SCENARIO=stack-capture.yaml
mkdir -p "$HOME" "$W" "$FIELDSEAL_STATE_DIR" /clistate/published

SUMMARY=()
stage() { printf '\n== %s\n' "$1"; }
note() { SUMMARY+=("$1"); }
run() { printf '+ fieldseal %s\n' "$*"; fieldseal "$@"; }
# Runs fieldseal, shows its output and also returns it.
capture() { printf '+ fieldseal %s\n' "$*" >&2; local out; out="$(fieldseal "$@" 2>&1)" || { printf '%s\n' "$out" >&2; return 1; }; printf '%s\n' "$out" >&2; printf '%s' "$out"; }

# The log's tree size: the second line of its signed checkpoint.
log_size() { curl -fsS --max-time 5 "$FIELDSEAL_TRANSLOG_URL/checkpoint" | sed -n 2p; }

# publish_artefact <name> <file> [provenance args...]: signs and publishes <file> through the stack's log with two of
# three publisher signatures, unless it is already there. The address of a publication changes
# with every signing, so the one published is remembered in /clistate with the registry that
# can prove it; if the proof still holds against the log, nothing is signed or appended.
# Sets PUBLISHED to "published" or "skipped". The result is kept at /published/<name>.published.
# An instrument is published with a salt of ours (ADR 0027), kept in /clistate/<name>.salt: no
# command prints the salt of a publication, and a layout binds to the fingerprint of its
# instrument, which the salt is part of. REVIEWERS, when set, replaces the default reviewers.
publish_artefact() {
  local name="$1" file="$2" mark="/clistate/$1.address" address prov doc="$1.yaml" salt=""
  shift 2
  mkdir -p "$W/publish/$name"; cd "$W/publish/$name"
  if [ "$(basename "$file")" = instrument.yaml ]; then
    # A survey is published from a folder (ADR 0041): its instrument and catalogues travel together.
    doc=instrument.yaml
    cat "$file" > "$doc"
    local po
    for po in "$(dirname "$file")"/i18n/*.po; do
      [ -f "$po" ] || continue
      mkdir -p i18n; cat "$po" > "i18n/$(basename "$po")"
    done
  else
    cat "$file" > "$doc"
  fi
  if [ -s "$mark" ] && address="$(cat "$mark")" && [ -s "/clistate/published/$name.published" ] && run log prove "$address"; then
    echo "already published (skipped)"
    PUBLISHED=skipped
  else
    # The custody directories are on a read-only mount: the CLI ignores usage-log write failures.
    [ "$doc" != instrument.yaml ] || { salt="$(head -c 32 /dev/urandom | od -An -vtx1 | tr -d ' \n')"; set -- --salt "$salt"; }
    prov="$(FIELDSEAL_SIGNER=soft:/authority/publish/builder capture artefact provenance "$doc" --out "$name.publication" --source abc123 --reviewers "${REVIEWERS:-reviewer-1:es,reviewer-2}" --at "$(date -u +%F)" "$@")"
    address="$(printf '%s' "$prov" | sed -n 's/.*(\(sha256:[0-9a-f]*\)).*/\1/p' | head -1)"
    [ -n "$address" ] || { echo "no artefact address in the provenance output" >&2; exit 1; }
    FIELDSEAL_SIGNER=soft:/authority/publish/pub-alice run artefact sign "$name.publication"
    FIELDSEAL_SIGNER=soft:/authority/publish/pub-bob run artefact sign "$name.publication"
    FIELDSEAL_SIGNER=soft:/authority/online run artefact publish "$name.publication"
    run log prove "$address"
    run artefact verify "$name.published" --trust-bundle "$TB"
    cat "$name.published" > "/clistate/published/$name.published"
    printf '%s\n' "$address" > "$mark"
    [ -z "$salt" ] || printf '%s\n' "$salt" > "/clistate/$name.salt"
    PUBLISHED=published
  fi
  # The intake app verifies every *.published in this directory against the trust bundle.
  cat "/clistate/published/$name.published" > "/published/$name.published"
  ADDRESS="$address"
  cd "$W"
}

# publish_layouts <survey>: publishes each of the survey's layouts after its instrument, under
# the name <survey>.<window> (compact, medium or expanded) that the reconciler looks up. A layout
# is bound to the fingerprint of the instrument just published, which takes the instrument's salt.
publish_layouts() {
  local survey="$1" layout window
  [ -s "/clistate/$survey.salt" ] || { echo "$survey is published but its salt is not in /clistate (published by an older stack?): run \`just purge\` and \`just up\`" >&2; exit 1; }
  for layout in "$EX/surveys/$survey"/layouts/*.yaml; do
    [ -f "$layout" ] || continue
    window="$(basename "${layout%.*}")"
    REVIEWERS=reviewer-1,reviewer-2 publish_artefact "$survey.$window.layout" "$layout" \
      --instrument "$EX/surveys/$survey/instrument.yaml" --salt "$(cat "/clistate/$survey.salt")"
    note_state
  done
}
# Keeps track of whether anything in this publish_all run was new.
ANY_STATE=skipped
note_state() { [ "$PUBLISHED" != published ] || ANY_STATE=published; }

publish_all() {
  local d="$W/publish"; mkdir -p "$d"
  ANY_STATE=skipped
  cat > "$d/deployment-policy.yaml" <<'YAML'
apiVersion: fieldseal.dev/v1alpha1
kind: Policy
metadata: { name: deployment-policy, version: 1.0.0 }
spec:
  schemaVersion: 1.0.0
  layer: { scope: deployment }
  publishing:
    requiredApprovals: { Instrument: 2, Policy: 2, TrustBundle: 2, Deployment: 2 }
    authorMayApprove: false
    publisherThreshold: { m: 2, n: 3 }
    allowedBuilders: [ "https://ci.example.org/builders/fieldseal-publish" ]
    allowedSources: [ "https://git.example.org/authority/artefacts" ]
    requireTransparencyLog: true
  factory:
    # Equal to the default. The demo's reset relies on this limit and on retirement: the
    # presenter retires the old device on the portal and registers again, and a retired
    # tenancy is not active, so the new one receives the cohort (Technical Plan 7.4).
    cohorts: { maxActiveTenanciesPerCohort: 1 }
YAML
  export FIELDSEAL_TRUST_BUNDLE="$TB" FIELDSEAL_POLICY="$d/deployment-policy.yaml"
  publish_artefact household-water-access "$EX/surveys/household-water-access/instrument.yaml"
  INSTRUMENT_ADDRESS="$ADDRESS"; note_state
  publish_layouts household-water-access
  publish_artefact school-meals-baseline "$EX/surveys/school-meals-baseline/instrument.yaml"
  note_state
  publish_layouts school-meals-baseline
  publish_artefact deployment-policy "$d/deployment-policy.yaml"
  note_state
  unset FIELDSEAL_TRUST_BUNDLE FIELDSEAL_POLICY
}

# 1. Publish the instrument and the deployment policy, then repeat to show it is idempotent.
seed() {
  stage "1. Publish the sample instruments, their layouts and the deployment policy through the stack's transparency log"
  local before after
  before="$(log_size)"; publish_all; after="$(log_size)"
  echo "log tree size: $before -> $after"
  local first="$ANY_STATE"
  if [ "$first" = skipped ]; then
    [ "$after" = "$before" ] || { echo "the log grew although nothing was published: $before -> $after" >&2; exit 1; }
  else
    [ "$after" -gt "$before" ] || { echo "the log did not grow on a publish: $before -> $after" >&2; exit 1; }
  fi
  echo "-- publishing again must change nothing"
  publish_all
  [ "$ANY_STATE" = skipped ] && [ "$(log_size)" = "$after" ] || { echo "a repeat publish changed the log" >&2; exit 1; }
  note "instrument $INSTRUMENT_ADDRESS, the layouts and the deployment policy in $FIELDSEAL_TRANSLOG_URL ($first); a repeat was skipped, log size unchanged at $after"
}

# The operator sign-in of the next two steps: the CLI opens the authorisation URL with the stack's
# opener (a passkey for product-owner; FIELDSEAL_OIDC_ISSUER and FIELDSEAL_OIDC_CLIENT_ID come
# from the demo service's environment). Each step signs in once, and prints `unchanged` when the
# factory already holds what it was asked to store.
BROWSER="${FIELDSEAL_BROWSER:-/opt/fieldseal/tools/stack-browser.sh}"
# The collector's account: product-owner's subject in the stack's realm.
ACCOUNT=00000000-0000-4000-8000-000000000003

issue() {
  stage "Issue the example rosters at the factory (operator sign-in)"
  run roster issue --factory-url "$FIELDSEAL_FACTORY_URL" --browser "$BROWSER" "$EX/rosters/village-a.yaml" "$EX/rosters/cohort-a.yaml"
  note "rosters village-a and cohort-a issued at the factory"
}

assign() {
  stage "Assign the cohorts to the collector's account (operator sign-in)"
  run roster assign --factory-url "$FIELDSEAL_FACTORY_URL" --browser "$BROWSER" --account "$ACCOUNT" \
    --assign household-water-access=village-a --assign school-meals-baseline=cohort-a
  note "household-water-access -> village-a and school-meals-baseline -> cohort-a assigned to account $ACCOUNT"
}

# 2. A device registers: the browser flow gets the token and calls tools/stack-enroll.sh.
enrol() {
  stage "2. Register a device: passkey sign-in, registration token, request, words confirmed in the portal"
  rm -rf /device/* /device/.[!.]* 2>/dev/null || true
  rm -f "$W/enrol.json"
  python3 -I /opt/fieldseal/tools/local-stack-passkey.py --on-token /opt/fieldseal/tools/stack-enroll.sh --emit-json "$W/enrol.json"
  WORDS="$(jq -r '.words' "$W/enrol.json")"
  TENANCY="$(jq -r '.tenancy' "$W/enrol.json")"
  [ -n "$TENANCY" ] && [ "$TENANCY" != null ] || { echo "the browser flow did not report a tenancy" >&2; exit 1; }
  note "device registered: tenancy ${TENANCY:0:16}..., fingerprint words '$WORDS' confirmed in the portal"
}

# 3. The device collects its certificate.
await_certificate() {
  stage "3. The device waits for its tenancy certificate"
  run registration wait "$TENANCY" --device-dir /device --timeout 60 --json
  [ -s /device/tenancy.certificate ] || { echo "no tenancy certificate in /device" >&2; exit 1; }
  note "tenancy certificate received (/device/tenancy.certificate)"
}

# 4. The device fetches the bundle the factory built for it.
bundle() {
  stage "4. The device fetches its bundle from the factory (GET /v1/bundle, proof of possession)"
  rm -rf /device/fetched && mkdir -p /device/fetched
  # The factory builds a bundle when the device registers and when a publication appears, which it
  # sees within the scan interval, so the first answer may be `no-bundle`: ask again for a minute.
  local out status deadline=$(( $(date +%s) + 60 ))
  while :; do
    printf '+ fieldseal bundle fetch --device-dir /device --factory-url %s --trust-bundle %s --out /device/fetched/\n' "$FIELDSEAL_FACTORY_URL" "$TB" >&2
    status=0
    out="$(fieldseal bundle fetch --device-dir /device --factory-url "$FIELDSEAL_FACTORY_URL" --trust-bundle "$TB" --out /device/fetched/ 2>&1)" || status=$?
    printf '%s\n' "$out" >&2
    [ "$status" -eq 0 ] && break
    if [ "$status" -eq 1 ] && printf '%s' "$out" | grep -q 'no-bundle' && [ "$(date +%s)" -lt "$deadline" ]; then
      echo "no bundle built yet; asking again in 2 s" >&2
      sleep 2
      continue
    fi
    echo "the factory did not deliver a bundle (exit $status)" >&2
    exit 1
  done
  local fsbs=(/device/fetched/*.fsb)
  BUNDLE_FILE="${fsbs[0]}"
  [ -s "$BUNDLE_FILE" ] || { echo "no bundle file in /device/fetched" >&2; exit 1; }
  note "bundle $(basename "$BUNDLE_FILE") fetched from the factory ($(wc -c < "$BUNDLE_FILE") bytes); the device verifies it when it imports it"
}

# 5. The registered device captures its own records and exports them.
capture_records() {
  stage "5. The registered device captures and exports"
  local out; out="$(capture device capture --device-dir /device --trust-bundle "$TB" --bundle "$BUNDLE_FILE" \
    --script "$EX/scenarios/$SCENARIO" --export /device/export.fieldseal)"
  [ -s /device/export.fieldseal ] || { echo "no export in /device" >&2; exit 1; }
  note "capture: $(printf '%s' "$out" | grep -ci 'capture') capture line(s); export /device/export.fieldseal ($(wc -c < /device/export.fieldseal) bytes)"
}

# Uploads the device's export and verifies every receipt against the trust bundle.
upload_export() {
  local n="$1" count=0 f
  rm -rf "$W/receipts"
  run export upload /device/export.fieldseal --to "$INTAKE" --trust-bundle "$TB" --receipts-dir "$W/receipts" --json
  for f in "$W"/receipts/*; do
    [ -f "$f" ] || continue
    run receipt verify "$f" --trust-bundle "$TB" --tenancy "$TENANCY"
    count=$((count + 1))
  done
  [ "$count" -gt 0 ] || { echo "the intake endpoint returned no receipts" >&2; exit 1; }
  note "upload $n: $count receipt(s), each verified against the trust bundle for tenancy ${TENANCY:0:16}..."
}

deliver() {
  stage "6. The registered device uploads to the intake endpoint ($INTAKE)"
  upload_export 1
}

# 7. What the intake landed for this device.
landing() {
  stage "7. The intake data contract and what landed for this device"
  run intake contract "$EX/surveys/$SURVEY/instrument.yaml" --out "$W/contract"
  echo "-- /landing"; ls -l /landing
  local rows
  rows="$(awk -F, -v t="$TENANCY" 'NR > 1 && $12 == t' /landing/observations.csv | wc -l | tr -d ' ')"
  [ "$rows" -gt 0 ] || { echo "no rows for tenancy ${TENANCY:0:16}... in /landing/observations.csv" >&2; exit 1; }
  echo "-- $rows observation row(s) for this device; the first:"
  awk -F, -v t="$TENANCY" 'NR > 1 && $12 == t { print "   " $5 "=" $6 }' /landing/observations.csv | head -8
  local losses findings
  losses="$(wc -l < /landing/losses.csv | tr -d ' ')"; findings="$(wc -l < /landing/findings.csv | tr -d ' ')"
  echo "-- losses.csv: $losses line(s); findings.csv: $findings line(s)"
  note "landing: $rows observation row(s) for this device; losses.csv $losses line(s), findings.csv $findings line(s)"
}

summary() {
  printf '\n== Summary (software keys, unattested devices, development custody)\n'
  local line; for line in "${SUMMARY[@]}"; do printf ' - %s\n' "$line"; done
}

# results_export <name>: the results export of the landing, written to /out/<name> (the stack's
# .out directory on the host), so that tools/stack-run.sh can compare two of them byte for byte.
results_export() {
  rm -rf "/out/$1"
  run intake results --landing /landing --published /published --export-key /authority/export-key/export.key \
    --trust-bundle "$TB" --out "/out/$1" >/dev/null
}

# After `just down` and `just up`: the same export goes up again and nothing changes (INT-013).
resume() {
  stage "Resume: the device registered before the restart uploads the same export again"
  [ -s /device/tenancy.certificate ] && [ -s /device/export.fieldseal ] || { echo "no registered device with an export in /device: run the demo first" >&2; exit 1; }
  TENANCY="$(tr -d '[:space:]' < /device/tenancy)"
  [ -n "$TENANCY" ] || { echo "/device/tenancy is empty" >&2; exit 1; }
  local st; st="$(capture registration status "$TENANCY")"
  printf '%s' "$st" | grep -q registered || { echo "the factory does not report the device as registered" >&2; exit 1; }
  local before after
  results_export results-before
  before="$(sha256sum /landing/observations.csv | cut -d' ' -f1)"
  upload_export 2
  after="$(sha256sum /landing/observations.csv | cut -d' ' -f1)"
  [ "$before" = "$after" ] || { echo "the landing file changed on a duplicate upload ($before -> $after)" >&2; exit 1; }
  note "/landing/observations.csv is byte-identical after the duplicate upload (sha256 ${after:0:16}...)"
  results_export results-after
  summary
  printf '\nthe device registered before the restart is still registered and uploaded the same export again, which changed nothing\n'
}


# -- The hands-on walkthrough (docs/tutorials/hands-on.md): one step per command, state kept in
# the device and clistate volumes between steps, files for you in deploy/local/.out (/out).
OUT=/out
need_device() { [ -s /device/tenancy ] || { echo "no registered device yet: run \`just enrol\` (or \`just register <token>\`) first" >&2; exit 1; }; TENANCY="$(tr -d '[:space:]' < /device/tenancy)"; }
need_bundle() { local fsbs=(/device/fetched/*.fsb); [ -s "${fsbs[0]}" ] || { echo "no bundle yet: run \`just bundle\` first" >&2; exit 1; }; BUNDLE_FILE="${fsbs[0]}"; }

step_authority() {
  stage "The authority: root, purpose keys and the trust bundle the stack's init created"
  run trust show --trust-bundle "$TB" --custody /authority/online
}

step_registry() {
  if [ -n "${1:-}" ]; then
    stage "One artefact in the register, verified as a device verifies it"
    run registry show "$1" --dir /published --trust-bundle "$TB" --log-url "$FIELDSEAL_TRANSLOG_URL"
  else
    stage "The register: every published artefact, verified, and the log's latest checkpoint"
    run registry list --dir /published --trust-bundle "$TB" --log-url "$FIELDSEAL_TRANSLOG_URL"
  fi
}

# fetch <name | sha256:address>: downloads a published artefact from the register, verified, and
# renders an instrument. A name that is not unique (another version, another kind) is refused
# with the candidates listed; give the address then.
step_fetch() {
  local wanted="${1:-school-meals-baseline}" json name version kind base layout
  stage "Download $wanted from the register, verify it and open it"
  mkdir -p "$OUT"
  rm -f "$OUT/.fetch.published" "$OUT/.fetch.yaml"
  json="$(capture registry fetch "$wanted" --dir /published --trust-bundle "$TB" --log-url "$FIELDSEAL_TRANSLOG_URL" --out "$OUT/.fetch.published" --document "$OUT/.fetch.yaml" --json)" || exit $?
  json="$(printf '%s\n' "$json" | grep '^{"address"' | tail -1)"
  name="$(printf '%s' "$json" | jq -r .name)"; version="$(printf '%s' "$json" | jq -r .version)"; kind="$(printf '%s' "$json" | jq -r .kind)"
  base="$OUT/$name-$version"
  mv "$OUT/.fetch.published" "$base.published"; mv "$OUT/.fetch.yaml" "$base.yaml"
  echo "fetched $kind $name $version ($(printf '%s' "$json" | jq -r .address)) into deploy/local/.out/$(basename "$base").{published,yaml}"
  [ "$kind" = Instrument ] || return 0
  layout="$EX/surveys/$name/layouts/compact.yaml"
  if [ -f "$layout" ]; then
    run instrument preview "$base.yaml" --layout "$layout" --window compact -o "$base.html"
  else
    run instrument preview "$base.yaml" -o "$base.html"
  fi
  printf '\nOpen deploy/local/.out/%s.html in your browser and answer it: every limit the instrument declares is enforced as you type.\n' "$(basename "$base")"
}

# register <token>: the manual path, with a token from the portal you signed in to yourself.
step_register() {
  : "${1:?give the registration token from the portal: just register FS1T:...}"
  stage "Register this device with your token"
  rm -rf /device/* /device/.[!.]* 2>/dev/null || true
  local json; json="$(FIELDSEAL_TOKEN="$1" /opt/fieldseal/tools/stack-enroll.sh | tail -1)"
  TENANCY="$(printf '%s' "$json" | jq -r '.tenancy')"
  printf '%s\n' "$TENANCY" > /device/tenancy
  printf '\nCompare these four words with the portal (http://localhost:8080) and confirm them there:\n\n    %s\n\nthen run: just wait\n' "$(printf '%s' "$json" | jq -r '.words')"
}

step_wait() { need_device; await_certificate; run registration status "$TENANCY"; }
step_bundle() { need_device; bundle; }
step_capture() { need_device; need_bundle; capture_records; }
step_upload() { need_device; [ -s /device/export.fieldseal ] || { echo "no export yet: run \`just capture\` first" >&2; exit 1; }; deliver; }
step_intake() { need_device; landing; }

case "${1:-demo}" in
  seed) seed; summary ;;
  demo) seed; issue; assign; enrol; await_certificate; bundle; capture_records; deliver; landing; summary ;;
  resume) seed; issue; assign; resume ;;
  issue) issue ;;
  assign) assign ;;
  authority) step_authority ;;
  publish) seed ;;
  registry) step_registry "${2:-}" ;;
  fetch) step_fetch "${2:-}" ;;
  enrol) seed; issue; assign; enrol; printf '%s\n' "$TENANCY" > /device/tenancy; await_certificate ;;
  register) step_register "${2:-}" ;;
  wait) step_wait ;;
  bundle) step_bundle ;;
  capture) step_capture ;;
  upload) step_upload ;;
  intake) step_intake ;;
  *) echo "usage: stack-demo.sh demo|seed|issue|assign|resume" >&2; exit 2 ;;
esac
