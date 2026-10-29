#!/usr/bin/env bash
# Publishes a survey, or every bundled example and the publishing policy, through the log of
# `just web`. It adds nothing to the CLI: it prints and runs the verbs of publish_artefact in
# tools/stack-demo.sh (artefact provenance, artefact sign for two of the three publisher keys,
# artefact publish) against the authority that tools/dev-web.sh made.
#
#   tools/dev-publish.sh <survey>    a survey name (surveys/<name>, then examples/surveys/<name>) or a survey folder
#   tools/dev-publish.sh --all       every survey under examples/surveys/, then the publishing policy
#                                    (what tools/dev-web.sh runs at start-up; what is published is skipped)
#
# `just publish <survey>` runs this. It needs `just web` running (the log) and, apart from that,
# FIELDSEAL_BIN (the CLI that tools/dev-web.sh built; built with tools/stack-cli.sh when unset).
# FIELDSEAL_INTAKE_PUBLISHED_DIR, when set, also receives each *.published file.
#
# Each instrument is published with a random salt (ADR 0027; nothing pins it). No CLI command
# prints the salt of a publication, so it is kept in <state>/dev-publish/<name>-<version>.salt, and
# the survey's layouts are bound to it. A name and version publish once: raise survey.version.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STATE="$ROOT/deploy/local/.state/dev-web"
A="$STATE/authority"
PUB="$STATE/published"
SALTS="$STATE/dev-publish"
POLICY="$ROOT/examples/deployments/policy/dev-web-publishing.yaml"
TRANSLOG="http://127.0.0.1:9001"

die() { printf 'publish: %s\n' "$*" >&2; exit 1; }
[ $# -eq 1 ] || die "usage: tools/dev-publish.sh <survey>|--all"
[ -f "$A/.initialised" ] || die "there is no authority yet. Start 'just web' first: it creates the keys, the trust bundle and the log."
curl -fsS -o /dev/null --max-time 3 "$TRANSLOG/checkpoint" || die "the log does not answer at $TRANSLOG. Start 'just web' first."

FS="${FIELDSEAL_BIN:-$("$ROOT/tools/stack-cli.sh")}"
export FIELDSEAL_ADAPTERS=files
export FIELDSEAL_STATE_DIR="$STATE/cli"
export FIELDSEAL_TRANSLOG_URL="$TRANSLOG"
export FIELDSEAL_LOG_ORIGIN="${FIELDSEAL_LOG_ORIGIN:-fieldseal.local/log}"
export FIELDSEAL_TRUST_BUNDLE="$A/trust-bundle.bundle"
export FIELDSEAL_POLICY="$POLICY"
mkdir -p "$PUB" "$SALTS" "$STATE/cli" "$SALTS/work"

# run <signer-dir> <fieldseal args...>: prints the command, runs it and keeps its output in $OUT.
OUT=""
run() {
  local signer="$1"; shift
  printf '+ fieldseal %s\n' "$*"
  local status=0
  OUT="$(FIELDSEAL_SIGNER="soft:$signer" "$FS" "$@" 2>&1)" || status=$?
  [ -z "$OUT" ] || printf '%s\n' "$OUT"
  return "$status"
}

# publish_file <published-name> <file> <reviewers> [provenance args...]: provenance, two of three
# signatures, publish. Sets ADDRESS. The file is left in $PUB/<published-name>.published.
publish_file() {
  local label="$1" file="$2" reviewers="$3"; shift 3
  local dir="$SALTS/work/$label"
  rm -rf "$dir"; mkdir -p "$dir"; cd "$dir"
  run "$A/publish/builder" artefact provenance "$file" --out "$label.publication" --source abc123 --reviewers "$reviewers" --at "$(date -u +%F)" "$@" \
    || die "artefact provenance failed for $file"
  ADDRESS="$(printf '%s' "$OUT" | sed -n 's/.*(\(sha256:[0-9a-f]*\)).*/\1/p' | head -1)"
  [ -n "$ADDRESS" ] || die "no artefact address in the provenance output"
  run "$A/publish/pub-alice" artefact sign "$label.publication" || die "artefact sign failed"
  run "$A/publish/pub-bob" artefact sign "$label.publication" || die "artefact sign failed"
  run "$A/online" artefact publish "$label.publication" || return 1
  cat "$label.published" > "$PUB/$label.published"
  if [ -n "${FIELDSEAL_INTAKE_PUBLISHED_DIR:-}" ]; then
    mkdir -p "$FIELDSEAL_INTAKE_PUBLISHED_DIR"; cat "$label.published" > "$FIELDSEAL_INTAKE_PUBLISHED_DIR/$label.published"
  fi
  cd "$ROOT"
}

# survey_folder <name|folder>: the folder of a survey.
survey_folder() {
  local d
  for d in "$1" "surveys/$1" "$ROOT/examples/surveys/$1"; do
    if [ -f "$d/instrument.yaml" ]; then (cd "$d" && pwd); return 0; fi
  done
  die "$1: no survey folder here (looked for $1, surveys/$1 and examples/surveys/$1, each with an instrument.yaml)"
}

# publish_survey <folder> <skip-if-published: 0|1>
publish_survey() {
  local folder="$1" skip="$2" name version listed started
  name="$(basename "$folder")"
  listed="$("$FS" survey list --root "$(dirname "$folder")" --json)" || die "$folder: fieldseal survey list failed"
  version="$(printf '%s' "$listed" | jq -r --arg n "$name" '.surveys[] | select(.name == $n) | .version')"
  [ -n "$version" ] || die "$folder: not listed by fieldseal survey list"
  local salt_file="$SALTS/$name-$version.salt" reviewers="reviewer-1,reviewer-2" po lang salt
  started="${EPOCHREALTIME/./}"
  # The reviewers cover every translation the survey declares (INS-083): one who holds each language.
  for po in "$folder"/i18n/*.po; do
    [ -f "$po" ] || continue
    lang="$(basename "$po" .po)"; reviewers="$reviewers,reviewer-$lang:$lang"
  done
  if [ -s "$salt_file" ]; then
    if [ "$skip" = 1 ]; then echo "$name $version: already published (skipped)"; else
      die "$name $version is already published, and a name and version publish once. Raise survey.version in $folder/instrument.yaml and run 'just publish $name' again."
    fi
  else
    salt="$(head -c 32 /dev/urandom | od -An -vtx1 | tr -d ' \n')"
    echo "== publishing $name $version"
    if ! publish_file "$name" "$folder/instrument.yaml" "$reviewers" --salt "$salt"; then
      if printf '%s' "$OUT" | grep -qi 'version'; then
        die "the artefact registry already holds $name $version, but the salt of that publication is not in $salt_file (was $STATE edited by hand?). The layouts are not published. Raise survey.version in $folder/instrument.yaml."
      fi
      die "artefact publish failed for $name"
    fi
    printf '%s\n' "$salt" > "$salt_file"
    echo "published $name $version at $ADDRESS in $(( (${EPOCHREALTIME/./} - started) / 1000 )) ms"
  fi
  # The layouts bind to the fingerprint of the instrument just published, so they use its salt.
  salt="$(cat "$salt_file")"
  local layout window
  # A layout file is published under the artefact name in its `layout.name`, which is `<survey>-<window>`
  # (artefact names are lower-case and hyphenated, so the factory finds layouts by that name). The
  # `<survey>.<window>.layout` used below only names the files this script keeps.
  for layout in "$folder"/layouts/*.yaml "$folder"/layouts/*.yml "$folder"/layouts/*.json; do
    [ -f "$layout" ] || continue
    window="$(basename "${layout%.*}")"
    if [ -s "$PUB/$name.$window.layout.published" ]; then echo "$name.$window: layout already published (skipped)"; continue; fi
    echo "== publishing the layout $name.$window"
    publish_file "$name.$window.layout" "$layout" "reviewer-1,reviewer-2" --instrument "$folder/instrument.yaml" --salt "$salt" || die "artefact publish failed for the layout $name.$window"
    echo "published layout $name.$window at $ADDRESS"
  done
}

publish_policy() {
  if [ -s "$PUB/deployment-policy.published" ]; then echo "deployment policy: already published (skipped)"; return; fi
  echo "== publishing the deployment policy"
  publish_file deployment-policy "$POLICY" "reviewer-1,reviewer-2" || die "artefact publish failed for the deployment policy"
  echo "published the deployment policy at $ADDRESS"
}

if [ "$1" = "--all" ]; then
  for d in "$ROOT"/examples/surveys/*/; do
    [ -f "$d/instrument.yaml" ] && publish_survey "$(cd "$d" && pwd)" 1
  done
  publish_policy
else
  publish_survey "$(survey_folder "$1")" 0
fi
