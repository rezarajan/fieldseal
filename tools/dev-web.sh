#!/usr/bin/env bash
# `just web`: the dev loop without containers. Runs the transparency log, the factory and the
# collector stand-in (fieldseal-web in stack mode) natively from a rendered deployment manifest,
# publishes the bundled examples and the publishing policy through the log, and re-reads the
# survey files on every request, so an edit shows at once. Ctrl-C stops everything.
#
#   tools/dev-web.sh            (normally: just web)
#   tools/dev-web.sh --check    start everything, wait for each service, run the edit-and-reload
#                               check, stop everything; exit 0 when every check passes
#
# State is in deploy/local/.state/dev-web/ (git-ignored): remove it to start over. `just web` and
# `just up` use the same ports, so they cannot run together. Environment: FIELDSEAL_BIN (a CLI to
# use instead of building one).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
STATE="$ROOT/deploy/local/.state/dev-web"
MANIFEST="examples/deployments/dev-web.yaml"
LOGS="$STATE/logs"
CHECK=0
case "${1:-}" in
  "") ;;
  --check) CHECK=1 ;;
  *) echo "usage: tools/dev-web.sh [--check]" >&2; exit 2 ;;
esac

say() { printf '%s\n' "$*"; }
die() { printf 'web: %s\n' "$*" >&2; exit 1; }

# 1. The ports. Later phases add 8180, 8480 and 8481.
PORTS=("8080:the factory" "8090:the collector stand-in" "9001:the transparency log")
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

mkdir -p "$STATE/authority" "$STATE/env" "$STATE/cli/registry" "$STATE/factory" "$STATE/log" "$STATE/logs" "$STATE/published"

# 2. The CLI, built once; tools/stack-init.sh and tools/dev-publish.sh use this binary.
FIELDSEAL_BIN="$("$ROOT/tools/stack-cli.sh")"
export FIELDSEAL_BIN
export FIELDSEAL_ENVIRONMENT=development

# 3. The manifest. The rendered environment is the only configuration the services read (DEP-012).
"$FIELDSEAL_BIN" deployment validate "$MANIFEST" >/dev/null || die "the manifest does not validate: fieldseal deployment validate $MANIFEST"
find "$STATE/env" -maxdepth 1 -name '*.env' -delete
"$FIELDSEAL_BIN" deployment render "$MANIFEST" --environment development --out "$STATE/env" >/dev/null || die "could not render $MANIFEST"
say "rendered the environment of $(basename "$MANIFEST") to deploy/local/.state/dev-web/env"

# 4. The authority, made once.
FIELDSEAL_AUTHORITY_DIR="$STATE/authority" "$ROOT/tools/stack-init.sh" >"$LOGS/authority.log" 2>&1 || { tail -n 20 "$LOGS/authority.log" >&2; die "could not create the authority (deploy/local/.state/dev-web/logs/authority.log)"; }

say "building the services"
cargo build -q -p fieldseal-translog -p fieldseal-factory -p fieldseal-web
TARGET="$(cargo metadata --format-version 1 --no-deps | jq -r .target_directory)/debug"

# start <name> <binary> <env file> [NAME=value...]: the process gets the rendered environment and
# nothing else of ours (the log refuses unknown FIELDSEAL_TRANSLOG_ variables).
start() {
  local name="$1" bin="$2" envfile="$3"; shift 3
  local vars=()
  [ -z "$envfile" ] || mapfile -t vars < <(grep -v '^[[:space:]]*\(#\|$\)' "$envfile")
  env -i PATH="$PATH" HOME="$HOME" FIELDSEAL_ENVIRONMENT=development "${vars[@]}" "$@" "$bin" >"$LOGS/$name.log" 2>&1 &
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

# 5. The log, then the bundled examples and the policy, which later steps need.
start translog "$TARGET/fieldseal-translog" "$STATE/env/publishing.env"
wait_for translog http://127.0.0.1:9001/checkpoint 60
"$ROOT/tools/dev-publish.sh" --all >"$LOGS/publish.log" 2>&1 || { tail -n 20 "$LOGS/publish.log" >&2; die "could not publish the examples (deploy/local/.state/dev-web/logs/publish.log)"; }
say "published the bundled instruments, layouts and policy (deploy/local/.state/dev-web/logs/publish.log)"

# 6. The factory, with its development identity (production refuses it at start-up).
start factory "$TARGET/fieldseal-factory" "$STATE/env/factory.env" FIELDSEAL_DEV_USERS="product-owner=collector+operator:hwk"
wait_for factory http://127.0.0.1:8080/healthz 60

# 7. The collector stand-in, on 127.0.0.1 while the services are on localhost, so cookies are not sent to it.
start web "$TARGET/fieldseal-web" "" \
  FIELDSEAL_WEB_STACK=true FIELDSEAL_WEB_CLI="$FIELDSEAL_BIN" FIELDSEAL_WEB_BIND=127.0.0.1:8090 \
  FIELDSEAL_WEB_EXAMPLES_DIR="$ROOT/examples" \
  FIELDSEAL_WEB_AUTHORITY_DIR="$STATE/authority" FIELDSEAL_WEB_PUBLISHED_DIR="$STATE/published" FIELDSEAL_WEB_REGISTRY_DIR="$STATE/cli/registry" \
  FIELDSEAL_WEB_SURVEY_COHORTS="school-meals-baseline=cohort-a,household-water-access=village-a" \
  FIELDSEAL_FACTORY_URL=http://localhost:8080 FIELDSEAL_LOG_URL=http://localhost:9001 FIELDSEAL_WEB_PUBLIC_URL=http://127.0.0.1:8090
wait_for web http://127.0.0.1:8090/healthz 60

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
  curl -fsS --max-time 10 http://127.0.0.1:8090/publishing | grep -q 'household-water-access' || die "check: the Publishing page does not list the published examples"
  say "check: the Publishing page lists the published examples"
  check_edit
  say "dev-web --check passed"
  exit 0
fi

cat <<MSG

just web is running (Ctrl-C stops everything). State: deploy/local/.state/dev-web/ (remove it to start over).
  Collector stand-in   http://127.0.0.1:8090   (edit a survey under examples/surveys/ and reload)
  Factory              http://localhost:8080
  Transparency log     http://localhost:9001/checkpoint
  Publish your survey  just publish <survey>   (then see the Publishing page)
Sign-in at the factory is its development identity (FIELDSEAL_IDENTITY=dev), login product-owner.
Not for production: the factory refuses this identity there. Logs: deploy/local/.state/dev-web/logs/
MSG

# Stop when any service stops.
wait -n "${PIDS[@]}" || true
die "a service stopped; see deploy/local/.state/dev-web/logs/"
