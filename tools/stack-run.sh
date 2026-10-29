#!/usr/bin/env bash
# Runs the demo service once: tools/stack-run.sh <step> [argument]   (just demo|seed|resume and
# the walkthrough steps: authority, publish, issue, assign, registry, fetch, enrol, register, wait,
# bundle, capture, upload, intake). `issue` issues the example rosters at the factory and `assign`
# assigns their cohorts to the collector's account; each asks for one operator sign-in, which the
# demo service answers with a passkey (tools/stack-browser.sh). `just up` runs seed, issue and
# assign; `demo`, `enrol` and `resume` run them again first, and they change nothing a second time.
# Starts the stack first if it is not up. The exit status is the demo's.
set -euo pipefail
# shellcheck source=stack-engine.sh
. "$(dirname "${BASH_SOURCE[0]}")/stack-engine.sh"

curl -fsS -o /dev/null --max-time 3 http://localhost:8080/readyz 2>/dev/null || "$ROOT/tools/stack-up.sh"
[ "${FIELDSEAL_SKIP_IMAGE_BUILD:-0}" = 1 ] || "$ROOT/tools/stack-images.sh" demo
cmd="${1:-demo}"
# Files the walkthrough hands you (fetched artefacts, rendered instruments) land here.
mkdir -p "$LOCAL/.out" && chmod 0777 "$LOCAL/.out"
status=0
"${COMPOSE[@]}" -f "$LOCAL/compose.yaml" --env-file "$LOCAL/.env.secrets" \
  --profile demo run --no-deps --rm -T demo "$@" || status=$?
[ "$status" = 0 ] && [ "$cmd" = resume ] || exit "$status"

# After a restart the intake app must have rebuilt its gate from the persisted submissions
# and recognised the second upload as a duplicate that landed nothing.
logs="$(compose logs intake 2>&1 || true)"
events="$(printf '%s\n' "$logs" | grep -o '{"event":.*}' || true)"
printf '\n== intake events\n'
printf '%s\n' "$events" | tail -5
last="$(printf '%s\n' "$events" | tail -2)"
fail() { printf 'stack: %s\n' "$1" >&2; exit 1; }
printf '%s\n' "$last" | grep -q '"event":"submission".*"new":false' || fail "the last events are not a duplicate submission (\"new\":false)"
printf '%s\n' "$last" | grep -q '"event":"landed".*"envelopes":0.*"observations":0' || fail "the last events do not show nothing landed"
printf '%s\n' "$events" | grep '"event":"replayed"' | grep -Eq '"landed":[1-9][0-9]*' || fail "no replayed event with landed > 0: the gate was not rebuilt after the restart"
# The resume step wrote the results export of the landing (fieldseal intake results) before and
# after the duplicate upload; the two directories must be identical byte for byte.
[ -d "$LOCAL/.out/results-before" ] && [ -d "$LOCAL/.out/results-after" ] || fail "the resume step did not write the results exports to deploy/local/.out"
diff -r "$LOCAL/.out/results-before" "$LOCAL/.out/results-after" || fail "the results export changed across the restart and the duplicate upload"
echo "ok: the results export is byte-identical before and after"
echo "ok: duplicate recognised, nothing landed, and the gate was rebuilt from the persisted submissions"
