#!/usr/bin/env bash
# Sourced by the stack scripts on the host: picks the container engine and its compose, and
# for rootless Podman points it at the configuration shipped in deploy/local/containers.
#
#   FIELDSEAL_CONTAINER_ENGINE   docker (default) or podman
#   FIELDSEAL_PODMAN_HOME        Podman's own HOME and storage (default ~/.local/share/fieldseal-podman),
#                                kept apart from any other Podman or Docker data
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOCAL="$ROOT/deploy/local"
# The example survey folders and rosters: the only place a script names these roots.
# shellcheck disable=SC2034
SURVEYS="$ROOT/examples/surveys"
# shellcheck disable=SC2034
ROSTERS="$ROOT/examples/rosters"
ENGINE="${FIELDSEAL_CONTAINER_ENGINE:-docker}"

say() { printf '%s\n' "$*"; }
die() { printf 'stack: %s\n' "$*" >&2; exit 1; }

case "$ENGINE" in
  docker)
    COMPOSE=(docker-compose) ;;
  podman)
    # A private HOME and XDG tree for Podman only, so nothing else's Podman data or config is
    # touched and the shipped configuration is what it reads. containers/image looks for
    # policy.json under $HOME/.config/containers, so a `podman` shim on PATH sets HOME.
    PODMAN_HOME="${FIELDSEAL_PODMAN_HOME:-$HOME/.local/share/fieldseal-podman}"
    mkdir -p "$PODMAN_HOME/home/.config/containers" "$PODMAN_HOME/bin"
    for f in policy.json registries.conf storage.conf containers.conf; do
      ln -sf "$LOCAL/containers/$f" "$PODMAN_HOME/home/.config/containers/$f"
    done
    REAL_PODMAN="$(PATH="${PATH}" command -v podman || true)"
    case "$REAL_PODMAN" in "$PODMAN_HOME"/bin/*) REAL_PODMAN="$(cat "$PODMAN_HOME/bin/.real")" ;; esac
    [ -n "$REAL_PODMAN" ] || die "podman is not on PATH (run through just, or inside: nix develop path:.)"
    printf '%s' "$REAL_PODMAN" > "$PODMAN_HOME/bin/.real"
    cat > "$PODMAN_HOME/bin/podman" <<SHIM
#!/bin/sh
HOME=$PODMAN_HOME/home XDG_DATA_HOME=$PODMAN_HOME/data XDG_CONFIG_HOME=$PODMAN_HOME/home/.config \\
XDG_RUNTIME_DIR="\${XDG_RUNTIME_DIR:-/run/user/\$(id -u)}" exec $REAL_PODMAN "\$@"
SHIM
    chmod +x "$PODMAN_HOME/bin/podman"
    export PATH="$PODMAN_HOME/bin:$PATH"
    export CONTAINERS_CONF="$LOCAL/containers/containers.conf"
    export CONTAINERS_REGISTRIES_CONF="$LOCAL/containers/registries.conf"
    export CONTAINERS_STORAGE_CONF="$LOCAL/containers/storage.conf"
    export PODMAN_COMPOSE_WARNING_LOGS=false
    COMPOSE=(podman-compose) ;;
  *) die "FIELDSEAL_CONTAINER_ENGINE must be docker or podman, not '$ENGINE'" ;;
esac
command -v "$ENGINE" >/dev/null || die "$ENGINE is not on PATH (run through just, or inside: nix develop path:.)"

# stage <name> <command...>: runs the command (or a function of the calling script), appends
# "<name><TAB><seconds>" to $LOCAL/.generated/stack-timing.tsv and returns the command's status.
# It prints nothing itself, so out=$(stage <name> <command...>) captures the command's output. The
# command runs as the condition of an `if`, so `set -e` is off inside a function passed to it:
# end every step of such a function with `|| die ...`.
TIMING_TSV="$LOCAL/.generated/stack-timing.tsv"
stage() {
  local name="$1" start end ms rc=0
  shift
  mkdir -p "$(dirname "$TIMING_TSV")"
  start="$(date +%s%N)"
  if "$@"; then rc=0; else rc=$?; fi
  end="$(date +%s%N)"
  ms=$(( (end - start) / 1000000 ))
  printf '%s\t%d.%03d\n' "$name" $((ms / 1000)) $((ms % 1000)) >> "$TIMING_TSV"
  return "$rc"
}

# stage_report: prints the recorded stages as an aligned table with the total, and copies the table
# to $LOCAL/.generated/stack-timing.txt.
stage_report() {
  [ -s "$TIMING_TSV" ] || return 0
  awk -F'\t' '
    { name[NR] = $1; secs[NR] = $2; total += $2; if (length($1) > width) width = length($1) }
    END {
      if (width < 5) width = 5
      printf "%-*s  %9s\n", width, "stage", "seconds"
      for (i = 1; i <= NR; i++) printf "%-*s  %9.3f\n", width, name[i], secs[i]
      printf "%-*s  %9.3f\n", width, "total", total
    }' "$TIMING_TSV" | tee "$(dirname "$TIMING_TSV")/stack-timing.txt"
}

# compose <args>: the stack's compose project, with the generated secrets as its environment.
compose() { "${COMPOSE[@]}" -f "$LOCAL/compose.yaml" --env-file "$LOCAL/.env.secrets" "$@"; }
