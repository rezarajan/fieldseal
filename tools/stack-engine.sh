#!/usr/bin/env bash
# Sourced by the stack scripts on the host: picks the container engine and its compose, and
# for rootless Podman points it at the configuration shipped in deploy/local/containers.
#
#   FIELDSEAL_CONTAINER_ENGINE   docker (default) or podman
#   FIELDSEAL_PODMAN_HOME        Podman's own HOME and storage (default ~/.local/share/fieldseal-podman),
#                                kept apart from any other Podman or Docker data
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOCAL="$ROOT/deploy/local"
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

# compose <args>: the stack's compose project, with the generated secrets as its environment.
compose() { "${COMPOSE[@]}" -f "$LOCAL/compose.yaml" --env-file "$LOCAL/.env.secrets" "$@"; }
