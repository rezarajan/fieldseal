# check=skip=FromPlatformFlagConstDisallowed
# (Deliberate: every stage is pinned to linux/amd64; see the note below.)
# Fieldseal build: Nix provides the pinned toolchain inside the container; the
# artefacts it produces (Android native libraries, Kotlin bindings, Python wheels) do not
# depend on Nix and are checked for that before they leave the build stage.
#
#   podman build --target artifacts --output type=local,dest=dist .
#   docker buildx build -f Containerfile --target artifacts --output type=local,dest=dist .
#
# Reuse a published toolchain image instead of provisioning one (see
# docs/reference/toolchain.md, "Continuous integration"):
#   ... --build-arg BUILDER_IMAGE=ghcr.io/rezarajan/fieldseal/builder:<tag>
#
# Optional smoke test, installing the wheel on a plain Debian image:
#   podman build --target smoke .
#
# Every stage is pinned to linux/amd64 on every host: Google's Linux Android
# SDK/NDK exist only for x86_64, and a single builder architecture keeps
# release artefacts identical whoever builds them. On ARM hosts (Apple
# Silicon, ARM Linux) this runs under Rosetta or QEMU: slower, same output.

# Which image the build stage starts from: the `toolchain` stage below by
# default, or a published builder image with the same flake inputs.
ARG BUILDER_IMAGE=toolchain

# ---------------------------------------------------------------------------
# toolchain: Nix plus the fully provisioned dev shell. Depends only on
# flake.nix, flake.lock and rust-toolchain.toml; published by CI as the
# builder image.
# nixos/nix 2.35.2 (multi-arch index digest)
FROM --platform=linux/amd64 docker.io/nixos/nix:2.35.2@sha256:7a007c766426c1877758ddc5cb87a965ac131fc78c582ce0083d922d51ae945c AS toolchain

LABEL org.opencontainers.image.source="https://github.com/rezarajan/fieldseal" \
      org.opencontainers.image.description="Fieldseal build toolchain: Nix dev shell with Rust, Android SDK/NDK, JDK, Python"

RUN printf '%s\n' \
      'experimental-features = nix-command flakes' \
      'accept-flake-config = false' \
      'filter-syscalls = false' \
    >> /etc/nix/nix.conf

WORKDIR /opt/fieldseal-toolchain
COPY flake.nix flake.lock rust-toolchain.toml ./
# The profile is a GC root for the dev shell, so garbage collection keeps the
# toolchain and drops only download archives and build-time leftovers.
RUN nix develop path:. --profile /nix/var/nix/profiles/fieldseal-dev --command true \
 && nix-collect-garbage \
 && nix develop path:. --command rustc --version

WORKDIR /src

# ---------------------------------------------------------------------------
# build: compile, then check that nothing depends on Nix.
FROM --platform=linux/amd64 ${BUILDER_IMAGE} AS build
WORKDIR /src

# Build and check. The workspace has many crates, so sources are copied whole
# and crates are fetched against the lockfile before building.
COPY . .
RUN nix develop path:. --command cargo fetch --locked \
 && nix develop path:. --command tools/build.sh \
 && nix develop path:. --command tools/check-portable.sh dist

# ---------------------------------------------------------------------------
# artifacts: dist/ only; no Nix, no toolchain.
FROM scratch AS artifacts
COPY --from=build /src/dist/ /

# ---------------------------------------------------------------------------
# smoke: proof that the Python wheel runs without Nix, on a stock glibc distribution.
FROM --platform=linux/amd64 docker.io/library/python:3.12-slim-bookworm AS smoke
COPY --from=build /src/dist/python/ /wheels/
RUN pip install --no-index --no-cache-dir /wheels/fieldseal-*.whl \
 && python -c "import fieldseal; print('fieldseal core', fieldseal.core_version())"
