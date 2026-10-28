#!/usr/bin/env bash
# Build every Fieldseal artefact into dist/. Run inside the Nix shell:
#   nix develop path:. --command tools/build.sh
# The Containerfile runs exactly this, then tools/check-portable.sh.
set -euo pipefail

cd "$(dirname "$0")/.."
DIST=${DIST:-dist}
MIN_SDK=${FIELDSEAL_ANDROID_MIN_SDK:?run inside the Nix shell}
ANDROID_HOST=${FIELDSEAL_ANDROID_HOST:-0}  # 0 on aarch64-linux: no Google SDK host tools
case "$(uname -s)" in Darwin) HOST_LIB_EXT=dylib ;; *) HOST_LIB_EXT=so ;; esac
ANDROID_ABIS=(arm64-v8a x86_64)  # devices, emulator
ANDROID_RUNTIME=runtimes/android  # the Android runtime (issue #51); built when present

# Replace machine-specific paths compiled into binaries (panic locations) with
# fixed prefixes: builds are then identical on any machine, and no builder's
# home directory or username ships in an artefact.
export RUSTFLAGS="--remap-path-prefix=${CARGO_HOME:-$HOME/.cargo}=/cargo --remap-path-prefix=$PWD=/fieldseal ${RUSTFLAGS:-}"

rm -rf "$DIST"
mkdir -p "$DIST"/android "$DIST"/python

step() { printf '\n==> %s\n' "$*"; }

step "Architecture: dependency rule (ADR 0028)"
python3 tools/check-architecture.py

step "Requirements: spec coverage (report only)"
if [ -d docs/reference/spec ]; then
  python3 tools/check-coverage.py
else
  echo "specs not present in this build context; skipped"
fi

step "Rust: tests"
cargo test --workspace --locked

step "Rust: supply-chain checks"
if [[ -f deny.toml ]]; then cargo deny --locked check; else echo "deny.toml not present yet; skipping"; fi

if [[ $ANDROID_HOST == 1 ]]; then
step "Android: native core for ${ANDROID_ABIS[*]} (minSdk $MIN_SDK)"
ndk_args=()
for abi in "${ANDROID_ABIS[@]}"; do ndk_args+=(-t "$abi"); done
cargo ndk "${ndk_args[@]}" --platform "$MIN_SDK" -o "$DIST/android/jniLibs" \
  build --release --locked -p fieldseal-uniffi

step "Android: Kotlin bindings (UniFFI)"
cargo build --release --locked -p fieldseal-uniffi
cargo run --release --locked -p fieldseal-uniffi --bin uniffi-bindgen -- \
  generate --library "target/release/libfieldseal_uniffi.$HOST_LIB_EXT" \
  --language kotlin --no-format --out-dir "$DIST/android/kotlin"
else
  step "Android: skipped on this host (no Android SDK/NDK); build it with the container"
fi

step "Python wheel for authority-side tools (manylinux_2_28, abi3)"
# Nix's Python sets _PYTHON_HOST_PLATFORM, which would override the manylinux tag.
env -u _PYTHON_HOST_PLATFORM maturin build --release --locked \
  --manifest-path crates/bindings/python/Cargo.toml \
  --target x86_64-unknown-linux-gnu \
  --zig --compatibility manylinux_2_28 \
  --out "$DIST/python"

if [[ $ANDROID_HOST == 1 && -f $ANDROID_RUNTIME/settings.gradle.kts ]]; then
  step "Android runtime: unit tests and APK"
  GEN=$ANDROID_RUNTIME/app/build/generated/fieldseal
  rm -rf "$GEN" && mkdir -p "$GEN"
  cp -r "$DIST/android/jniLibs" "$GEN/jniLibs"
  cp -r "$DIST/android/kotlin" "$GEN/kotlin"
  gradle -p "$ANDROID_RUNTIME" --console=plain testDebugUnitTest assembleRelease
  # Unsigned: the release signing key never enters the build container
  # (docs/explanation/build-system.md, "Release signing").
  cp "$ANDROID_RUNTIME"/app/build/outputs/apk/release/app-release-unsigned.apk "$DIST/android/fieldseal-collect-unsigned.apk"
fi

step "Checksums"
(cd "$DIST" && find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS)
echo "Artefacts in $DIST/"
