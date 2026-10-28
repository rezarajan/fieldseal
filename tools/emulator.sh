#!/usr/bin/env bash
# Create (once) and start the Fieldseal test emulator. Run inside the emulator shell:
#   nix develop path:.#emulator --command tools/emulator.sh [--headless]
# Linux needs KVM; macOS uses the Hypervisor framework. Not available on
# aarch64-linux. The AVD lives in ./.android (ignored by git).
set -euo pipefail

cd "$(dirname "$0")/.."
PLATFORM=${FIELDSEAL_ANDROID_PLATFORM:?run inside nix develop path:.#emulator}
AVD=fieldseal-device
ABI=${FIELDSEAL_EMULATOR_ABI:-x86_64}  # arm64-v8a on Apple Silicon, x86_64 elsewhere
IMAGE="system-images;android-$PLATFORM;google_apis;$ABI"

if [[ $(uname -s) == Linux && ! -e /dev/kvm ]]; then
  echo "No /dev/kvm: the emulator needs hardware virtualisation." >&2; exit 1
fi  # macOS uses the Hypervisor framework; nothing to check

if ! avdmanager list avd -c | grep -qx "$AVD"; then
  mkdir -p "$ANDROID_AVD_HOME"
  # pixel_tablet: a 10.95" landscape tablet profile, close to the target hardware.
  echo no | avdmanager create avd --name "$AVD" --package "$IMAGE" --device pixel_tablet
fi

args=(-avd "$AVD" -no-snapshot-save -no-boot-anim -camera-back virtualscene)
if [[ ${1:-} == --headless ]]; then
  args+=(-no-window -gpu swiftshader_indirect -no-audio)
fi
exec emulator "${args[@]}"
