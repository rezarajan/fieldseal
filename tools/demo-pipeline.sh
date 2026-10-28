#!/usr/bin/env bash
# The local demo: the connected flow through the real `fieldseal` commands, end to end, with
# software keys, and a summary at the end. Nothing leaves this machine.
#
#   tools/demo-pipeline.sh [work-dir]
#
# Stages, each a real command (docs/reference/spec/cli.md):
#   1  root ceremony and purpose keys      trust root-init, keys generate, trust issue, trust bundle
#   2  publish the sample instrument       artefact provenance|sign|publish, log prove, artefact verify
#                                          (two of three publisher signatures, a transparency log)
#   3  register a device                   registration token|request|inspect|approve (words confirmed)
#   4  build and check a sealed bundle     bundle build|verify|inspect
#   5  the device, delivery and receipt    device simulate (capture, resurvey, nonresponse, export,
#                                          background upload, receipt, clear), export verify|repair
#   6  the intake gate                     intake practice|contract|run (long format files)
#
# Every key is a software key in a local directory and every device is unattested (CLI-007);
# production uses hardware-backed custody and attested devices. The stages share the authority
# of stages 1-3; the device simulator and the intake gate use the practice authority (their
# own fixed seed), as `fieldseal device simulate` and `fieldseal intake` do, and say so.
#
# Environment: FIELDSEAL_BIN (default target/debug/fieldseal, built with cargo if missing).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="$(cd "$(mktemp -d -p "${TMPDIR:-/tmp}" fieldseal-demo.XXXXXX 2>/dev/null || mktemp -d)" && pwd)"
if [ "$#" -ge 1 ]; then
  mkdir -p "$1"
  OUT="$(cd "$1" && pwd)"
fi
FS="${FIELDSEAL_BIN:-$ROOT/target/debug/fieldseal}"
EX="$ROOT/examples"

if [ ! -x "$FS" ]; then
  echo "== building fieldseal"
  (cd "$ROOT" && cargo build -p fieldseal-cli --locked)
fi

SUMMARY=()
stage() { printf '\n== %s\n' "$1"; }
note() { SUMMARY+=("$1"); }
run() { printf '+ fieldseal %s\n' "$*"; "$FS" "$@"; }
# Runs fieldseal, keeps its output for the summary, and shows it.
capture() { printf '+ fieldseal %s\n' "$*" >&2; local out; out="$("$FS" "$@" 2>&1)"; printf '%s\n' "$out" >&2; printf '%s' "$out"; }
sha() { if command -v sha256sum >/dev/null; then printf '%s' "$1" | sha256sum | cut -d' ' -f1; else printf '%s' "$1" | shasum -a 256 | cut -d' ' -f1; fi; }

cd "$OUT"
echo "work directory: $OUT"
unset FIELDSEAL_SIGNER FIELDSEAL_POLICY FIELDSEAL_TRUST_BUNDLE FIELDSEAL_ADAPTERS FIELDSEAL_FACTORY_URL FIELDSEAL_STATE_DIR || true

# -- 1. Root ceremony and purpose keys ---------------------------------------------------------
stage "1. Root ceremony and purpose keys (TRU-002, TRU-010, TRU-020)"
cat > ceremony.yaml <<'YAML'
authority: example-authority
threshold: 2-of-3
custodians: [custodian-a, custodian-b, custodian-c]
witnesses: [witness-1]
held: 2026-01-15T08:00:00Z
validity: 3650d
YAML
run trust root-init --ceremony ceremony.yaml --out root

certify() { # custody-dir purpose name validity [extra trust-issue args...]
  local dir="$1" purpose="$2" name="$3" validity="$4"; shift 4
  "$FS" keys generate --purpose "$purpose" --custody "$dir" --csr "csr/$name.csr" >/dev/null
  FIELDSEAL_SIGNER=soft:root "$FS" trust issue --purpose "$purpose" --csr "csr/$name.csr" --out certs --at 2026-01-16 --validity "$validity" "$@" >/dev/null
  echo "certified $purpose key: $name"
}
for who in alice bob carol; do certify "pub-$who" publisher "pub-$who" 730d; done
certify builder builder builder 365d
certify online registration reg-sign 365d
certify online receipt receipt 365d
"$FS" keys generate --purpose registration --algorithm x25519 --custody online --csr csr/reg-seal.csr >/dev/null
FIELDSEAL_SIGNER=soft:root "$FS" trust issue --purpose registration --csr csr/reg-seal.csr --out certs --at 2026-01-16 --validity 365d >/dev/null
echo "certified registration sealing key: reg-seal"
"$FS" keys generate --purpose record --custody online --csr csr/record.csr >/dev/null
FIELDSEAL_SIGNER=soft:root "$FS" trust issue --purpose record --csr csr/record.csr --out certs --at 2026-01-16 --period 2026-27 --period-start 2026-02-01 --period-end 2026-12-01 --retention 180d >/dev/null
echo "certified record key for collection period 2026-27"
printf -- '- platform: software\n  appId: fieldseal-simulator\n  signingDigests: [%s]\n' "$(sha fieldseal-simulator)" > builds.yaml
FIELDSEAL_SIGNER=soft:root run trust bundle --roots root/root.crt --pins certs --runtime-builds builds.yaml --log-origin fieldseal-local-log --out trust-bundle.bundle --at 2026-01-16
note "authority: root ceremony (2-of-3 custodians), $(ls certs | wc -l | tr -d ' ') purpose-key certificates, one trust bundle"

# -- 2. Publish the sample instrument ----------------------------------------------------------
stage "2. Publish the sample instrument with threshold signatures and the transparency log (PUB)"
cat > policy.yaml <<'YAML'
apiVersion: fieldseal.dev/v1alpha1
kind: Policy
metadata: { name: authority-publishing, version: 1.0.0 }
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
YAML
cp "$EX/instruments/household-water-access.yaml" water.yaml
mkdir -p i18n/water && cp "$EX"/instruments/i18n/household-water-access/*.po i18n/water/   # its translations (ADR 0040)
export FIELDSEAL_ADAPTERS=files FIELDSEAL_TRUST_BUNDLE=trust-bundle.bundle FIELDSEAL_POLICY=policy.yaml
PROV="$(FIELDSEAL_SIGNER=soft:builder capture artefact provenance water.yaml --source abc123 --reviewers reviewer-1:es,reviewer-2 --at 2026-02-01)"
ADDRESS="$(printf '%s' "$PROV" | sed -n 's/.*(\(sha256:[0-9a-f]*\)).*/\1/p' | head -1)"
FIELDSEAL_SIGNER=soft:pub-alice run artefact sign water.publication
FIELDSEAL_SIGNER=soft:pub-bob run artefact sign water.publication
run artefact publish water.publication --custody online
run log prove "$ADDRESS"
VERIFIED="$(capture artefact verify water.published --trust-bundle trust-bundle.bundle)"
note "instrument $ADDRESS published: $(printf '%s' "$VERIFIED" | sed 's/^water.published: //')"
unset FIELDSEAL_POLICY FIELDSEAL_ADAPTERS

# -- 3. Register a device ----------------------------------------------------------------------
stage "3. Portal token, request, fingerprint words, approval (REG-004..032)"
export FIELDSEAL_TRUST_BUNDLE=trust-bundle.bundle FIELDSEAL_FACTORY_URL=https://factory.example.org FIELDSEAL_SIGNER=soft:online
run registration token --account alice --at 2026-02-01T08:00:00Z --out alice.token
REQ="$(capture registration request --token alice.token --out alice.request --json)"
WORDS="$(printf '%s' "$REQ" | sed -n 's/.*"words":"\([^"]*\)".*/\1/p')"
TENANCY="$(printf '%s' "$REQ" | sed -n 's/.*"tenancy":"\([^"]*\)".*/\1/p')"
run registration inspect alice.request --at 2026-02-01T08:05:00Z
echo "the collector reads the four words on the device and on the portal: $WORDS"
run registration approve alice.request --allow-unattested --words "$WORDS" --at 2026-02-01T08:05:00Z
note "device registered: tenancy ${TENANCY:0:16}..., fingerprint words '$WORDS' confirmed, tenancy certificate alice.tenancy-certificate (software keys, unattested)"
unset FIELDSEAL_TRUST_BUNDLE FIELDSEAL_FACTORY_URL FIELDSEAL_SIGNER

# -- 4. Build and check a bundle ---------------------------------------------------------------
stage "4. A bundle sealed to the device, verified the way the device verifies it (DIS-030)"
mkdir -p out
BUILD="$(capture bundle build --instrument "$EX/instruments/household-water-access.yaml" --layout "$EX/layouts/household-water-access.compact.yaml" --roster "$EX/rosters/household-water-access.yaml" --out-dir out/bundle --time 1800000000000 --allow-unattested)"
BUNDLE="$(ls out/bundle/*.fsb)"
run bundle inspect "$BUNDLE" --trust out/bundle/trust-bundle.cbor --now 1800172800000
VB="$(capture bundle verify "$BUNDLE" --trust out/bundle/trust-bundle.cbor --device-file out/bundle/device.txt --now 1800172800000)"
note "bundle: $(basename "$BUNDLE") $(printf '%s' "$VB" | head -1 | sed 's/^[^:]*: //')"
note "bundle contents: $(printf '%s' "$BUILD" | grep 'instrument(s)' | head -1)"

# -- 5. The device: capture, export, upload, receipt, clear ------------------------------------
stage "5. Device: capture, resurvey, nonresponse, export, background upload, receipt, clear (COL, DEL)"
mkdir -p out/device
SIM="$(cd out/device && capture device simulate --script "$EX/scenarios/connected-flow.yaml" --review)"
note "device: $(printf '%s' "$SIM" | grep -c '^step [0-9]*: \(capture\|status\)') capture/status records sealed; $(printf '%s' "$SIM" | grep 'upload:' | sed 's/^step [0-9]*: //')"
note "gate: $(printf '%s' "$SIM" | grep 'intake gate' | sed 's/.*intake gate: //')"
note "device: $(printf '%s' "$SIM" | grep 'clear through' | sed 's/^step [0-9]*: //')"
note "journal: $(printf '%s' "$SIM" | grep '^journal:' | sed 's/^journal: //')"
run export inspect out/device/export.fieldseal
EV="$(capture export verify out/device/export.fieldseal --seed 5)"
note "export file: $(printf '%s' "$EV" | head -1 | sed 's/^[^:]*: //')"

echo
echo "-- a damaged export file is repaired from parity, byte for byte (WIRE-109, CLI-016)"
cp out/device/export.fieldseal out/device/damaged.fieldseal
printf '\377' | dd of=out/device/damaged.fieldseal bs=1 seek=900 conv=notrunc 2>/dev/null
set +e
"$FS" export verify out/device/damaged.fieldseal --seed 5
BROKEN=$?
set -e
[ "$BROKEN" -ne 0 ] || { echo "expected the damaged export to fail verification" >&2; exit 1; }
RP="$(capture export repair out/device/damaged.fieldseal -o out/device/repaired.fieldseal --seed 5)"
cmp out/device/export.fieldseal out/device/repaired.fieldseal
note "damage: a flipped byte failed verification (exit $BROKEN); repair from parity restored the file exactly ($(printf '%s' "$RP" | grep -o 'rebuilt [0-9]* shard(s)' | head -1))"

# -- 6. The intake gate ------------------------------------------------------------------------
stage "6. Intake: the gate and the long-format landing (INT)"
run intake contract "$EX/instruments/household-water-access.yaml" --out out/landing
PR="$(capture intake practice --out out/practice.fieldseal)"
GATE="$(capture intake run out/practice.fieldseal --device practice-device --seed 7 --instrument "$EX/instruments/household-water-access.yaml" --out out/landing)"
note "intake: $(printf '%s' "$GATE" | head -1); $(printf '%s' "$GATE" | grep 'landed' | sed 's/^ *//')"
note "landing directory: out/landing ($(find out/landing -type f | wc -l | tr -d ' ') file(s), data contract included)"

# -- Summary -----------------------------------------------------------------------------------
printf '\n== Summary (all keys software, all devices unattested)\n'
for line in "${SUMMARY[@]}"; do printf ' - %s\n' "$line"; done
printf '\nFiles are in %s\n' "$OUT"
