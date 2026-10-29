#!/usr/bin/env bash
# The stack's one authority, made once (marker /authority/.initialised) and shared read-only by
# the services: the root ceremony, the purpose keys and their certificates, the transparency
# log's signing key and the trust bundle that pins the log by origin and key.
# Development custody: software keys in a volume. Runs as the `init` compose service, and from
# tools/dev-web.sh with FIELDSEAL_AUTHORITY_DIR (an absolute path) and FIELDSEAL_BIN set.
set -euo pipefail

A="${FIELDSEAL_AUTHORITY_DIR:-/authority}"
LOG_ORIGIN="${FIELDSEAL_LOG_ORIGIN:-fieldseal.local/log}"

# The export pseudonymisation key (Technical Plan 6): 32 random bytes, mode 0600, made here and
# nowhere else (the intake app and the CLI only read it). An existing file is left unchanged, and
# this step comes before the early exit so that an authority made before this key existed gets one.
EK="$A/export-key"
if [ ! -f "$EK/export.key" ]; then
  mkdir -p "$EK"
  ( umask 077; head -c 32 /dev/urandom > "$EK/export.key" )
  chmod 600 "$EK/export.key"
  echo "export key: $EK/export.key"
fi
[ ! -f "$A/.initialised" ] || { echo "authority already initialised"; exit 0; }

FS="${FIELDSEAL_BIN:-fieldseal}"
today="$(date -u +%F)"
yesterday="$(date -u -d 'yesterday' +%F)"
later="$(date -u -d '+700 days' +%F)"
echo "== initialising the stack's authority (dates relative to $today)"
# A half-finished earlier run leaves nothing behind.
find "$A" -mindepth 1 -maxdepth 1 ! -name export-key -exec rm -rf {} +
cd "$A"

cat > "$A/ceremony.yaml" <<YAML
authority: local-stack-authority
threshold: 2-of-3
custodians: [custodian-a, custodian-b, custodian-c]
witnesses: [witness-1]
held: ${yesterday}T00:00:00Z
validity: 3650d
YAML
"$FS" trust root-init --ceremony ceremony.yaml --out root >/dev/null

# certify <custody-dir> <purpose> <csr-name> <validity> [trust issue args...]
certify() {
  local dir="$1" purpose="$2" name="$3" validity="$4"; shift 4
  "$FS" keys generate --purpose "$purpose" --custody "$dir" --csr "csr/$name.csr" >/dev/null
  issue "$purpose" "$name" "$validity" "$@"
}
issue() { # purpose csr-name validity [extra...]
  local purpose="$1" name="$2" validity="$3"; shift 3
  FIELDSEAL_SIGNER=soft:"$A/root" "$FS" trust issue --purpose "$purpose" --csr "csr/$name.csr" \
    --out certs --at "$today" --validity "$validity" "$@" >/dev/null
  echo "certified $purpose key: $name"
}

for who in alice bob carol; do certify "publish/pub-$who" publisher "pub-$who" 730d; done
certify publish/builder builder builder 365d  # the builder purpose allows at most a year

# Online custody: what the factory and the intake endpoint hold.
O=online
certify "$O" registration reg-sign 365d
"$FS" keys generate --purpose registration --algorithm x25519 --custody "$O" --csr csr/reg-seal.csr >/dev/null
issue registration reg-seal 365d
"$FS" keys generate --purpose record --algorithm x25519 --custody "$O" --csr csr/record.csr >/dev/null
issue record record 720d --period stack --period-start "$yesterday" --period-end "$later" --retention 180d
certify "$O" receipt receipt 365d
certify "$O" receiver receiver 365d
certify "$O" factory factory 365d   # signs the bundles

printf -- '- platform: software\n  appId: fieldseal-simulator\n  signingDigests: [%s]\n' \
  "$(printf fieldseal-simulator | sha256sum | cut -d' ' -f1)" > builds.yaml

# The log's signing key, and the bundle that pins the log by origin and key.
key="$("$FS" log key --key-file "$A/translog.key" --generate | sed -n 's/^public_key=//p')"
[ -n "$key" ] || { echo "no log public key" >&2; exit 1; }
FIELDSEAL_SIGNER=soft:"$A/root" "$FS" trust bundle --roots root/root.crt --pins certs \
  --runtime-builds builds.yaml --log "$LOG_ORIGIN=$key" --out trust-bundle.bundle --at "$today" >/dev/null
echo "trust bundle: $A/trust-bundle.bundle (log $LOG_ORIGIN pinned)"
touch "$A/.initialised"
