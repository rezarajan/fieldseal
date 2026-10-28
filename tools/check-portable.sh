#!/usr/bin/env bash
# Fail if any artefact in dist/ depends on Nix, or would not load on its
# target. Checks every ELF file, including those inside wheels and APKs:
#   - no /nix/store in RPATH/RUNPATH, interpreter or embedded strings
#   - no builder home-directory paths (/home, /Users, /root) in any file
#   - Android libraries link only against platform libraries and use
#     16 KB-aligned segments (required for 16 KB-page devices)
#   - Linux libraries need at most glibc 2.28 (manylinux_2_28)
set -euo pipefail

DIST=${1:-dist}
MAX_GLIBC=2.28
ANDROID_ALLOWED_NEEDED='^(libc|libm|libdl|liblog|libandroid)\.so$'
LINUX_ALLOWED_NEEDED='^(libc|libm|libdl|libpthread|librt|libgcc_s|ld-linux-x86-64)\.so(\.[0-9]+)*$'
# Third-party prebuilt libraries from Maven (pinned by checksum). They were
# built on their maintainers' machines and embed those paths, which is not a
# leak from our builders; every other rule still applies to them.
THIRD_PARTY_PREBUILT='^lib(jnidispatch|androidx\.graphics\.path)\.so$'

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
fail=0
bad() { echo "FAIL  $1: $2"; fail=1; }

# Unpack archives so their ELF contents are checked too.
cp -r "$DIST" "$work/tree"
while IFS= read -r -d '' archive; do
  unzip -qo "$archive" -d "$archive.unzipped"
done < <(find "$work/tree" -type f \( -name '*.whl' -o -name '*.apk' -o -name '*.aar' \) -print0)

checked=0
while IFS= read -r -d '' f; do
  [[ $(file -b "$f") == ELF* ]] || continue
  checked=$((checked + 1))
  rel=${f#"$work/tree/"}
  before=$fail

  # Capture tool output first: with pipefail, `cmd | grep -q` reports a
  # failure when grep exits early, which would hide a match.
  dyn=$(readelf -d "$f")
  strs=$(strings -a "$f")
  if grep -q '/nix/store' <<<"$strs"; then
    bad "$rel" "contains a /nix/store path"
  fi
  if [[ ! $(basename "$f") =~ $THIRD_PARTY_PREBUILT ]] && grep -qE '(^|[^[:alnum:]])/(home|Users|root)/' <<<"$strs"; then
    bad "$rel" "contains a builder home-directory path"
  fi
  if grep -E '\((RPATH|RUNPATH)\)' <<<"$dyn" | grep -q '/nix/'; then
    bad "$rel" "RPATH/RUNPATH points into /nix"
  fi
  interp=$(readelf -p .interp "$f" 2>/dev/null | grep -o '/[^ ]*' || true)
  if [[ $interp == /nix/* ]]; then
    bad "$rel" "interpreter is $interp"
  fi

  needed=$(sed -n 's/.*(NEEDED).*\[\(.*\)\]/\1/p' <<<"$dyn")
  # Android libraries carry the NDK's .note.android.ident section.
  sections=$(readelf -S "$f")
  if grep -q '\.note\.androi' <<<"$sections"; then
    for lib in $needed; do
      [[ $lib =~ $ANDROID_ALLOWED_NEEDED ]] || bad "$rel" "needs non-platform library $lib"
    done
    aligns=$(readelf -lW "$f" | awk '$1=="LOAD" {print $NF}')
    if grep -qv '^0x\(4000\|10000\)$' <<<"$aligns"; then
      bad "$rel" "LOAD segments are not 16 KB aligned"
    fi
  else
    for lib in $needed; do
      [[ $lib =~ $LINUX_ALLOWED_NEEDED ]] || bad "$rel" "needs non-system library $lib"
    done
    newest=$(objdump -T "$f" | grep -o 'GLIBC_[0-9.]*' | sed 's/GLIBC_//' | sort -V | tail -1 || true)
    if [[ -n $newest ]] && [[ $(printf '%s\n%s\n' "$newest" "$MAX_GLIBC" | sort -V | tail -1) != "$MAX_GLIBC" ]]; then
      bad "$rel" "needs glibc $newest (> $MAX_GLIBC)"
    fi
  fi
  [[ $fail == "$before" ]] && echo "ok    $rel"
done < <(find "$work/tree" -type f -print0)

# Non-ELF files (metadata, SBOMs, bindings) must not carry Nix or builder paths either.
while IFS= read -r leak; do
  bad "${leak#"$work/tree/"}" "contains a /nix/store or builder home-directory path"
done < <(grep -rlaE '/nix/store|(^|[^[:alnum:]])/(home|Users|root)/' "$work/tree" --exclude='*.so' --exclude='*.whl' --exclude='*.apk' || true)

command -v auditwheel >/dev/null || echo "note  auditwheel not available on this host (Linux only); glibc check above still applies"
for whl in "$DIST"/python/*.whl; do
  [[ -e $whl ]] || continue
  case $whl in *-none-any.whl) continue ;; esac
  [[ $whl == *manylinux_2_28* ]] || bad "$whl" "wheel is not tagged manylinux_2_28"
  command -v auditwheel >/dev/null || continue
  aw=$(auditwheel show "$whl" 2>&1)
  grep -q 'manylinux_2_28' <<<"$aw" || bad "$whl" "auditwheel does not report manylinux_2_28"
done

if [[ $checked -eq 0 ]]; then
  bad "$DIST" "no ELF files found"
fi
if [[ $fail -ne 0 ]]; then
  echo "Portability check failed"
  exit 1
fi
echo "Portability check passed ($checked ELF files)"
