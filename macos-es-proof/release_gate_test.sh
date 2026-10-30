#!/usr/bin/env bash
set -euo pipefail

# WO-140@v1: exercise the sourceable release gate with sealed and rejected fixtures.
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
# WO-140@v1: let the mutation proof substitute only the gate implementation.
PACKAGE_RELEASE_SH="${PACKAGE_RELEASE_SH:-$SCRIPT_DIR/package-release.sh}"
# WO-140@v1: source the gate without requiring packaging inputs.
RELEASE_GATE_LIB_ONLY=1 . "$PACKAGE_RELEASE_SH"

# WO-140@v1: isolate receipt fixtures from the release work directory.
WORK=$(mktemp -d "${TMPDIR:-/tmp}/bulwark-release-gate-test.XXXXXX")
trap 'rm -rf "$WORK"' EXIT
# WO-140@v1: hash a stable stand-in for the exact upload binary.
BINARY="$WORK/bulwark"
printf 'fixture binary\n' > "$BINARY"
# WO-140@v1: compare receipts against the fixture binary's real digest.
HASH=$(shasum -a 256 "$BINARY" | awk '{print $1}')
# WO-140@v1: use fixed source identities so mismatch fixtures are deterministic.
HEAD_SHA=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
# WO-140@v1: keep the mismatched source distinct without runtime dependencies.
OTHER_SHA=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
# WO-140@v1: use fixed code-signature identities for deterministic gate fixtures.
GATE_CDHASH=cccccccccccccccccccccccccccccccccccccccc
# WO-140@v1: keep the mismatched gate identity visibly distinct.
OTHER_CDHASH=dddddddddddddddddddddddddddddddddddddddd

# WO-140@v1: pin receipt identity fields that require signed hardware to produce.
assert_seal_identity_contract() {
  local script field
  for script in "$SCRIPT_DIR/verify-gate.sh" "$SCRIPT_DIR/verify-allowlist-gate.sh"; do
    for field in bulwark_path bulwark_source bulwark_version bulwark_sha256 gate_cdhash head_sha; do
      grep -q "echo \"$field:" "$script" || {
        echo "FAIL: $script does not write $field"
        exit 1
      }
    done
    grep -q 'codesign -dvvv' "$script" || {
      echo "FAIL: $script does not read the gate CDHash"
      exit 1
    }
    grep -q 'source SHA unknown' "$script" || {
      echo "FAIL: $script can seal without a source SHA"
      exit 1
    }
    grep -q '==> bulwark binary:' "$script" || {
      echo "FAIL: $script does not print the resolved binary"
      exit 1
    }
  done
  grep -q 'sudo BULWARK_SOURCE_SHA=' "$PACKAGE_RELEASE_SH" || {
    echo "FAIL: package seal commands do not pass the tag source SHA"
    exit 1
  }
  echo "PASS: hardware-seal receipt identity contract present"
}

# WO-140@v1: write only the receipt fields consumed by the upload gate.
# WO-140@v1: include gate identity unless a fixture intentionally omits it.
write_receipt() {
  local path="$1" verdict="$2" sha="$3" hash="$4" cdhash="${5-}"
  {
    printf 'verdict:               %s\n' "$verdict"
    printf 'head_sha:              %s\n' "$sha"
    printf 'bulwark_sha256:        %s\n' "$hash"
    if [ -n "$cdhash" ]; then
      printf 'gate_cdhash:           %s\n' "$cdhash"
    fi
  } > "$path"
}

# WO-140@v1: a rejected fixture must fail and name its failed identity check.
# WO-140@v1: pass the expected signed-gate identity into every negative case.
expect_rejected() {
  local name="$1" expected="$2" dir="$3" expected_cdhash="${4-$GATE_CDHASH}" output
  if output=$(release_gate "$dir" "$HEAD_SHA" "$BINARY" "$expected_cdhash" 2>&1); then
    echo "FAIL: $name was accepted"
    exit 1
  fi
  if ! grep -qF "$expected" <<<"$output"; then
    echo "FAIL: $name did not name '$expected': $output"
    exit 1
  fi
  echo "PASS: $name rejected ($expected)"
}

# WO-140@v1: missing either hardware-seal receipt blocks the upload.
missing="$WORK/missing"
mkdir -p "$missing"
write_receipt "$missing/gate-receipt.txt" "SEALED - fixture" "$HEAD_SHA" "$HASH" "$GATE_CDHASH"
expect_rejected "missing receipt" "missing receipt" "$missing"

# WO-140@v1: a negative hardware verdict can never authorize an upload.
not_sealed="$WORK/not-sealed"
mkdir -p "$not_sealed"
write_receipt "$not_sealed/gate-receipt.txt" "NOT SEALED - fixture" "$HEAD_SHA" "$HASH" "$GATE_CDHASH"
write_receipt "$not_sealed/allowlist-gate-receipt.txt" "SEALED - fixture" "$HEAD_SHA" "$HASH" "$GATE_CDHASH"
expect_rejected "NOT SEALED verdict" "is not SEALED" "$not_sealed"

# WO-140@v1: receipts from another source commit cannot authorize this tag.
wrong_sha="$WORK/wrong-sha"
mkdir -p "$wrong_sha"
write_receipt "$wrong_sha/gate-receipt.txt" "SEALED - fixture" "$OTHER_SHA" "$HASH" "$GATE_CDHASH"
write_receipt "$wrong_sha/allowlist-gate-receipt.txt" "SEALED - fixture" "$HEAD_SHA" "$HASH" "$GATE_CDHASH"
expect_rejected "head_sha mismatch" "head_sha mismatch" "$wrong_sha"

# WO-140@v1: receipts from another binary cannot authorize the upload artifact.
wrong_hash="$WORK/wrong-hash"
mkdir -p "$wrong_hash"
write_receipt "$wrong_hash/gate-receipt.txt" "SEALED - fixture" "$HEAD_SHA" "$HASH" "$GATE_CDHASH"
case "$HASH" in
  0*) WRONG_HASH="1${HASH#?}" ;;
  *) WRONG_HASH="0${HASH#?}" ;;
esac
write_receipt "$wrong_hash/allowlist-gate-receipt.txt" "SEALED - fixture" "$HEAD_SHA" "$WRONG_HASH" "$GATE_CDHASH"
expect_rejected "bulwark_sha256 mismatch" "bulwark_sha256 mismatch" "$wrong_hash"

# WO-140@v1: a receipt without signed-gate identity cannot authorize upload.
missing_cdhash="$WORK/missing-cdhash"
mkdir -p "$missing_cdhash"
write_receipt "$missing_cdhash/gate-receipt.txt" "SEALED - fixture" "$HEAD_SHA" "$HASH" ""
write_receipt "$missing_cdhash/allowlist-gate-receipt.txt" "SEALED - fixture" "$HEAD_SHA" "$HASH" "$GATE_CDHASH"
expect_rejected "gate_cdhash missing" "gate_cdhash missing" "$missing_cdhash"

# WO-140@v1: a receipt from another signed gate cannot authorize upload.
wrong_cdhash="$WORK/wrong-cdhash"
mkdir -p "$wrong_cdhash"
write_receipt "$wrong_cdhash/gate-receipt.txt" "SEALED - fixture" "$HEAD_SHA" "$HASH" "$OTHER_CDHASH"
write_receipt "$wrong_cdhash/allowlist-gate-receipt.txt" "SEALED - fixture" "$HEAD_SHA" "$HASH" "$GATE_CDHASH"
expect_rejected "gate_cdhash mismatch" "gate_cdhash mismatch" "$wrong_cdhash"

# WO-140@v1: upload cannot proceed without a readable expected gate identity.
empty_cdhash="$WORK/empty-cdhash"
mkdir -p "$empty_cdhash"
write_receipt "$empty_cdhash/gate-receipt.txt" "SEALED - fixture" "$HEAD_SHA" "$HASH" "$GATE_CDHASH"
write_receipt "$empty_cdhash/allowlist-gate-receipt.txt" "SEALED - fixture" "$HEAD_SHA" "$HASH" "$GATE_CDHASH"
expect_rejected "empty expected gate_cdhash" "expected gate_cdhash missing" "$empty_cdhash" ""

# WO-140@v1: matching sealed receipts authorize the exact source, binary and gate.
sealed="$WORK/sealed"
mkdir -p "$sealed"
write_receipt "$sealed/gate-receipt.txt" "SEALED - fixture" "$HEAD_SHA" "$HASH" "$GATE_CDHASH"
write_receipt "$sealed/allowlist-gate-receipt.txt" "SEALED - fixture" "$HEAD_SHA" "$HASH" "$GATE_CDHASH"
release_gate "$sealed" "$HEAD_SHA" "$BINARY" "$GATE_CDHASH"
echo "PASS: matching sealed receipts accepted"
assert_seal_identity_contract

# WO-174@v1: make package expansion deterministic while exercising the real payload gate.
fake_bin="$WORK/bin"
mkdir -p "$fake_bin"
cat > "$fake_bin/pkgutil" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
[ "$1" = "--expand-full" ]
# WO-255@v1: like the real tool, refuse a destination that already exists.
[ ! -e "$3" ] || { echo "Could not unarchive $2 (File exists)" >&2; exit 1; }
mkdir -p "$3/Payload/usr/local/bin"
case "$PKG_PAYLOAD_SOURCE" in
  __fail__) exit 1 ;;
  __missing__) exit 0 ;;
  *) cp "$PKG_PAYLOAD_SOURCE" "$3/Payload/usr/local/bin/bulwark" ;;
esac
SH
chmod +x "$fake_bin/pkgutil"
PATH="$fake_bin:$PATH"
export PATH
pkg="$WORK/bulwark.pkg"
: > "$pkg"

# WO-174@v1: a package payload with bytes outside the receipts must block upload.
expect_pkg_rejected() {
  local name="$1" expected="$2" package="$3" payload="$4" output
  if output=$(PKG_PAYLOAD_SOURCE="$payload" release_pkg_gate \
    "$sealed" "$HEAD_SHA" "$package" "$GATE_CDHASH" 2>&1); then
    echo "FAIL: $name was accepted"
    exit 1
  fi
  if ! grep -qF "$expected" <<<"$output"; then
    echo "FAIL: $name did not name '$expected': $output"
    exit 1
  fi
  echo "PASS: $name rejected ($expected)"
}

mismatched_payload="$WORK/pkg-bulwark-mismatch"
printf 'different package payload\n' > "$mismatched_payload"
expect_pkg_rejected "package payload mismatch" "bulwark_sha256 mismatch" \
  "$pkg" "$mismatched_payload"

# WO-174@v1: the exact signed payload is accepted, while a missing package is not evidence.
PKG_PAYLOAD_SOURCE="$BINARY" release_pkg_gate \
  "$sealed" "$HEAD_SHA" "$pkg" "$GATE_CDHASH"
echo "PASS: matching package payload accepted"
expect_pkg_rejected "missing package" "missing package" \
  "$WORK/missing.pkg" "$BINARY"
expect_pkg_rejected "failed package expansion" "cannot expand package" \
  "$pkg" "__fail__"
expect_pkg_rejected "missing package payload" "exactly one bulwark payload" \
  "$pkg" "__missing__"

# WO-253@v1: the shipped gate is PREV's only while its inputs are unchanged; otherwise a
# freshly built gate must be supplied, and the refusal names how to build one.
expect_gate_plan() {
  local name="$1" gate_app="$2" changed="$3" expected="$4" plan
  plan=$(gate_plan "$gate_app" "$changed") || {
    echo "FAIL: $name was refused"
    exit 1
  }
  [ "$plan" = "$expected" ] || {
    echo "FAIL: $name planned '$plan', expected '$expected'"
    exit 1
  }
  echo "PASS: $name plans $expected"
}

# WO-253@v1: a refused plan must name the way forward, not just stop.
expect_gate_plan_refused() {
  local name="$1" gate_app="$2" changed="$3" output
  shift 3
  if output=$(gate_plan "$gate_app" "$changed" 2>&1); then
    echo "FAIL: $name was accepted: $output"
    exit 1
  fi
  local needle
  for needle in "$@"; do
    grep -qF "$needle" <<<"$output" || {
      echo "FAIL: $name did not name '$needle': $output"
      exit 1
    }
  done
  echo "PASS: $name refused"
}

expect_gate_plan "unchanged inputs, no fresh gate" "" 0 reuse
expect_gate_plan "changed inputs, fresh gate" "$WORK/bulwark_es_gate.app" 1 fresh
expect_gate_plan "unchanged inputs, fresh gate" "$WORK/bulwark_es_gate.app" 0 fresh
expect_gate_plan_refused "changed inputs, no fresh gate" "" 1 build-gate-bundle.sh GATE_APP
expect_gate_plan_refused "relative fresh gate" "bulwark_es_gate.app" 1 "absolute path"

# WO-255@v1: a stand-in for `codesign -dvvv` that keeps writing after the leaf
# Authority line, well past one pipe buffer, the way the real tool keeps writing.
FAKE_CODESIGN_MODE=signed
# shellcheck disable=SC2329  # called indirectly by signing_authority
# WO-255@v1: signed stand-in; prints the leaf Authority, then keeps writing.
codesign() {
  [ "$FAKE_CODESIGN_MODE" = signed ] && echo "CDHash=0123456789abcdef0123456789abcdef01234567"
  [ "$FAKE_CODESIGN_MODE" = signed ] && echo "Authority=Developer ID Application: Test (TEAMID)"
  echo "Authority=Developer ID Certification Authority"
  local i
  for i in $(seq 1 2000); do
    echo "Detail-$i=........................................................................"
  done
}

# WO-255@v1: under pipefail the reader must take the leaf authority without
# cutting the writer off (an early exit kills codesign with SIGPIPE, status 141).
FAKE_CODESIGN_MODE=signed
if ! authority=$(signing_authority "$WORK/bulwark"); then
  echo "FAIL: signing authority unreadable from a signed binary"
  exit 1
fi
[ "$authority" = "Developer ID Application: Test (TEAMID)" ] || {
  echo "FAIL: signing authority read as '$authority'"
  exit 1
}
echo "PASS: signing authority read in full output under pipefail"

# WO-255@v1: the upload gate reads the gate CDHash the same way; it must not cut codesign off either.
if ! cdhash=$(gate_cdhash "$WORK/bulwark_es_gate.app"); then
  echo "FAIL: gate CDHash unreadable from a signed bundle"
  exit 1
fi
[ "$cdhash" = 0123456789abcdef0123456789abcdef01234567 ] || {
  echo "FAIL: gate CDHash read as '$cdhash'"
  exit 1
}
echo "PASS: gate CDHash read in full output under pipefail"

# WO-255@v1: an unsigned binary still has no leaf authority to report.
FAKE_CODESIGN_MODE=unsigned
# shellcheck disable=SC2329  # called indirectly by signing_authority
# WO-255@v1: unsigned stand-in; no Authority line at all.
codesign() { echo "code object is not signed at all"; }
if authority=$(signing_authority "$WORK/bulwark"); then
  echo "FAIL: unsigned binary reported authority '$authority'"
  exit 1
fi
echo "PASS: unsigned binary has no signing authority"
# WO-255@v1: an unsigned bundle has no CDHash to bind the seal receipts to.
if cdhash=$(gate_cdhash "$WORK/bulwark_es_gate.app"); then
  echo "FAIL: unsigned bundle reported CDHash '$cdhash'"
  exit 1
fi
echo "PASS: unsigned bundle has no gate CDHash"
unset -f codesign

# WO-255@v1: no release-path script may read codesign output with an awk that exits
# early; build-cli-pkg.sh had a third copy, and its fallback re-sign changed the
# sealed bytes inside the pkg.
for script in "$PACKAGE_RELEASE_SH" "$SCRIPT_DIR/build-cli-pkg.sh"; do
  if grep -nE 'codesign -dv+' "$script" | grep -qE 'exit *\}'; then
    echo "FAIL: $script reads codesign output with an early-exit awk on one line"
    exit 1
  fi
  if grep -nE 'found = 1; exit' "$script" >/dev/null; then
    echo "FAIL: $script stops reading codesign output at the first match"
    exit 1
  fi
done
echo "PASS: release-path codesign readers consume the whole output"
