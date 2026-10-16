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
write_receipt() {
  local path="$1" verdict="$2" sha="$3" hash="$4"
  {
    printf 'verdict:               %s\n' "$verdict"
    printf 'head_sha:              %s\n' "$sha"
    printf 'bulwark_sha256:        %s\n' "$hash"
  } > "$path"
}

# WO-140@v1: a rejected fixture must fail and name its failed identity check.
expect_rejected() {
  local name="$1" expected="$2" dir="$3" output
  if output=$(release_gate "$dir" "$HEAD_SHA" "$BINARY" 2>&1); then
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
write_receipt "$missing/gate-receipt.txt" "SEALED - fixture" "$HEAD_SHA" "$HASH"
expect_rejected "missing receipt" "missing receipt" "$missing"

# WO-140@v1: a negative hardware verdict can never authorize an upload.
not_sealed="$WORK/not-sealed"
mkdir -p "$not_sealed"
write_receipt "$not_sealed/gate-receipt.txt" "NOT SEALED - fixture" "$HEAD_SHA" "$HASH"
write_receipt "$not_sealed/allowlist-gate-receipt.txt" "SEALED - fixture" "$HEAD_SHA" "$HASH"
expect_rejected "NOT SEALED verdict" "is not SEALED" "$not_sealed"

# WO-140@v1: receipts from another source commit cannot authorize this tag.
wrong_sha="$WORK/wrong-sha"
mkdir -p "$wrong_sha"
write_receipt "$wrong_sha/gate-receipt.txt" "SEALED - fixture" "$OTHER_SHA" "$HASH"
write_receipt "$wrong_sha/allowlist-gate-receipt.txt" "SEALED - fixture" "$HEAD_SHA" "$HASH"
expect_rejected "head_sha mismatch" "head_sha mismatch" "$wrong_sha"

# WO-140@v1: receipts from another binary cannot authorize the upload artifact.
wrong_hash="$WORK/wrong-hash"
mkdir -p "$wrong_hash"
write_receipt "$wrong_hash/gate-receipt.txt" "SEALED - fixture" "$HEAD_SHA" "$HASH"
case "$HASH" in
  0*) WRONG_HASH="1${HASH#?}" ;;
  *) WRONG_HASH="0${HASH#?}" ;;
esac
write_receipt "$wrong_hash/allowlist-gate-receipt.txt" "SEALED - fixture" "$HEAD_SHA" "$WRONG_HASH"
expect_rejected "bulwark_sha256 mismatch" "bulwark_sha256 mismatch" "$wrong_hash"

# WO-140@v1: matching sealed receipts authorize the exact source and binary.
sealed="$WORK/sealed"
mkdir -p "$sealed"
write_receipt "$sealed/gate-receipt.txt" "SEALED - fixture" "$HEAD_SHA" "$HASH"
write_receipt "$sealed/allowlist-gate-receipt.txt" "SEALED - fixture" "$HEAD_SHA" "$HASH"
release_gate "$sealed" "$HEAD_SHA" "$BINARY"
echo "PASS: matching sealed receipts accepted"
assert_seal_identity_contract
