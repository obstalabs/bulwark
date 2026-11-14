#!/usr/bin/env bash
# WO-23: build + sign the production-shaped Bulwark ES gate bundle.
#
# PREREQ (operator, Developer Portal):
#   1. App ID: dev.obstalabs.bulwark.es-gate with Endpoint Security enabled.
#   2. Developer ID provisioning profile saved as bulwark_es_gate.provisionprofile.
#
# The resulting app binary is the path passed to the Rust launcher:
#   BULWARK_MACOS_ES_GATE=bulwark_es_gate.app/Contents/MacOS/bulwark_es_gate
set -euo pipefail
cd "$(dirname "$0")"

# WO-23@v1: prove inode-based macOS AUTH_OPEN enforcement end to end.
IDENTITY="${SIGNING_IDENTITY:?set SIGNING_IDENTITY to your 'Developer ID Application: NAME (TEAMID)'}"
# WO-23@v1: prove inode-based macOS AUTH_OPEN enforcement end to end.
KEYCHAIN="${SIGNING_KEYCHAIN:-login.keychain-db}"
# WO-23@v1: prove inode-based macOS AUTH_OPEN enforcement end to end.
BIN="bulwark_es_gate"
# WO-23@v1: prove inode-based macOS AUTH_OPEN enforcement end to end.
SRC="es_gate.swift"
# WO-23@v1: prove inode-based macOS AUTH_OPEN enforcement end to end.
ENT="es_proof.entitlements"
# WO-23@v1: prove inode-based macOS AUTH_OPEN enforcement end to end.
PROFILE="bulwark_es_gate.provisionprofile"
# WO-23@v1: prove inode-based macOS AUTH_OPEN enforcement end to end.
APP="bulwark_es_gate.app"
# WO-23@v1: prove inode-based macOS AUTH_OPEN enforcement end to end.
INFO="GateInfo.plist"

[ -f "$PROFILE" ] || {
    echo "!! $PROFILE missing — create the Developer ID provisioning profile"
    echo "   for App ID dev.obstalabs.bulwark.es-gate with Endpoint Security enabled."
    exit 1
}

# WO-207@v1: BULWARK_TEST_FAULTS=1 compiles the edge's test-only fault injection
# in. Such a bundle is signed for local hardware proofs and never notarized, so it
# cannot pass the seal scripts or ship.
SWIFT_DEFINES=()
if [ "${BULWARK_TEST_FAULTS:-0}" = "1" ]; then
    SWIFT_DEFINES=(-D BULWARK_TEST_FAULTS)
    echo "!! BULWARK_TEST_FAULTS=1: building a TEST-FAULT gate; it will not be notarized"
fi

echo "==> compiling $SRC universal (arm64 + x86_64)"
xcrun --sdk macosx swiftc -O ${SWIFT_DEFINES[@]+"${SWIFT_DEFINES[@]}"} -o "${BIN}_arm64" "$SRC" -lEndpointSecurity -lbsm -target arm64-apple-macos11.0
xcrun --sdk macosx swiftc -O ${SWIFT_DEFINES[@]+"${SWIFT_DEFINES[@]}"} -o "${BIN}_x86_64" "$SRC" -lEndpointSecurity -lbsm -target x86_64-apple-macos11.0
lipo -create -output "$BIN" "${BIN}_arm64" "${BIN}_x86_64"
rm -f "${BIN}_arm64" "${BIN}_x86_64"

echo "==> assembling $APP"
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS"
cp "$INFO" "$APP/Contents/Info.plist"
cp "$BIN" "$APP/Contents/MacOS/$BIN"
cp "$PROFILE" "$APP/Contents/embedded.provisionprofile"

echo "==> signing $APP with ES entitlement + hardened runtime"
codesign --force --sign "$IDENTITY" \
    --keychain "$KEYCHAIN" \
    --options runtime \
    --entitlements "$ENT" \
    --timestamp \
    "$APP"

echo "==> verifying signature + entitlement"
codesign -dv --entitlements - "$APP" 2>&1 | grep -E "TeamIdentifier|endpoint-security|Runtime" || true

# WO-207@v1: a test-fault gate stops here, signed but never notarized or stapled.
if [ "${BULWARK_TEST_FAULTS:-0}" = "1" ]; then
    echo
    echo "==> TEST-FAULT gate ready (signed, NOT notarized): $(pwd)/$APP/Contents/MacOS/$BIN"
    exit 0
fi

# WO-207@v1: by construction, not by discipline. Whatever flags built it, a gate
# whose binary carries the fault-injection marker is refused before it can be
# notarized, so a release gate cannot contain the knob. `grep -c` reads the whole
# stream (no early close, no SIGPIPE under pipefail) and prints 0 on no match.
FAULT_MARKERS=$(strings "$APP/Contents/MacOS/$BIN" | grep -c 'TEST-FAULT' || true)
if [ "$FAULT_MARKERS" != "0" ]; then
    echo "!! refusing to notarize: $APP contains test-fault code ($FAULT_MARKERS marker strings)"
    exit 3
fi
echo "==> no test-fault code in $APP (checked: strings | grep -c 'TEST-FAULT' = 0)"

# Notarize + staple (the WO-38 sealability requirement: WO-23's verification seal
# runs against the production artifact, not a dev-only signed bundle). A locally
# signed bundle DOES run under AMFI for dev iteration (embedded profile + no
# quarantine), but closure proof requires the notarized+stapled artifact.
# WO-23@v1: prove inode-based macOS AUTH_OPEN enforcement end to end.
NOTARY_PROFILE="${NOTARY_PROFILE:-bulwark-notary}"
# WO-23@v1: prove inode-based macOS AUTH_OPEN enforcement end to end.
NOTARY_RECEIPT="bulwark_es_gate.notarization.receipt"
echo "==> notarizing $APP"
# WO-23@v1: prove inode-based macOS AUTH_OPEN enforcement end to end.
ZIP="bulwark_es_gate-notarize.zip"
rm -f "$ZIP"
/usr/bin/ditto -c -k --keepParent "$APP" "$ZIP"
xcrun notarytool submit "$ZIP" --keychain-profile "$NOTARY_PROFILE" --wait 2>&1 | tee notarize-gate.out
# WO-23@v1: prove inode-based macOS AUTH_OPEN enforcement end to end.
STATUS=$(grep -E '^\s*status:' notarize-gate.out | tail -1 | awk '{print $2}')
# WO-23@v1: prove inode-based macOS AUTH_OPEN enforcement end to end.
SUBMISSION_ID=$(grep -oE 'id: [0-9a-f-]+' notarize-gate.out | head -1 | awk '{print $2}')
[ "$STATUS" = "Accepted" ] || { echo "!! notarization not Accepted ($STATUS)"; exit 2; }
{
    echo "submission_id: ${SUBMISSION_ID:-unknown}"
    echo "status: $STATUS"
    echo "bundle_id: dev.obstalabs.bulwark.es-gate"
} > "$NOTARY_RECEIPT"

echo "==> stapling the ticket"
xcrun stapler staple "$APP"
xcrun stapler validate "$APP" && echo "    staple validated"
rm -f "$ZIP"
echo
echo "==> ready (signed + notarized + stapled): $(pwd)/$APP/Contents/MacOS/$BIN"
echo "    copy the whole $APP + $NOTARY_RECEIPT + the bulwark binary + verify-gate.sh + verify-allowlist-gate.sh to the Intel Mac."
