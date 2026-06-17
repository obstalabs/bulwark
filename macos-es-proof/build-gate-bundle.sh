#!/usr/bin/env bash
# build + sign the production-shaped Bulwark ES gate bundle.
#
# PREREQ (operator, Developer Portal):
#   1. App ID: dev.obstalabs.bulwark.es-gate with Endpoint Security enabled.
#   2. Developer ID provisioning profile saved as bulwark_es_gate.provisionprofile.
#
# The resulting app binary is the path passed to the Rust launcher:
#   BULWARK_MACOS_ES_GATE=bulwark_es_gate.app/Contents/MacOS/bulwark_es_gate
set -euo pipefail
cd "$(dirname "$0")"

IDENTITY="${SIGNING_IDENTITY:?set SIGNING_IDENTITY to your 'Developer ID Application: NAME (TEAMID)'}"
KEYCHAIN="${SIGNING_KEYCHAIN:-login.keychain-db}"
BIN="bulwark_es_gate"
SRC="es_gate.swift"
ENT="es_proof.entitlements"
PROFILE="bulwark_es_gate.provisionprofile"
APP="bulwark_es_gate.app"
INFO="GateInfo.plist"

[ -f "$PROFILE" ] || {
    echo "!! $PROFILE missing — create the Developer ID provisioning profile"
    echo "   for App ID dev.obstalabs.bulwark.es-gate with Endpoint Security enabled."
    exit 1
}

echo "==> compiling $SRC universal (arm64 + x86_64)"
xcrun --sdk macosx swiftc -O -o "${BIN}_arm64" "$SRC" -lEndpointSecurity -lbsm -target arm64-apple-macos11.0
xcrun --sdk macosx swiftc -O -o "${BIN}_x86_64" "$SRC" -lEndpointSecurity -lbsm -target x86_64-apple-macos11.0
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

# Notarize + staple (the verification seal runs against the production artifact,
# not a dev-only signed bundle). A locally
# signed bundle DOES run under AMFI for dev iteration (embedded profile + no
# quarantine), but closure proof requires the notarized+stapled artifact.
NOTARY_PROFILE="${NOTARY_PROFILE:-bulwark-notary}"
NOTARY_RECEIPT="bulwark_es_gate.notarization.receipt"
echo "==> notarizing $APP"
ZIP="bulwark_es_gate-notarize.zip"
rm -f "$ZIP"
/usr/bin/ditto -c -k --keepParent "$APP" "$ZIP"
xcrun notarytool submit "$ZIP" --keychain-profile "$NOTARY_PROFILE" --wait 2>&1 | tee notarize-gate.out
STATUS=$(grep -E '^\s*status:' notarize-gate.out | tail -1 | awk '{print $2}')
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
