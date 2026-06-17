#!/usr/bin/env bash
# build es_proof as a .app BUNDLE with an embedded provisioning
# profile, so AMFI authorizes the restricted ES entitlement.
#
# WHY: AMFI error -413 "No matching profile found" — the
# com.apple.developer.endpoint-security.client entitlement is RESTRICTED and
# requires a provisioning profile at runtime. A bare Mach-O can't carry one; a
# bundle embeds it at Contents/embedded.provisionprofile. Bundles can also be
# STAPLED (bare binaries can't), so notarization sticks offline too.
#
# PREREQ (operator, Developer Portal — developer.apple.com/account):
#   1. Identifiers -> new App ID, bundle ID EXACTLY: dev.obstalabs.bulwark.es-proof
#      enable the "Endpoint Security" App Service / capability.
#   2. Profiles -> new "Developer ID" provisioning profile for that App ID +
#      your Developer ID Application cert. Download it.
#   3. Save it next to this script as: es_proof.provisionprofile
#
# Run on the M2 (after ./build.sh has produced the signed universal binary):
#   ./build-bundle.sh
set -euo pipefail
cd "$(dirname "$0")"

IDENTITY="${SIGNING_IDENTITY:?set SIGNING_IDENTITY to your 'Developer ID Application: NAME (TEAMID)'}"
KEYCHAIN="${SIGNING_KEYCHAIN:-login.keychain-db}"
BIN="es_proof"
ENT="es_proof.entitlements"
PROFILE="es_proof.provisionprofile"
APP="es_proof.app"
NOTARY_PROFILE="${NOTARY_PROFILE:-bulwark-notary}"
# copied with the bundle so prove.sh can cite notarization evidence.
NOTARY_RECEIPT="notarization.receipt"

[ -f "$BIN" ]     || { echo "!! $BIN missing — run ./build.sh first"; exit 1; }
[ -f "$PROFILE" ] || { echo "!! $PROFILE missing — download the Developer ID provisioning"
                       echo "   profile for App ID dev.obstalabs.bulwark.es-proof (Endpoint Security"
                       echo "   capability) and save it here as $PROFILE. See header."; exit 1; }

echo "==> assembling $APP"
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS"
cp Info.plist "$APP/Contents/Info.plist"
cp "$BIN" "$APP/Contents/MacOS/$BIN"
cp "$PROFILE" "$APP/Contents/embedded.provisionprofile"

echo "==> signing the bundle (Developer ID + ES entitlement + hardened runtime)"
codesign --force --sign "$IDENTITY" \
    --keychain "$KEYCHAIN" \
    --options runtime \
    --entitlements "$ENT" \
    --timestamp \
    "$APP"

echo "==> verifying signature + embedded profile"
codesign -dv --entitlements - "$APP" 2>&1 | grep -E "TeamIdentifier|endpoint-security|Runtime" || true
[ -f "$APP/Contents/embedded.provisionprofile" ] && echo "    embedded.provisionprofile present"

echo "==> notarizing the bundle"
ZIP="es_proof-app-notarize.zip"
rm -f "$ZIP"
/usr/bin/ditto -c -k --keepParent "$APP" "$ZIP"
xcrun notarytool submit "$ZIP" --keychain-profile "$NOTARY_PROFILE" --wait 2>&1 | tee notarize-bundle.out
STATUS=$(grep -E '^\s*status:' notarize-bundle.out | tail -1 | awk '{print $2}')
SUBMISSION_ID=$(grep -oE 'id: [0-9a-f-]+' notarize-bundle.out | head -1 | awk '{print $2}')
[ "$STATUS" = "Accepted" ] || { echo "!! notarization not Accepted ($STATUS)"; exit 2; }
{
    echo "submission_id: ${SUBMISSION_ID:-unknown}"
    echo "status: $STATUS"
    echo "bundle_id: dev.obstalabs.bulwark.es-proof"
} > "$NOTARY_RECEIPT"

echo "==> stapling the ticket to the bundle (bundles CAN staple — bare binaries cannot)"
xcrun stapler staple "$APP"
xcrun stapler validate "$APP" && echo "    staple validated"
rm -f "$ZIP"

echo
echo "==> $APP is signed + notarized + stapled with an embedded ES provisioning profile."
echo "    Copy the WHOLE $APP dir + $NOTARY_RECEIPT + prove.sh to the Intel Mac, then:"
echo "      sudo $APP/Contents/MacOS/$BIN <marker>"
echo "    or run ./prove.sh (it targets the bundle binary if present)."
