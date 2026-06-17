#!/usr/bin/env bash
# notarize the signed ES proof binary so AMFI authorizes its restricted
# Endpoint Security entitlement.
#
# WHY: the ES client entitlement is RESTRICTED. A valid Developer-ID signature
# with the entitlement embedded is necessary but NOT sufficient — AMFI SIGKILLs
# the binary at exec ("Killed: 9") until the entitlement is AUTHORIZED.
# Notarization is the production-correct authorization (no SIP/AMFI disabling).
#
# PREREQ (one-time): store notary credentials in the keychain:
#   xcrun notarytool store-credentials "bulwark-notary" \
#       --apple-id "<your-apple-id>" --team-id "<YOUR_TEAM_ID>" --password "<app-specific-pw>"
#
# Run on the M2 AFTER ./build.sh:  ./notarize.sh
#
# NOTE on bare binaries: notarytool needs a .zip/.pkg/.dmg, and a bare Mach-O
# CANNOT be stapled (only bundles/pkgs/dmgs staple a ticket). For a bare binary,
# notarization registers the signature with Apple so AMFI honors it on run
# (online assessment). If that proves insufficient for the ES entitlement, the
# next step is to wrap es_proof in an .app bundle (staple-able + can carry a
# provisioning profile) — a known fork.
set -euo pipefail
cd "$(dirname "$0")"

BIN="es_proof"
PROFILE="${NOTARY_PROFILE:-bulwark-notary}"
ZIP="es_proof-notarize.zip"

[ -f "$BIN" ] || { echo "!! $BIN not found — run ./build.sh first"; exit 1; }

echo "==> verifying the binary is properly signed before notarizing"
codesign -dv "$BIN" 2>&1 | grep -E "TeamIdentifier|Runtime" || true
codesign -d --entitlements - "$BIN" 2>&1 | grep -q endpoint-security || { echo "!! ES entitlement missing — re-run build.sh"; exit 1; }

echo "==> zipping for notarytool (it does not accept bare Mach-O)"
rm -f "$ZIP"
/usr/bin/ditto -c -k --keepParent "$BIN" "$ZIP"

echo "==> submitting to Apple notary (profile: $PROFILE) — waits for the result"
xcrun notarytool submit "$ZIP" --keychain-profile "$PROFILE" --wait 2>&1 | tee notarize.out

SUBMIT_ID=$(grep -oE 'id: [0-9a-f-]+' notarize.out | head -1 | awk '{print $2}')
STATUS=$(grep -E '^\s*status:' notarize.out | tail -1 | awk '{print $2}')
echo
echo "==> submission id: ${SUBMIT_ID:-unknown}  status: ${STATUS:-unknown}"

if [ "${STATUS:-}" != "Accepted" ]; then
    echo "!! not Accepted. Fetch the log for the reason:"
    echo "   xcrun notarytool log ${SUBMIT_ID:-<id>} --keychain-profile $PROFILE"
    exit 2
fi

echo "==> Accepted. Bare binary cannot be stapled; AMFI authorizes via online"
echo "    assessment. Re-copy $BIN to the Intel Mac and run ./prove.sh again."
echo "    (If AMFI still kills it, wrap es_proof in an .app bundle and staple —"
echo "     see notarize.sh header.)"
rm -f "$ZIP"
