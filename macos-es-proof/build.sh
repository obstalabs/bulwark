#!/usr/bin/env bash
# build + sign the ES proof binary on the M2 (develop/build/sign host).
#
# Produces a Developer-ID-signed, hardened-runtime, ES-entitled Mach-O.
# Notarization is a separate step (notarize.sh) because it needs network +
# credentials. The signed binary alone is enough to test es_new_client on the
# Intel Mac (notarization gates *distribution*, not local execution on a machine
# that trusts the signing identity); notarize before any real distribution.
#
# Run on the M2:  ./build.sh
set -euo pipefail
cd "$(dirname "$0")"

IDENTITY="${SIGNING_IDENTITY:?set SIGNING_IDENTITY to your 'Developer ID Application: NAME (TEAMID)'}"
# Pin to login.keychain: the Developer ID key lives there, and pinning makes the
# build deterministic regardless of keychain search order (a stale locked
# keychain earlier in the search list caused an ad-hoc fallback otherwise).
KEYCHAIN="${SIGNING_KEYCHAIN:-login.keychain-db}"
BIN="es_proof"
SRC="es_proof.swift"
ENT="es_proof.entitlements"

echo "==> compiling $SRC universal (arm64 + x86_64) — runs on the M2 AND the Intel test Mac"
# ES requires the entitlement + signature, both arch-independent. Build each
# arch then lipo into a universal Mach-O so one signed binary runs everywhere.
xcrun --sdk macosx swiftc -O -o "${BIN}_arm64" "$SRC" -lEndpointSecurity -target arm64-apple-macos11.0
xcrun --sdk macosx swiftc -O -o "${BIN}_x86_64" "$SRC" -lEndpointSecurity -target x86_64-apple-macos11.0
lipo -create -output "$BIN" "${BIN}_arm64" "${BIN}_x86_64"
rm -f "${BIN}_arm64" "${BIN}_x86_64"
echo "    -> $(file "$BIN" | sed 's/.*: //')"

echo "==> code-signing with hardened runtime + ES entitlement"
# --options runtime = hardened runtime (required for notarization + ES).
# The entitlement is what makes es_new_client succeed instead of NOT_ENTITLED.
codesign --force --sign "$IDENTITY" \
    --keychain "$KEYCHAIN" \
    --options runtime \
    --entitlements "$ENT" \
    --timestamp \
    "$BIN"

echo "==> verifying signature + entitlement"
codesign -dv --entitlements - "$BIN" 2>&1 | grep -E "Authority|Identifier|endpoint-security|Runtime" || true
echo
echo "==> signed binary ready: $(pwd)/$BIN"
echo "    next: ./notarize.sh (before distribution) OR copy to the Intel Mac and run ./prove.sh"
