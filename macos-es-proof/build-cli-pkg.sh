#!/usr/bin/env bash
# build a signed + notarized + STAPLED .pkg for the bulwark CLI.
#
# WHY a .pkg (not a bare binary): a bare Mach-O cannot be stapled, so a bare
# notarized binary relies on Gatekeeper's ONLINE check (needs internet on first
# run). A .pkg CAN be stapled, so Gatekeeper trusts it OFFLINE. This is the
# documented Apple behavior, not a bug — stapler only works on containers
# (.pkg/.dmg/.app). cargo-dist and the wider Rust ecosystem do the same.
#
# The CLI binary inside is signed (Developer ID Application) + notarized already;
# this wraps it in a .pkg signed with the Developer ID INSTALLER cert (a separate
# cert from Application), notarizes the pkg, and staples it.
#
# PREREQ: a "Developer ID Installer: NAME (TEAMID)" cert in the keychain
# (developer.apple.com -> Certificates -> Developer ID Installer).
#
# Run on the M2 after `cargo build --release --target <triple>` for each arch.
set -euo pipefail
cd "$(dirname "$0")/.."

VERSION="${VERSION:-0.7.0}"
INSTALLER_ID="${INSTALLER_ID:?set INSTALLER_ID to your 'Developer ID Installer: NAME (TEAMID)'}"
APP_ID="${APP_ID:?set APP_ID to your 'Developer ID Application: NAME (TEAMID)'}"
KEYCHAIN="${SIGNING_KEYCHAIN:-login.keychain-db}"
NOTARY_PROFILE="${NOTARY_PROFILE:-bulwark-notary}"
OUT="${OUT:-/tmp/bulwark-pkg}"
mkdir -p "$OUT"

for triple in x86_64-apple-darwin aarch64-apple-darwin; do
  bin="target/${triple}/release/bulwark"
  [ -x "$bin" ] || { echo "!! $bin missing — cargo build --release --target $triple"; exit 1; }

  echo "==> [$triple] re-sign the CLI (Developer ID Application + hardened runtime)"
  codesign --force --sign "$APP_ID" --keychain "$KEYCHAIN" --options runtime --timestamp "$bin"

  echo "==> [$triple] stage + pkgbuild"
  root="$OUT/root-${triple}"
  rm -rf "$root"; mkdir -p "$root/usr/local/bin"
  # COPYFILE_DISABLE keeps macOS from writing AppleDouble (._*) resource-fork
  # sidecars into the package payload (harmless but sloppy to ship).
  COPYFILE_DISABLE=1 cp "$bin" "$root/usr/local/bin/bulwark"
  # belt-and-suspenders: strip any xattrs + stray ._* before pkgbuild
  xattr -cr "$root" 2>/dev/null || true
  find "$root" -name '._*' -delete 2>/dev/null || true
  unsigned="$OUT/bulwark-${VERSION}-${triple}-unsigned.pkg"
  pkgbuild --root "$root" --identifier "dev.obstalabs.bulwark" \
    --version "$VERSION" --install-location "/" "$unsigned"

  echo "==> [$triple] sign the pkg (Developer ID Installer)"
  signed="$OUT/bulwark-${VERSION}-${triple}.pkg"
  productsign --sign "$INSTALLER_ID" --keychain "$KEYCHAIN" "$unsigned" "$signed"
  rm -f "$unsigned"

  echo "==> [$triple] notarize the pkg"
  xcrun notarytool submit "$signed" --keychain-profile "$NOTARY_PROFILE" --wait 2>&1 | tee "$OUT/notarize-${triple}.out"
  status=$(grep -E '^\s*status:' "$OUT/notarize-${triple}.out" | tail -1 | awk '{print $2}')
  [ "$status" = "Accepted" ] || { echo "!! notarization not Accepted ($status)"; exit 2; }

  echo "==> [$triple] staple the ticket to the pkg (offline-trusted)"
  xcrun stapler staple "$signed"
  xcrun stapler validate "$signed" && echo "    staple validated"
  shasum -a 256 "$signed" | tee "$signed.sha256"
done

echo
echo "==> signed + notarized + stapled pkgs in $OUT/:"
ls -la "$OUT"/*.pkg
echo "    upload these to the bulwark v${VERSION} release and point the formula at them."
