#!/usr/bin/env bash
# bulwark macOS manual packaging for a tagged release (CI does not sign macOS, WO-95).
# Usage: VERSION=0.9.4 PREV=0.9.3 bash macos-es-proof/package-release.sh <phase>
# (W defaults to $TMPDIR/bulwark-pkg-$VERSION; set it to keep the work dir elsewhere.)
#
# WHEN: after the v* tag's release.yml run is green. It publishes darwin tarballs
# WITHOUT bulwark_es_gate.app and no .pkg; this script supplies both.
# PRECONDITIONS: Developer ID Application + Installer certs in the login keychain
# (security find-identity -v -p basic); notarytool keychain profile "bulwark-notary";
# Full Disk Access for the terminal (re-check after every macOS update, else the
# seals fail with "es_new_client failed: 4").
# ORDER: stage -> seal (run the two printed sudo lines, both SEALED) -> repack
#   -> APP_ID=... INSTALLER_ID=... pkg (about 1 min per arch) -> verify
#   -> upload (PUBLIC) -> homebrew-tap bump (formula: version, 4 urls/sha256,
#   darwin sums from $W/out; cask: version + 2 pkg sha256).
# KNOWN HARMLESS: the tarball binary stays ad-hoc signed (only the pkg's carries
# Developer ID); pkgbuild prints "write: Permission denied" x4 and the payload has
# four ._* AppleDouble entries, as 0.9.2 had. Apple 403 = re-accept the developer
# agreement, rerun pkg. Proven on 0.9.3 (2026-10-16).
#
# Phases, run in order:
#   stage    download the CI darwin tarballs + PREV's notarized gate app; verify both
#   seal     re-run both seals on the exact pair that ships (needs sudo)
#   repack   rebuild both darwin tarballs with bulwark_es_gate.app + .sha256
#   pkg      signed + notarized + stapled .pkg per arch (needs APP_ID, INSTALLER_ID)
#   verify   re-check every artifact from a fresh extract
#   upload   gh release upload --clobber (public: run only when you mean it)
#
# The gate app is reused from PREV, which is valid only while es_gate.swift,
# es_proof.entitlements and GateInfo.plist are unchanged vPREV..vVERSION; stage
# refuses otherwise (then rebuild with macos-es-proof/build-gate-bundle.sh).
set -euo pipefail

# WO-140@v1: read one exact identity field from a hardware-seal receipt.
release_receipt_field() {
  local receipt="$1" field="$2"
  awk -v field="$field" '
    index($0, field ":") == 1 {
      sub(/^[^:]*:[[:space:]]*/, "")
      print
      found = 1
      exit
    }
    END { if (!found) exit 1 }
  ' "$receipt"
}

# WO-140@v1: refuse release upload unless both seals name this source and binary.
release_gate() {
  local seal_dir="$1" expected_sha="$2" binary="$3" expected_hash
  local receipt verdict receipt_sha receipt_hash
  expected_hash=$(shasum -a 256 "$binary" | awk '{print $1}') || {
    echo "!! release seal check failed: cannot hash binary $binary" >&2
    return 1
  }
  for receipt in "$seal_dir/gate-receipt.txt" "$seal_dir/allowlist-gate-receipt.txt"; do
    if [ ! -f "$receipt" ]; then
      echo "!! release seal check failed: missing receipt $receipt" >&2
      return 1
    fi
    verdict=$(release_receipt_field "$receipt" verdict) || {
      echo "!! release seal check failed: verdict missing from $receipt" >&2
      return 1
    }
    case "$verdict" in
      SEALED*) ;;
      *)
        echo "!! release seal check failed: $receipt is not SEALED" >&2
        return 1
        ;;
    esac
    receipt_sha=$(release_receipt_field "$receipt" head_sha) || {
      echo "!! release seal check failed: head_sha missing from $receipt" >&2
      return 1
    }
    if [ "$receipt_sha" != "$expected_sha" ]; then
      echo "!! release seal check failed: head_sha mismatch in $receipt" >&2
      return 1
    fi
    receipt_hash=$(release_receipt_field "$receipt" bulwark_sha256) || {
      echo "!! release seal check failed: bulwark_sha256 missing from $receipt" >&2
      return 1
    }
    if [ "$receipt_hash" != "$expected_hash" ]; then
      echo "!! release seal check failed: bulwark_sha256 mismatch in $receipt" >&2
      return 1
    fi
  done
}

# WO-140@v1: let fixture tests source the pure upload gate without release inputs.
if [ -n "${RELEASE_GATE_LIB_ONLY:-}" ]; then return 0 2>/dev/null || exit 0; fi

# WO-95@v1: the release being packaged; required so a run never guesses it.
VERSION="${VERSION:?set VERSION to the tagged release, e.g. 0.9.4}"
# WO-95@v1: the release whose notarized gate app is reused when the gate sources are unchanged.
PREV="${PREV:?set PREV to the previous release whose notarized gate app is reused}"
# WO-95@v1: the GitHub repo whose tagged release receives the macOS assets.
REPO=obstalabs/bulwark
# WO-95@v1: the checkout this script lives in; gh and git run from it.
SRC_REPO="$(cd "$(dirname "$0")/.." && pwd)"
# WO-95@v1: scratch work dir for downloads, seals and the upload set.
W="${W:-${TMPDIR:-/tmp}/bulwark-pkg-${VERSION}}"
# WO-95@v1: the two macOS targets release.yml builds.
TRIPLES=(aarch64-apple-darwin x86_64-apple-darwin)
# WO-95@v1: the signed Endpoint Security gate bundle the darwin tarballs must carry.
APP=bulwark_es_gate.app

# WO-95@v1: every phase stops at the first failed check, so a broken artifact never reaches upload.
die() { echo "!! $*" >&2; exit 1; }
# WO-95@v1: gh picks the GitHub account from the repo checkout, so release calls run from there.
gh_() { (cd "$SRC_REPO" && gh "$@"); }   # gh resolves the account from the repo cwd

# WO-95@v1: the CI release ships darwin tarballs without the signed gate app; stage collects the CI
# build and the previous notarized gate, refusing reuse when the gate sources changed.
stage() {
  git -C "$SRC_REPO" diff --quiet "v$PREV" "v$VERSION" -- macos-es-proof/es_gate.swift \
    macos-es-proof/es_proof.entitlements macos-es-proof/GateInfo.plist \
    || die "gate inputs changed v$PREV..v$VERSION: rebuild the gate app (build-gate-bundle.sh), do not reuse"
  rm -rf "$W"; mkdir -p "$W/dl" "$W/ci" "$W/prev"
  for t in "${TRIPLES[@]}"; do
    gh_ release download "v$VERSION" --repo "$REPO" -D "$W/dl" \
      -p "bulwark-$VERSION-$t.tar.gz" -p "bulwark-$VERSION-$t.tar.gz.sha256"
    gh_ release download "v$PREV" --repo "$REPO" -D "$W/dl" -p "bulwark-$PREV-$t.tar.gz"
    (cd "$W/dl" && shasum -a 256 -c "bulwark-$VERSION-$t.tar.gz.sha256")
    tar xzf "$W/dl/bulwark-$VERSION-$t.tar.gz" -C "$W/ci"
    mkdir -p "$W/prev/$t" && tar xzf "$W/dl/bulwark-$PREV-$t.tar.gz" -C "$W/prev/$t"
  done
  local a="$W/prev/aarch64-apple-darwin/bulwark-$PREV-aarch64-apple-darwin/$APP"
  local i="$W/prev/x86_64-apple-darwin/bulwark-$PREV-x86_64-apple-darwin/$APP"
  diff -r "$a" "$i" >/dev/null || die "the two $PREV tarballs carry different gate apps"
  COPYFILE_DISABLE=1 cp -R "$a" "$W/$APP"
  check_app "$W/$APP"
  for t in "${TRIPLES[@]}"; do
    local b="$W/ci/bulwark-$VERSION-$t/bulwark"
    [ "$("$b" --version 2>/dev/null || echo cross)" = "bulwark $VERSION" ] \
      || [ "$t" = x86_64-apple-darwin ] || die "$b does not report bulwark $VERSION"
    lipo -archs "$b"
  done
  echo "==> staged in $W"
}

# WO-95@v1: a gate app is shippable only if universal, ES-entitled, stapled and notarized.
check_app() {
  local app="$1"
  [ "$(lipo -archs "$app/Contents/MacOS/bulwark_es_gate")" = "x86_64 arm64" ] || die "gate not universal"
  codesign --verify --deep --strict "$app"
  codesign -d --entitlements - "$app" 2>&1 | grep -q endpoint-security || die "ES entitlement missing"
  xcrun stapler validate "$app" >/dev/null || die "staple invalid"
  spctl -a -vv "$app" 2>&1 | grep -q 'source=Notarized Developer ID' || die "spctl not notarized"
  echo "    gate app ok: $app"
}

# WO-95@v1: the hardware seals must run on the exact binary + gate pair that ships.
seal() {
  # The seal scripts cd into their own directory and look for ./bulwark_es_gate.app,
  # so seal from a staging copy instead of swapping the app in the checkout.
  local s="$W/seal"; rm -rf "$s"; mkdir -p "$s"
  cp "$SRC_REPO/macos-es-proof/verify-gate.sh" "$SRC_REPO/macos-es-proof/verify-allowlist-gate.sh" "$s/"
  COPYFILE_DISABLE=1 cp -R "$W/$APP" "$s/"
  cp "$W/ci/bulwark-$VERSION-aarch64-apple-darwin/bulwark" "$s/bulwark"
  # WO-140@v1: bind both receipts to the commit named by the release tag.
  local source_sha
  source_sha=$(git -C "$SRC_REPO" rev-parse "v$VERSION^{commit}") \
    || die "cannot resolve v$VERSION to a source commit"
  [[ "$source_sha" =~ ^[0-9a-fA-F]{40}$ ]] || die "v$VERSION source SHA is not 40 hex characters"
  echo "Run both, expect SEALED from each:"
  printf '  sudo BULWARK_SOURCE_SHA=%q BULWARK=%q %q\n' "$source_sha" "$s/bulwark" "$s/verify-gate.sh"
  printf '  sudo BULWARK_SOURCE_SHA=%q BULWARK=%q %q\n' "$source_sha" "$s/bulwark" "$s/verify-allowlist-gate.sh"
}

# WO-95@v1: rebuild the darwin tarballs with the gate app, in the layout release.yml uses.
repack() {
  mkdir -p "$W/out"
  for t in "${TRIPLES[@]}"; do
    local name="bulwark-$VERSION-$t" d="$W/ci/bulwark-$VERSION-$t"
    rm -rf "${d:?}/$APP"; COPYFILE_DISABLE=1 cp -R "$W/$APP" "$d/$APP"
    COPYFILE_DISABLE=1 tar -C "$W/ci" -czf "$W/out/$name.tar.gz" "$name"
    (cd "$W/out" && shasum -a 256 "$name.tar.gz" | awk '{print $1 "  " $2}' > "$name.tar.gz.sha256")
    cat "$W/out/$name.tar.gz.sha256"
  done
}

# WO-95@v1: signed, notarized and stapled .pkg per arch, built from the released CI binaries.
pkg() {
  : "${APP_ID:?set APP_ID to 'Developer ID Application: NAME (TEAMID)'}"
  : "${INSTALLER_ID:?set INSTALLER_ID to 'Developer ID Installer: NAME (TEAMID)'}"
  # build-cli-pkg.sh cds to its parent and reads target/<triple>/release/bulwark;
  # give it a staging root holding the CI binaries so the pkg ships the released bits.
  local r="$W/pkgroot"; rm -rf "$r"; mkdir -p "$r/macos-es-proof"
  cp "$SRC_REPO/macos-es-proof/build-cli-pkg.sh" "$r/macos-es-proof/"
  for t in "${TRIPLES[@]}"; do
    mkdir -p "$r/target/$t/release"
    cp "$W/ci/bulwark-$VERSION-$t/bulwark" "$r/target/$t/release/bulwark"
  done
  VERSION="$VERSION" OUT="$W/pkg" bash "$r/macos-es-proof/build-cli-pkg.sh"
  for t in "${TRIPLES[@]}"; do
    local p="bulwark-$VERSION-$t.pkg"
    (cd "$W/pkg" && shasum -a 256 "$p" | awk '{print $1 "  " $2}' > "$p.sha256" && cp "$p" "$p.sha256" "$W/out/")
  done
}

# WO-95@v1: re-check every artifact from a fresh extract before anything is published.
verify() {
  local v="$W/verify"; rm -rf "$v"; mkdir -p "$v"
  for t in "${TRIPLES[@]}"; do
    local name="bulwark-$VERSION-$t"
    (cd "$W/out" && shasum -a 256 -c "$name.tar.gz.sha256" && shasum -a 256 -c "$name.pkg.sha256")
    tar xzf "$W/out/$name.tar.gz" -C "$v"
    [ -z "$(tar tzf "$W/out/$name.tar.gz" | grep '/\._' || true)" ] || die "AppleDouble entries in $name.tar.gz"
    check_app "$v/$name/$APP"
    cmp "$v/$name/bulwark" "$W/ci/$name/bulwark"
    pkgutil --check-signature "$W/out/$name.pkg" | grep -q 'Developer ID Installer' || die "pkg not Installer-signed"
    xcrun stapler validate "$W/out/$name.pkg" >/dev/null || die "pkg staple invalid"
    spctl -a -vv -t install "$W/out/$name.pkg" 2>&1 | grep -q accepted || die "pkg rejected by spctl"
  done
  "$v/bulwark-$VERSION-aarch64-apple-darwin/bulwark" --version
  echo "==> all artifacts verified; upload set:"; ls -1 "$W/out"
}

# WO-95@v1: replace the CI darwin assets and add the pkgs on the tagged release.
upload() {
  # WO-140@v1: the shared upload point fails before gh sees any unsealed asset.
  local source_sha sealed_binary
  source_sha=$(git -C "$SRC_REPO" rev-parse "v$VERSION^{commit}") \
    || die "cannot resolve v$VERSION to a source commit"
  [[ "$source_sha" =~ ^[0-9a-fA-F]{40}$ ]] || die "v$VERSION source SHA is not 40 hex characters"
  sealed_binary="$W/ci/bulwark-$VERSION-aarch64-apple-darwin/bulwark"
  release_gate "$W/seal" "$source_sha" "$sealed_binary" \
    || die "macOS release upload refused: hardware seal evidence does not match v$VERSION"
  gh_ release upload "v$VERSION" --repo "$REPO" --clobber "$W"/out/*
  gh_ release view "v$VERSION" --repo "$REPO" --json assets -q '.assets[].name'
}

case "${1:-}" in
  stage|seal|repack|pkg|verify|upload) "$1" ;;
  *) die "usage: $0 stage|seal|repack|pkg|verify|upload" ;;
esac
