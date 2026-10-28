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
# ORDER: stage -> sign -> seal (run the two printed sudo lines, both SEALED) -> repack
#   -> APP_ID=... INSTALLER_ID=... pkg (about 1 min per arch) -> verify
#   -> upload (PUBLIC) -> homebrew-tap bump (formula: version, 4 urls/sha256,
#   darwin sums from $W/out; cask: version + 2 pkg sha256).
# KNOWN HARMLESS: pkgbuild prints "write: Permission denied" x4 and the payload has
# four ._* AppleDouble entries, as 0.9.2 had. Apple 403 = re-accept the developer
# agreement, rerun pkg. Proven on 0.9.3 (2026-10-16).
# WO-140@v1: document the exact scope of the binary exercised by hardware seals.
# WO-174@v1: make shipped artifact identity match the selected seal policy.
# The arm64 tarball and .pkg ship the same Developer-ID-signed binary the seals ran.
# The x86_64 binary is built from the same tag and signed the same way but is not
# hardware-sealed; its release binding is the tag SHA, by decision.
#
# Phases, run in order:
#   stage    download the CI darwin tarballs; take the gate from GATE_APP or PREV; verify both
#   sign     Developer-ID-sign both staged CLI binaries before any hardware seal
#   seal     re-run both seals on the exact pair that ships (needs sudo)
#   repack   rebuild both darwin tarballs with bulwark_es_gate.app + .sha256
#   pkg      signed + notarized + stapled .pkg per arch (needs APP_ID, INSTALLER_ID)
#   verify   re-check every artifact from a fresh extract
#   upload   gh release upload --clobber (public: run only when you mean it)
#
# The gate app is reused from PREV, which is valid only while es_gate.swift,
# es_proof.entitlements and GateInfo.plist are unchanged vPREV..vVERSION; stage
# refuses otherwise. Then build a fresh signed + notarized + stapled gate and pass it:
#   SIGNING_IDENTITY="Developer ID Application: ..." bash macos-es-proof/build-gate-bundle.sh
#   GATE_APP=$PWD/macos-es-proof/bulwark_es_gate.app VERSION=... PREV=... \
#     bash macos-es-proof/package-release.sh stage
# (WO-253@v1: GATE_APP must be absolute; stage runs check_app on it before downloading.)
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
# WO-140@v1: bind the receipts to the signed gate extracted from the upload artifact.
release_gate() {
  local seal_dir="$1" expected_sha="$2" binary="$3" expected_cdhash="$4" expected_hash
  local receipt verdict receipt_sha receipt_hash receipt_cdhash
  if [ -z "$expected_cdhash" ]; then
    echo "!! release seal check failed: expected gate_cdhash missing" >&2
    return 1
  fi
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
    receipt_cdhash=$(release_receipt_field "$receipt" gate_cdhash) || {
      echo "!! release seal check failed: gate_cdhash missing from $receipt" >&2
      return 1
    }
    if [ "$receipt_cdhash" != "$expected_cdhash" ]; then
      echo "!! release seal check failed: gate_cdhash mismatch in $receipt" >&2
      return 1
    fi
  done
}

# WO-174@v1: require the arm64 package payload to match the same seal receipts.
release_pkg_gate() {
  local seal_dir="$1" expected_sha="$2" package="$3" expected_cdhash="$4"
  local expand_dir payload="" candidate payload_count=0
  if [ ! -f "$package" ]; then
    echo "!! release seal check failed: missing package $package" >&2
    return 1
  fi
  expand_dir=$(mktemp -d "${TMPDIR:-/tmp}/bulwark-pkg-gate.XXXXXX") || {
    echo "!! release seal check failed: cannot create package expansion directory" >&2
    return 1
  }
  if ! pkgutil --expand-full "$package" "$expand_dir"; then
    rm -rf "$expand_dir"
    echo "!! release seal check failed: cannot expand package $package" >&2
    return 1
  fi
  while IFS= read -r -d '' candidate; do
    payload="$candidate"
    payload_count=$((payload_count + 1))
  done < <(find "$expand_dir" -type f -path '*/Payload/usr/local/bin/bulwark' -print0)
  if [ "$payload_count" -ne 1 ]; then
    rm -rf "$expand_dir"
    echo "!! release seal check failed: package must contain exactly one bulwark payload (found $payload_count)" >&2
    return 1
  fi
  if ! release_gate "$seal_dir" "$expected_sha" "$payload" "$expected_cdhash"; then
    rm -rf "$expand_dir"
    return 1
  fi
  rm -rf "$expand_dir"
}

# WO-253@v1: pick the gate the release ships. PREV's notarized gate is reused only while its
# inputs are unchanged; otherwise the operator supplies a freshly built one through GATE_APP.
# Prints `reuse` or `fresh`; refuses (status 1, reason on stderr) when neither is possible.
gate_plan() {
  local gate_app="$1" inputs_changed="$2"
  if [ -n "$gate_app" ]; then
    case "$gate_app" in
      /*) echo fresh; return 0 ;;
      *) echo "!! GATE_APP must be an absolute path: $gate_app" >&2; return 1 ;;
    esac
  fi
  if [ "$inputs_changed" = 0 ]; then
    echo reuse
    return 0
  fi
  echo "!! gate inputs changed since the previous release: build a fresh gate with" \
    "macos-es-proof/build-gate-bundle.sh and set GATE_APP to its absolute path" >&2
  return 1
}

# WO-140@v1: let fixture tests source the pure upload gate without release inputs.
if [ -n "${RELEASE_GATE_LIB_ONLY:-}" ]; then return 0 2>/dev/null || exit 0; fi

# WO-95@v2: the release being packaged; required so a run never guesses it.
VERSION="${VERSION:?set VERSION to the tagged release, e.g. 0.9.4}"
# WO-95@v2: the release whose notarized gate app is reused when the gate sources are unchanged.
PREV="${PREV:?set PREV to the previous release whose notarized gate app is reused}"
# WO-95@v2: the GitHub repo whose tagged release receives the macOS assets.
REPO=obstalabs/bulwark
# WO-95@v2: the checkout this script lives in; gh and git run from it.
SRC_REPO="$(cd "$(dirname "$0")/.." && pwd)"
# WO-95@v2: scratch work dir for downloads, seals and the upload set.
W="${W:-${TMPDIR:-/tmp}/bulwark-pkg-${VERSION}}"
# WO-95@v2: the two macOS targets release.yml builds.
TRIPLES=(aarch64-apple-darwin x86_64-apple-darwin)
# WO-95@v2: the signed Endpoint Security gate bundle the darwin tarballs must carry.
APP=bulwark_es_gate.app

# WO-95@v2: every phase stops at the first failed check, so a broken artifact never reaches upload.
die() { echo "!! $*" >&2; exit 1; }
# WO-95@v2: gh picks the GitHub account from the repo checkout, so release calls run from there.
gh_() { (cd "$SRC_REPO" && gh "$@"); }   # gh resolves the account from the repo cwd

# WO-95@v2: the CI release ships darwin tarballs without the signed gate app; stage collects the CI
# build and a notarized gate.
# WO-253@v1: that gate is PREV's while its sources are unchanged, else the fresh GATE_APP.
stage() {
  # WO-253@v1: a failed comparison (missing tag) must stop, not read as "inputs changed".
  local changed=0 plan
  git -C "$SRC_REPO" diff --quiet "v$PREV" "v$VERSION" -- macos-es-proof/es_gate.swift \
    macos-es-proof/es_proof.entitlements macos-es-proof/GateInfo.plist || changed=$?
  case "$changed" in
    0|1) ;;
    *) die "cannot compare gate inputs v$PREV..v$VERSION (git exit $changed)" ;;
  esac
  plan=$(gate_plan "${GATE_APP:-}" "$changed") || die "no gate to ship for v$VERSION"
  # WO-253@v1: vet a supplied gate before downloading anything.
  if [ "$plan" = fresh ]; then
    [ -d "$GATE_APP" ] || die "GATE_APP is not a directory: $GATE_APP"
    check_app "$GATE_APP"
  fi
  rm -rf "$W"; mkdir -p "$W/dl" "$W/ci" "$W/prev"
  for t in "${TRIPLES[@]}"; do
    gh_ release download "v$VERSION" --repo "$REPO" -D "$W/dl" \
      -p "bulwark-$VERSION-$t.tar.gz" -p "bulwark-$VERSION-$t.tar.gz.sha256"
    (cd "$W/dl" && shasum -a 256 -c "bulwark-$VERSION-$t.tar.gz.sha256")
    tar xzf "$W/dl/bulwark-$VERSION-$t.tar.gz" -C "$W/ci"
    # WO-253@v1: PREV's tarballs are needed only to reuse its gate.
    if [ "$plan" = reuse ]; then
      gh_ release download "v$PREV" --repo "$REPO" -D "$W/dl" -p "bulwark-$PREV-$t.tar.gz"
      mkdir -p "$W/prev/$t" && tar xzf "$W/dl/bulwark-$PREV-$t.tar.gz" -C "$W/prev/$t"
    fi
  done
  # WO-253@v1: ship the supplied fresh gate, or PREV's when its inputs are unchanged.
  if [ "$plan" = fresh ]; then
    COPYFILE_DISABLE=1 cp -R "$GATE_APP" "$W/$APP"
  else
    local a="$W/prev/aarch64-apple-darwin/bulwark-$PREV-aarch64-apple-darwin/$APP"
    local i="$W/prev/x86_64-apple-darwin/bulwark-$PREV-x86_64-apple-darwin/$APP"
    diff -r "$a" "$i" >/dev/null || die "the two $PREV tarballs carry different gate apps"
    COPYFILE_DISABLE=1 cp -R "$a" "$W/$APP"
  fi
  check_app "$W/$APP"
  for t in "${TRIPLES[@]}"; do
    local b="$W/ci/bulwark-$VERSION-$t/bulwark"
    [ "$("$b" --version 2>/dev/null || echo cross)" = "bulwark $VERSION" ] \
      || [ "$t" = x86_64-apple-darwin ] || die "$b does not report bulwark $VERSION"
    lipo -archs "$b"
  done
  echo "==> staged in $W"
}

# WO-95@v2: a gate app is shippable only if universal, ES-entitled, stapled and notarized.
check_app() {
  local app="$1"
  [ "$(lipo -archs "$app/Contents/MacOS/bulwark_es_gate")" = "x86_64 arm64" ] || die "gate not universal"
  codesign --verify --deep --strict "$app"
  codesign -d --entitlements - "$app" 2>&1 | grep -q endpoint-security || die "ES entitlement missing"
  xcrun stapler validate "$app" >/dev/null || die "staple invalid"
  spctl -a -vv "$app" 2>&1 | grep -q 'source=Notarized Developer ID' || die "spctl not notarized"
  echo "    gate app ok: $app"
}

# WO-174@v1: read the leaf signing authority used to identify the CLI signer.
signing_authority() {
  codesign -dvvv "$1" 2>&1 | awk -F= '
    /^Authority=/ { print substr($0, index($0, "=") + 1); found = 1; exit }
    END { if (!found) exit 1 }
  '
}

# WO-174@v1: sign both release binaries before sealing or packaging either one.
sign() {
  : "${APP_ID:?set APP_ID to 'Developer ID Application: NAME (TEAMID)'}"
  local keychain="${SIGNING_KEYCHAIN:-login.keychain-db}"
  local t source signed authority signed_hash hash_file="$W/signed.sha256.tmp"
  rm -rf "$W/signed"; mkdir -p "$W/signed"
  rm -f "$W/signed.sha256" "$hash_file"
  for t in "${TRIPLES[@]}"; do
    source="$W/ci/bulwark-$VERSION-$t/bulwark"
    signed="$W/signed/$t/bulwark"
    mkdir -p "$(dirname "$signed")"
    COPYFILE_DISABLE=1 cp "$source" "$signed"
    codesign --force --sign "$APP_ID" --keychain "$keychain" \
      --options runtime --timestamp "$signed"
    codesign --verify --strict "$signed"
    authority=$(signing_authority "$signed") \
      || die "cannot read signing authority from $signed"
    [ "$authority" = "$APP_ID" ] \
      || die "$signed was signed by '$authority', expected '$APP_ID'"
    signed_hash=$(shasum -a 256 "$signed" | awk '{print $1}')
    printf '%s  %s/bulwark\n' "$signed_hash" "$t" >> "$hash_file"
  done
  mv "$hash_file" "$W/signed.sha256"
  echo "==> Developer-ID-signed binaries staged in $W/signed"
}

# WO-95@v2: the hardware seals must run on the exact binary + gate pair that ships.
seal() {
  # The seal scripts cd into their own directory and look for ./bulwark_es_gate.app,
  # so seal from a staging copy instead of swapping the app in the checkout.
  local s="$W/seal"; rm -rf "$s"; mkdir -p "$s"
  # WO-174@v1: refuse unless the signing manifest still matches both staged binaries.
  [ -f "$W/signed.sha256" ] || die "sign phase has not recorded signed binary hashes"
  (cd "$W/signed" && shasum -a 256 -c "$W/signed.sha256") \
    || die "signed binary hash does not match the sign phase"
  cp "$SRC_REPO/macos-es-proof/verify-gate.sh" "$SRC_REPO/macos-es-proof/verify-allowlist-gate.sh" "$s/"
  COPYFILE_DISABLE=1 cp -R "$W/$APP" "$s/"
  # WO-174@v1: seal the signed arm64 bytes that both arm64 artifacts will ship.
  cp "$W/signed/aarch64-apple-darwin/bulwark" "$s/bulwark"
  # WO-140@v1: bind both receipts to the commit named by the release tag.
  local source_sha
  source_sha=$(git -C "$SRC_REPO" rev-parse "v$VERSION^{commit}") \
    || die "cannot resolve v$VERSION to a source commit"
  [[ "$source_sha" =~ ^[0-9a-fA-F]{40}$ ]] || die "v$VERSION source SHA is not 40 hex characters"
  echo "Run both, expect SEALED from each:"
  printf '  sudo BULWARK_SOURCE_SHA=%q BULWARK=%q %q\n' "$source_sha" "$s/bulwark" "$s/verify-gate.sh"
  printf '  sudo BULWARK_SOURCE_SHA=%q BULWARK=%q %q\n' "$source_sha" "$s/bulwark" "$s/verify-allowlist-gate.sh"
}

# WO-95@v2: rebuild the darwin tarballs with the gate app, in the layout release.yml uses.
repack() {
  mkdir -p "$W/out"
  for t in "${TRIPLES[@]}"; do
    local name="bulwark-$VERSION-$t" d="$W/ci/bulwark-$VERSION-$t"
    # WO-174@v1: repack the signed copy, never the unsigned CI download.
    COPYFILE_DISABLE=1 cp "$W/signed/$t/bulwark" "$d/bulwark"
    rm -rf "${d:?}/$APP"; COPYFILE_DISABLE=1 cp -R "$W/$APP" "$d/$APP"
    COPYFILE_DISABLE=1 tar -C "$W/ci" -czf "$W/out/$name.tar.gz" "$name"
    (cd "$W/out" && shasum -a 256 "$name.tar.gz" | awk '{print $1 "  " $2}' > "$name.tar.gz.sha256")
    cat "$W/out/$name.tar.gz.sha256"
  done
}

# WO-95@v2: signed, notarized and stapled .pkg per arch, built from the released CI binaries.
pkg() {
  : "${APP_ID:?set APP_ID to 'Developer ID Application: NAME (TEAMID)'}"
  : "${INSTALLER_ID:?set INSTALLER_ID to 'Developer ID Installer: NAME (TEAMID)'}"
  # build-cli-pkg.sh cds to its parent and reads target/<triple>/release/bulwark;
  # give it a staging root holding the CI binaries so the pkg ships the released bits.
  # WO-174@v1: populate that staging root with the already signed release copies.
  local r="$W/pkgroot"; rm -rf "$r"; mkdir -p "$r/macos-es-proof"
  cp "$SRC_REPO/macos-es-proof/build-cli-pkg.sh" "$r/macos-es-proof/"
  for t in "${TRIPLES[@]}"; do
    mkdir -p "$r/target/$t/release"
    cp "$W/signed/$t/bulwark" "$r/target/$t/release/bulwark"
  done
  VERSION="$VERSION" OUT="$W/pkg" bash "$r/macos-es-proof/build-cli-pkg.sh"
  for t in "${TRIPLES[@]}"; do
    local p="bulwark-$VERSION-$t.pkg"
    (cd "$W/pkg" && shasum -a 256 "$p" | awk '{print $1 "  " $2}' > "$p.sha256" && cp "$p" "$p.sha256" "$W/out/")
  done
}

# WO-95@v2: re-check every artifact from a fresh extract before anything is published.
verify() {
  local v="$W/verify"; rm -rf "$v"; mkdir -p "$v"
  for t in "${TRIPLES[@]}"; do
    local name="bulwark-$VERSION-$t"
    (cd "$W/out" && shasum -a 256 -c "$name.tar.gz.sha256" && shasum -a 256 -c "$name.pkg.sha256")
    tar xzf "$W/out/$name.tar.gz" -C "$v"
    [ -z "$(tar tzf "$W/out/$name.tar.gz" | grep '/\._' || true)" ] || die "AppleDouble entries in $name.tar.gz"
    check_app "$v/$name/$APP"
    # WO-174@v1: the archive must preserve the exact signed staging bytes.
    cmp "$v/$name/bulwark" "$W/signed/$t/bulwark"
    pkgutil --check-signature "$W/out/$name.pkg" | grep -q 'Developer ID Installer' || die "pkg not Installer-signed"
    xcrun stapler validate "$W/out/$name.pkg" >/dev/null || die "pkg staple invalid"
    spctl -a -vv -t install "$W/out/$name.pkg" 2>&1 | grep -q accepted || die "pkg rejected by spctl"
  done
  "$v/bulwark-$VERSION-aarch64-apple-darwin/bulwark" --version
  echo "==> all artifacts verified; upload set:"; ls -1 "$W/out"
}

# WO-95@v2: replace the CI darwin assets and add the pkgs on the tagged release.
# WO-140@v1: validate identity from a fresh extract of the archive sent to GitHub.
upload() {
  # WO-140@v1: the shared upload point fails before gh sees any unsealed asset.
  local source_sha archive package extract_dir extracted_name sealed_binary sealed_app expected_cdhash
  source_sha=$(git -C "$SRC_REPO" rev-parse "v$VERSION^{commit}") \
    || die "cannot resolve v$VERSION to a source commit"
  [[ "$source_sha" =~ ^[0-9a-fA-F]{40}$ ]] || die "v$VERSION source SHA is not 40 hex characters"
  archive="$W/out/bulwark-$VERSION-aarch64-apple-darwin.tar.gz"
  [ -f "$archive" ] || die "macOS release upload refused: missing archive $archive"
  extract_dir=$(mktemp -d "$W/upload-check.XXXXXX") \
    || die "macOS release upload refused: cannot create extraction directory"
  if ! tar -xzf "$archive" -C "$extract_dir"; then
    rm -rf "$extract_dir"
    die "macOS release upload refused: cannot extract $archive"
  fi
  extracted_name="bulwark-$VERSION-aarch64-apple-darwin"
  sealed_binary="$extract_dir/$extracted_name/bulwark"
  sealed_app="$extract_dir/$extracted_name/$APP"
  if [ ! -x "$sealed_binary" ] || [ ! -d "$sealed_app" ]; then
    rm -rf "$extract_dir"
    die "macOS release upload refused: extracted archive is missing the binary or gate app"
  fi
  if ! expected_cdhash=$(codesign -dvvv "$sealed_app" 2>&1 | awk -F= '/^CDHash=/{print $2; exit}'); then
    rm -rf "$extract_dir"
    die "macOS release upload refused: cannot read gate CDHash from extracted archive"
  fi
  if [ -z "$expected_cdhash" ]; then
    rm -rf "$extract_dir"
    die "macOS release upload refused: gate CDHash missing from extracted archive"
  fi
  if ! release_gate "$W/seal" "$source_sha" "$sealed_binary" "$expected_cdhash"; then
    rm -rf "$extract_dir"
    die "macOS release upload refused: hardware seal evidence does not match v$VERSION"
  fi
  # WO-174@v1: the arm64 package payload must be the same signed bytes the seals ran.
  package="$W/out/bulwark-$VERSION-aarch64-apple-darwin.pkg"
  if ! release_pkg_gate "$W/seal" "$source_sha" "$package" "$expected_cdhash"; then
    rm -rf "$extract_dir"
    die "macOS release upload refused: package payload does not match the hardware seal"
  fi
  rm -rf "$extract_dir"
  gh_ release upload "v$VERSION" --repo "$REPO" --clobber "$W"/out/*
  gh_ release view "v$VERSION" --repo "$REPO" --json assets -q '.assets[].name'
}

# WO-174@v1: expose signing as a required phase before either seal or package build.
case "${1:-}" in
  stage|sign|seal|repack|pkg|verify|upload) "$1" ;;
  *) die "usage: $0 stage|sign|seal|repack|pkg|verify|upload" ;;
esac
