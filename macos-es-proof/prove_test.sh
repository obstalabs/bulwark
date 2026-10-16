#!/usr/bin/env bash
# WO-38: deterministic source checks for sealable app-bundle proof evidence.
set -euo pipefail
cd "$(dirname "$0")"

# WO-38@v1: seal proof output only from a validated notarized app bundle.
fail() {
    echo "prove_test.sh: $*" >&2
    exit 1
}

# WO-38@v1: seal proof output only from a validated notarized app bundle.
contains() {
    local needle="$1"
    grep -Fq "$needle" prove.sh || fail "prove.sh missing: $needle"
}

# WO-38@v1: seal proof output only from a validated notarized app bundle.
not_contains() {
    local needle="$1"
    if grep -Fq "$needle" prove.sh; then
        fail "prove.sh must not contain: $needle"
    fi
}

contains 'APP_BIN="$APP_BUNDLE/Contents/MacOS/es_proof"'
contains 'NOTARY_RECEIPT="notarization.receipt"'
not_contains 'ES_BIN="./es_proof"'
contains 'xcrun stapler validate "$APP_BUNDLE"'
contains 'spctl -a -vv "$APP_BUNDLE"'
contains 'client_path:'
contains 'bundle_id:'
contains 'stapler:'
contains 'spctl:'
contains 'notary:'
contains '[ "${BUNDLE_VALID:-0}" = 1 ]'
contains 'verdict:        SEALED'
