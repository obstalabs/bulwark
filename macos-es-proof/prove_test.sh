#!/usr/bin/env bash
# deterministic source checks for sealable app-bundle proof evidence.
set -euo pipefail
cd "$(dirname "$0")"

fail() {
    echo "prove_test.sh: $*" >&2
    exit 1
}

contains() {
    local needle="$1"
    grep -Fq "$needle" prove.sh || fail "prove.sh missing: $needle"
}

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
