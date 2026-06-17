#!/usr/bin/env bash
# prove the macOS ES gate on the Intel test Mac.
#
# RUN THIS ON THE INTEL MAC (the expendable box), NOT the M2 daily driver.
# AUTH mode holds the kernel on our verdict; if es_proof wedges, every watched
# open stalls until it dies. Stop with Ctrl-C. Worst case: the open() of a marker
# file stays blocked until you kill es_proof; recovery is just `sudo pkill
# es_proof`. No system extension is installed (root-binary delivery), so there is
# no sysex to wedge and no recovery-mode boot in the normal case.
#
# Proves: a DENY verdict makes a real open() FAIL, an ALLOW verdict lets it
# SUCCEED. Emits a receipt (receipt.txt) capturing both outcomes.
set -uo pipefail
cd "$(dirname "$0")"

APP_BUNDLE="es_proof.app"
APP_BIN="$APP_BUNDLE/Contents/MacOS/es_proof"
BUNDLE_ID="dev.obstalabs.bulwark.es-proof"
NOTARY_RECEIPT="notarization.receipt"
ES_BIN="$APP_BIN"

# only the notarized+stapled app-bundle path can seal . A bare Mach-O
# can be a dev diagnostic on an AMFI-disabled machine, but it is not closure proof.
if [ ! -x "$ES_BIN" ]; then
    echo "!! $ES_BIN missing — run ./build.sh then ./build-bundle.sh, and copy"
    echo "   the whole $APP_BUNDLE directory plus $NOTARY_RECEIPT to the Intel Mac."
    exit 2
fi
echo "==> using ES client: $ES_BIN"

echo "==> validating sealable app bundle"
CODESIGN_DETAILS=$(codesign -dv "$APP_BUNDLE" 2>&1)
SIGNED_BUNDLE_ID=$(printf "%s\n" "$CODESIGN_DETAILS" | awk -F= '/Identifier=/{print $2; exit}')
[ "$SIGNED_BUNDLE_ID" = "$BUNDLE_ID" ] && BUNDLE_ID_OK=1 || BUNDLE_ID_OK=0

if codesign -d --entitlements - "$APP_BUNDLE" 2>/dev/null | grep -q endpoint-security; then
    ENTITLEMENT_OK=1
else
    ENTITLEMENT_OK=0
fi

if STAPLER_OUTPUT=$(xcrun stapler validate "$APP_BUNDLE" 2>&1); then
    STAPLER_OK=1
else
    STAPLER_OK=0
fi

if SPCTL_OUTPUT=$(spctl -a -vv "$APP_BUNDLE" 2>&1); then
    SPCTL_OK=1
else
    SPCTL_OK=0
fi

NOTARY_SUBMISSION_ID="MISSING"
NOTARY_STATUS="MISSING"
if [ -f "$NOTARY_RECEIPT" ]; then
    NOTARY_SUBMISSION_ID=$(awk -F': ' '/^submission_id:/{print $2; exit}' "$NOTARY_RECEIPT")
    NOTARY_STATUS=$(awk -F': ' '/^status:/{print $2; exit}' "$NOTARY_RECEIPT")
fi
[ "$NOTARY_STATUS" = "Accepted" ] && NOTARY_OK=1 || NOTARY_OK=0

if [ "$BUNDLE_ID_OK" = 1 ] && [ "$ENTITLEMENT_OK" = 1 ] && [ "$STAPLER_OK" = 1 ] && [ "$SPCTL_OK" = 1 ] && [ "$NOTARY_OK" = 1 ]; then
    BUNDLE_VALID=1
else
    BUNDLE_VALID=0
fi

echo "   bundle_id:   ${SIGNED_BUNDLE_ID:-MISSING} (expected $BUNDLE_ID)"
echo "   entitlement: $([ "$ENTITLEMENT_OK" = 1 ] && echo PRESENT || echo MISSING)"
echo "   stapler:     $([ "$STAPLER_OK" = 1 ] && echo OK || echo FAILED)"
echo "   spctl:       $([ "$SPCTL_OK" = 1 ] && echo OK || echo FAILED)"
echo "   notary:      status=${NOTARY_STATUS:-MISSING} submission_id=${NOTARY_SUBMISSION_ID:-MISSING}"
if [ "$BUNDLE_VALID" != 1 ]; then
    echo "!! App bundle is not sealable; refusing to run a seal proof."
    echo "   stapler output: ${STAPLER_OUTPUT:-not run}"
    echo "   spctl output: ${SPCTL_OUTPUT:-not run}"
    exit 2
fi

MARKER="BULWARK_DENY_$$"           # unique per run
DENY_FILE="/tmp/${MARKER}_secret.txt"
ALLOW_FILE="/tmp/allowed_$$_plain.txt"
RECEIPT="receipt.txt"

echo "secret-contents" > "$DENY_FILE"
echo "plain-contents"  > "$ALLOW_FILE"

cleanup() { sudo pkill -f "es_proof $MARKER" 2>/dev/null; rm -f "$DENY_FILE" "$ALLOW_FILE"; }
trap cleanup EXIT

# Pre-authorize sudo FIRST so the password prompt does not race the background
# launch (the earlier bug: `sudo ... &` fought the prompt and es_proof never ran).
echo "==> sudo is needed to run the ES client as root; authorize now:"
sudo -v || { echo "!! sudo auth failed"; exit 1; }

echo "==> starting ES gate (deny-marker=$MARKER) as root"
sudo "$ES_BIN" "$MARKER" > es_proof.log 2>&1 &
sleep 3   # let es_new_client + es_subscribe come up

# Capture the REAL es_proof pid (es_proof prints "pid=NNNN"); $! is only the sudo
# wrapper. We liveness-check the actual client, not the wrapper, and not a stale
# log line — a grep for "gate is LIVE" is satisfied by a corpse's last words.
ES_REAL_PID=$(grep -oE 'pid=[0-9]+' es_proof.log | head -1 | cut -d= -f2)

# alive: the ES client process is still running RIGHT NOW (not just "was logged").
alive() { [ -n "${ES_REAL_PID:-}" ] && sudo kill -0 "$ES_REAL_PID" 2>/dev/null; }

if ! grep -q "gate is LIVE" es_proof.log 2>/dev/null || ! alive; then
    echo "!! ES client is not live. Log:"; cat es_proof.log
    echo
    echo "   Diagnose:"
    echo "   - 'Killed: 9' (kernel SIGKILL) AFTER 'gate is LIVE' -> the handler did not"
    echo "       answer an AUTH event correctly (wrong responder / missed deadline);"
    echo "       the kernel killed the client. Check es_proof.log for a FATAL respond line."
    echo "   - 'Killed: 9' with EMPTY log    -> AMFI/entitlement (needs bundle+profile+notarize+FDA)."
    echo "   - 'ERR_NOT_PERMITTED'           -> the calling terminal needs Full Disk Access."
    echo "   - 'ERR_NOT_ENTITLED'            -> binary lacks/incorrectly carries the entitlement."
    exit 2
fi
echo "   gate is live (pid $ES_REAL_PID, verified running)."

# Liveness at the START of the test window. A FAIL/PASS measured against a dead
# gate is meaningless (the bug we just fixed produced exactly that), so we record
# alive-at-both-ends in the receipt and refuse to seal if the gate died mid-test.
alive && ALIVE_BEFORE=1 || ALIVE_BEFORE=0

echo
echo "==> TEST 1 (DENY): open a file whose path contains the marker -- expect FAILURE"
if cat "$DENY_FILE" >/dev/null 2>deny_err.txt; then
    DENY_RESULT="FAIL: the marked file was READABLE (gate did NOT deny)"
    DENY_OK=0
else
    DENY_RESULT="PASS: open() denied -> $(cat deny_err.txt | head -1)"
    DENY_OK=1
fi
echo "   $DENY_RESULT"

echo
echo "==> TEST 2 (ALLOW): open a plain file -- expect SUCCESS"
if OUT=$(cat "$ALLOW_FILE" 2>/dev/null) && [ "$OUT" = "plain-contents" ]; then
    ALLOW_RESULT="PASS: open() allowed, read \"$OUT\""
    ALLOW_OK=1
else
    ALLOW_RESULT="FAIL: the plain file was NOT readable (gate over-denied)"
    ALLOW_OK=0
fi

# Liveness at the END of the test window.
alive && ALIVE_AFTER=1 || ALIVE_AFTER=0
echo "   $ALLOW_RESULT"

echo
echo "==> tearing down gate"
# es_proof runs as a root child of the sudo wrapper; pkill by name reaches the
# real process. Deleting the client releases any held AUTH events (fail-closed).
sudo pkill -f "es_proof $MARKER" 2>/dev/null
[ -n "${ES_REAL_PID:-}" ] && sudo kill "$ES_REAL_PID" 2>/dev/null
sleep 1

# Emit the receipt (the proof artifact).
{
  echo "# bulwark macOS ES gate — proof receipt"
  echo "date_utc:       $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "host:           $(hostname) / $(sw_vers -productVersion) / $(uname -m)"
  echo "client_path:    $ES_BIN"
  echo "bundle_id:      ${SIGNED_BUNDLE_ID:-MISSING} (expected $BUNDLE_ID)"
  echo "stapler:        $([ "${STAPLER_OK:-0}" = 1 ] && echo OK || echo FAILED)"
  echo "spctl:          $([ "${SPCTL_OK:-0}" = 1 ] && echo OK || echo FAILED)"
  echo "notary:         status=${NOTARY_STATUS:-MISSING} submission_id=${NOTARY_SUBMISSION_ID:-MISSING}"
  echo "binary:         $(codesign -dv "$ES_BIN" 2>&1 | grep Identifier | head -1)"
  echo "entitlement:    $(codesign -d --entitlements - "$ES_BIN" 2>/dev/null | grep -q endpoint-security && echo 'com.apple.developer.endpoint-security.client PRESENT' || echo 'MISSING')"
  echo "es_new_client:  $(grep -q 'entitlement accepted' es_proof.log && echo 'OK (entitlement accepted by kernel)' || echo 'FAILED')"
  echo "auth_subscribed:$(grep -q 'gate is LIVE' es_proof.log && echo 'yes (AUTH_OPEN)' || echo 'no')"
  echo "gate_alive:     before_tests=$([ "${ALIVE_BEFORE:-0}" = 1 ] && echo yes || echo no) after_tests=$([ "${ALIVE_AFTER:-0}" = 1 ] && echo yes || echo no)"
  echo "deny_test:      $DENY_RESULT"
  echo "allow_test:     $ALLOW_RESULT"
  # Seal requires: app-bundle validation, deny, allow, and liveness at BOTH ends
  # of the test window. Without the bundle check, an AMFI-disabled dev run could
  # clerk-stamp a bare-binary shortcut as production evidence.
  if [ "${BUNDLE_VALID:-0}" = 1 ] && [ "${DENY_OK:-0}" = 1 ] && [ "${ALLOW_OK:-0}" = 1 ] && [ "${ALIVE_BEFORE:-0}" = 1 ] && [ "${ALIVE_AFTER:-0}" = 1 ]; then
    echo "verdict:        SEALED — the ES gate denied a real open() and allowed another, gate alive throughout, on a real Mac."
  elif [ "${BUNDLE_VALID:-0}" != 1 ]; then
    echo "verdict:        NOT SEALED — the app bundle was not validated as signed, notarized, stapled, and assessable."
  elif [ "${ALIVE_BEFORE:-0}" != 1 ] || [ "${ALIVE_AFTER:-0}" != 1 ]; then
    echo "verdict:        NOT SEALED — the gate was NOT alive across the full test window; results are meaningless (gate died, likely SIGKILL — see es_proof.log)."
  else
    echo "verdict:        NOT SEALED — see deny_test/allow_test above."
  fi
} | tee "$RECEIPT"

echo
echo "==> receipt written to $(pwd)/$RECEIPT"
