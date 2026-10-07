#!/usr/bin/env bash
# WO-41: verify the production macOS ES allow-list gate on the entitled Intel Mac.
#
# RUN ON THE INTEL MAC (the expendable box), NOT the M2 daily driver. AUTH mode
# holds the kernel on the edge's verdict; a wedged edge stalls watched opens.
# No system extension is installed (root-launched bundle), so recovery is just
# `sudo pkill bulwark_es_gate`.
#
# This exercises the WO-41 acceptance claims through the REAL `bulwark run`
# path (not the es_proof stand-in), and seals a receipt only if all pass:
#   1. an allowed folder is readable by the supervised tree
#   2. a sibling folder is denied by default, with no prompt
#   3. a symlink escape from the allowed folder to the sibling is denied
#   4. hardlinks follow inode identity (WO-68/72): a hardlink OF THE GRANTED
#      file placed outside the folder is allowed (same inode, same content), and
#      a FOREIGN file hardlinked INTO the folder after launch is denied with a
#      receipt (its inode was never in the launch snapshot)
#   5. /bin/bash + /bin/cat launch through the macOS runtime base set
#   6. >=1000 opens complete without a gate death (no deadline misses / SIGKILL)
#
# Prereqs on this Mac:
#   - bulwark binary built for macOS (cargo build) at ./bulwark or on PATH
#   - the signed+notarized+stapled gate bundle bulwark_es_gate.app present
#   - BULWARK_MACOS_ES_GATE exported to the edge binary inside the bundle
#   - the calling terminal has Full Disk Access
set -uo pipefail

# WO-137@v1: TEST 4 helpers. Pure (no sudo, no cd, no side effects) so the
# verdict can be exercised against fixture evidence without root:
# `VERIFY_ALLOWLIST_LIB_ONLY=1 . ./verify-allowlist-gate.sh` defines them and
# returns before anything below the marker runs.
#
# evidence_grep <pattern> <file>: prints 1 on a match, 0 on no match, and
# "err" when grep could not inspect the file (exit 2), so a read error is never
# read as "not found" and never passes. The subject is always a file argument,
# never a producer pipe (SIGPIPE under pipefail would turn a match into a miss).
evidence_grep() {
  grep -q -- "$1" "$2"
  case "$?" in
    0) echo 1 ;;
    1) echo 0 ;;
    *) echo err ;;
  esac
}

# test4_verdict <stdout-file> <stderr-file> <receipts-file> <foreign-ino> <linked-after-launch>
# prints the first reason the foreign-hardlink check FAILS, nothing when it is a
# clean deny. It is a deny only if the link was created after the supervised
# tree was already running, the foreign content stayed hidden, the supervised
# shell reported the read denied, the edge did not die, no allow receipt names
# the foreign inode and an allow-list deny receipt does. Missing evidence fails.
test4_verdict() {
  local out="$1" err="$2" rcpt="$3" ino="$4" linked="$5" hit
  [ "$linked" = 1 ] || { echo "link was not created after launch (RUN_STARTED never seen)"; return; }
  [ -r "$out" ] || { echo "stdout file missing or unreadable: $out"; return; }
  hit=$(evidence_grep "foreign-secret" "$out")
  [ "$hit" = 0 ] || { echo "foreign content reached the supervised shell (grep: $hit)"; return; }
  hit=$(evidence_grep "^HARDLINK_IN_DENIED$" "$out")
  [ "$hit" = 1 ] || { echo "supervised read of the planted link was not reported denied (grep: $hit)"; return; }
  [ -r "$err" ] || { echo "stderr file missing or unreadable: $err"; return; }
  hit=$(evidence_grep "ES edge exited" "$err")
  [ "$hit" = 0 ] || { echo "abnormal edge exit reported (grep: $hit)"; return; }
  [ -r "$rcpt" ] || { echo "receipts file missing or unreadable: $rcpt"; return; }
  hit=$(evidence_grep "\"ino\":$ino,\"decision\":\"allow\"" "$rcpt")
  [ "$hit" = 0 ] || { echo "an allow receipt names the foreign inode $ino (grep: $hit)"; return; }
  hit=$(evidence_grep "\"ino\":$ino,\"decision\":\"deny\",\"source\":\"allowlist\"" "$rcpt")
  [ "$hit" = 1 ] || { echo "no allow-list deny receipt for the foreign inode $ino (grep: $hit)"; return; }
}

if [ -n "${VERIFY_ALLOWLIST_LIB_ONLY:-}" ]; then return 0 2>/dev/null || exit 0; fi

# ---- executable-only setup from here on (not run when sourced as a library) ----
cd "$(dirname "$0")"

BULWARK="${BULWARK:-./bulwark}"
GATE_APP="bulwark_es_gate.app"
GATE_EDGE="$GATE_APP/Contents/MacOS/bulwark_es_gate"
GATE_BUNDLE_ID="dev.obstalabs.bulwark.es-gate"
RECEIPT="allowlist-gate-receipt.txt"
EVENT_RECEIPTS="allowlist-gate-events.jsonl"
SUP_OUT_KEEP="allowlist-supervised.out"
SUP_ERR_KEEP="allowlist-supervised.err"
LOAD_OUT_KEEP="allowlist-load.out"
LOAD_ERR_KEEP="allowlist-load.err"

fail() { echo "!! $*"; exit 2; }

[ -x "$BULWARK" ] || fail "bulwark binary not found at $BULWARK (cargo build for macOS first)"
[ -x "$GATE_EDGE" ] || fail "gate edge not found at $GATE_EDGE - run ./build-gate-bundle.sh and copy the whole $GATE_APP here"

# Same bundle-sealability gate as WO-38/WO-23: only the signed/notarized/
# stapled production bundle is closure proof.
echo "==> validating sealable gate bundle"
SIGNED_ID=$(codesign -dv "$GATE_APP" 2>&1 | awk -F= '/Identifier=/{print $2; exit}')
[ "$SIGNED_ID" = "$GATE_BUNDLE_ID" ] && BUNDLE_ID_OK=1 || BUNDLE_ID_OK=0
codesign -d --entitlements - "$GATE_APP" 2>/dev/null | grep -q endpoint-security && ENT_OK=1 || ENT_OK=0
xcrun stapler validate "$GATE_APP" >/dev/null 2>&1 && STAPLE_OK=1 || STAPLE_OK=0
spctl -a -vv "$GATE_APP" >/dev/null 2>&1 && SPCTL_OK=1 || SPCTL_OK=0
echo "   bundle_id=$SIGNED_ID id_ok=$BUNDLE_ID_OK entitlement=$ENT_OK staple=$STAPLE_OK spctl=$SPCTL_OK"
[ "$BUNDLE_ID_OK" = 1 ] && [ "$ENT_OK" = 1 ] && [ "$STAPLE_OK" = 1 ] && [ "$SPCTL_OK" = 1 ] && BUNDLE_VALID=1 || BUNDLE_VALID=0

export BULWARK_MACOS_ES_GATE="$PWD/$GATE_EDGE"

# WO-41: deny-mode can pass with an old edge, so explicitly reject stale
# bundles that cannot parse allow-list config lines.
if strings "$GATE_EDGE" | grep -q "allowlist" && \
   strings "$GATE_EDGE" | grep -q "allow_glob" && \
   strings "$GATE_EDGE" | grep -q "allow_root"; then
    EDGE_ALLOWLIST_OK=1
else
    EDGE_ALLOWLIST_OK=0
fi
echo "   allowlist_edge=$EDGE_ALLOWLIST_OK"
if [ "$EDGE_ALLOWLIST_OK" != 1 ]; then
  {
    echo "# bulwark macOS ES ALLOW-LIST GATE - WO-41 verification receipt"
    echo "date_utc:              $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "host:                  $(hostname) / $(sw_vers -productVersion) / $(uname -m)"
    echo "gate_bundle_id:        ${SIGNED_ID:-MISSING} (expected $GATE_BUNDLE_ID)"
    echo "bundle_sealable:       $([ "${BUNDLE_VALID:-0}" = 1 ] && echo yes || echo no) (id+entitlement+staple+spctl)"
    echo "edge_allowlist:        FAIL (missing allowlist/allow_glob/allow_root markers)"
    echo "verdict:               NOT SEALED - gate edge does not contain allow-list support; rebuild and copy a fresh bulwark_es_gate.app."
  } | tee "$RECEIPT"
  exit 2
fi

WORK="$(mktemp -d /tmp/bulwark-allowlist-verify.XXXXXX)"
ALLOW_DIR="$WORK/allowed"
DENY_DIR="$WORK/sibling"
ALLOW_FILE="$ALLOW_DIR/allowed.txt"
DENY_FILE="$DENY_DIR/secret.txt"
SYMLINK_ESCAPE="$ALLOW_DIR/symlink_escape.txt"
HARDLINK_OUTSIDE="$DENY_DIR/hardlink_to_allowed.txt"
# WO-137@v1: a foreign file that is hardlinked INTO the granted folder only
# after the run has started (TEST 4), so its inode is not in the launch snapshot.
FOREIGN_DIR="$WORK/foreign"
FOREIGN_FILE="$FOREIGN_DIR/planted.txt"
FOREIGN_IN_GRANT="$ALLOW_DIR/planted_link.txt"
mkdir -p "$ALLOW_DIR" "$DENY_DIR" "$FOREIGN_DIR"
echo "allowed-ok" > "$ALLOW_FILE"
echo "outside-secret" > "$DENY_FILE"
echo "foreign-secret" > "$FOREIGN_FILE"
ln -s "$DENY_FILE" "$SYMLINK_ESCAPE"
ln "$ALLOW_FILE" "$HARDLINK_OUTSIDE"
FOREIGN_INO=$(stat -f %i "$FOREIGN_FILE") || fail "cannot stat $FOREIGN_FILE"
: > "$EVENT_RECEIPTS"

cleanup() { sudo pkill -f bulwark_es_gate 2>/dev/null; rm -rf "$WORK"; }
trap cleanup EXIT

echo "==> sudo needed (ES gate runs as root); authorize now:"
sudo -v || fail "sudo auth failed"

echo
echo "==> TEST 1/2/3/4a/5 (allow-list supervised tree): expect allow dir readable, sibling and symlink denied, granted-inode hardlink readable"
SUP_OUT="$WORK/supervised.out"
SUP_ERR="$WORK/supervised.err"
sudo BULWARK_MACOS_ES_GATE="$BULWARK_MACOS_ES_GATE" "$BULWARK" run \
  --deny-all \
  --allow "$ALLOW_DIR/**" \
  --receipts "$PWD/$EVENT_RECEIPTS" \
  -- /bin/bash -c "
    if out=\$(/bin/cat '$ALLOW_FILE' 2>&1); then echo \"ALLOW_FILE_OK:\$out\"; else echo \"ALLOW_FILE_DENIED:\$out\"; fi
    if /bin/cat '$DENY_FILE' >/dev/null 2>&1; then echo \"OUTSIDE_READABLE\"; else echo \"OUTSIDE_DENIED\"; fi
    if /bin/cat '$SYMLINK_ESCAPE' >/dev/null 2>&1; then echo \"SYMLINK_ESCAPE_READABLE\"; else echo \"SYMLINK_ESCAPE_DENIED\"; fi
    if /bin/cat '$HARDLINK_OUTSIDE' >/dev/null 2>&1; then echo \"HARDLINK_OUTSIDE_READABLE\"; else echo \"HARDLINK_OUTSIDE_DENIED\"; fi
  " > "$SUP_OUT" 2> "$SUP_ERR"
SUP_STATUS=$?
cp "$SUP_OUT" "$SUP_OUT_KEEP"
cp "$SUP_ERR" "$SUP_ERR_KEEP"

ALLOW_FILE_OK=$(grep -q "^ALLOW_FILE_OK:allowed-ok$" "$SUP_OUT" && echo 1 || echo 0)
DENY_OUTSIDE_OK=$(grep -q "^OUTSIDE_DENIED$" "$SUP_OUT" && echo 1 || echo 0)
DENY_SYMLINK_OK=$(grep -q "^SYMLINK_ESCAPE_DENIED$" "$SUP_OUT" && echo 1 || echo 0)
# WO-137@v1 (TEST 4a): grants are inode identities (WO-68/72), so a hardlink of
# the GRANTED file placed outside the folder is the granted content under another
# name and is ALLOWED; reading it discloses nothing the grant did not already
# allow. The pre-2026-06-24 path-scoped expectation (denied) was replaced per the
# WO-137 operator ruling; the escape that matters runs the other way (TEST 4b).
HARDLINK_OUTSIDE_OK=$(grep -q "^HARDLINK_OUTSIDE_READABLE$" "$SUP_OUT" && echo 1 || echo 0)
grep -qi "allow this read" "$SUP_OUT" "$SUP_ERR" && NO_PROMPT_OK=0 || NO_PROMPT_OK=1
echo "   status=$SUP_STATUS allow_file=$ALLOW_FILE_OK outside_deny=$DENY_OUTSIDE_OK symlink_deny=$DENY_SYMLINK_OK granted_hardlink_allow=$HARDLINK_OUTSIDE_OK no_prompt=$NO_PROMPT_OK"
while IFS= read -r line; do echo "     $line"; done < "$SUP_OUT"
if [ "$SUP_STATUS" -ne 0 ]; then
  echo "   bulwark run exited $SUP_STATUS; stderr saved to $PWD/$SUP_ERR_KEEP"
  while IFS= read -r line; do echo "     stderr: $line"; done < "$SUP_ERR"
fi

# WO-137@v1: TEST 4b. The grant snapshot is taken before the agent is spawned,
# so a file hardlinked into the granted folder once the supervised shell is
# running presents an inode the snapshot never recorded; the edge must deny it
# and write an allow-list deny receipt for that inode. The supervised shell
# announces RUN_STARTED (its stdout is an inherited fd, so no open is gated),
# THIS unsupervised shell then creates the link, and the supervised shell polls
# for it with stat (not an open) before trying the read. Pre-launch planting is
# out of scope by design: a foreign hardlink already inside the grant at launch
# is snapshotted like any multi-linked file (documented limitation, WO-138).
echo
echo "==> TEST 4b (foreign file hardlinked into the granted folder AFTER launch, ino=$FOREIGN_INO): expect DENIED with an allow-list receipt"
T4_OUT="$WORK/hardlink_in.out"
T4_ERR="$WORK/hardlink_in.err"
: > "$T4_OUT"
sudo BULWARK_MACOS_ES_GATE="$BULWARK_MACOS_ES_GATE" "$BULWARK" run \
  --deny-all \
  --allow "$ALLOW_DIR/**" \
  --receipts "$PWD/$EVENT_RECEIPTS" \
  -- /bin/bash -c "
    echo RUN_STARTED
    for i in \$(seq 1 200); do [ -e '$FOREIGN_IN_GRANT' ] && break; /bin/sleep 0.1; done
    if [ ! -e '$FOREIGN_IN_GRANT' ]; then echo LINK_NEVER_APPEARED; exit 3; fi
    if out=\$(/bin/cat '$FOREIGN_IN_GRANT' 2>&1); then echo \"HARDLINK_IN_READABLE:\$out\"; else echo \"HARDLINK_IN_DENIED\"; fi
  " > "$T4_OUT" 2> "$T4_ERR" &
T4_PID=$!
LINKED_AFTER_LAUNCH=0
for i in $(seq 1 300); do
  if grep -q "^RUN_STARTED$" "$T4_OUT" 2>/dev/null; then break; fi
  sleep 0.1
done
if grep -q "^RUN_STARTED$" "$T4_OUT" 2>/dev/null; then
  ln "$FOREIGN_FILE" "$FOREIGN_IN_GRANT" && LINKED_AFTER_LAUNCH=1
fi
wait "$T4_PID"
T4_STATUS=$?
T4_REASON=$(test4_verdict "$T4_OUT" "$T4_ERR" "$EVENT_RECEIPTS" "$FOREIGN_INO" "$LINKED_AFTER_LAUNCH")
[ "$T4_STATUS" = 0 ] && [ -z "$T4_REASON" ] && T4_FOREIGN_OK=1 || T4_FOREIGN_OK=0
echo "   status=$T4_STATUS linked_after_launch=$LINKED_AFTER_LAUNCH foreign_hardlink_deny=$T4_FOREIGN_OK${T4_REASON:+ ($T4_REASON)}"
while IFS= read -r line; do echo "     $line"; done < "$T4_OUT"
if [ "$T4_STATUS" -ne 0 ]; then
  echo "   bulwark run exited $T4_STATUS"
  while IFS= read -r line; do echo "     stderr: $line"; done < "$T4_ERR"
fi

echo
echo "==> TEST 6 (>=1000 opens under allow-list without a deadline miss): expect gate survives"
LOAD_OUT="$WORK/load.out"
LOAD_ERR="$WORK/load.err"
sudo BULWARK_MACOS_ES_GATE="$BULWARK_MACOS_ES_GATE" "$BULWARK" run \
  --deny-all \
  --allow "$ALLOW_DIR/**" \
  --receipts "$PWD/$EVENT_RECEIPTS" \
  -- /bin/bash -c "
    n=0
    for i in \$(seq 1 1200); do /bin/cat '$ALLOW_FILE' >/dev/null 2>&1 && n=\$((n+1)); done
    echo \"opened \$n\"
  " > "$LOAD_OUT" 2> "$LOAD_ERR"
LOAD_STATUS=$?
cp "$LOAD_OUT" "$LOAD_OUT_KEEP"
cp "$LOAD_ERR" "$LOAD_ERR_KEEP"
LOAD_N=$(grep -oE 'opened [0-9]+' "$LOAD_OUT" | awk '{print $2}')
[ "$LOAD_STATUS" = 0 ] && [ "${LOAD_N:-0}" -ge 1000 ] && LOAD_OK=1 || LOAD_OK=0
echo "   status=$LOAD_STATUS opens completed: ${LOAD_N:-0} (>=1000 required) -> $([ "$LOAD_OK" = 1 ] && echo PASS || echo FAIL)"
if [ "$LOAD_STATUS" -ne 0 ]; then
  echo "   bulwark run exited $LOAD_STATUS; stderr saved to $PWD/$LOAD_ERR_KEEP"
  while IFS= read -r line; do echo "     stderr: $line"; done < "$LOAD_ERR"
fi

echo
{
  echo "# bulwark macOS ES ALLOW-LIST GATE - verification receipt"
  echo "date_utc:              $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "host:                  $(hostname) / $(sw_vers -productVersion) / $(uname -m)"
  echo "gate_bundle_id:        ${SIGNED_ID:-MISSING} (expected $GATE_BUNDLE_ID)"
  echo "bundle_sealable:       $([ "${BUNDLE_VALID:-0}" = 1 ] && echo yes || echo no) (id+entitlement+staple+spctl)"
  echo "edge_allowlist:        $([ "$EDGE_ALLOWLIST_OK" = 1 ] && echo PASS || echo FAIL)"
  echo "test1_run_status:      $([ "$SUP_STATUS" = 0 ] && echo PASS || echo "FAIL ($SUP_STATUS)")"
  echo "test1_allow_file:      $([ "$ALLOW_FILE_OK" = 1 ] && echo PASS || echo FAIL)"
  echo "test2_deny_sibling:    $([ "$DENY_OUTSIDE_OK" = 1 ] && echo PASS || echo FAIL)"
  echo "test2_no_prompt:       $([ "$NO_PROMPT_OK" = 1 ] && echo PASS || echo FAIL)"
  echo "test3_deny_symlink:    $([ "$DENY_SYMLINK_OK" = 1 ] && echo PASS || echo FAIL)"
  echo "test4a_granted_hardlink: $([ "$HARDLINK_OUTSIDE_OK" = 1 ] && echo PASS || echo FAIL) (hardlink of the granted inode outside the folder: allowed, same content)"
  echo "test4b_foreign_hardlink: $([ "$T4_FOREIGN_OK" = 1 ] && echo PASS || echo "FAIL (${T4_REASON:-run status $T4_STATUS})") (foreign ino $FOREIGN_INO linked into the folder after launch: denied, receipt)"
  echo "test5_base_set_launch: $([ "$ALLOW_FILE_OK" = 1 ] && echo PASS || echo FAIL) (/bin/bash + /bin/cat ran)"
  echo "test6_run_status:      $([ "$LOAD_STATUS" = 0 ] && echo PASS || echo "FAIL ($LOAD_STATUS)")"
  echo "test6_throughput:      $([ "$LOAD_OK" = 1 ] && echo PASS || echo FAIL) (${LOAD_N:-0} opens)"
  echo "event_receipts:        $PWD/$EVENT_RECEIPTS"
  echo "supervised_stdout:     $PWD/$SUP_OUT_KEEP"
  echo "supervised_stderr:     $PWD/$SUP_ERR_KEEP"
  echo "load_stdout:           $PWD/$LOAD_OUT_KEEP"
  echo "load_stderr:           $PWD/$LOAD_ERR_KEEP"
  if [ "${BUNDLE_VALID:-0}" = 1 ] && [ "$EDGE_ALLOWLIST_OK" = 1 ] && \
     [ "$SUP_STATUS" = 0 ] && [ "$T4_STATUS" = 0 ] && [ "$LOAD_STATUS" = 0 ] && \
     [ "$ALLOW_FILE_OK" = 1 ] && [ "$DENY_OUTSIDE_OK" = 1 ] && \
     [ "$NO_PROMPT_OK" = 1 ] && [ "$DENY_SYMLINK_OK" = 1 ] && \
     [ "$HARDLINK_OUTSIDE_OK" = 1 ] && [ "$T4_FOREIGN_OK" = 1 ] && \
     [ "$LOAD_OK" = 1 ]; then
    echo "verdict:               SEALED - allow-list mode allowed the grant (by path and by hardlink of the granted inode), denied the sibling, the symlink escape and a foreign file hardlinked into the grant after launch with a receipt, launched through the macOS base set, and survived 1000+ opens on a real Mac."
  elif [ "${BUNDLE_VALID:-0}" != 1 ]; then
    echo "verdict:               NOT SEALED - gate bundle not validated (sign/notarize/staple/spctl)."
  elif [ "$EDGE_ALLOWLIST_OK" != 1 ]; then
    echo "verdict:               NOT SEALED - gate edge does not contain allow-list support; rebuild and copy a fresh bulwark_es_gate.app."
  elif [ "$SUP_STATUS" != 0 ] || [ "$T4_STATUS" != 0 ] || [ "$LOAD_STATUS" != 0 ]; then
    echo "verdict:               NOT SEALED - bulwark run failed; inspect preserved stderr files."
  else
    echo "verdict:               NOT SEALED - see failing test(s) above."
  fi
} | tee "$RECEIPT"

echo
echo "==> receipt written to $PWD/$RECEIPT"
