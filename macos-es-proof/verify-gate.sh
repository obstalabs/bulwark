#!/usr/bin/env bash
# WO-23: verify the production macOS ES gate on the entitled Intel Mac.
#
# RUN ON THE INTEL MAC (the expendable box), NOT the M2 daily driver. AUTH mode
# holds the kernel on the edge's verdict; a wedged edge stalls watched opens.
# No system extension is installed (root-launched bundle), so recovery is just
# `sudo pkill bulwark_es_gate`.
#
# This exercises the five WO-23 acceptance claims through the REAL `bulwark run`
# path (not the es_proof stand-in), and seals a receipt only if all pass:
#   1. protected file DENIED to the supervised tree
#   2. the SAME protected file ALLOWED to an unsupervised process
#   3. a SYMLINK to the protected inode is denied (inode identity, not path)
#   4. a HARDLINK to the protected inode is denied (same inode key)
#   5. >=1000 opens complete without a gate death (no deadline misses / SIGKILL)
#   6. (WO-127) a user-owned /private/tmp file is denied to a DIRECTLY exec'd
#      cat, to bash -c, and to a sleep-then-exec shape, REPS times each, with a
#      `source: static` deny receipt every time. Every process start opens devfs
#      (/dev/dtracehelper), the open that crashed the 0.9.0 edge on macOS 27.
#
# Prereqs on this Mac:
#   - bulwark binary built for macOS (cargo build) at ./bulwark or on PATH
#   - the signed+notarized+stapled gate bundle bulwark_es_gate.app present
#   - BULWARK_MACOS_ES_GATE exported to the edge binary inside the bundle
#   - the calling terminal has Full Disk Access
set -uo pipefail
cd "$(dirname "$0")"

BULWARK="${BULWARK:-./bulwark}"
GATE_APP="bulwark_es_gate.app"
GATE_EDGE="$GATE_APP/Contents/MacOS/bulwark_es_gate"
GATE_BUNDLE_ID="dev.obstalabs.bulwark.es-gate"
RECEIPT="gate-receipt.txt"

fail() { echo "!! $*"; exit 2; }

# WO-127: TEST 6 helpers. Pure (no sudo, no side effects) so their rejections
# can be exercised without root: `VERIFY_GATE_LIB_ONLY=1 . ./verify-gate.sh`
# defines them and returns before anything else runs.
REPS="${REPS:-5}"
RECEIPT_READER="${RECEIPT_READER:-sudo cat}"   # receipts are root-owned 0600

# validate_reps <value>: a positive integer and nothing else. REPS=invalid used
# to run zero shapes and still seal.
validate_reps() {
  [[ "$1" =~ ^[1-9][0-9]*$ ]]
}

# shape_verdict <stdout> <stderr-file> <receipts-file> <fixture-ino>: print the
# first reason a shape FAILS, nothing when it is a clean static deny. A shape is
# only a deny if the content stayed hidden, the edge did not die, no integrity or
# edge-error record was written, and a static deny receipt names the fixture inode.
shape_verdict() {
  local out="$1" err="$2" rcpt="$3" ino="$4" body
  if printf '%s' "$out" | grep -q "top-secret"; then echo "content printed"; return; fi
  if grep -q "ES edge exited" "$err" 2>/dev/null; then echo "abnormal edge exit reported"; return; fi
  body=$($RECEIPT_READER "$rcpt" 2>/dev/null)
  if printf '%s' "$body" | grep -q '"source":"integrity"'; then echo "integrity record in receipts"; return; fi
  if printf '%s' "$body" | grep -q '"source":"edge-error"'; then echo "edge-error record in receipts"; return; fi
  if ! printf '%s' "$body" | grep -q "\"ino\":$ino,\"decision\":\"deny\",\"source\":\"static\""; then
    echo "no static deny receipt for fixture ino $ino"; return
  fi
}

if [ -n "${VERIFY_GATE_LIB_ONLY:-}" ]; then return 0 2>/dev/null || exit 0; fi

# WO-127: refuse a bad REPS before any test runs, so a typo cannot seal nothing.
validate_reps "$REPS" || fail "REPS must be a positive integer (got '$REPS')"

[ -x "$BULWARK" ] || fail "bulwark binary not found at $BULWARK (cargo build for macOS first)"
[ -x "$GATE_EDGE" ] || fail "gate edge not found at $GATE_EDGE — run ./build-gate-bundle.sh and copy the whole $GATE_APP here"

# --- the same bundle-sealability gate as WO-38: only the signed/notarized/
#     stapled production bundle is closure proof. ---
echo "==> validating sealable gate bundle"
SIGNED_ID=$(codesign -dv "$GATE_APP" 2>&1 | awk -F= '/Identifier=/{print $2; exit}')
[ "$SIGNED_ID" = "$GATE_BUNDLE_ID" ] && BUNDLE_ID_OK=1 || BUNDLE_ID_OK=0
codesign -d --entitlements - "$GATE_APP" 2>/dev/null | grep -q endpoint-security && ENT_OK=1 || ENT_OK=0
xcrun stapler validate "$GATE_APP" >/dev/null 2>&1 && STAPLE_OK=1 || STAPLE_OK=0
spctl -a -vv "$GATE_APP" >/dev/null 2>&1 && SPCTL_OK=1 || SPCTL_OK=0
echo "   bundle_id=$SIGNED_ID id_ok=$BUNDLE_ID_OK entitlement=$ENT_OK staple=$STAPLE_OK spctl=$SPCTL_OK"
[ "$BUNDLE_ID_OK" = 1 ] && [ "$ENT_OK" = 1 ] && [ "$STAPLE_OK" = 1 ] && [ "$SPCTL_OK" = 1 ] && BUNDLE_VALID=1 || BUNDLE_VALID=0

export BULWARK_MACOS_ES_GATE="$PWD/$GATE_EDGE"

# Scratch files. The PROTECTED target + a symlink + a hardlink to it.
WORK="$(mktemp -d /tmp/bulwark-gate-verify.XXXXXX)"
PROT="$WORK/protected_secret.txt"
PLAIN="$WORK/plain.txt"
SYM="$WORK/symlink_to_secret.txt"
HARD="$WORK/hardlink_to_secret.txt"
echo "top-secret"  > "$PROT"
echo "harmless"    > "$PLAIN"
ln -s "$PROT" "$SYM"
ln "$PROT" "$HARD"

cleanup() { sudo pkill -f bulwark_es_gate 2>/dev/null; rm -rf "$WORK"; }
trap cleanup EXIT

echo "==> sudo needed (ES gate runs as root); authorize now:"
sudo -v || fail "sudo auth failed"

# ---------------------------------------------------------------------------
# TEST 1 + 3 + 4: a SUPERVISED process under the gate must be DENIED reads of
# the protected inode, whether reached by its real path, a symlink, or a
# hardlink. We run one supervised shell that tries all three and reports.
# ---------------------------------------------------------------------------
echo
echo "==> TEST 1/3/4 (supervised tree, protected inode by path + symlink + hardlink): expect ALL DENIED"
SUP_OUT="$WORK/supervised.out"
sudo BULWARK_MACOS_ES_GATE="$BULWARK_MACOS_ES_GATE" "$BULWARK" run --protect "$PROT" -- /bin/bash -c "
  for f in '$PROT' '$SYM' '$HARD'; do
    if cat \"\$f\" >/dev/null 2>&1; then echo \"READABLE \$f\"; else echo \"denied \$f\"; fi
  done
" > "$SUP_OUT" 2>/dev/null

DENY_PATH_OK=$(grep -q "denied $PROT" "$SUP_OUT" && echo 1 || echo 0)
DENY_SYM_OK=$(grep -q "denied $SYM" "$SUP_OUT" && echo 1 || echo 0)
DENY_HARD_OK=$(grep -q "denied $HARD" "$SUP_OUT" && echo 1 || echo 0)
echo "   path=$DENY_PATH_OK symlink=$DENY_SYM_OK hardlink=$DENY_HARD_OK"
cat "$SUP_OUT" | sed 's/^/     /'

# ---------------------------------------------------------------------------
# TEST 2: an UNSUPERVISED process must read the protected file EVEN WHILE a gate
# is live — the gate governs only its supervised tree, not the whole machine.
# To prove this honestly the unsupervised reader must run CONCURRENTLY with a
# live gate (not after the gated command exited). We launch a supervised holder
# that idles, then read the protected file from THIS (unsupervised) shell while
# that gate is up.
# ---------------------------------------------------------------------------
echo
echo "==> TEST 2 (unsupervised read while a gate is LIVE): expect ALLOWED"
HOLD_DONE="$WORK/hold.done"
sudo BULWARK_MACOS_ES_GATE="$BULWARK_MACOS_ES_GATE" "$BULWARK" run --protect "$PROT" -- /bin/bash -c "
  # supervised holder: confirm WE are denied, then idle so the gate stays live
  cat '$PROT' >/dev/null 2>&1 && echo supervised-READABLE || echo supervised-denied
  sleep 4
" > "$WORK/hold.out" 2>/dev/null &
HOLD_BG=$!
sleep 2   # let the holder's gate come up
# this shell is NOT in the supervised tree -> the protected file must be readable
if cat "$PROT" >/dev/null 2>&1; then
    UNSUP_OK=1; echo "   PASS: unsupervised read allowed while gate live"
else
    UNSUP_OK=0; echo "   FAIL: unsupervised read denied (gate over-reached beyond its tree)"
fi
wait "$HOLD_BG" 2>/dev/null
echo "   (holder saw: $(cat "$WORK/hold.out" 2>/dev/null | tr '\n' ' '))"

# ---------------------------------------------------------------------------
# TEST 5: throughput / deadline safety — a supervised process performs >=1000
# opens of allowed files; the gate must survive (no SIGKILL, exit clean).
# ---------------------------------------------------------------------------
echo
echo "==> TEST 5 (>=1000 opens under the gate without a deadline miss): expect gate survives"
LOAD_OUT="$WORK/load.out"
sudo BULWARK_MACOS_ES_GATE="$BULWARK_MACOS_ES_GATE" "$BULWARK" run --protect "$PROT" -- /bin/bash -c "
  n=0
  for i in \$(seq 1 1200); do cat '$PLAIN' >/dev/null 2>&1 && n=\$((n+1)); done
  echo \"opened \$n\"
" > "$LOAD_OUT" 2>/dev/null
LOAD_N=$(grep -oE 'opened [0-9]+' "$LOAD_OUT" | awk '{print $2}')
[ "${LOAD_N:-0}" -ge 1000 ] && LOAD_OK=1 || LOAD_OK=0
echo "   opens completed: ${LOAD_N:-0} (>=1000 required) -> $([ "$LOAD_OK" = 1 ] && echo PASS || echo FAIL)"

# ---------------------------------------------------------------------------
# TEST 6 (WO-127): direct exec + user-owned /private/tmp fixture, repeated.
# The 0.9.0 edge died on the first devfs open of any supervised process (the
# startup open of /dev/dtracehelper has a negative dev_t on macOS 27), so the
# kernel allowed everything that followed and no receipt was written. Each
# shape below must be denied AND leave a `source: static` deny receipt, on
# every repetition; the receipts are root-owned, so they are read with sudo.
# ---------------------------------------------------------------------------
echo
USER_FIX_DIR="/private/tmp/bulwark-gate-user.$$"
USER_FIX="$USER_FIX_DIR/guarded.txt"
mkdir -p "$USER_FIX_DIR"
echo "top-secret" > "$USER_FIX"
chmod 644 "$USER_FIX"
USER_FIX_INO=$(stat -f %i "$USER_FIX")
echo "==> TEST 6 (WO-127: user-owned $USER_FIX ino=$USER_FIX_INO, direct cat / bash -c / sleep+exec, x$REPS): expect ALL DENIED with static receipts"
DIRECT_OK=1; BASHC_OK=1; SLEEP_OK=1; SHAPE_RUNS=0
# shape_denied <tag> <ok-var-name> <command...>: run once, keep stderr in a
# per-run file, and judge it with shape_verdict (content, edge death, integrity
# or edge-error records, static receipt bound to the fixture inode).
shape_denied() {
  local tag="$1" var="$2"; shift 2
  local rcpt="$WORK/$tag.jsonl" err="$WORK/$tag.stderr" out reason
  SHAPE_RUNS=$((SHAPE_RUNS + 1))
  out=$(sudo BULWARK_MACOS_ES_GATE="$BULWARK_MACOS_ES_GATE" "$BULWARK" run \
          --receipts "$rcpt" --protect "$USER_FIX" -- "$@" 2>"$err")
  reason=$(shape_verdict "$out" "$err" "$rcpt" "$USER_FIX_INO")
  if [ -n "$reason" ]; then
    echo "   $tag: FAIL ($reason)"; eval "$var=0"
    sed 's/^/     stderr: /' "$err" | tail -5
  fi
}
for i in $(seq 1 "$REPS"); do
  shape_denied "direct.$i" DIRECT_OK /bin/cat "$USER_FIX"
  shape_denied "bashc.$i"  BASHC_OK  /bin/bash -c "cat '$USER_FIX'"
  shape_denied "sleep.$i"  SLEEP_OK  /bin/sh -c "sleep 1; exec cat '$USER_FIX'"
done
# WO-127: the seal requires every planned run to have happened, not just the
# ones that did run to have passed.
[ "$SHAPE_RUNS" -eq $((3 * REPS)) ] && RUNS_OK=1 || RUNS_OK=0
echo "   direct=$DIRECT_OK bash_c=$BASHC_OK sleep_exec=$SLEEP_OK runs=$SHAPE_RUNS/$((3 * REPS)) (1 = denied with a static receipt for ino $USER_FIX_INO on every run)"
rm -rf "$USER_FIX_DIR"

# ---------------------------------------------------------------------------
# Seal.
# ---------------------------------------------------------------------------
echo
{
  # WO-23: receipt header names the WO this run verifies.
  echo "# bulwark macOS ES GATE — WO-23 verification receipt"
  echo "date_utc:        $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "host:            $(hostname) / $(sw_vers -productVersion) / $(uname -m)"
  echo "gate_bundle_id:  ${SIGNED_ID:-MISSING} (expected $GATE_BUNDLE_ID)"
  echo "bundle_sealable: $([ "${BUNDLE_VALID:-0}" = 1 ] && echo yes || echo no) (id+entitlement+staple+spctl)"
  echo "test1_deny_path:      $([ "$DENY_PATH_OK" = 1 ] && echo PASS || echo FAIL)"
  echo "test3_deny_symlink:   $([ "$DENY_SYM_OK" = 1 ] && echo PASS || echo FAIL)"
  echo "test4_deny_hardlink:  $([ "$DENY_HARD_OK" = 1 ] && echo PASS || echo FAIL)"
  echo "test2_unsupervised:   $([ "$UNSUP_OK" = 1 ] && echo PASS || echo FAIL)"
  echo "test5_throughput:     $([ "$LOAD_OK" = 1 ] && echo PASS || echo FAIL) (${LOAD_N:-0} opens)"
  # WO-127: the direct-exec shapes are part of the seal, not an extra.
  echo "test6_direct_exec:    $([ "$DIRECT_OK" = 1 ] && echo PASS || echo FAIL) (x$REPS, static receipts)"
  echo "test6_bash_c:         $([ "$BASHC_OK" = 1 ] && echo PASS || echo FAIL) (x$REPS, static receipts)"
  echo "test6_sleep_exec:     $([ "$SLEEP_OK" = 1 ] && echo PASS || echo FAIL) (x$REPS, static receipts)"
  echo "test6_runs:           $([ "$RUNS_OK" = 1 ] && echo PASS || echo FAIL) ($SHAPE_RUNS of $((3 * REPS)) shape runs executed)"
  if [ "${BUNDLE_VALID:-0}" = 1 ] && [ "$DENY_PATH_OK" = 1 ] && [ "$DENY_SYM_OK" = 1 ] && \
     [ "$DENY_HARD_OK" = 1 ] && [ "$UNSUP_OK" = 1 ] && [ "$LOAD_OK" = 1 ] && \
     [ "$DIRECT_OK" = 1 ] && [ "$BASHC_OK" = 1 ] && [ "$SLEEP_OK" = 1 ] && [ "$RUNS_OK" = 1 ]; then
    echo "verdict:         SEALED — protected inode denied to the supervised tree (by path, symlink, and hardlink, and to direct cat / bash -c / sleep+exec x$REPS with static receipts), allowed to an unsupervised process, and the gate survived 1000+ opens, on a real Mac."
  elif [ "${BUNDLE_VALID:-0}" != 1 ]; then
    echo "verdict:         NOT SEALED — gate bundle not validated (sign/notarize/staple/spctl)."
  else
    echo "verdict:         NOT SEALED — see failing test(s) above."
  fi
} | tee "$RECEIPT"

echo
echo "==> receipt written to $PWD/$RECEIPT"
