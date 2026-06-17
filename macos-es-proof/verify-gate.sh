#!/usr/bin/env bash
# verify the production macOS ES gate on the entitled Intel Mac.
#
# RUN ON THE INTEL MAC (the expendable box), NOT the M2 daily driver. AUTH mode
# holds the kernel on the edge's verdict; a wedged edge stalls watched opens.
# No system extension is installed (root-launched bundle), so recovery is just
# `sudo pkill bulwark_es_gate`.
#
# This exercises the five acceptance claims through the REAL `bulwark run`
# path (not the es_proof stand-in), and seals a receipt only if all pass:
#   1. protected file DENIED to the supervised tree
#   2. the SAME protected file ALLOWED to an unsupervised process
#   3. a SYMLINK to the protected inode is denied (inode identity, not path)
#   4. a HARDLINK to the protected inode is denied (same inode key)
#   5. >=1000 opens complete without a gate death (no deadline misses / SIGKILL)
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

[ -x "$BULWARK" ] || fail "bulwark binary not found at $BULWARK (cargo build for macOS first)"
[ -x "$GATE_EDGE" ] || fail "gate edge not found at $GATE_EDGE — run ./build-gate-bundle.sh and copy the whole $GATE_APP here"

# --- the same bundle-sealability gate as only the signed/notarized/
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
# Seal.
# ---------------------------------------------------------------------------
echo
{
  echo "# bulwark macOS ES GATE — verification receipt"
  echo "date_utc:        $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "host:            $(hostname) / $(sw_vers -productVersion) / $(uname -m)"
  echo "gate_bundle_id:  ${SIGNED_ID:-MISSING} (expected $GATE_BUNDLE_ID)"
  echo "bundle_sealable: $([ "${BUNDLE_VALID:-0}" = 1 ] && echo yes || echo no) (id+entitlement+staple+spctl)"
  echo "test1_deny_path:      $([ "$DENY_PATH_OK" = 1 ] && echo PASS || echo FAIL)"
  echo "test3_deny_symlink:   $([ "$DENY_SYM_OK" = 1 ] && echo PASS || echo FAIL)"
  echo "test4_deny_hardlink:  $([ "$DENY_HARD_OK" = 1 ] && echo PASS || echo FAIL)"
  echo "test2_unsupervised:   $([ "$UNSUP_OK" = 1 ] && echo PASS || echo FAIL)"
  echo "test5_throughput:     $([ "$LOAD_OK" = 1 ] && echo PASS || echo FAIL) (${LOAD_N:-0} opens)"
  if [ "${BUNDLE_VALID:-0}" = 1 ] && [ "$DENY_PATH_OK" = 1 ] && [ "$DENY_SYM_OK" = 1 ] && \
     [ "$DENY_HARD_OK" = 1 ] && [ "$UNSUP_OK" = 1 ] && [ "$LOAD_OK" = 1 ]; then
    echo "verdict:         SEALED — protected inode denied to the supervised tree (by path, symlink, and hardlink), allowed to an unsupervised process, and the gate survived 1000+ opens, on a real Mac."
  elif [ "${BUNDLE_VALID:-0}" != 1 ]; then
    echo "verdict:         NOT SEALED — gate bundle not validated (sign/notarize/staple/spctl)."
  else
    echo "verdict:         NOT SEALED — see failing test(s) above."
  fi
} | tee "$RECEIPT"

echo
echo "==> receipt written to $PWD/$RECEIPT"
