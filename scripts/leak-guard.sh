#!/usr/bin/env bash
# leak-guard: fail if internal-only references appear in the tracked tree.
#
# This is a structural backstop for the "code is born public-clean" rule. It
# describes the SHAPE of an internal reference, never a specific instance — so the
# guard itself leaks nothing. Run in CI on every push/PR and locally pre-commit.
#
# Exit 0 = clean. Exit 1 = a forbidden pattern was found (printed with location).
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

fail=0
flag() {
  # $1 = human label, $2 = extended-regex. Print matches, set fail.
  local label="$1" re="$2" hits
  # Search tracked files only; skip this script and the workflow that runs it
  # (they legitimately contain the patterns as regex text).
  hits=$(git grep -nE "$re" -- ':!scripts/leak-guard.sh' ':!.github/workflows/leak-guard.yml' 2>/dev/null || true)
  if [ -n "$hits" ]; then
    echo "BLOCKED — $label:"
    echo "$hits"
    echo
    fail=1
  fi
}

# Guard policy: strip what we do NOT sell, and PII. Everything else may ship.
#
# ALLOWED in source (these are shipping products / OSS — they are the funnel, not a
# leak): WO-NNNN provenance tags (Workledger, hiveram.com); hivebus (hivebus.dev OSS +
# the boardroom feature of neurorouter-pro); NeuroRouter / nr-pro; vectorcourt / oracul;
# pastewatch. Do NOT add rules blocking these — doing so removes the funnel on purpose.
#
# BLOCKED (rules 1-2 below): tooling we do NOT sell yet, plus internal workflow
# artifacts that are never a product. These must not enter the public tree.
flag "unsold internal tooling name (tokencontrol/wocontrol are not products yet)" \
  'tokencontrol|wocontrol'
flag "internal workflow artifact (belongs out-of-band, never in public source)" \
  '(docs/plans/|work-orders\.md|codex exec )'

# PII / credential guards below remain: real signing identities and Team IDs must
# never enter the tree.

# 1. A REAL code-signing identity: 'Developer ID ...: First Last (TEAMID)' where the
#    team id is the genuine 10-char form. The documented placeholder is
#    '... NAME (TEAMID)' / '... <NAME> (<TEAMID>)', which does NOT match (the team id
#    must be exactly 10 of [A-Z0-9]). So real identities trip; placeholders do not.
flag "real Apple signing identity (use an env var / placeholder)" \
  'Developer ID [A-Za-z]+: [A-Za-z]+ [A-Za-z]+ \([A-Z0-9]{10}\)'

# 2. A bare Apple Team ID assigned to a variable/flag: --team-id "XXXXXXXXXX" or
#    team-id=XXXXXXXXXX with the genuine 10-char form (placeholder is <YOUR_TEAM_ID>,
#    which has non-alnum chars and so does not match the 10-char run). POSIX ERE
#    (git grep) — no \b; use a non-alnum boundary or end-of-line instead.
flag "hard-coded Apple Team ID (use an env var / placeholder)" \
  'team[_-]?id[^A-Za-z0-9]+[A-Z0-9]{10}([^A-Za-z0-9]|$)'

if [ "$fail" -ne 0 ]; then
  echo "leak-guard: internal references must not enter the public tree."
  echo "See CONTRIBUTING — code is born public-clean; track internals out-of-band."
  exit 1
fi
echo "leak-guard: clean."
