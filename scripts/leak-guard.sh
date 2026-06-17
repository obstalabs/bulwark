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

# 1. Work-order references (internal tracking; belong in the ledger, not the code).
flag "work-order reference (use the ledger, not a code comment)" \
  'WO-[0-9]+'

# 2. A REAL code-signing identity: 'Developer ID ...: First Last (TEAMID)' where the
#    team id is the genuine 10-char form. The documented placeholder is
#    '... NAME (TEAMID)' / '... <NAME> (<TEAMID>)', which does NOT match (the team id
#    must be exactly 10 of [A-Z0-9]). So real identities trip; placeholders do not.
flag "real Apple signing identity (use an env var / placeholder)" \
  'Developer ID [A-Za-z]+: [A-Za-z]+ [A-Za-z]+ \([A-Z0-9]{10}\)'

# 3. A bare Apple Team ID assigned to a variable/flag: --team-id "XXXXXXXXXX" or
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
