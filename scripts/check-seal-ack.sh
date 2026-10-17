#!/usr/bin/env bash
set -euo pipefail

# WO-140@v1: enforce one acknowledgement when a PR crosses the kernel boundary.
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
# WO-140@v1: keep CI and local checks on the same boundary definition.
# WO-175@v1: let the base-branch runner supply the trusted boundary definition.
BOUNDARY_PATHS="${BOUNDARY_PATHS:-$SCRIPT_DIR/boundary-paths.txt}"

# WO-140@v1: make malformed invocations fail before inspecting commit messages.
die() {
  echo "!! $*" >&2
  exit 2
}

# WO-140@v1: compare one bounded commit range against the shared boundary list.
# WO-140@v1: disable rename folding so deleted boundary names remain visible.
check_seal_ack() {
  local base="$1" head="$2" changed file line pattern bodies matched
  local -a boundary_files=()
  [ -s "$BOUNDARY_PATHS" ] || die "boundary path list missing or empty: $BOUNDARY_PATHS"
  changed=$(git diff --name-only --no-renames "$base...$head") \
    || die "cannot diff $base...$head"
  while IFS= read -r file; do
    [ -n "$file" ] || continue
    matched=0
    while IFS= read -r line || [ -n "$line" ]; do
      pattern="${line%%#*}"
      pattern="${pattern#"${pattern%%[![:space:]]*}"}"
      pattern="${pattern%"${pattern##*[![:space:]]}"}"
      [ -n "$pattern" ] || continue
      if [[ "$file" == $pattern ]]; then
        matched=1
        break
      fi
    done < "$BOUNDARY_PATHS"
    [ "$matched" = 0 ] || boundary_files+=("$file")
  done <<< "$changed"

  [ "${#boundary_files[@]}" -gt 0 ] || return 0
  bodies=$(git log --format=%B "$base..$head") \
    || die "cannot read commit messages in $base..$head"
  if grep -Fqx 'Seal-required: acknowledged' <<< "$bodies"; then
    return 0
  fi
  echo "!! hardware-seal acknowledgement missing for boundary change(s):" >&2
  printf '  %s\n' "${boundary_files[@]}" >&2
  echo "add this exact commit-body line: Seal-required: acknowledged" >&2
  return 1
}

[ "$#" -eq 2 ] || die "usage: $0 <base> <head>"
check_seal_ack "$1" "$2"
