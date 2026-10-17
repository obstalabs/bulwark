#!/usr/bin/env bash
set -euo pipefail

# WO-175@v1: judge the head range with the base branch's checker and boundary list.
[ "$#" -eq 1 ] || {
  echo "usage: $0 <base-ref>" >&2
  exit 2
}
base_ref="$1"

# WO-175@v1: keep extracted controls isolated when no CI temp directory is supplied.
cleanup_temp=0
if [ -z "${RUNNER_TEMP:-}" ]; then
  RUNNER_TEMP=$(mktemp -d "${TMPDIR:-/tmp}/bulwark-seal-ack.XXXXXX")
  cleanup_temp=1
fi
if [ "$cleanup_temp" -eq 1 ]; then
  trap 'rm -rf "$RUNNER_TEMP"' EXIT
fi

check="$RUNNER_TEMP/check-seal-ack.sh"
boundary_paths="$RUNNER_TEMP/boundary-paths.txt"

# WO-175@v1: fall back only while the base predates the acknowledgement control.
if git cat-file -e "$base_ref:scripts/check-seal-ack.sh" 2>/dev/null \
  && git cat-file -e "$base_ref:scripts/boundary-paths.txt" 2>/dev/null; then
  git show "$base_ref:scripts/check-seal-ack.sh" > "$check"
  git show "$base_ref:scripts/boundary-paths.txt" > "$boundary_paths"
else
  echo "[bulwark] base branch lacks the seal-ack files; using head copies"
  git show "HEAD:scripts/check-seal-ack.sh" > "$check"
  git show "HEAD:scripts/boundary-paths.txt" > "$boundary_paths"
fi

# WO-175@v1: run the selected checker against the trusted boundary list.
BOUNDARY_PATHS="$boundary_paths" bash "$check" "$base_ref" HEAD
