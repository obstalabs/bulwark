#!/usr/bin/env bash
# WO-135@v2: fail when a glibc-linked binary needs a newer glibc than GLIBC_FLOOR.
#
# Usage: scripts/check-glibc-floor.sh <binary>
#   GLIBC_FLOOR  highest glibc symbol version the binary may require (default 2.31)
#   READELF      readelf-compatible reader, invoked as `$READELF -V <binary>`
#                (default: readelf; tests feed a text fixture through a cat-like reader)
#
# Every GLIBC_* requirement in the version-needs output is collected. A
# requirement whose suffix is not <digits>(.<digits>)* (GLIBC_ABI_DT_RELR,
# GLIBC_PRIVATE, anything unknown) fails the check by name: it encodes a loader
# feature the numeric floor cannot vouch for. Versions are compared component by
# component (2.3.4 is above 2.3 and below 2.4). A binary with no GLIBC_
# requirement at all fails too: it is not the glibc build this guard is for.
set -euo pipefail

floor="${GLIBC_FLOOR:-2.31}"
reader="${READELF:-readelf}"
numeric='^[0-9]+(\.[0-9]+)*$'

if [ "$#" -ne 1 ]; then
  echo "usage: $0 <binary>" >&2
  exit 64
fi
bin="$1"
if [ ! -f "$bin" ]; then
  echo "::error::$bin: no such file"
  exit 1
fi
if [[ ! "$floor" =~ $numeric ]]; then
  echo "::error::GLIBC_FLOOR '$floor' is not a numeric version"
  exit 64
fi

# WO-135@v2: version_gt A B: true when A is newer than B, comparing each dot
# component (a string compare would put 2.10 below 2.9).
version_gt() {
  local IFS=.
  local -a a=($1) b=($2)
  local i n=${#a[@]}
  if [ "${#b[@]}" -gt "$n" ]; then
    n=${#b[@]}
  fi
  for ((i = 0; i < n; i++)); do
    local x=${a[i]:-0} y=${b[i]:-0}
    if ((10#$x > 10#$y)); then
      return 0
    fi
    if ((10#$x < 10#$y)); then
      return 1
    fi
  done
  return 1
}

# The reader's failure is the script's failure (set -e, no pipe to hide it).
verneed=$("$reader" -V "$bin")

# Tri-state grep: 0 = requirements found, 1 = none, anything else = grep failed.
set +e
matches=$(grep -oE 'GLIBC_[A-Za-z0-9_.]+' <<<"$verneed")
rc=$?
set -e
case "$rc" in
  0) ;;
  1)
    echo "::error::$bin: no GLIBC_ version requirement found; not a glibc-linked binary"
    exit 1
    ;;
  *)
    echo "::error::$bin: grep failed while reading version requirements (rc=$rc)"
    exit 2
    ;;
esac
reqs=$(sort -u <<<"$matches")

highest=""
while IFS= read -r req; do
  if [ -z "$req" ]; then
    continue
  fi
  ver="${req#GLIBC_}"
  if [[ ! "$ver" =~ $numeric ]]; then
    echo "::error::$bin requires $req, which is not a numeric glibc version the floor $floor can vouch for"
    exit 1
  fi
  if [ -z "$highest" ] || version_gt "$ver" "$highest"; then
    highest="$ver"
  fi
done <<<"$reqs"

echo "$bin: highest glibc symbol version required = $highest; floor = $floor"
if version_gt "$highest" "$floor"; then
  echo "::error::$bin requires glibc $highest, above the floor $floor"
  exit 1
fi
echo "ok: $bin stays within glibc $floor"
