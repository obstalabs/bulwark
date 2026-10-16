#!/usr/bin/env bash
set -euo pipefail

# WO-140@v1: prove boundary acknowledgement against isolated commit histories.
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
# WO-140@v1: exercise the repository check rather than a fixture copy.
CHECK="$SCRIPT_DIR/check-seal-ack.sh"
# WO-140@v1: keep fixture repositories outside the source tree.
WORK=$(mktemp -d "${TMPDIR:-/tmp}/bulwark-seal-ack-test.XXXXXX")
trap 'rm -rf "$WORK"' EXIT

# WO-140@v1: create fixture commits without inheriting workstation commit hooks.
fixture_commit() {
  local repo="$1" parent="$2" subject="$3" seal_marker="$4" tree commit message
  tree=$(git -C "$repo" write-tree)
  message="$subject

WO: bulwark/WO-140"
  if [ "$seal_marker" = 1 ]; then
    message="$subject

Seal-required: acknowledged

WO: bulwark/WO-140"
  fi
  if [ -n "$parent" ]; then
    commit=$(printf '%s\n' "$message" | git -C "$repo" commit-tree "$tree" -p "$parent")
  else
    commit=$(printf '%s\n' "$message" | git -C "$repo" commit-tree "$tree")
  fi
  git -C "$repo" update-ref refs/heads/fixture "$commit"
  printf '%s\n' "$commit"
}

# WO-140@v1: create one two-commit fixture repository for a named case.
new_fixture() {
  local name="$1" repo base
  repo="$WORK/$name"
  mkdir -p "$repo"
  git -C "$repo" init -q -b fixture
  git -C "$repo" config user.name fixture
  git -C "$repo" config user.email fixture@example.invalid
  printf 'base\n' > "$repo/README.md"
  git -C "$repo" add README.md
  base=$(fixture_commit "$repo" "" "test: add base" 0)
  printf '%s\n' "$repo"
}

# WO-140@v1: assert a fixture is rejected and names its boundary path.
expect_rejected() {
  local name="$1" repo="$2" base="$3" head="$4" expected="$5" output
  if output=$(cd "$repo" && "$CHECK" "$base" "$head" 2>&1); then
    echo "FAIL: $name was accepted"
    exit 1
  fi
  grep -qF "$expected" <<< "$output" || {
    echo "FAIL: $name did not name $expected: $output"
    exit 1
  }
  echo "PASS: $name rejected ($expected)"
}

# WO-140@v1: assert a fixture is accepted without suppressing script errors.
expect_accepted() {
  local name="$1" repo="$2" base="$3" head="$4"
  (cd "$repo" && "$CHECK" "$base" "$head")
  echo "PASS: $name accepted"
}

# WO-140@v1: a boundary change without the exact marker fails.
repo=$(new_fixture no-marker)
base=$(git -C "$repo" rev-parse HEAD)
mkdir -p "$repo/src"
printf '// bulwark/WO-140@v1: boundary fixture.\n' > "$repo/src/allowlist.rs"
git -C "$repo" add src/allowlist.rs
head=$(fixture_commit "$repo" "$base" "test: change boundary" 0)
expect_rejected "boundary without marker" "$repo" "$base" "$head" "src/allowlist.rs"

# WO-140@v1: the exact commit-body marker acknowledges a boundary change.
repo=$(new_fixture with-marker)
base=$(git -C "$repo" rev-parse HEAD)
mkdir -p "$repo/src"
printf '// bulwark/WO-140@v1: boundary fixture.\n' > "$repo/src/allowlist.rs"
git -C "$repo" add src/allowlist.rs
head=$(fixture_commit "$repo" "$base" "test: change boundary" 1)
expect_accepted "boundary with marker" "$repo" "$base" "$head"

# WO-140@v1: a documentation-only change needs no hardware-seal marker.
repo=$(new_fixture readme-only)
base=$(git -C "$repo" rev-parse HEAD)
printf 'docs only\n' >> "$repo/README.md"
git -C "$repo" add README.md
head=$(fixture_commit "$repo" "$base" "docs: update readme" 0)
expect_accepted "README-only change" "$repo" "$base" "$head"
