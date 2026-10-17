#!/usr/bin/env bash
set -euo pipefail

# WO-140@v1: prove boundary acknowledgement against isolated commit histories.
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
# WO-140@v1: exercise the repository check rather than a fixture copy.
# WO-140@v1: let the red proof substitute the pre-fix boundary checker.
CHECK="${CHECK:-$SCRIPT_DIR/check-seal-ack.sh}"
# WO-175@v1: exercise the base-copy runner while keeping its red substitute injectable.
RUNNER="${RUNNER:-$SCRIPT_DIR/run-seal-ack.sh}"
RUNNER_FAILURES=0
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

# WO-175@v1: assert the base-copy runner rejects a weakened head control.
expect_runner_rejected() {
  local name="$1" repo="$2" base="$3" expected="$4" output runner_temp
  runner_temp="$WORK/runner-$name"
  mkdir -p "$runner_temp"
  if output=$(cd "$repo" && RUNNER_TEMP="$runner_temp" "$RUNNER" "$base" 2>&1); then
    echo "FAIL: $name was accepted"
    RUNNER_FAILURES=$((RUNNER_FAILURES + 1))
    return
  fi
  if ! grep -qF "$expected" <<< "$output"; then
    echo "FAIL: $name did not name $expected: $output"
    RUNNER_FAILURES=$((RUNNER_FAILURES + 1))
    return
  fi
  echo "PASS: $name rejected ($expected)"
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

# WO-140@v1: a renamed boundary source remains visible under its old protected name.
repo=$(new_fixture renamed-boundary)
base=$(git -C "$repo" rev-parse HEAD)
mkdir -p "$repo/src"
printf '// bulwark/WO-140@v1: rename fixture.\n' > "$repo/src/gate.rs"
git -C "$repo" add src/gate.rs
base=$(fixture_commit "$repo" "$base" "test: seed renamed boundary" 1)
git -C "$repo" mv src/gate.rs src/gate2.rs
printf '// edited after rename\n' >> "$repo/src/gate2.rs"
git -C "$repo" add src/gate2.rs
head=$(fixture_commit "$repo" "$base" "test: rename boundary" 0)
expect_rejected "renamed boundary" "$repo" "$base" "$head" "src/gate.rs"

# WO-140@v1: deleting a boundary source cannot remove the acknowledgement requirement.
repo=$(new_fixture deleted-boundary)
base=$(git -C "$repo" rev-parse HEAD)
mkdir -p "$repo/src"
printf '// bulwark/WO-140@v1: deletion fixture.\n' > "$repo/src/gate.rs"
git -C "$repo" add src/gate.rs
base=$(fixture_commit "$repo" "$base" "test: seed deleted boundary" 1)
git -C "$repo" rm -q src/gate.rs
head=$(fixture_commit "$repo" "$base" "test: delete boundary" 0)
expect_rejected "deleted boundary" "$repo" "$base" "$head" "src/gate.rs"

# WO-140@v1: weakening the boundary list itself requires acknowledgement.
repo=$(new_fixture boundary-list-only)
base=$(git -C "$repo" rev-parse HEAD)
mkdir -p "$repo/scripts"
printf 'src/gate.rs\n' > "$repo/scripts/boundary-paths.txt"
git -C "$repo" add scripts/boundary-paths.txt
head=$(fixture_commit "$repo" "$base" "test: change boundary list" 0)
expect_rejected "boundary list change" "$repo" "$base" "$head" "scripts/boundary-paths.txt"

# WO-175@v1: replacing the head checker cannot weaken the base branch's control.
repo=$(new_fixture weakened-head-checker)
base=$(git -C "$repo" rev-parse HEAD)
mkdir -p "$repo/scripts" "$repo/src"
cp "$SCRIPT_DIR/check-seal-ack.sh" "$repo/scripts/check-seal-ack.sh"
cp "$SCRIPT_DIR/boundary-paths.txt" "$repo/scripts/boundary-paths.txt"
printf '// base gate\n' > "$repo/src/gate.rs"
git -C "$repo" add scripts/check-seal-ack.sh scripts/boundary-paths.txt src/gate.rs
base=$(fixture_commit "$repo" "$base" "test: seed seal control" 1)
printf '#!/usr/bin/env bash\nexit 0\n' > "$repo/scripts/check-seal-ack.sh"
printf '// unacknowledged change\n' >> "$repo/src/gate.rs"
git -C "$repo" add scripts/check-seal-ack.sh src/gate.rs
fixture_commit "$repo" "$base" "test: weaken checker" 0 >/dev/null
expect_runner_rejected "weakened head checker" "$repo" "$base" "src/gate.rs"

# WO-175@v1: removing a head boundary entry cannot weaken the base branch's list.
repo=$(new_fixture weakened-head-list)
base=$(git -C "$repo" rev-parse HEAD)
mkdir -p "$repo/scripts" "$repo/src"
cp "$SCRIPT_DIR/check-seal-ack.sh" "$repo/scripts/check-seal-ack.sh"
cp "$SCRIPT_DIR/boundary-paths.txt" "$repo/scripts/boundary-paths.txt"
printf '// base gate\n' > "$repo/src/gate.rs"
git -C "$repo" add scripts/check-seal-ack.sh scripts/boundary-paths.txt src/gate.rs
base=$(fixture_commit "$repo" "$base" "test: seed boundary list" 1)
printf 'src/allowlist.rs\n' > "$repo/scripts/boundary-paths.txt"
printf '// unacknowledged change\n' >> "$repo/src/gate.rs"
git -C "$repo" add scripts/boundary-paths.txt src/gate.rs
fixture_commit "$repo" "$base" "test: weaken boundary list" 0 >/dev/null
expect_runner_rejected "weakened head list" "$repo" "$base" "src/gate.rs"

# WO-175@v1: report every base-copy bypass in one deterministic fixture run.
if [ "$RUNNER_FAILURES" -ne 0 ]; then
  exit 1
fi
