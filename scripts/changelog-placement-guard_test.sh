# Ported from pastewatch scripts/changelog-placement-guard.sh at 7d39c370c050 (bulwark/WO-294).
# shellcheck shell=bash
# WO-294@v1: fail the fixture suite on an unsuccessful assertion.
set -euo pipefail

# WO-294@v1: locate the guard independently of the caller's working directory.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# WO-294@v1: fixtures execute the guard used by CI.
GUARD="$SCRIPT_DIR/changelog-placement-guard.sh"
# WO-294@v1: keep fixture repositories and output in a temporary directory.
FIXTURE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/bulwark-placement-tests.XXXXXX")"
trap 'rm -rf "$FIXTURE_DIR"' EXIT
# WO-294@v1: prevent inherited repository paths from routing fixture writes to the checkout.
unset GIT_DIR GIT_COMMON_DIR GIT_OBJECT_DIRECTORY GIT_ALTERNATE_OBJECT_DIRECTORIES GIT_WORK_TREE GIT_INDEX_FILE
# WO-294@v1: build the fixtures in an isolated bare repository.
REPO="$FIXTURE_DIR/repo.git"
git init --bare --quiet "$REPO"
# WO-294@v1: count cases after verifying their results.
CASES=0

# WO-294@v1: assemble deterministic commit histories entirely in the fixture repository.
commit_fixture() {
    local content="$1" subject="$2" parent="${3:-}" blob tree
    blob="$(printf '%s' "$content" | git --git-dir="$REPO" hash-object -w --stdin)"
    tree="$(printf '100644 blob %s\tCHANGELOG.md\n' "$blob" | git --git-dir="$REPO" mktree)"
    # WO-294@v1: allow both root and descendant commits in the fixture history.
    local args=("$tree")
    if [[ -n "$parent" ]]; then args+=(-p "$parent"); fi
    printf '%s\n' "$subject" | GIT_AUTHOR_NAME=fixture GIT_COMMITTER_NAME=fixture \
        GIT_AUTHOR_EMAIL=fixture@example.invalid GIT_COMMITTER_EMAIL=fixture@example.invalid \
        GIT_AUTHOR_DATE=2026-11-21T00:00:00Z GIT_COMMITTER_DATE=2026-11-21T00:00:00Z \
        git --git-dir="$REPO" commit-tree "${args[@]}"
}

# WO-294@v1: verify that accepted changes report success with no diagnostics.
accepts() {
    local name="$1" content="$2" subject="$3" parent="${4:-$BASE}" head
    head="$(commit_fixture "$content" "$subject" "$parent")"
    # WO-294@v1: compare the full fixture range even when the head has an intermediate parent.
    if ! GIT_DIR="$REPO" bash "$GUARD" "$BASE" "$head" > "$FIXTURE_DIR/output" 2> "$FIXTURE_DIR/error"; then
        printf 'FAIL: %s was refused\n' "$name" >&2
        exit 1
    fi
    [[ ! -s "$FIXTURE_DIR/error" ]]
    grep -Fq 'Changelog placement check passed' "$FIXTURE_DIR/output"
    CASES=$((CASES + 1))
}

# WO-294@v1: verify that rejected changes identify the line and published section.
rejects() {
    local name="$1" content="$2" subject="$3" line="$4" parent="${5:-$BASE}" head
    head="$(commit_fixture "$content" "$subject" "$parent")"
    # WO-294@v1: require failure even for a rejection case with a release commit in its stack.
    if GIT_DIR="$REPO" bash "$GUARD" "$BASE" "$head" > "$FIXTURE_DIR/output" 2> "$FIXTURE_DIR/error"; then
        printf 'FAIL: %s was accepted\n' "$name" >&2
        exit 1
    fi
    [[ ! -s "$FIXTURE_DIR/output" ]]
    grep -Fq "file=CHANGELOG.md,line=$line::" "$FIXTURE_DIR/error"
    grep -Fq 'previously released section [0.12.0]' "$FIXTURE_DIR/error"
    # WO-294@v1: keep line contents out of refusal diagnostics.
    if grep -Fq 'misplaced fixture text' "$FIXTURE_DIR/error"; then
        printf 'FAIL: %s printed line contents\n' "$name" >&2
        exit 1
    fi
    CASES=$((CASES + 1))
}

# WO-294@v1: put both unpublished and published notes in the base fixture.
BASE_TEXT=$'# Changelog\n\n## [Unreleased]\n\n### Fixed\n\n- Upcoming change.\n\n## [0.12.0] - 2026-11-20\n\n- Published change.\n'
BASE="$(commit_fixture "$BASE_TEXT" 'chore: fixture base')"
# WO-294@v1: ordinary pull requests can add a line to Unreleased.
accepts unreleased-addition \
    $'# Changelog\n\n## [Unreleased]\n\n### Fixed\n\n- Upcoming change.\n- New change.\n\n## [0.12.0] - 2026-11-20\n\n- Published change.\n' \
    'fix: add new change'
# WO-294@v1: ordinary additions to the published version fail and name the added line.
rejects published-addition "$BASE_TEXT"$'- misplaced fixture text\n' 'fix: add new change' 12

# WO-294@v1: capture a release that moves the Unreleased notes into a new version.
RELEASE_TEXT=$'# Changelog\n\n## [Unreleased]\n\n## [0.13.0] - 2026-11-21\n\n### Fixed\n\n- Upcoming change.\n\n## [0.12.0] - 2026-11-20\n\n- Published change.\n'
# WO-294@v1: retain the inherited release subject form.
accepts release-moves-unreleased "$RELEASE_TEXT" 'chore: release v0.13.0'
# WO-294@v1: retain the inherited version bump subject form.
accepts bump-moves-unreleased "$RELEASE_TEXT" 'chore: bump version to 0.13.0'
# WO-294@v1: a section introduced by the pull request can receive notes with an ordinary subject.
accepts new-release-section "$RELEASE_TEXT" 'docs: prepare release notes'
# WO-294@v1: make the newly introduced version available to a later commit in the same stack.
RELEASE_HEAD="$(commit_fixture "$RELEASE_TEXT" 'chore: release 0.13.0' "$BASE")"
accepts stacked-new-release-section \
    "${RELEASE_TEXT/Upcoming change./$'Upcoming change.\n- Stacked fix.'}" \
    'fix: add stacked change' "$RELEASE_HEAD"
# WO-294@v1: a release subject leaves every other published version protected.
rejects release-cannot-rewrite-older "$BASE_TEXT"$'- misplaced fixture text\n' 'chore: release v0.13.0' 12
# WO-294@v1: a non-tip release subject also leaves older versions protected.
rejects stacked-release-cannot-rewrite-older "$RELEASE_TEXT"$'- misplaced fixture text\n' 'fix: add stacked note' 14 "$RELEASE_HEAD"
# WO-294@v1: the inherited release subject authorizes its named version.
accepts release-can-edit-named-section "$BASE_TEXT"$'- Release correction.\n' 'chore: release v0.12.0'
# WO-294@v1: recognize an unprefixed release subject before the head of a pull request.
NAMED_RELEASE="$(commit_fixture "$BASE_TEXT" 'chore: release 0.12.0' "$BASE")"
accepts stacked-release-can-edit-named-section "$BASE_TEXT"$'- Release correction.\n' 'fix: stack release change' "$NAMED_RELEASE"
# WO-294@v1: extra words invalidate the release subject exception.
rejects near-miss-release-subject "$BASE_TEXT"$'- misplaced fixture text\n' 'chore: release v0.12.0 later' 12
# WO-294@v1: unrelated commits leave changelog placement valid.
accepts unchanged "$BASE_TEXT" 'fix: unrelated change'

# WO-294@v1: permit the exact published-note correction subject.
accepts operator-typo-correction "${BASE_TEXT/Published change./Published correction.}" 'chore: fix changelog'
# WO-294@v1: corrections with additional subject text still follow the placement rule.
rejects near-miss-typo-subject "$BASE_TEXT"$'- misplaced fixture text\n' 'chore: fix changelog later' 12

# WO-294@v1: a release may not delete a line from another published section.
rejects release-cannot-delete-older \
    $'# Changelog\n\n## [Unreleased]\n\n## [0.13.0] - 2026-11-21\n\n- Release change.\n\n## [0.12.0] - 2026-11-20\n' \
    'chore: release v0.13.0' 10

# WO-294@v1: protect a section published at the base tip after the branch forked.
TIP_TEXT=$'# Changelog\n\n## [Unreleased]\n\n## [0.13.0] - 2026-11-21\n\n- Released on main.\n\n## [0.12.0] - 2026-11-20\n\n- Published change.\n'
PUBLISHED_TIP="$(commit_fixture "$TIP_TEXT" 'chore: release v0.13.0' "$BASE")"
FORK_HEAD="$(commit_fixture "${TIP_TEXT/Released on main./Ordinary branch change.}" 'fix: new change' "$BASE")"
# WO-294@v1: confirm that an independent branch cannot add to the newly published version.
if GIT_DIR="$REPO" bash "$GUARD" "$PUBLISHED_TIP" "$FORK_HEAD" > "$FIXTURE_DIR/output" 2> "$FIXTURE_DIR/error"; then
    printf 'FAIL: section published after the fork was not protected\n' >&2
    exit 1
fi
grep -Fq 'previously released section [0.13.0]' "$FIXTURE_DIR/error"
CASES=$((CASES + 1))

# WO-294@v1: give the base tip a published-note correction after the branch forked.
MAIN_TIP="$(commit_fixture "${BASE_TEXT/Published change./Corrected published change.}" 'docs: fix published notes' "$BASE")"
STALE_HEAD="$(commit_fixture "$BASE_TEXT" 'fix: unrelated stale branch' "$BASE")"
# WO-294@v1: measure a stale branch against its fork so base-only changes are excluded.
if ! GIT_DIR="$REPO" bash "$GUARD" "$MAIN_TIP" "$STALE_HEAD" > "$FIXTURE_DIR/output" 2> "$FIXTURE_DIR/error"; then
    printf 'FAIL: stale branch was blamed for later main changes\n' >&2
    exit 1
fi
[[ ! -s "$FIXTURE_DIR/error" ]]
CASES=$((CASES + 1))

# WO-294@v1: model a stack that originally put its note under Unreleased.
PRE_RELEASE_TEXT=$'# Changelog\n\n## [Unreleased]\n\n- Published change.\n'
BASE="$(commit_fixture "$PRE_RELEASE_TEXT" 'chore: fixture before release')"
accepts stack4-before-release "$PRE_RELEASE_TEXT"$'- misplaced fixture text\n' 'fix: add stack note'
# WO-294@v1: use the published release as the base of the rebased stack.
REBASED_TEXT=$'# Changelog\n\n## [Unreleased]\n\n## [0.12.0] - 2026-11-20\n\n- Published change.\n'
BASE="$(commit_fixture "$REBASED_TEXT" 'chore: release 0.12.0' "$BASE")"
rejects stack4-rebased-addition "$REBASED_TEXT"$'- misplaced fixture text\n' 'fix: add stack note' 8

# WO-294@v1: invalid commit arguments must fail before placement is reported as valid.
if GIT_DIR="$REPO" bash "$GUARD" "$BASE" absent > "$FIXTURE_DIR/output" 2> "$FIXTURE_DIR/error"; then
    printf 'FAIL: invalid commit input was accepted\n' >&2
    exit 1
fi
[[ ! -s "$FIXTURE_DIR/output" ]]
CASES=$((CASES + 1))
printf 'Passed %d changelog placement cases\n' "$CASES"
