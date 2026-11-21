#!/usr/bin/env bash
# Ported from pastewatch scripts/changelog-placement-guard.sh at 7d39c370c050 (bulwark/WO-294).
# shellcheck shell=bash
# WO-294@v1: failures while reading committed changelogs must fail the placement check.
set -euo pipefail

# WO-294@v1: require the pull request's base tip and actual head as inputs.
if [[ $# -ne 2 ]]; then
    printf 'Usage: %s BASE_COMMIT HEAD_COMMIT\n' "$0" >&2
    exit 64
fi
# WO-294@v1: include published headings at the current base tip after a branch forks.
BASE_TIP="$(git rev-parse --verify --end-of-options "${1}^{commit}")"
# WO-294@v1: inspect the actual pull-request head.
HEAD="$(git rev-parse --verify --end-of-options "${2}^{commit}")"
# WO-294@v1: attribute only changes since the fork to the pull request.
BASE="$(git merge-base "$BASE_TIP" "$HEAD")"

# WO-294@v1: keep the exact published-note correction subject at the pull-request head.
HEAD_SUBJECT="$(git show -s --format=%s "$HEAD")"
# WO-294@v1: ordinary pull requests must observe the placement rule.
CORRECTION=0
# WO-294@v1: authorize corrections only with the exact correction subject.
if [[ "$HEAD_SUBJECT" == 'chore: fix changelog' ]]; then CORRECTION=1; fi

# WO-294@v1: release exceptions can originate in any commit since the fork.
SUBJECTS="$(git log --format=%s "$BASE..$HEAD")"
# WO-294@v1: match the repository's release subject and the two inherited forms.
RELEASE_SUBJECT='^chore: (release v?|bump version to )([0-9]+\.[0-9]+\.[0-9]+)$'
# WO-294@v1: retain every version explicitly named by a release commit in the range.
RELEASE_VERSIONS=""
# WO-294@v1: check the entire range so a stacked fix can follow the release commit.
while IFS= read -r SUBJECT; do
    # WO-294@v1: add just the version named in an exact release subject.
    if [[ "$SUBJECT" =~ $RELEASE_SUBJECT ]]; then
        RELEASE_VERSIONS+="${BASH_REMATCH[2]} "
    fi
done <<< "$SUBJECTS"

# WO-294@v1: keep temporary blob and diff copies outside the checkout.
FIXTURE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/bulwark-changelog-placement.XXXXXX")"
trap 'rm -rf "$FIXTURE_DIR"' EXIT
git show "$BASE:CHANGELOG.md" > "$FIXTURE_DIR/base"
# WO-294@v1: use both base revisions to identify published sections.
git show "$BASE_TIP:CHANGELOG.md" > "$FIXTURE_DIR/tip"
git show "$HEAD:CHANGELOG.md" > "$FIXTURE_DIR/head"
git diff --no-color --no-ext-diff --no-textconv --unified=0 "$BASE" "$HEAD" -- CHANGELOG.md > "$FIXTURE_DIR/diff"

# WO-294@v1: check additions and removals against the released sections.
awk -v releases="$RELEASE_VERSIONS" -v correction="$CORRECTION" '
    # WO-294@v1: give each named release its own exception.
    BEGIN {
        split(releases, versions)
        for (i in versions) exempt[versions[i]] = 1
    }
    # WO-294@v1: identify sections with a literal version heading.
    function version(line, result) {
        sub(/\r$/, "", line)
        if (line !~ /^##[[:space:]]+\[[0-9]+\.[0-9]+\.[0-9]+\]([[:space:]]|$)/) return ""
        result = line
        sub(/^##[[:space:]]+\[/, "", result)
        sub(/\].*$/, "", result)
        return result
    }
    # WO-294@v1: retain the original section for each removed line.
    FILENAME == ARGV[1] {
        value = version($0)
        if (value != "") published[value] = 1
        if ($0 ~ /^##[[:space:]]/) old_section = value
        old_sections[FNR] = old_section
        next
    }
    # WO-294@v1: protect versions published on the base branch after the fork.
    FILENAME == ARGV[2] {
        value = version($0)
        if (value != "") published[value] = 1
        next
    }
    # WO-294@v1: look up additions in the head changelog.
    FILENAME == ARGV[3] {
        if ($0 ~ /^##[[:space:]]/) section = version($0)
        sections[FNR] = section
        next
    }
    # WO-294@v1: initialize both line numbers from each diff hunk header.
    /^@@ / {
        split($0, fields, " ")
        range = fields[3]
        sub(/^\+/, "", range)
        split(range, offsets, ",")
        line = offsets[1] + 0
        old_range = fields[2]
        sub(/^-/, "", old_range)
        split(old_range, old_offsets, ",")
        old_line = old_offsets[1] + 0
        in_hunk = 1
        next
    }
    # WO-294@v1: skip diff metadata before the first hunk.
    !in_hunk { next }
    # WO-294@v1: identify added lines by their position in the head changelog.
    /^\+/ {
        section = sections[line]
        # WO-294@v1: require a named release or exact correction for additions to published notes.
        if (section in published && !(section in exempt) && !correction) {
            printf "::error file=CHANGELOG.md,line=%d::Added line is in previously released section [%s]; use [Unreleased].\n", line, section > "/dev/stderr"
            rejected = 1
        }
        line++
        next
    }
    # WO-294@v1: identify removed lines by their position at the fork.
    /^-/ {
        section = old_sections[old_line]
        # WO-294@v1: protect published notes even when a hunk only removes lines.
        if (section in published && !(section in exempt) && !correction) {
            printf "::error file=CHANGELOG.md,line=%d::Removed line is in previously released section [%s]; use [Unreleased].\n", old_line, section > "/dev/stderr"
            rejected = 1
        }
        old_line++
        next
    }
    # WO-294@v1: context lines consume positions in both revisions.
    /^ / { line++; old_line++ }
    # WO-294@v1: report success only after all changed lines pass.
    END {
        if (rejected) exit 1
        print "Changelog placement check passed"
    }
' "$FIXTURE_DIR/base" "$FIXTURE_DIR/tip" "$FIXTURE_DIR/head" "$FIXTURE_DIR/diff"
