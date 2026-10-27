#!/usr/bin/env bash
#
# The improvement loop, unattended: N iterations of `/improve`, each a FRESH Claude Code
# session in one worktree, each ending in a commit or a reason it did not make one.
#
# Why a fresh session per iteration rather than `/loop` in one: a session's recall
# degrades as its context grows, and an iteration needs none of the previous one's
# transcript — only its commit and its handoff (`.claude/RESUME.md`). This is the "Ralph"
# loop (one task per run, the tests as back-pressure), bounded: it stops at the first
# iteration that needs a human, finds nothing, or does not commit.
#
# Nothing leaves the machine but the model calls: no push, no merge. The branch waits
# for review — `git log -p main..improve-<date>`, then `git merge` from the main checkout.
# Until it is merged, each run CONTINUES that branch rather than starting another from
# `main`, which would redo yesterday's step; and once HLB_IMPROVE_MAX_PENDING commits (12)
# wait for review, a run does nothing — an unread pile is not progress.
#
# Usage: scripts/improve.sh [iterations=3] [budget-usd-per-iteration=10]
# Run by hand only, by the owner's decision (2026-10-27): no timer starts it.
#
# ⚠️ Each iteration builds and runs the suite — heavy I/O on this machine. Run it when
# nobody needs the desktop.

set -uo pipefail

iterations=${1:-3}
budget=${2:-10}
main=$(git -C "$(dirname "$0")" rev-parse --path-format=absolute --git-common-dir) || exit 1
main=${main%/.git}

# The newest improve branch `main` does not contain yet, if any.
name=
while read -r branch; do
    git -C "$main" merge-base --is-ancestor "$branch" main || {
        name=$branch
        break
    }
done < <(git -C "$main" for-each-ref --sort=-committerdate --format='%(refname:short)' 'refs/heads/improve-*')

if [[ -n $name ]]; then
    pending=$(git -C "$main" rev-list --count "main..$name")
    if ((pending >= ${HLB_IMPROVE_MAX_PENDING:-12})); then
        echo "$(date '+%F %T') $name: $pending commits await review; nothing done."
        exit 0
    fi
else
    name="improve-$(date +%F)"
fi
tree="$main/.claude/worktrees/$name"
logs="$main/.git/improve-logs/$name"

if [[ ! -d $tree ]]; then
    if git -C "$main" show-ref -q "refs/heads/$name"; then
        git -C "$main" worktree add -q "$tree" "$name" || exit 1
    else
        git -C "$main" worktree add -q "$tree" -b "$name" main || exit 1
    fi
    # What `claude -w` gets: its own target/, reflinked; node_modules shared.
    "$main/scripts/worktree-target.sh" "$tree"
    [[ -d $main/web/node_modules ]] && ln -s ../../../../web/node_modules "$tree/web/node_modules"
fi
mkdir -p "$logs"
cd "$tree" || exit 1
start=$(git rev-parse HEAD)

for ((i = 1; i <= iterations; i++)); do
    before=$(git rev-parse HEAD)
    log="$logs/$(date +%H%M%S)-$i.json"
    echo "$(date '+%F %T') iteration $i/$iterations in $tree (log: $log)"

    claude -p "/improve" --output-format json --max-budget-usd "$budget" >"$log"
    result=$(jq -r '.result // empty' "$log" 2>/dev/null)
    verdict=$(grep -oE '^IMPROVE: [a-z-]+' <<<"$result" | head -1)
    echo "  ${verdict:-IMPROVE: (no verdict line)} — cost \$$(jq -r '.total_cost_usd // "?"' "$log")"

    [[ $verdict == "IMPROVE: done" ]] || break
    [[ $(git rev-parse HEAD) != "$before" ]] || {
        echo "  said done but committed nothing: stopping"
        break
    }
done

echo
echo "Branch $name:"
git log --oneline "$start..HEAD" | head -20
echo "Review: git -C '$main' log -p main..$name    Merge: git -C '$main' merge $name"
