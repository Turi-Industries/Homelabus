#!/usr/bin/env bash
#
# SessionStart — tell a session where it stands before it reads anything: which checkout
# it is in, what the other checkouts are doing, who holds the lab, and the handoff the
# previous session left.
#
# Why: several sessions run on this repository at once. A session that does not know it
# shares the main checkout edits beside another one's half-finished change, and the Stop
# gate then judges both. And after `/clear` or a compaction, the handoff is the only
# memory of the task — the path-scoped rules are not re-read until a file matches again.
#
# Everything printed here costs context in every session: keep it to facts a session acts
# on, and never more than a screen.

set -uo pipefail

input=$(cat)
cwd=$(jq -r '.cwd // empty' <<<"$input")
source=$(jq -r '.source // "startup"' <<<"$input")
[[ -n $cwd ]] || cwd=$PWD
cd "$cwd" 2>/dev/null || exit 0
root=$(git rev-parse --show-toplevel 2>/dev/null) || exit 0
cd "$root" || exit 0

common=$(git rev-parse --path-format=absolute --git-common-dir)
gitdir=$(git rev-parse --path-format=absolute --git-dir)
branch=$(git branch --show-current)

dirty() { git -C "$1" status --porcelain 2>/dev/null | wc -l; }

out=()
# A worktree builds in its own `target/`, reflinked from the main checkout's: a shared
# one hands each checkout the other's crates (the script says how).
if [[ $gitdir != "$common" && -x scripts/worktree-target.sh ]]; then
    seeded=$(scripts/worktree-target.sh "$root" 2>&1) && [[ -n $seeded ]] && out+=("$seeded")
fi
# `catalog/apps` is the `homelabus-catalog` repository: a fresh worktree has it empty,
# and the build refuses to carry a catalog with no app.
if [[ -f .gitmodules && ! -e catalog/apps/.git ]]; then
    if git submodule update --init --quiet 2>/dev/null; then
        out+=("\`catalog/apps\` checked out (the \`homelabus-catalog\` submodule).")
    else
        out+=("⚠️ \`catalog/apps\` is empty and \`git submodule update --init\` failed: nothing builds until it is checked out.")
    fi
fi
if [[ $gitdir == "$common" ]]; then
    out+=("This session is in the MAIN checkout, on \`$branch\`.")
else
    out+=("This session is in the worktree \`${root##*/}\`, on branch \`$branch\`. Commit here; the main checkout is another session's.")
fi

# The other checkouts, with what they hold uncommitted: that is where another session is
# probably working right now.
main=${common%/.git}
others=()
while read -r path; do
    [[ $path == "$root" ]] && continue
    b=$(git -C "$path" branch --show-current 2>/dev/null)
    n=$(dirty "$path")
    label=${path#"$main"/}
    [[ $path == "$main" ]] && label="the main checkout"
    others+=("  - $label, on \`${b:-detached}\`, $n uncommitted file(s)")
done < <(git worktree list --porcelain | sed -n 's/^worktree //p')
if ((${#others[@]})); then
    out+=("Other checkouts of this repository:" "${others[@]}")
fi

n=$(dirty .)
if [[ $gitdir == "$common" && $source == startup && $n -gt 0 ]]; then
    out+=("⚠️ $n uncommitted file(s) here that this session did not write — another session may be editing them, and the Stop gate will judge them as yours. For parallel work, start with \`claude -w <name>\`.")
fi

# Leases taken by `lease.sh`: a shared resource another session is driving.
for lease in "$common"/hlb-leases/*; do
    [[ -f $lease ]] || continue
    IFS=$'\t' read -r holder where since <"$lease"
    out+=("The \`${lease##*/}\` lease is held by session ${holder:0:8} in \`${where##*/}\` since $(date -d "@$since" +%H:%M).")
done

# What the nightly `scripts/improve.sh` left for review: unread, it blocks the next run.
while read -r branch; do
    git merge-base --is-ancestor "$branch" main 2>/dev/null && continue
    out+=("The improvement loop's branch \`$branch\` has $(git rev-list --count "main..$branch") commit(s) awaiting review: \`git log -p main..$branch\`.")
done < <(git for-each-ref --format='%(refname:short)' 'refs/heads/improve-*')

# The handoff `/handoff` writes. Shown in full: it is the task, and short by design.
resume=.claude/RESUME.md
if [[ -f $resume ]]; then
    age=$(($(date +%s) - $(stat -c %Y "$resume")))
    out+=("" "Handoff left in \`$resume\`, $((age / 3600)) h $((age % 3600 / 60)) min ago. Continue from it unless the user says otherwise; delete it once the task it describes is committed:" "" "$(head -c 6000 "$resume")")
fi

printf '%s\n' "${out[@]}"
exit 0
