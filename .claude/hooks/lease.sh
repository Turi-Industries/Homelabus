#!/usr/bin/env bash
#
# PreToolUse (Bash) and SessionEnd — one session at a time on what every checkout shares.
#
# Worktrees separate the files; they do not separate the machine. Two sessions driving the
# lab's Swarm at once deploy over each other's services and each reads the other's state
# as its own result. Two browser suites start their controllers on the same fixed ports
# (8431-8435) and the second fails at start-up, or worse, tests against the first one's
# controller. Neither failure names the other session.
#
# A lease is a file in the repository's common git directory, so every worktree sees it:
# the session id, its checkout, and when it last used the resource. Another session's
# fresh lease refuses the command with who holds it; a lease unused for HLB_LEASE_TTL
# seconds (30 min) is stale and taken over, since a killed session never releases.
# SessionEnd releases this session's leases. HLB_LEASES=0 turns it off.
#
# The patterns match the commands that drive the resource, not every mention of it: a
# `grep hlb-lab` takes nothing.

set -uo pipefail

input=$(cat)
[[ ${HLB_LEASES:-1} == 0 ]] && exit 0

session=$(jq -r '.session_id // empty' <<<"$input")
cwd=$(jq -r '.cwd // empty' <<<"$input")
event=$(jq -r '.hook_event_name // empty' <<<"$input")
[[ -n $session && -n $cwd ]] || exit 0
common=$(git -C "$cwd" rev-parse --path-format=absolute --git-common-dir 2>/dev/null) || exit 0
dir="$common/hlb-leases"

if [[ $event == SessionEnd ]]; then
    for lease in "$dir"/*; do
        [[ -f $lease ]] && [[ $(cut -f1 "$lease") == "$session" ]] && rm -f "$lease"
    done
    exit 0
fi

command=$(jq -r '.tool_input.command // empty' <<<"$input")
resource=
if grep -qE 'docker (exec|cp)[^|;&]* hlb-lab|/lab/vm\.sh|(^|[ /])lab\.sh' <<<"$command"; then
    resource=lab
elif grep -qE 'bun run (test:browser|shots)|playwright test' <<<"$command"; then
    resource=browser
fi
[[ -n $resource ]] || exit 0

mkdir -p "$dir"
lease="$dir/$resource"
now=$(date +%s)
ttl=${HLB_LEASE_TTL:-1800}

exec 9>"$dir/.lock"
flock -w 5 9 || exit 0

if [[ -f $lease ]]; then
    IFS=$'\t' read -r holder where since <"$lease"
    if [[ $holder != "$session" ]] && ((now - since < ttl)); then
        reason="The $resource is leased by another Claude session (${holder:0:8}, in ${where##*/}), last used $(((now - since) / 60)) min ago. Two sessions on it at once corrupt each other's results without saying so. Wait for it, work on something else, or ask the user to release it: rm '$lease'."
        jq -n --arg r "$reason" '{
          hookSpecificOutput: {
            hookEventName: "PreToolUse",
            permissionDecision: "deny",
            permissionDecisionReason: $r
          }
        }'
        exit 0
    fi
fi

printf '%s\t%s\t%s\n' "$session" "$cwd" "$now" >"$lease"
exit 0
