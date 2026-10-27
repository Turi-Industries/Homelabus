#!/usr/bin/env bash
#
# PostToolUse — say when a session has grown long enough to be worth ending.
#
# Measured on 2026-10-27 over this repository's last eleven long sessions: a median
# context of 200-340k tokens, peaks of 380-695k, one compaction in total. Recall and
# instruction-following degrade as the context grows, well before any limit (Chroma's
# "context rot", 2025; IFScale, 2025), and nothing in a session says so: a session at
# 500k feels the same from inside as one at 80k. Compaction is no rescue — it drops the
# path-scoped rules until a file matches them again.
#
# So the number is put in front of the model once per HLB_CONTEXT_STEP tokens past
# HLB_CONTEXT_NUDGE (250k, then every 100k), with what to do about it: finish the step,
# write the handoff, `/clear`. Never mid-change — a handoff written halfway through an
# edit records a state that does not compile. HLB_CONTEXT_NUDGE=0 turns it off.
#
# The count is the last main-thread assistant message's usage — input plus cache, which
# is the whole context the model just read. `tac` reads from the end, so a 16 MB
# transcript costs what its last few lines do.

set -uo pipefail

input=$(cat)
nudge=${HLB_CONTEXT_NUDGE:-250000}
step=${HLB_CONTEXT_STEP:-100000}
((nudge > 0)) || exit 0

transcript=$(jq -r '.transcript_path // empty' <<<"$input")
session=$(jq -r '.session_id // empty' <<<"$input")
cwd=$(jq -r '.cwd // empty' <<<"$input")
[[ -f $transcript && -n $session ]] || exit 0

tokens=$(tac "$transcript" | grep -m1 '"type":"assistant"' | jq -r '
  .message.usage // {} |
  (.input_tokens // 0) + (.cache_read_input_tokens // 0) + (.cache_creation_input_tokens // 0)
' 2>/dev/null)
[[ $tokens =~ ^[0-9]+$ ]] && ((tokens >= nudge)) || exit 0

bucket=$(((tokens - nudge) / step))
common=$(git -C "${cwd:-.}" rev-parse --path-format=absolute --git-common-dir 2>/dev/null) || exit 0
mkdir -p "$common/hlb-context"
seen="$common/hlb-context/$session"
[[ -f $seen && $(cat "$seen") -ge $bucket ]] && exit 0
echo "$bucket" >"$seen"
# Old sessions' markers are never read again.
find "$common/hlb-context" -type f -mtime +7 -delete 2>/dev/null

k=$((tokens / 1000))
jq -n --arg k "$k" '{
  systemMessage: ("Context at \($k)k tokens — consider /handoff, then /clear."),
  hookSpecificOutput: {
    hookEventName: "PostToolUse",
    additionalContext: ("This session'"'"'s context is at \($k)k tokens. Long contexts measurably degrade recall and instruction-following, and this one will not get shorter. At the next natural boundary — the current change compiling and committed, never halfway through an edit — run /handoff and suggest the user /clear. If the task is nearly done, finish it first.")
  }
}'
exit 0
