#!/usr/bin/env bash
#
# PostToolUse — keep an edited Rust file formatted, and surface clippy for its crate
# in the same turn instead of at `/check` time, three edits later.
#
# Why a hook and not a line in CLAUDE.md: an instruction is advisory and competes for
# attention with every other instruction; a hook runs whatever the model decides. The
# two things it enforces are the two the gate refuses anyway (`cargo fmt --all` and
# zero clippy warnings), so nothing here is a new rule — it just arrives earlier.
#
# Cost, measured warm on this workspace: `cargo fmt -p` is 0.07 s; `cargo clippy -p` is
# ~1 s on most crates, 7-8 s on `hlb-controller`. Set HLB_HOOK_CLIPPY=0 to
# keep the formatting and skip the lint.
#
# Errors are reported with exit 2, which puts them in front of Claude. Warnings go back
# as context on exit 0 — a multi-file change is legitimately warning-dirty in the middle,
# and blocking on every intermediate edit would train the reader to ignore the hook.

set -uo pipefail

input=$(cat)
file=$(jq -r '.tool_input.file_path // empty' <<<"$input")
[[ -n $file && $file == *.rs ]] || exit 0

# The checkout holding the FILE, not the session's cwd: a session in one worktree can
# edit another's file, and a cwd below the root would leave `crates/` unmatched below.
root=$(git -C "$(dirname "$file")" rev-parse --show-toplevel 2>/dev/null) || exit 0
cd "$root" || exit 0

# crates/<name>/... -> <name>. The directory name is the package name here, and a file
# outside crates/ has no package to scope to.
rel=${file#"$root"/}
[[ $rel == crates/*/* ]] || exit 0
crate=${rel#crates/}
crate=${crate%%/*}
[[ -f "crates/$crate/Cargo.toml" ]] || exit 0
[[ -x scripts/worktree-target.sh ]] && scripts/worktree-target.sh "$root" >/dev/null 2>&1

cargo fmt -p "$crate" >/dev/null 2>&1

[[ ${HLB_HOOK_CLIPPY:-1} == 0 ]] && exit 0

report=$(cargo clippy -p "$crate" --all-targets --message-format short 2>&1 |
    grep -E '^[^[:space:]].*: (warning|error)' | head -20)
[[ -n $report ]] || exit 0

if grep -q ': error' <<<"$report"; then
    {
        echo "clippy does not compile $crate:"
        echo "$report"
    } >&2
    exit 2
fi

jq -n --arg r "$report" --arg c "$crate" '{
  hookSpecificOutput: {
    hookEventName: "PostToolUse",
    additionalContext: ("clippy warnings in \($c). This repository'"'"'s gate requires zero, so these have to go before the change is done:\n" + $r)
  }
}'
exit 0
