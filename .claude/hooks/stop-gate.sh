#!/usr/bin/env bash
#
# Stop — refuse to end the turn on a tree the gate would reject.
#
# `rust-gate.sh` runs per edit and sees one crate: it catches a clippy warning where it
# was written, and nothing else. It cannot see a change in `hlb-types` breaking `hlb-cli`,
# it never runs a test, and it never validates the catalog. That gap is this hook.
#
# Why blocking rather than advisory: while a human reads every turn, an advisory message
# is enough — they see red and say so. The moment a run is unattended, the only thing
# standing between a broken tree and "finished" is something that refuses to finish. That
# is the whole reason the Stop event can block.
#
# ## The two things that make it bearable
#
# It skips a clean tree entirely. `git status` deciding means a turn that asked a
# question, read code, or edited documentation other than `CLAUDE.md` and the rules
# costs nothing at all.
#
# It skips a tree it has already passed. The fingerprint below is the content of every
# Rust and catalog source; the gate runs once per distinct state, not once per turn. Two
# turns of thinking about the same green tree pay for the first only.
#
# Measured warm on this workspace: ~14 s for the suite, ~0.2 s for clippy when the
# PostToolUse hook has already compiled the crate, and the catalog is instant. The
# interface's check, tests and build add ~7 s, and only when `web/` changed.
#
# ## Loops
#
# 🔴 `stop_hook_active` is not optional. It is true when this hook is already blocking,
# and blocking again from there is an infinite turn — Claude is told to keep working, the
# gate still fails, the hook blocks again. One block, then the failure is Claude's to fix
# with the output in front of it.
#
# ## Parallel sessions
#
# It judges the checkout it runs in, whoever changed it. Two sessions in the main
# checkout each answer for the other's half-finished edit — which is why parallel work
# goes in worktrees (`claude -w <name>`), each with its own stamp below.
#
# HLB_STOP_GATE=0 turns it off.

set -uo pipefail

input=$(cat)
[[ $(jq -r '.stop_hook_active // false' <<<"$input") == true ]] && exit 0
[[ ${HLB_STOP_GATE:-1} == 0 ]] && exit 0

cwd=$(jq -r '.cwd // empty' <<<"$input")
root=$(git -C "${cwd:-.}" rev-parse --show-toplevel 2>/dev/null) || exit 0
cd "$root" || exit 0
[[ -d crates && -d catalog ]] || exit 0
# A worktree entered mid-session had no SessionStart to give it its own `target/`.
[[ -x scripts/worktree-target.sh ]] && scripts/worktree-target.sh "$root" >/dev/null 2>&1

# A clean tree is a committed tree, and the commit was gated.
changed() {
    ! git diff --quiet HEAD -- "$@" 2>/dev/null ||
        [[ -n $(git ls-files --others --exclude-standard -- "$@") ]]
}
# `CLAUDE.md` and the rules are in it because `hlb-types/tests/instructions.rs` reads
# them: a documentation turn can fail the suite, and did — `CLAUDE.md` past its 200 lines.
watched=(crates catalog web CLAUDE.md .claude/rules)
changed "${watched[@]}" || exit 0

fingerprint=$(
    {
        git ls-files -- "${watched[@]}"
        git ls-files --others --exclude-standard -- "${watched[@]}"
    } | grep -E '\.(rs|ya?ml|toml|sql|ts|svelte|css|html|json|lock|md)$' | sort |
        xargs cat 2>/dev/null | sha256sum
)
# Per checkout: in a worktree `.git` is a file, and a stamp under it could never be
# written — the gate would rerun on every turn. `--git-path` names the worktree's own.
stamp=$(git rev-parse --git-path hlb-stop-gate)
[[ -f $stamp && $(cat "$stamp" 2>/dev/null) == "$fingerprint" ]] && exit 0

block() {
    jq -n --arg r "$1" '{
      hookSpecificOutput: {
        hookEventName: "Stop",
        decision: "block",
        reason: $r
      }
    }'
    exit 0
}

if ! out=$(cargo fmt --all --check 2>&1); then
    block "The gate refuses this tree: cargo fmt --all would rewrite it.

$(head -40 <<<"$out")

Run \`cargo fmt --all\`."
fi

if ! out=$(cargo clippy --all-targets --message-format short 2>&1); then
    block "The gate refuses this tree: clippy does not compile it.

$(grep -E ': (warning|error)' <<<"$out" | head -25)"
fi
if warnings=$(grep -E ': warning' <<<"$out" | head -25) && [[ -n $warnings ]]; then
    block "The gate refuses this tree: it requires zero clippy warnings.

$warnings"
fi

if ! out=$(cargo test 2>&1); then
    block "The gate refuses this tree: tests fail.

$(grep -E '^(test .* FAILED|---- |assertion|  left:|  right:|error)' <<<"$out" | head -30)"
fi

# Through cargo, not `./target/debug/hlb`: that binary is from the last build, which may
# predate this checkout's latest edit. `cargo run` relinks it, compiled by the tests.
if ! out=$(cargo run -q -p hlb-cli -- catalog validate 2>&1); then
    block "The gate refuses this tree: the catalog is not valid.

$(head -20 <<<"$out")"
fi

# The interface, only when it moved: a Rust change that alters the API regenerates
# `web/openapi.json`, which is under `web/` and so brings this along with it.
if changed web; then
    command -v bun >/dev/null ||
        block "The gate refuses this tree: web/ changed and bun is not installed to check it."
    [[ -d web/node_modules ]] || (cd web && bun install --frozen-lockfile >/dev/null 2>&1)
    for step in check test build; do
        if ! out=$(cd web && bun run "$step" 2>&1); then
            block "The gate refuses this tree: \`bun run $step\` fails in web/.

$(grep -vE '^\$ |openapi-typescript|paraglide-js\]|^\s*$' <<<"$out" | tail -30)"
        fi
    done
fi

printf '%s' "$fingerprint" >"$stamp"
exit 0
