---
name: improve
description: One iteration of the improvement loop — read the scorecard, pick the single most valuable step toward the project's goals, do it test-first in this worktree, prove it, record it, commit. Run by hand or by scripts/improve.sh, one fresh session per iteration.
disable-model-invocation: true
---

The goals, in the owner's words: deploy Homelabus on any machine as easily and as fast
as possible; never lose data; never have it stolen, trusting no provider; add an app to
the catalog without touching Rust; the vital apps available while the house is down;
always up to date without breaking; simple and beautiful for whoever runs it, households
first. `ROADMAP.md`, plan G, turns them into eight ordered phases; `scripts/scorecard.sh`
turns them into numbers.

One iteration is ONE change, finished: proven, recorded, committed. Not three started.

## 0. Where you are

Run `git rev-parse --git-dir --git-common-dir`. If the two are the same you are in the
main checkout, where another session may be working: stop, and say to start with
`claude -w improve-<date>` or `scripts/improve.sh`. Read `.claude/RESUME.md` if the
SessionStart hook showed one: a previous iteration may have left its next step.

## 1. Measure

```sh
scripts/scorecard.sh
```

Keep its output: the report quotes the row you moved, before and after.

## 2. Choose — in this order, first match wins

1. **The gate is red** on this branch: fix that, nothing else.
2. **A handoff names a next step** that is still right: take it.
3. **A goal has no number** (`UNMEASURED`) and its probe can be built without hardware,
   a domain or a decision: build the probe. An unmeasured goal cannot be improved on
   purpose.
4. **The roadmap's next step in the earliest unfinished phase** of plan G — the phases
   are ordered by risk; its schema gaps are ranked by how many apps they unblock.

Never choose: anything needing the owner's decision (a security trade-off, a cost, data
deleted, a public release, a push), real hardware or a real domain, the lab while
`lease.sh` gives it to another session, or the main checkout. Those go in the report
under **Needs you**, with what you would do and why — and the iteration ends there if
nothing else qualifies. Saying "nothing safe to do" is a valid result; inventing work is
not.

Size it so a reviewer reads the diff in ten minutes. Bigger: do its first slice, and
write the rest as the handoff's next steps.

## 3. Do it the way this repository does

- **The failing test first**, shown failing, then the change. A rule that matters is a
  test that walks the directory, never a comment or a hand list (`CLAUDE.md`).
- Read the domain rule for what you touch before you touch it.
- 🔴 **Never move a number by moving the measure.** Do not edit `scripts/scorecard.sh`,
  loosen an assertion, `#[ignore]` a test, widen an allow-list or split a commit so a row
  reads better. Models handed a failing check edit the check (ImpossibleBench, 2025);
  this repository's own history has three tests that passed while guarding nothing. If a
  measure is wrong, say so in the report and fix it in a separate iteration whose whole
  subject is the measure.
- `Unimplemented` is never `Done`; preview by default; idempotent and resumable — the
  invariants in `CLAUDE.md` bind an unattended run more, not less.

## 4. Prove and record

- The gate green (the Stop hook will refuse otherwise), and the specific test named.
- `scripts/scorecard.sh` again; quote the row.
- In the commit message: what changed, the number before and after, what was NOT
  proven. Update `ROADMAP.md` where it stated the old state.
- Commit on this worktree's branch, a message in the repository's style. Never push,
  never merge into `main`: the owner reviews the branch.

## 5. Report

End with exactly one line the loop script reads, then the details for the owner, in
French:

```
IMPROVE: done | needs-human | nothing — <one sentence>
```

- **Done**: the commit, the row before → after, the test that proves it.
- **Needs you**: each decision, with your recommendation.
- **Next**: what the next iteration should take — also written to `.claude/RESUME.md`
  through `/handoff` when it is a continuation.
