---
name: handoff
description: Write the handoff a fresh session continues from — goal, state, next step, how to verify — into .claude/RESUME.md, before /clear or at the end of a long session.
---

Write `.claude/RESUME.md` in this checkout (gitignored, one per worktree), replacing any
previous one. The SessionStart hook shows it to the next session in this checkout, in
full: that session knows NOTHING else — not this conversation, not what you tried, not
which rules fired. Write for it.

Before writing, make the state worth handing over: the change compiles, and what is
finished is committed. A handoff describing a half-applied edit hands over a broken tree.

Keep it under 60 lines, in this shape:

```markdown
# <the task, one line>

Asked: <the user's request, in their words where they matter — and in what language
they want replies>

## Done
- <commit sha> <what it did> — verified by <the test or command, and its result>

## State
- Branch / worktree: <name>; uncommitted: <files, and why they are not committed yet>
- <what is true now that the code does not make obvious: a lab VM left running, a
  lease held, a migration applied on the lab but not in a test>

## Next
1. <the very next action, concrete enough to start without reading anything else>
2. ...

## Decided, and why
- <a choice the next session must not reopen, with its reason or the number behind it>

## Traps met
- <what cost time here and would again: a command that lies, a test that passes
  vacuously>. Anything durable belongs in `.claude/rules/` as well — the handoff dies
  with the task.

## Verify with
<the exact commands that prove the task done>
```

Then tell the user, in their language, that the handoff is written and that `/clear` (or
a new `claude -w <name>` session in this worktree) continues from it.

Do not copy into it what `git log` or `ROADMAP.md` already hold: point at
them. Do not record secrets, tokens or the vault's key — the file is plain text on disk.
