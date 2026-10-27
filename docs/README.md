# Documentation

Where each kind of writing lives, and why it lives there. The split is by **when it has
to be read**, not by subject — that is what keeps a session from carrying the whole
corpus around.

| | Loaded | Holds |
|---|---|---|
| [`../CLAUDE.md`](../CLAUDE.md) | every session, in full | what you need before you know what you are working on |
| [`../.claude/rules/`](../.claude/rules/) | when you read a file it covers | the domain traps, one file per domain |
| [`../crates/hlb-cli/CLAUDE.md`](../crates/hlb-cli/CLAUDE.md) | when you read that crate | which domain rule a verb belongs to |
| [`../.claude/hooks/`](../.claude/hooks/) | after every edit to a `.rs` file, and at the end of a turn | `fmt` and clippy on the crate; the whole gate before a turn ends |
| this directory | when you open it | reference, history, and the record |

## The domain rules

🔴 Each entry cost real debugging time. Most describe a failure that is **silent** — the
thing looks like it worked — and several contradict what the code appears to do.

They live in `.claude/rules/` rather than here because each one carries a `paths:` glob
in its frontmatter: the file enters Claude Code's context by itself when a file it
covers is read, and costs nothing the rest of the time. They are ordinary markdown and
committed like the rest of the repository, so read them directly whenever you want.

| Rule | Domain |
|---|---|
| [rust.md](../.claude/rules/rust.md) | Rust, `sqlx`, tests, source-scanning tests, clippy |
| [databases.md](../.claude/rules/databases.md) | PostgreSQL, MariaDB, SQLite, dumps, replication |
| [backups.md](../.claude/rules/backups.md) | restic, destinations, freshness, verification |
| [mail.md](../.claude/rules/mail.md) | Stalwart, JMAP, Sieve, aliases, addy.io |
| [security.md](../.claude/rules/security.md) | tokens, roles, sessions, CSRF, the vault, forward-auth |
| [storage.md](../.claude/rules/storage.md) | ZFS, pools, datasets, NFS, storage tiers |
| [operations.md](../.claude/rules/operations.md) | the executor and journal, deploying, reconciliation, guides, runbooks |
| [operations-swarm.md](../.claude/rules/operations-swarm.md) | Swarm tasks, placement, the overlay, bollard, probes, the integration tests |
| [operations-monitoring.md](../.claude/rules/operations-monitoring.md) | the watchdog, the agent protocol, Prometheus series, alerts and mutes, notifications |
| [operations-updates.md](../.claude/rules/operations-updates.md) | registries, digests, rehearsing a major, `hlb upgrade`, pruning |
| [operations-ingress.md](../.claude/rules/operations-ingress.md) | Caddy, certificates, routes, DNS providers, exposure |
| [interface-web.md](../.claude/rules/interface-web.md) | all of `web/`: generated code, the client, the derived shell, the action panel |
| [interface-api.md](../.claude/rules/interface-api.md) | the API contract the interface is generated from |
| [interface-screens.md](../.claude/rules/interface-screens.md) | screens and layout: Tailwind roles, tables, modals, the home, forms |
| [interface-portal.md](../.claude/rules/interface-portal.md) | screens for people: invitations, sign-up, the status page, the kiosk |
| [interface-themes.md](../.claude/rules/interface-themes.md) | palettes, colour-blind limits, the theme a person picks |
| [interface-tests.md](../.claude/rules/interface-tests.md) | browser tests against real controllers, the contact sheet |

Which files make a rule fire is its `paths:` frontmatter and nothing else. This table
had a column copying it, and the copy had drifted — `security.md` has fifteen globs, the
column named five crates — so it went (2026-10-27).

⚠️ Claude Code loads at most **40,000 characters** of a rule in a 200K-token session, and
cuts the rest without a word; `instructions.rs` refuses a rule past it. `operations.md`
and `interface.md` reached 36,000 and were split by `paths:` on 2026-10-27, every entry
kept — checked by its bold lead against the originals; the next to watch is `security.md`.

A domain rule also holds the invariants that belong to that domain alone. The ones that
hold everywhere stayed in `CLAUDE.md`.

## What is enforced rather than written down

An instruction is advice and competes with every other instruction; a hook runs
whatever the model decides. `.claude/settings.json` carries, each script saying why:

| Hook | Event | Does |
|---|---|---|
| `rust-gate.sh` | after an edit | formats the edited crate and reports its clippy — the gate's two cheapest checks, one edit after the mistake instead of ten |
| `stop-gate.sh` | end of turn | refuses to end on a checkout the gate would reject; once per distinct state, per worktree |
| `session-start.sh` | start, `/clear`, compaction | where the session stands: its checkout, the others, the leases, the handoff |
| `lease.sh` | before a command, end of session | the lab and the browser suite's ports, to one session at a time |
| `context-budget.sh` | after a tool | past 250k tokens of context, says so once per 100k |

And `permissions.deny` on `*.key` at any depth, on `Cargo.lock` and on `target/`: the
vault's master key was committed once, and a boundary is not a reminder.

`crates/hlb-types/tests/instructions.rs` fails if a hook points at a script that is
missing or not executable — a hook that does not run leaves no trace.

## Several sessions, and long ones

Sessions run in parallel, one git worktree each (`claude -w <name>`). The settings make
a worktree branch from the local `HEAD` — `main` is often ahead of `origin` — and share
`web/node_modules` by symlink. 🔴 Not `target/`: cargo names a workspace crate's
artifacts by its path relative to the workspace, so two checkouts write the same files,
and freshness by mtime then hands each the other's crates without a word — on
2026-10-27 a worktree compiled against the main checkout's `hlb-api`.
`scripts/worktree-target.sh` gives each worktree its own, reflinked from the main
checkout's: three seconds and no space on btrfs, third-party crates reused, this
checkout's own crates rebuilt once. `instructions.rs` refuses `target` in
`worktree.symlinkDirectories`. What a worktree cannot separate — the lab's Swarm, ports
8431-8435 — is leased.

A session is not kept alive past its task. Measured on 2026-10-27, this repository's
long sessions ran at a median context of 200-340k tokens and peaked at 695k; reliability
degrades with length long before the window fills (Chroma, *Context Rot*, 2025), and a
compaction drops the path-scoped rules. So: `/handoff` writes `.claude/RESUME.md`, which
the next session in that checkout is shown in full, and `/clear` starts it.

## Skills, and the loop

| Skill | For |
|---|---|
| `/check` | the whole gate, in a forked context so its output stays out of the conversation |
| `/shots` | every screen, every theme, both languages, on one page |
| `/handoff` | the state a fresh session continues from |
| `/new-app` | an app as a manifest — and a schema gap recorded, never an app special-cased in Rust |
| `/improve` | one step toward the project's goals, test-first, committed on its worktree's branch |

`scripts/scorecard.sh` prints the project's goals as numbers — deploy anywhere, never
lose data, never have it stolen, an app without Rust, always available, always up to
date, simple — and says UNMEASURED where the
repository cannot answer. `scripts/improve.sh N` runs `/improve` N times, one fresh
session each, in one worktree, and stops at the first iteration that needs a human or
commits nothing. It never pushes or merges: the branch waits for review, and the next
run continues it rather than redoing its step from `main`. Twelve commits unreviewed and
a run does nothing. It is started by hand only — a nightly timer was set up and removed
the same day, by decision. `SessionStart` names the branch waiting for review.

## Reference and record

| File | What it is |
|---|---|
| [cli-tour.md](cli-tour.md) | every `hlb` verb, with a runnable example |
| [../ROADMAP.md](../ROADMAP.md) | what is left, and what was ruled out |

There is no `design/` directory: the interface's decisions are rules, in
`.claude/rules/interface-*.md`. A
documentation file describing something that does not exist yet is worse than no file.
