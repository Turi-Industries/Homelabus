# CLAUDE.md

Guidance for Claude Code (claude.ai/code) when working in this repository.

## Language

**Everything in this project is in English**: code, comments, error messages, CLI
output, test names, documentation, commit messages. Only accented test fixtures remain
from the French original — they *are* the test, so do not "fix" them.

Comments explain *why*, not *what*. A comment restating the line below it is noise; one
recording the trap a line avoids is why this codebase stays maintainable. Keep them
short and anchored to the code they sit on. Never point at `PLAN.md` or any other
external design document: it is not in the published repository, so a reader cannot
follow the pointer.

## The gate

Every change leaves these green. Scope them to the crate you are touching — the
workspace suite is slow enough that running it each time discourages running it at all.

```sh
cargo fmt --all
cargo clippy --all-targets                                      # zero warnings
cargo test -p hlb-resolver                                      # prefer this while iterating
cargo test -p hlb-state -- completed_actions_survive_a_replan   # a single test
cargo test                                                      # the whole workspace
cargo run -q -p hlb-cli -- catalog validate                # ./target/debug/hlb may predate an edit
cd web && bun run check && bun run test && bun run test:browser   # when web/ changed; the last builds
```
`/check` runs all of it and reports what failed.

⚠️ **`hlb` needs state and a vault** — only `cluster init` creates them unless given:

```sh
export HLB_STATE=/tmp/try.db HLB_MASTER_KEY=/tmp/try.key
```

Swarm integration tests are `#[ignore]`d so `cargo test` stays fast and usable without
Docker; `.claude/rules/operations-swarm.md` has the invocation and its one trap. Every `hlb`
verb with a runnable example is in [docs/cli-tour.md](docs/cli-tour.md).

## The repository

Thirty crates, and the web interface in `web/`. Which one owns what, so a search starts in the right place:

| | |
|---|---|
| **Core** | `hlb-types` (the schema), `hlb-catalog`, `hlb-resolver` (capabilities + graph), `hlb-engine` (executor), `hlb-state` (SQLite), `hlb-orchestrator` (Swarm), `hlb-backup-run` (the one backup pass the CLI and the controller both run, and the restores and proofs built on it) |
| **Service clients** | `hlb-mail` (Stalwart), `hlb-identity` (PocketID), `hlb-bitwarden` (Vaultwarden: members, the emergency vault, Bitwarden's client cryptography), `hlb-termix` (Termix: the nodes' hosts, key and accounts), `hlb-objstore` (Garage, and the S3 calls proving a backup destination out of reach), `hlb-ingress` (Caddy), `hlb-registry` |
| **Domain logic** | `hlb-users`, `hlb-metrics`, `hlb-backup`, `hlb-notify`, `hlb-guide`, `hlb-platform`, `hlb-secrets` |
| **The machines** | `hlb-agent`, `hlb-bootstrap`, `hlb-mesh`, `hlb-updater`, `hlb-selfupdate`, `hlb-gitops` |
| **Surfaces** | `hlb-cli`, `hlb-controller` (daemon + HTTP API), `hlb-api` (the API's types), `web/` (SvelteKit: modules, inbox, action panel — CONTRIBUTING says how it is put together) |

`hlb-types` is the **only schema definition**, consumed by Rust and by `schemars` for
YAML autocompletion; no other crate redefines these types. Domain crates depend on
`hlb-types` alone and never touch the network — the network clients sit beside them,
which is what keeps the logic testable without a server.

⚠️ **The interface is SvelteKit, and its shell is derived from `web/src/lib/modules/`**
— a page is declared in its module and written under `routes/(shell)/`, or a test
fails. Its TypeScript is generated from the controller's OpenAPI, never hand-written;
business rules stay in Rust; the document is `web/openapi.json`, refused when stale.
Check `.svelte` code with the Svelte plugin's `svelte-autofixer`.

## The central idea: the capability resolver

This structures everything else. A manifest **never** says "connect to `postgres:5432`".
It declares a **need**:

```yaml
requires:
  - kind: database
    engine: postgres
  - kind: sso
    mode: native
    redirectPaths: ["/user/oauth2/PocketID/callback"]
```

`hlb-resolver` turns needs into concrete actions: create the database and an isolated
role, generate the secret, register an OIDC client whose URIs are **computed from the
domain chosen at install time**. Consequence: the same manifest works whatever the real
topology is.

`Capability` is an exhaustive enum. **Adding a variant breaks compilation everywhere a
`match` must be updated** — the main reason this is written in Rust. Do not defeat that
with a `_ =>` arm; note that a `..` in a pattern does the same damage more quietly.

```
catalog/*/manifest.yaml
   ↓  hlb-catalog     load, validate, check folder name == metadata.name
Manifest (hlb-types)
   ↓  hlb-resolver    capability resolution + dependency graph
Plan { actions: Vec<Action> }
   ↓  hlb-engine      execution: preview by default, idempotent, resumable
hlb-orchestrator      trait Orchestrator → bollard → Docker Swarm
   ↕  hlb-state       frozen manifest + progress journal (SQLite)
```

**Docker Swarm has no `depends_on`.** It starts everything in parallel, and an app
starting before PostgreSQL crash-loops. `hlb-resolver::graph` derives the order from
`requires` and shuts down in reverse. Adding a platform service to the catalog updates
the graph automatically — there is no hand-maintained list, and a capability pointing at
a service absent from the catalog fails `hlb catalog validate`.

## Invariants not to break

Encoded in tests. If one fails, the code is usually wrong, not the test. Invariants that
belong to a single domain live with that domain's traps in `.claude/rules/`.

- **Preview by default.** `Executor` changes nothing without `.apply(true)`. Over HTTP
  the same rule is `?apply=true` — visiting a screen must never execute anything. Tests
  walk the OpenAPI document the router is built from: a route declaring no role, preview
  or public status fails.
- **`Unimplemented` is never `Done`.** An action the executor cannot perform yet is
  recorded as unimplemented and reported as such. Never pretend a database was
  provisioned.
- **Idempotent and resumable.** `record_plan` does not overwrite a `done` action; the
  executor skips finished work and stops at the first failure rather than cascading.
- **A declaration nobody reads is worse than no declaration.** Whatever a manifest
  declares must reach the executor and change what it does, or be REFUSED at preview
  time alongside the other blockers. Silently honouring it as its default is the failure
  mode: the app starts, looks healthy, and loses data.
- **A hand-maintained list drifts.** Thirteen have, here, eleven after the lesson was
  written down; `.claude/rules/rust.md` enumerates them. A test that must know about every
  screen, field, file or message key walks the directory or the struct, never a list
  someone has to remember to update. ⚠️ A list disguises itself well — of the last four,
  all read as deliberate and two carried a comment saying why — and the scan replacing
  one is itself a list of the shapes it matches: the newest found 70 of 75 and passed, so
  **the floor under a scan is not decoration.**
- **`deny_unknown_fields` everywhere.** A manifest typo is refused with its line number.

## Conventions

- **No `unwrap` / `expect` in production** (`warn` lint in the workspace). Allowed in
  tests via `clippy.toml` — there, `expect("message")` *is* the assertion.
- **Typed errors per crate** (`thiserror`), never a bare `String`. The CLI unwinds the
  cause chain.
- **Plans must be reproducible.** The topological sort breaks ties alphabetically; a
  plan that varies between runs makes snapshot tests worthless.
- **Tests named as assertions**: `postgres_comes_before_its_consumers`,
  `unimplemented_is_never_reported_as_done`.

## The traps, and how they reach you

🔴 Every entry in `.claude/rules/` cost real debugging time, and most describe a failure
that is SILENT — the thing looks like it worked. **They load by themselves**: a rule
enters context when you read a file its `paths:` glob covers, so mail work pays for the
mail traps only. Planning before reading any code, **open the matching rule yourself.**

| Rule | Covers | Rule | Covers |
|---|---|---|---|
| `rust.md` | Rust, `sqlx`, tests, source scans, clippy, toolchains | `databases.md` | PostgreSQL, MariaDB, SQLite, dumps, replication |
| `backups.md` | restic, destinations, freshness, RPO, verification | `mail.md` | Stalwart, JMAP, Sieve, aliases, addy.io, PocketID |
| `security.md` | tokens, roles, sessions, CSRF, the vault, forward-auth, the emergency kit | `storage.md` | ZFS, pools, datasets, NFS, storage tiers |
| `operations*.md` | deploying, reconciliation, runbooks; `-swarm`, `-monitoring`, `-updates`, `-ingress` | `interface-*.md` | `-web`, `-api` (the contract), `-screens`, `-portal`, `-themes`, `-tests` |

## Several sessions at once

Several sessions work here at once, **each in its own worktree** — `claude -w <name>`,
from local `HEAD`. 🔴 Never one `target/` for two checkouts: same artifact names, so each
silently builds against the other's crates. A worktree's is reflinked from the main one
(`scripts/worktree-target.sh`, seconds, no space). Merge from the main checkout; never a
bare `git stash`.

## What runs by itself

Enforcement, not advice — each script in `.claude/hooks/` says why it exists.

- **After every edit to a `.rs` file**, `rust-gate.sh` formats its crate and reports
  clippy for it: re-read before editing again. Errors block, warnings come back as
  context. `HLB_HOOK_CLIPPY=0` keeps the formatting and drops the lint.
- **The turn does not end on a tree the gate would reject.** `stop-gate.sh` runs fmt,
  clippy, the suite, `catalog validate` and, if `web/` moved, its check, tests and
  build — once per distinct state of the checkout, nothing on a clean one.
  `HLB_STOP_GATE=0` turns it off.
- **What worktrees do not separate is leased**: the lab, and the browser suite's fixed
  ports, to one session at a time (`lease.sh`). A refusal names the holder.
- **A session learns where it stands** (`session-start.sh`): its checkout, the others,
  the leases, and the handoff `/handoff` left in `.claude/RESUME.md`. Past 250k tokens
  `context-budget.sh` says so: finish the step, `/handoff`, `/clear`.
- **`*.key` can be neither read nor edited**, at any depth — the vault's master key was
  committed once already. `Cargo.lock` is denied too: use `cargo tree` / `cargo info`.

## Where everything else lives

| | |
|---|---|
| [ROADMAP.md](ROADMAP.md) | what is left to do, and what was ruled out |
| [CHANGELOG.md](CHANGELOG.md) | what changed in each release — `git cliff`, from the commits |
| [docs/cli-tour.md](docs/cli-tour.md) | every `hlb` verb, with a runnable example |
| [CONTRIBUTING.md](CONTRIBUTING.md) | the gate, themes, and the interface's tools (Svelte plugin, Playwright MCP) |
| [.claude/skills/](.claude/skills/) | `/check` `/shots` `/handoff`, `/new-app` (no Rust), `/improve` — one step toward the goals `scripts/scorecard.sh` measures; `scripts/improve.sh` loops it |

## Repository hygiene

🔴 **The vault's master key never goes into git** — tracked once (2026-08-16 to 21),
history purged, key rotated. No exception to `*.key` in `.gitignore`. Rotation is `hlb
secrets-rekey`; `security.md` says why the key-file swap is yours. `PLAN.md` stays local.
