# Contributing

## Getting a working checkout

```sh
cargo build
cargo test                      # unit tests, no external dependency
cargo clippy --all-targets      # must stay at zero warnings
cargo fmt --all                 # enforced in CI
```

The unit suite needs nothing but a Rust toolchain. Integration tests are `#[ignore]`d
so that `cargo test` stays fast and usable without Docker — see the README for how to
run each family.

## Language

**English**, everywhere: code, comments, error messages, CLI output, tests,
documentation, commit messages.

Comments explain *why*, not *what*. A comment that restates the line below it is
noise; one that records the trap a line avoids is the reason this codebase is
maintainable. Keep them short and anchored to the code they sit on.

## Invariants

These are encoded in tests. If a test fails, the code is usually wrong, not the test.

- **Preview by default.** `Executor` changes nothing without `.apply(true)`, and the
  HTTP transposition is `?apply=true`. Visiting a screen must never execute anything.
- **`Unimplemented` is never `Done`.** An action the executor cannot perform yet is
  recorded as unimplemented and reported as such. Never pretend a database was
  provisioned.
- **Idempotent and resumable.** `record_plan` does not overwrite a `done` action; the
  executor skips finished work and stops at the first failure instead of cascading.
- **Reconciliation never deletes an orphan, never resurrects a failed install, and
  never forces a convergence in flight.** A system that over-corrects is more
  dangerous than one that corrects nothing.
- **Blocking guides stop before any modification.** No point deploying an app whose
  DNS does not exist.
- **The update policy is not negotiable.** `start-first` + `failure_action: rollback`
  + `monitor` are hard-coded. An app that cannot cope belongs on `channel: pin`.
- **Secure by default.** `read_only_rootfs`, `cap_drop: [ALL]`, `no_new_privileges`,
  no published ports, `private` exposure.
- **`deny_unknown_fields` everywhere.** A typo in a manifest is rejected with its line
  number, never silently ignored.
- **A secret never enters a plan.** Plans are displayed, stored in SQLite and exported
  to the Git mirror. Secret tokens are substituted in the executor, at deploy time.
- **Stale data must never look fresh.** `Resource<T>` carries its own freshness and the
  type forces you to look at it.

## Style

- **No `unwrap` / `expect` in production code** — both are `warn` lints in the
  workspace. They are allowed in tests via `clippy.toml`, where `expect("message")`
  *is* the assertion.
- **Typed errors per crate** (`thiserror`), never a bare `String`.
- **`Capability` is an exhaustive enum.** Adding a variant must break compilation
  everywhere a `match` needs updating — that is the main reason this is written in
  Rust. Never paper over it with a `_ =>` arm, and beware `..` in a pattern: it has
  exactly the same effect and the compiler cannot warn you.
- **Plans must be reproducible.** The topological sort breaks ties alphabetically; a
  plan that varies between runs makes snapshot tests worthless.
- **Tests are named as assertions**: `postgres_comes_before_its_consumers`,
  `unimplemented_is_never_reported_as_done`.

## Pull requests

Keep a pull request to one subject. A commit that does not compile breaks `git bisect`,
which is the tool you will want the day something regresses.

Explain the *reasoning* in the commit message, not the diff — the diff is already
there. If a change reverses an earlier decision, say which one and why.

CI runs format, clippy, the unit suite, a minimum-supported-Rust-version check and a
web UI build. All five must pass.
