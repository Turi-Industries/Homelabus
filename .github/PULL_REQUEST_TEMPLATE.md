<!-- Thank you. A vulnerability goes through SECURITY.md, never a pull request. -->

## What and why

<!-- What changes for someone running Homelabus, and the reason. Link the issue or
discussion if there is one. -->

## How it was checked

<!-- The command you ran and what it showed. A change to what an app or a backup does is
best shown on a real cluster; say if it was not. -->

- [ ] The gate is green: `cargo fmt --all`, `cargo clippy --all-targets` (zero
      warnings), `cargo test`, `cargo run -q -p hlb-cli -- catalog validate`
- [ ] If `web/` changed: `bun run check && bun run test && bun run test:browser`
- [ ] A new rule is held by a test, shown failing without the change
- [ ] Not in [GOVERNANCE.md](../GOVERNANCE.md)'s list of what will not be merged

By opening this pull request, I agree that my contribution is licensed under the
AGPL-3.0-or-later, like the rest of the project.
