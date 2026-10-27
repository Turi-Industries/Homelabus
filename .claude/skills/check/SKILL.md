---
name: check
description: Run the full gate — fmt, clippy, tests, catalog, the interface — and report what failed.
# Forked: the gate prints thousands of lines, and only the verdict and the failures
# belong in the conversation that asked for it.
context: fork
---

Run the workspace's complete verification gate, in this order, and stop reporting
success the moment any step fails:

```sh
cargo fmt --all --check
cargo clippy --all-targets      # must stay at ZERO warnings, not "few"
cargo test --workspace          # swarm integration tests are #[ignore]d on purpose
```

Then the catalog, through cargo — `./target/debug/hlb` may predate the last edit:

```sh
cargo run -q -p hlb-cli -- catalog validate
```

Then the interface, from `web/` (`bun install` first if `node_modules` is missing):

```sh
bun run check          # svelte-check, zero warnings — the browser tests included
bun run test           # vitest
bun run test:browser   # builds the app, then Playwright against real controllers (~35 s)
```

The browser suite starts its own controllers through `cargo run` on ports 8431–8434,
so a controller left running on one of those fails it at start-up — say which.

Report the actual numbers — tests passed, clippy warning count — not "everything is
green". If a step fails, show the failing output rather than summarising it: a
summarised compiler error sends the reader looking in the wrong place.

⚠️ Do not run `cargo test -- --ignored`: those need Docker Swarm, `DOCKER_HOST`, and a
live cluster. They are excluded from this gate deliberately.
