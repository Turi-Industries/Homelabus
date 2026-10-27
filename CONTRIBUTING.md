# Contributing

Everyone taking part follows the [code of conduct](CODE_OF_CONDUCT.md). A vulnerability
goes through [SECURITY.md](SECURITY.md), never a public issue. What will not be merged,
however well written, is in [GOVERNANCE.md](GOVERNANCE.md) — read it before a large
change.

A contribution is licensed under the AGPL-3.0-or-later, like the rest of the project —
no CLA, no sign-off. `REUSE.toml` says who owns each file: something copied in from
elsewhere (a logo, a key) gets its own annotation there, or `reuse lint` refuses it in CI.
Questions go to [SUPPORT.md](SUPPORT.md)'s places, and each release's changes to
[CHANGELOG.md](CHANGELOG.md), written by `git cliff` from the commits.

## Getting a working checkout

```sh
cargo build
cargo test                      # unit tests, no external dependency
cargo clippy --all-targets      # must stay at zero warnings
cargo fmt --all                 # enforced in CI
```

The unit suite needs nothing but a Rust toolchain. Integration tests are `#[ignore]`d
so that `cargo test` stays fast and usable without Docker; each family is run on its
own:

```sh
# Swarm
docker swarm init
cargo test -p hlb-orchestrator -- --ignored --test-threads=1 --nocapture

# PostgreSQL isolation — proves a compromised Gitea cannot read Vaultwarden's data.
# A security claim is proven, not assumed.
docker run -d --name hlb-test-pg -e POSTGRES_PASSWORD=test -p 55432:5432 postgres:17-alpine
export HLB_TEST_PG=postgres://postgres:test@localhost:55432/postgres
cargo test -p hlb-platform -- --ignored --test-threads=1 --nocapture

# Backup and restore: these really destroy data and check it comes back identical,
# including a pg_dump taken *during* concurrent writes.
cargo test -p hlb-backup -- --ignored --test-threads=1 --nocapture

# Real registries — the OCI auth dance differs per registry and cannot be stubbed
cargo test -p hlb-registry -- --ignored --nocapture

# PocketID — its API shape was established by probing; these tests are the only
# guarantee the client stays correct
cargo test -p hlb-identity -- --ignored --test-threads=1 --nocapture

# Termix given the nodes: its pinned image, and real sshd's (Debian, Alpine) standing
# for nodes — the key, the account, a rotation, a node leaving
cargo test -p hlb-termix --test live_node -- --ignored --nocapture
cargo test -p hlb-engine --test live_termix -- --ignored --nocapture

# A catalog app's assertions, and its guide's `api` step, against a container of its
# pinned image (instructions in the file's header)
HLB_ASSERT_APP=termix HLB_ASSERT_CONTAINER=my-termix \
  cargo test -p hlb-guide --test live_assertions -- --ignored --nocapture
```

---

> ⚠️ **On macOS (colima or Docker Desktop), `DOCKER_HOST` is mandatory.** `bollard`
> looks for `/var/run/docker.sock`, which does not exist there, and every Docker-facing
> command fails with `SocketNotFoundError`:
> `export DOCKER_HOST=$(docker context inspect -f '{{.Endpoints.docker.Host}}')`

## Declaring a theme

An installation can add its own themes without touching Rust: one YAML file per theme in
`themes/`, loaded by the controller at startup (`--themes <dir>`, `HLB_THEMES`).
`themes/ardoise.yaml` is a complete, working example and doubles as the format's
documentation — every key in it is required.

```sh
hlb config appearance --theme Ardoise --apply   # make it the installation's default
```

The name then appears in Settings beside the three shipped themes, and
`hlb_api::THEMES` keeps its meaning: the SHIPPED list. Declared themes widen it; the
controller serves and checks shipped ∪ declared, and so does the CLI.

⚠️ A theme is refused, never half-applied, in three places and each says why:
`deny_unknown_fields` rejects a typo'd key with the key named, `CustomTheme::problems`
reports every malformed colour at once rather than one per reload, and
`Palette::validate` refuses one that is illegible — too little contrast, or two states
that converge under one of the three colour-vision deficiencies. That last check is the
same one that caught four real merges in the shipped themes.

## The interface

SvelteKit, in `web/`, built with Bun. With Claude Code, two tools come with the
repository: the official Svelte plugin (enabled in `.claude/settings.json`: Svelte
documentation, the `svelte-autofixer`, a Svelte file agent) and the Playwright MCP
server (`.mcp.json`), which drives the running interface. Two things are installed
apart — the plugin's language server, and the browser Playwright drives:

```sh
bun add -g svelte-language-server
npx @playwright/mcp@0.0.83 install-browser chrome-for-testing   # the one .mcp.json pins
```

Working on it:

```sh
cd web
bun install                 # also generates the API types and the messages
bun run dev                 # http://localhost:5173, the API proxied to a controller
                            # on 127.0.0.1:8420 (HLB_CONTROLLER to change it)
bun run check && bun run test && bun run build
bun run test:browser        # builds, then Playwright against real controllers
bun run shots               # the contact sheet: target/shots/index.html
```

`test:browser` starts a populated controller (`--demo`) and an empty one with `cargo
run`, on ports 8431–8434, and walks every page of both: what it refuses is in
`web/e2e/`, one file per question. The browser is the one `@playwright/test` pins —
`bunx playwright install chromium` once. A failure leaves a trace in
`web/test-results/` (`bunx playwright show-trace …`).

`shots` photographs every screen in every theme, both languages, wide and at 360 px,
against the same controllers (so not while `test:browser` runs), plus a demonstration
of a thousand accounts: ~1,800 images in under three minutes, laid out one section per screen with filters. Nothing is compared —
it is there so that looking is cheap; `/shots` runs it and says what to look for.

`bun run build` writes `web/build`, which the controller serves with `--ui-dir
web/build`. Three things are generated before every check, test and build, and never
written by hand: `src/lib/api/schema.d.ts` (types, from `openapi.json`),
`src/lib/api/requires.ts` (the right each route needs, from the same document) and
`src/lib/paraglide/` (from `messages/*.json`).

### How it is put together

| Where | What |
|---|---|
| `src/lib/modules/<id>/module.ts` | A module declares itself: its pages, the GET routes each reads, its inbox feeds, what `Ctrl+K` finds. Found by walking the folder — nobody lists modules. |
| `src/routes/(shell)/` | The pages inside the console. The shell (`+layout.svelte`) builds the navigation, the tabs, the inbox counts and the palette from the modules. |
| `src/routes/(bare)/` | The three pages with no navigation: `/signup`, `/uptime`, `/kiosk`. |
| `src/lib/resource.svelte.ts` | `read(path)` — the one way a page reads: shared per route, timed out, polled while watched, stale responses discarded. |
| `src/lib/action.svelte.ts` | `proposal()` and the action panel — the one way a page changes something. |
| `src/lib/ui/` | `Loaded` (the loading, failed and stale states, worded once), `Card`, `Row`, `Mark`, `Gauge`… |
| `src/lib/words.ts` | How the server's judged structures are said — exhaustive `switch`es and `Record`s. |
| `src/lib/widgets.ts` | The cards the home can pin, one per `hlb_api::HomeWidget` variant. |

### Adding things

- **A page**: add it to its module's `pages` (path, label, the GET routes it reads),
  then write `src/routes/(shell)/<path>/+page.svelte`. Navigation and tabs follow; who
  sees it comes from the routes it reads. `modules.test.ts` fails if either half is
  missing.
- **A module**: a new folder in `src/lib/modules/` with a `module.ts` exporting
  `module`. Its `id` is the folder's name.
- **Something for the inbox**: a `feed(path, data => items)` in the module's `inbox`.
  Give an item a `subject` (`app:<name>`) when another module may report the same thing.
- **A card for the home**: a variant in `hlb_api::HomeWidget`, then its component in
  the module's folder and its entry in `widgets.ts` — the `Record` does not compile
  until both sides agree.
- **An action**: `panel.propose(proposal(title, 'post', '/api/…', { path, body }))`.
  The preview, the execution and the saved plan are the same request. Offer the button
  only when `may(route, method)` says the person can.
- **Text**: a key in `messages/en.json` AND `messages/fr.json`, with the same inputs. A
  key missing from one, or said by nothing, fails `messages.test.ts`. A figure that can
  reach four digits goes through `format.ts` and enters the message as a string.
- **A colour**: a palette role (`text-critical`, `bg-surface`), never a hex value or a
  stock Tailwind colour — `sources.test.ts` refuses both.

## Adding an app to the catalog

An app is a folder under `catalog/` holding its `manifest.yaml` and, if it needs one, a
`guide.yaml`. `hlb catalog validate` must pass; it refuses a typo with its line number.

- **Needs, never addresses.** `requires` says what the app needs (`database`, `sso`,
  `smtp`, `storage`…); `env` and `files` receive it through tokens —
  `{{ db.url }}`, `{{ oidc.client_id }}`, `{{ smtp.from }}`. A capability no token reads
  is refused: what is provisioned for it would reach nothing. A value Homelabus should
  invent is `{{ secret.<name> }}` (`:hex`, `:bcrypt` for the forms some software wants).
- **Read the image, not its documentation.** Every setting is checked against the
  source of the version pinned: a variable the image does not read is a declaration
  nobody reads, and the app runs on its default. Look at its entrypoint too — an image
  whose entrypoint is a bare CLI runs nothing without its command.
- **Close every door, and declare it.** Sign-up, local passwords, a default
  administrator, a first-run wizard: each one closed by the configuration has an
  `assertion` that reads it back from the running app — its own endpoint, its task's
  environment, or one `SELECT` on its database. If the app makes its first visitor the
  administrator, the guide's `api` step makes that account at the install, with a
  `probe` so it is never replayed.
- **Prove it on the image.** Run the pinned image with the manifest's environment and
  `cargo test -p hlb-guide --test live_assertions -- --ignored` (instructions in its
  header): every assertion must hold — and must fail once you open the door by hand,
  or it reads nothing.

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
- **A setting is judged by its effect.** What a manifest closes, an `assertion` reads
  back from the running app every night; one not read lately is unknown, never fine.
- **A secret never enters a plan.** Plans are displayed, stored in SQLite and exported
  to the Git mirror. Secret tokens are substituted in the executor, at deploy time.
- **Stale data must never look fresh.** Whatever the interface shows carries when it
  was received, and an unreachable controller is shown, never papered over.

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

CI runs format, clippy, the unit suite, a minimum-supported-Rust-version check, and the
interface's check, tests and build. All five must pass.
