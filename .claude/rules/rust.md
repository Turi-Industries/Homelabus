---
paths:
  - "crates/**/*.rs"
  - "**/Cargo.toml"
  - "clippy.toml"
---

# Rust and tooling

Traps in the language, the test harness and the toolchain. Several describe a test that
passes while guarding nothing.

- **Line continuations in test YAML.** A trailing `\` eats the newline *and* the next
  line's indentation, breaking YAML confusingly. Use raw strings `r#"..."#` for any
  test manifest.
- **A *forgotten* line continuation is the twin trap.** Without the trailing `\` the
  text renders with a gap in the middle ("server side,        not in this browser").
  Invisible while reading, obvious on screen — hence a test refusing two consecutive
  spaces in any displayed string.
- **A regex-based source scanner misses strings with line continuations.** They are not
  closed on their own line. Scanners read *strings* (a state-machine extractor), not
  lines — and scanning raw code shouts at `Some(s) => f(s)`, a perfectly legitimate
  pattern.
- **A wire key renamed on ONE side fails in silence.** `nouveau` → `new_one` hit the
  JMAP creation id: the write side changed, both read sides did not. JMAP answers under
  the id it was given, so `notCreated` stopped matching — and a failed account creation
  returns HTTP 200. The account simply would not exist, with nothing to say so until the
  first lost email. It is now one `CREATION_ID` constant, and a test refuses a literal
  creeping back. The same class covers on-disk filenames (`hlb.new` for the self-update
  swap), route paths, **saved plan bodies** (`named_plans.body` replays a request
  verbatim, so a renamed field drops out of every recorded plan — use
  `serde(alias = "<old>")`) and **values written into the database** (profile names,
  backup classes, secret purposes, theme names: rename one and the row silently stops
  matching).
- **A global rename is verified by the compiler for identifiers, and by NOTHING for
  string literals.** SQL, protocol keys, file paths and route paths all live in strings.
  Audit them separately, literal by literal, against the previous revision. 🔴 This
  fired on 2026-08-27: a French-to-English identifier pass rewrote `"backup-en-retard"`
  to `"backup-en-lag"` — an alert rule name `CLAUDE.md` then named as deliberately
  frozen. The suite stayed green, because no test compared a rule name against anything.
  (The freeze rested on "mutes persist by name", which was not true then — nothing
  stored a mute — and the names went to English on purpose on 2026-10-05. ⚠️ It IS true
  since 2026-10-06: `alert_mutes.rule` is a stored value.) What caught
  it: extracting every string literal in `crates/` at `HEAD` and in the working tree with the same
  state-machine stripper the language test uses, and diffing the two multisets. Twenty
  other literals had changed and all twenty were legitimate (format-string placeholders,
  a container path used in the function that mounts it, assertion messages) — the point
  is that the diff is small enough to read, so read it. ⚠️ The one exception to "never
  touch a string": an inline format capture (`"{prefixe}/{database}"`) IS an identifier
  living in one. A rename that skips strings leaves the capture naming a variable that is
  gone — the compiler says so, and the fix is to rename `{old}` and `{old:` patterns,
  not to start editing literals.
- **A word-list scanner is only as good as its list, and the list is never done.**
  `english_only.rs` refuses French identifiers from the list in `tests/data/non-english-words.txt`. Three passes were
  declared finished on it; the fourth grew the list from 99 words to 240 by sweeping
  against four different French vocabularies and found **130** more identifiers, the last
  nine only when the sweep reached everyday nouns (`bureau`, `enfant`, `pile`, `trou`).
  When you find a French identifier, add its word to the list — that is the mechanism,
  and "the scan passes" means "the list found nothing", not "there is nothing". The
  fifth pass (2026-10-05) had no dictionary on the machine and used another filter: a
  word found in identifiers and NEVER in a comment or a Markdown file is suspect, since
  the prose is English. 146 words, 179 identifiers — `Maillon`, `RouteMutante`,
  `Limiteur`, a `SortQuorum::Tient` serialised as `"tient"`. A second run of the filter
  found one more (`occupation`), and then only English. 🔴 And it BLANKS string
  literals, which is where the values that outlive a rename live: twelve French ones,
  nine of them stored, survived five passes — audit actions (`gerer-accounts`), the actor `anonyme`,
  break-glass ids (`deux-passkeys`) — while `retrait` and `deux` sat in its list.
  `every_value_a_program_reads_is_english` now reads the literals shaped like a
  value (lower case, no space), outside tests.
- **The thirteen hand-maintained lists that drifted here**, since `CLAUDE.md` names the
  count and not the cases. Three were found on 2026-08-27 in one corner, each hiding the
  next: `AppTab::implemented()` named six of seven variants and never mentioned
  `Updates`; the test guarding the tab bars listed two expected labels per screen, so it
  could not see a third that was missing; and `a_dead_route_is_invisible`'s "served to
  other clients" exemption had grown to sixteen paths crediting a CLI that requests two.
  The others are the two below (files to scan, French words), the interface's i18n
  message keys — each screen's test listed its own, eighty for the dashboard, and a key
  added tomorrow was simply absent — and the screens the two-consecutive-spaces test
  named. 🔴 The eighth: an icon test walked a `const ALL: [Icon; 10]` written out by
  hand, while the build shipped the whole `assets/icons/` directory — so an asset that
  shipped without being added to the array was validated by nothing. **What ships is
  what a test walks.** (Several of these lived in the egui interface, retired
  2026-10-05; the lesson did not leave with it.) Nine, ten and eleven, found on
  2026-10-05: two controller tests over server text and one `hlb-api` test each scanned
  six, seven and two files by hand, out of 26 and 6 — the refusals rewritten that day in
  `bitwarden.rs` and `signin.rs` were covered by neither. Twelve, found the same day:
  the test refusing anonymous callers named five read routes of the 34 that require a
  role, and the role-threshold test walked only the 25 that write. Both walk the OpenAPI
  document now — nothing had leaked, which is luck, not coverage. Thirteen, found on
  2026-10-18: the README's table of crates had lost three of thirty (`hlb-backup-run`,
  `hlb-bitwarden`, `hlb-termix`) while `CLAUDE.md`'s held them all; a prose table is a
  list too. `every_crate_is_named_where_the_crates_are_listed` walks `crates/`.
- **A string extractor that splits lines on `//` is not reading strings.** It cuts
  `"https://"` in half, and every quote after it in the file is read the wrong way round.
  Invisible while a test scans six chosen files; the day it walked the directory it
  reached `signin.rs` and reported a "string" made of code. Track `//` only OUTSIDE a
  string, and step over `'"'` and lifetimes.
- **A scan that cuts a file at `#[cfg(test)]` stops reading early in two ways.** Code
  written AFTER a test module was cut with it: `record_plan` sat below `actions.rs`'s
  tests and no controller scan had ever read it. And the cut matched the `#[cfg(test)]`
  that `auth.rs` carries INDENTED inside a macro, so the second half of that file — the
  authorization extractor — was invisible too. Cut at `\n#[cfg(test)]`, and the
  controller's `production_sources` refuses code after a test module. The three other
  files laid out that way (`pitr.rs`, `access.rs`, `hlb-ingress`'s `lib.rs`) had their
  modules moved last the same day. 🔴 It came back outside the controller, where nothing
  refused it: on 2026-10-19 `pgdump.rs` held `restic/restic:latest` below its tests,
  out of reach of the scan pinning every image, beside `sqlite.rs` and `hlb-ingress`
  again. `no_code_follows_a_test_module` (`hlb-types/tests/english_only.rs`) walks every
  crate now; the scans share one extractor, `hlb-types/tests/scan/`.
- **A hand-maintained list of files to scan drifts.** The two-consecutive-spaces test
  listed its screens by hand; three screens written later were missing from it and the
  check silently stopped covering them. It walks the directory now.
- **A source-scanning test must assemble its patterns.** The test forbidding "action(s)"
  fired on its own source three times. Use `format!("({})", "s")` rather than the
  literal.
- **`..` in a pattern has the same effect as a `_ =>` arm.** Seen on
  `Capability::Sso { redirect_paths, .. }`: `mode` was ignored, so an app in
  `mode: none` got an OIDC client with EMPTY URIs. The compiler cannot tell you — which
  is exactly what exhaustiveness was supposed to prevent.
- **A validator nobody calls validates nothing.** Phase 7's `validate_catalog_images`
  was written, tested on its own, and never called by `catalog validate`: the catalog
  was pinned only because a command had written the digests. A rule of the catalog goes
  into `Catalog::validate_all`, and its test goes THROUGH `validate_all`.
- **`cargo audit` reads `.cargo/audit.toml`**: an ignored advisory carries the reason
  it does not reach Homelabus, and the condition that brings it back. CI runs it; it
  found ten on its first run.
- **`sqlx` uses runtime queries**, not compile-time macros: those need `DATABASE_URL` at
  build time. Compile-time SQL checking is therefore **not** in place.
- **CI runs a newer clippy than a Homebrew toolchain.** `/opt/homebrew/bin/rustc` is
  Homebrew's own build, not a rustup shim, and it shadows rustup on `PATH`. A lint
  added in a newer clippy passes locally and fails CI — `result_large_err` did exactly
  that. Use `~/.rustup/toolchains/*/bin/cargo` when you need to match CI.
- **Two checkouts never share a `target/`.** Cargo names a workspace crate's artifacts
  by its path RELATIVE to the workspace — a worktree and the main checkout both write
  `libhlb_types-314d7a8feb810695.rmeta` — and judges a path crate fresh by mtimes, so
  whichever built last silently supplies the other's crates. Seen 2026-10-27 as
  "missing field `fix`" in code that had no such field; a suite that passed on the other
  checkout's code would have said nothing. `scripts/worktree-target.sh` reflinks a
  worktree its own; `instructions.rs` refuses `target` in `worktree.symlinkDirectories`.
- **A second `[[bin]]` makes `cargo run -p <crate>` refuse to choose.** `hlb-privd`
  joined `hlb-controller` and the browser suite, which starts the controller so,
  failed in CI only: the stop gate runs it when `web/` moved. `default-run` names
  the one meant.
- **In-memory SQLite** requires `max_connections(1)`, or each connection sees a
  different database.
- **`SystemTime::now()` has no nanosecond resolution on macOS.** A unique id built on it
  alone produces duplicates between two close calls.
- **The host temp directory is NOT shared with the Docker VM on macOS.** Any scratch
  space mounted into a container must be a *Docker volume* (or a path under `/Users`),
  and its content read from a container. A `tempfile::tempdir()` appears empty there,
  which makes a healthy backup look empty. **This trap appeared three times**: restic
  verification, SQL dumps, recovery drills.
