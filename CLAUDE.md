# CLAUDE.md

Guidance for Claude Code (claude.ai/code) when working in this repository.

## Language

**Everything in this project is in English**: code, comments, error messages, CLI
output, test names, documentation, commit messages.

Comments explain *why*, not *what*. A comment restating the line below it is noise; one
recording the trap a line avoids is why this codebase stays maintainable. Keep them
short and anchored to the code they sit on. Do not reference an external design
document — if a decision needs explaining, explain it here or next to the code.

> Historical note: this project was written in French until 2026-08-21 and translated.
> Some lower-level comments may still be French — translate them as you touch them,
> and keep meaning over literalness. The reasoning is the value, not the wording.

## Commands

```sh
cargo test                      # unit tests, no external dependency
cargo test -p hlb-resolver      # a single crate
cargo test -p hlb-state -- completed_actions_survive_a_replan   # a single test
cargo clippy --all-targets      # must stay at zero warnings
cargo fmt --all                 # enforced in CI
cargo build
```

### Swarm integration tests

`#[ignore]`d so `cargo test` stays fast and usable without Docker.

```sh
docker swarm init
export DOCKER_HOST=$(docker context inspect -f '{{.Endpoints.docker.Host}}')
cargo test -p hlb-orchestrator -- --ignored --test-threads=1 --nocapture
```

⚠️ **On macOS (colima / Docker Desktop), `DOCKER_HOST` is mandatory.** `bollard` looks
for `/var/run/docker.sock`, which does not exist. Without it, every integration test
and `hlb ps` / `hlb install` fails with `SocketNotFoundError`.

### Trying the CLI

```sh
./target/debug/hlb catalog validate
./target/debug/hlb order
./target/debug/hlb plan gitea --domain git.example.org
./target/debug/hlb install valkey            # preview
./target/debug/hlb install valkey --apply    # real execution

./target/debug/hlb backup dest list
./target/debug/hlb backup status             # freshness PER destination
./target/debug/hlb metrics rules
./target/debug/hlb metrics deadman --ntfy https://ntfy.sh/watchdog
./target/debug/hlb replication config nas-01
./target/debug/hlb user list
./target/debug/hlb user alias sieve remy     # --apply to install in Stalwart
./target/debug/hlb user role remy admin      # --apply; refuses to demote the last one
./target/debug/hlb user sessions remy        # --close <ref>|all
./target/debug/hlb audit --verify            # chain integrity

# The UI, with no cluster and no Docker — the fastest way to see it
./target/debug/hlb-controller --demo --listen 127.0.0.1:8420 &
./target/debug/hlb-ui --url http://127.0.0.1:8420 --route /apps
```

⚠️ **Most commands need state and a vault.** To try things without touching a real
install:

```sh
export HLB_STATE=/tmp/try.db HLB_MASTER_KEY=/tmp/try.key
```

⚠️ Node tiers are real Swarm placement constraints. `hlb node add` sets them; on a
manually joined node you must do it yourself, or nothing schedules and `wait_healthy`
times out:

```sh
docker node update --label-add tier=heavy $(docker node ls -q)
```

## Architecture

### The central idea: the capability resolver

This structures everything else. A manifest **never** says "connect to
`postgres:5432`". It declares a **need**:

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
`match` must be updated** — the main reason this is written in Rust. Do not break it
with a `_ =>` arm.

### The flow

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

### Crate dependencies

`hlb-types` is the foundation: **the only schema definition**, consumed by Rust code
and by `schemars` (JSON Schema for YAML autocompletion). No other crate redefines these
types.

⚠️ There is no OpenAPI and there will not be one: since choosing egui, `hlb-api`
defines the API types **once** for both the server and the interface, both in Rust.

```
hlb-types  ←  hlb-resolver  ←  hlb-engine  →  hlb-orchestrator
     ↑              ↑              ↓
hlb-catalog    hlb-state    ←──────┘
     ↑              ↑
hlb-users      hlb-cli (assembles everything)   hlb-api  →  hlb-ui
```

Domain crates depend only on `hlb-types` and never touch the network: `hlb-users`
(accounts, aliases, quotas, Sieve), `hlb-metrics` (rules, deadman). Network clients sit
beside them — `hlb-mail`, `hlb-identity`, `hlb-objstore` — which keeps the logic
testable without a server.

### Dependency ordering

**Docker Swarm has no `depends_on`.** It starts everything in parallel, and an app
starting before PostgreSQL crash-loops. `hlb-resolver::graph` derives the graph from
`requires` (via `Capability::platform_service()`) and produces a topological order.
Shutdown runs in reverse.

Adding a platform service to the catalog updates the graph automatically — there is
**no hand-maintained list**. A capability pointing at a service absent from the catalog
fails `hlb catalog validate`.

## Invariants not to break

These are encoded in tests. If a test fails, the code is usually wrong, not the test.

- **Preview by default.** `Executor` changes nothing without `.apply(true)`. Over HTTP
  the same rule is `?apply=true` — visiting a screen must never execute anything. A
  test walks the list used to build the router and checks no route acts without it.
- **`Unimplemented` is never `Done`.** An action the executor cannot perform yet is
  recorded as unimplemented and reported as such. Never pretend a database was
  provisioned.
- **Idempotent and resumable.** `record_plan` does not overwrite a `done` action; the
  executor skips finished work and stops at the first failure rather than cascading.
- **Reconciliation never deletes an orphan, never resurrects a failed install, and
  never forces a convergence in flight.** A system that over-corrects is more dangerous
  than one that corrects nothing. Key distinction: the Swarm *instruction*
  (`desired_replicas`) comes from a decision and gets corrected; *progress*
  (`running_replicas`) is transient and gets left alone.
- **Blocking guides stop before any modification.** No point deploying an app whose DNS
  does not exist or whose admin account was never created.
- **The update policy is not negotiable.** `start-first` + `failure_action: rollback` +
  `monitor` are hard-coded in `hlb-orchestrator`, not configurable per app. An app that
  cannot cope belongs on `channel: pin`.
- **Secure by default.** `read_only_rootfs`, `cap_drop: [ALL]`, `no_new_privileges`, no
  published ports, `private` exposure. Defaults go the safe way.
- **`deny_unknown_fields` everywhere.** A typo in a manifest is rejected with its line
  number, never silently ignored.
- **Configuration routes have no preview, and that is a declared choice.** Writing a
  brand name is idempotent and reversible; forcing a round trip would train people to
  click twice, which drains the protection where it matters. The `preview: false` field
  is explicit and a test locks the short exemption list.

## Conventions

- **No `unwrap` / `expect` in production** (`warn` lint in the workspace). Allowed in
  tests via `clippy.toml` — there, `expect("message")` *is* the assertion.
- **Typed errors per crate** (`thiserror`), never a bare `String`. The CLI unwinds the
  cause chain.
- **Plans must be reproducible.** The topological sort breaks ties alphabetically; a
  plan that varies between runs makes snapshot tests worthless.
- **Tests named as assertions**: `postgres_comes_before_its_consumers`,
  `unimplemented_is_never_reported_as_done`.

## Known pitfalls

Each of these cost real debugging time. They are recorded so they are not rediscovered
during an outage.

### Rust and tooling

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
- **A source-scanning test must assemble its patterns.** The test forbidding "action(s)"
  fired on its own source three times. Use `format!("({})", "s")` rather than the
  literal.
- **`..` in a pattern has the same effect as a `_ =>` arm.** Seen on
  `Capability::Sso { redirect_paths, .. }`: `mode` was ignored, so an app in
  `mode: none` got an OIDC client with EMPTY URIs. The compiler cannot tell you — which
  is exactly what exhaustiveness was supposed to prevent.
- **`sqlx` uses runtime queries**, not compile-time macros: those need `DATABASE_URL` at
  build time. Compile-time SQL checking is therefore **not** in place.
- **In-memory SQLite** requires `max_connections(1)`, or each connection sees a
  different database.
- **`SystemTime::now()` has no nanosecond resolution on macOS.** A unique id built on it
  alone produces duplicates between two close calls.
- **`std::time::Instant::now()` PANICS in WebAssembly**, and there is no thread and no
  `sleep`. All freshness goes through egui's clock, and polling is driven by the render
  loop — one code path for native and web.
- **The host temp directory is NOT shared with the Docker VM on macOS.** Any scratch
  space mounted into a container must be a *Docker volume* (or a path under `/Users`),
  and its content read from a container. A `tempfile::tempdir()` appears empty there,
  which makes a healthy backup look empty. **This trap appeared three times**: restic
  verification, SQL dumps, recovery drills.

### Databases

- **A PostgreSQL extension cannot be installed from SQL.** It must be in the server
  IMAGE, or `CREATE EXTENSION` fails with "is not available", which looks like a
  permissions problem. And it is **per-database**: installed on `postgres`, it succeeds
  and the app never sees it.
- **Changing the PostgreSQL image's libc breaks text indexes.** musl (alpine) and glibc
  (debian) do not sort alike. B-trees built under one become incoherent under the other:
  incomplete searches, unique constraints letting duplicates through. PostgreSQL only
  warns about a "collation version mismatch". Hence `REINDEX DATABASE` +
  `REFRESH COLLATION VERSION`.
- **The role belongs to the APP, not to the database.** Seafile wants three databases
  and connects to them with a single account. Naming the role after the database would
  produce three accounts for one credential set, and the app would fail on two of them.
- **`pg_basebackup` goes through the replication protocol**, which `pg_hba.conf` treats
  as a separate database. A user who connects fine with `psql` is refused. The official
  image only allows replication from `127.0.0.1`: you need
  `host replication all all scram-sha-256`.
- **`pg_basebackup -R` overwrites `postgresql.auto.conf`**, which is read AFTER
  `postgresql.conf` and therefore wins. The `primary_conninfo` it writes has no
  `application_name`: settings placed BEFORE are silently lost and every standby
  announces itself as `walreceiver`. You then see a node falling behind without knowing
  which one.
- **A brand-new replication slot retains nothing** until a standby connects (absent
  `immediately_reserve`). The dangerous case is not the never-used slot, it is the one
  *that has been used* and whose consumer disappeared: only that one grows `pg_wal`.
- **A failing WAL `archive_command` does not lose journals, it keeps them.** `pg_wal`
  grows until the disk is full. Archiving to a broken destination is more dangerous than
  not archiving.
- **A MariaDB dump does NOT include routines, triggers or events** without
  `--routines --triggers --events`. The dump succeeds, restores without error, and the
  app is subtly broken — a missing trigger only shows on the first affected write.
- **`--single-transaction` only protects transactional tables.** On MyISAM or Aria the
  option is accepted with NO warning and provides no consistency. Hence reading engines
  before each dump — and an unreadable list means `LockRequired`, never "it is probably
  InnoDB".
- **A truncated MariaDB dump is still valid SQL.** Interrupted, it restores a database
  missing tables, without a single error. The `-- Dump completed` line is the only proof
  of completeness — hence the ban on `--skip-comments`, which would remove it.
- **A MariaDB user is `'name'@'host'`.** Without an explicit host part the app is
  refused from another container, with a message about an incorrect password. And
  `_`/`%` are WILDCARDS in a `GRANT`.
- **A SQLite file cannot be copied hot.** In WAL mode restic copies three files one
  after another while the app writes. `VACUUM INTO` produces a consistent snapshot, and
  the failure only shows at restore time.

### Backups

- **A metric that is absent beats a zero.** `hlb_backup_age_seconds` is not emitted when
  no backup has succeeded: a `0` would mean "backed up just now", and the alert would
  never fire for the most at-risk apps.
- **A fresh destination masks a stale one.** `MAX(finished_at)` across all destinations
  made an off-site dead for three weeks look like a two-hour-old backup, because the NAS
  was running. Freshness is measured PER destination, and the summary shows the worst
  case — otherwise it contradicts the detail right below it, and the summary is what
  people read.
- **Configured is not protected.** The number of declared destinations says nothing
  about the number of copies: a failing destination protects nothing.
- **A failure on one destination must never starve the others.** An unreachable off-site
  that aborted the loop would also skip the local backup: both copies lost for one
  failure.
- **Deadlines are per destination.** Judged globally, the off-site is skipped whenever
  the NAS was just served — it would then never receive anything while the global status
  looked fresh.
- **A REPEATED failure must be visible before the staleness threshold.** A destination
  failing every attempt stays "fresh" for twelve hours at the default interval. Hence
  the consecutive-failure counter, displayed immediately.
- **`datetime('now')` has ONE SECOND resolution.** A success and the failure following
  it within the same second carry the same timestamp, and a strict comparison excludes
  them — the counter stays at zero while everything fails. Order by `id`, which is
  monotonic.
- **`credentials_secret` is the NAME of the secret, not its value.** Passing it through
  would send "backup-dest-offsite" as the S3 access key, and the server would answer
  "invalid signature" — an error that points nowhere.
- **A restic S3 repository is not MOUNTED.** Mounting it creates an empty directory and
  restic replies "repository does not exist", naming a local path unrelated to the real
  destination. And joining an internal Garage needs a `--network`.
- **Comparing sizes does not detect corruption.** A flipped bit leaves the file the same
  size. Hence `restic check --read-data-subset` on top of the count.
- **Two numbers for a backup, not one.** RPO says what you would lose; confidence says
  what you know about that copy. A fresh backup never read back is a hypothesis, and
  showing it green is the lie this system exists to prevent. RPO is measured on
  up-to-date destinations only.
- **"No up-to-date copy" covers two opposite situations.** Never backed up (nothing
  exists) and stale backups (copies exist, they are old) are not repaired the same way.
  Seen on screen: "NO copy" next to two destinations showing "1 d" reads as a
  contradiction, and you then doubt the whole screen.
- **Homelabus's own state was not backed up.** Brand, themes, announcements, roles,
  invitations, recovery attestations, plans, actually-published routes: all of it lives
  in the state database and nothing copied it. A restore returned running apps in an
  installation that no longer knew who the administrator was.

### Mail

- **Stalwart has no REST API for accounts.** Everything goes through JMAP (`POST /jmap/`,
  capability `urn:stalwart:jmap`, methods `x:Account/set` and `x:Domain/query`), from
  **v0.16** only. The discriminator is `@type`, `emailAddress` is computed by the
  server, and a failing `/set` still returns HTTP 200 — the failure lives in
  `notCreated`. **A filter condition carries only ONE property**: each key overwrites
  the previous, so you need an `AND` of separate conditions.
- **JMAP `update` REPLACES the whole property.** There is no "add an alias" operation:
  writing a single alias would erase all the others, without raising an error. Hence
  read-modify-write — and two simultaneous updates would lose the first.
- **A Sieve script does not travel in the JMAP call.** `SieveScript` only carries a
  `blobId`: upload the content, then reference it. And **without
  `onSuccessActivateScript` the script exists and sorts NOTHING** — a completely silent
  failure, the rules visible in Roundcube and having no effect.
- **A Sieve script is a SINGLE file per account.** Rewriting it wholesale would erase
  hand-written rules — hours of tuning, lost without warning, for a simple alias
  creation. Hence a marker-delimited block: Homelabus writes only between the markers,
  and the block goes at the END (at the top it would catch messages before the user's
  own rules).
- **An unescaped quote in a folder name breaks the WHOLE script**, including the user's
  rules, which Stalwart then rejects wholesale. The name comes from the user: escape it.
- **`NULL` ≠ empty string for a sorting folder.** `NULL` = "nothing was decided", offer
  a default; `""` = "I do NOT want sorting", an explicit choice. Confusing them
  re-imposes a folder on every regeneration.
- **A mail server CANNOT expire an alias.** A Stalwart account's `aliases` list has no
  dates: what is written stays. Hence **three** states, not two: valid,
  expired-and-removed, and 🔴 expired-but-STILL-ACTIVE.
- **A guessable alias defeats compartmentalisation.** If Amazon's is
  `amazon@example.org`, then `paypal@`, `bank@` and `tax@` probably exist too, and a
  bulk sender tries them all for the price of one. The hint never *is* the address: it
  is followed by a random suffix.
- **The point of a disposable alias is not disposal, it is attribution.** One address per
  recipient tells you *who* leaked it. Hence keeping the readable hint: fifty purely
  random addresses lose the only real benefit.
- **Disabling beats deleting.** A deleted alias rejects mail and teaches nothing;
  disabled, it also rejects but lets you count what still hits it — so you learn how long
  a merchant kept selling the address.
- **Marking an alias "purged" without removing it from the server is worse than doing
  nothing.** The address would still receive AND nothing would say so: the silence would
  sustain the belief that the door is closed. The state is only marked AFTER the actual
  removal, and a purge without Stalwart refuses rather than lying.
- **What matters in a purge is what stays OPEN, not the error count.** An error-free
  purge that removed nothing leaves as many doors open as one that failed loudly.
- **A half-created account looks functional.** Identity without a mailbox: the person
  signs in everywhere and their address receives nothing. It only shows on the first lost
  email, often a password reset. The state is named, and creation is resumable.
- **PocketID has no password**: passkey authentication. So you do not hand over an
  initial secret but a **single-use token**, shown once and never stored.
- **🔴 idmail and `hlb-mail` cannot coexist.** idmail does not talk to Stalwart: it
  REPLACES its directory (external sqlite `directory`). Together they would produce an
  alias created over JMAP in a directory Stalwart no longer consults — the address would
  receive nothing, with nothing to signal it. Hence the addy.io-compatible API on the
  Homelabus side rather than integrating idmail.
- **The addy.io API contract is imposed by BITWARDEN**, not by us. Read from its source
  (`libs/tools/generator/core/src/integration/addy-io.ts`): the response must be
  `{data:{email}}` — at the root the client reads `undefined` and the alias exists
  server-side without anyone knowing.
- **The addy.io protocol has no field for choosing the mailbox.** Bitwarden only sends
  `domain` and `description`. The destination therefore lives on the TOKEN — one token
  per mailbox — and a token pointing at a vanished mailbox FAILS rather than falling
  back to the default: the user would believe their aliases are filed where they are not.

### Security and authorization

- **An API token carries a ROLE, not an identity.** Enough to read state, wrong as soon
  as a request acts FOR someone: without a binding, a stolen token would create aliases
  on anyone's mailbox. An unbound `admin` token is therefore refused where a bound
  `operator` passes.
- **An authenticated role is not an authorized role.** `Role::allows` existed with no
  production caller: every handler took `_auth: Authenticated` and ignored the role.
  Authorization now lives in the TYPE of the argument (`Authorized<CanOperate>`) — the
  compiler demands it in the signature, so it cannot be forgotten.
- **A bare `403` makes you doubt everything.** It does not say whether you are on the
  wrong screen, the system is broken, or a right is missing. The refusal names the
  action, the required role, the held role and **who can grant it** — and returns `None`
  when allowed, so a refusal cannot be shown by mistake.
- **A person's role is re-read on EVERY request**, never frozen into the session. Frozen,
  removing someone's admin rights would have no effect for twelve hours — and you remove
  them precisely when you are in a hurry.
- **`SameSite=Lax` is not enough against CSRF.** Any mutating request carried by a cookie
  requires the `X-HLB-UI` header. Token calls are exempt: with no cookie there is no
  ambient authority to hijack.
- **A `Secure` cookie is NOT set at all over `http://`.** The attribute follows the
  public URL and is never hard-coded, or local development loops on the sign-in screen
  **with no error message at all**.
- **The web token goes through the URL FRAGMENT**, never the query string: a `?token=`
  ends up in access logs, `Referer` headers and every proxy.
- **An API token is never stored in clear**, not even in the vault: a SHA-256
  fingerprint is kept. A leak reveals that a token exists, not its value.
- **An `id_token` signature is not verified** — and that is correct: it is fetched by the
  controller itself over TLS, never received from the browser. ⚠️ This reasoning would
  NOT hold for an implicit flow.
- **Trusting `X-Forwarded-For` without a trusted proxy defeats rate limiting**: each
  attacker gets a fresh counter on every request, and the protection looks like it
  works. Hence `--trusted-proxy`, explicit.
- **Forward-auth must erase incoming identity headers.** Otherwise
  `curl -H "X-Auth-Request-User: admin"` is enough to impersonate an account.
- **An open PromQL relay is exfiltration.** `{__name__=~".+"}` returns the whole
  database: hostnames, paths, app names — the map of the installation, to anyone holding
  a `viewer` token. Hence an **allowlist** of prefixes: you cannot enumerate what is
  dangerous, you can enumerate what is useful.
- **A missing scanner is not a green light.** `NotChecked` is distinct from `Clean`:
  treating "trivy absent" as "nothing found" disables the check while looking like it ran.
- **`sshd` SILENTLY ignores `authorized_keys`** if it is group-readable, or if `~/.ssh`
  is. The key looks installed and nothing works.
- **CrowdSec only goes on the front Caddy.** The backend only sees the front's IP:
  putting the bouncer there would ban its own front on the first attacker.
- **A secret must never enter a plan.** The plan passes through `hlb plan` (display), the
  SQLite state (recording) and the Git mirror (export with history). Secret token
  substitution therefore happens in the executor, at deploy time. `{{ db.url }}` counts
  as a secret despite looking like an address: it contains the password.
- **An unresolved token stays literal, never empty.** An empty variable looks like
  missing configuration: the app complains about a bad password and you go looking at the
  password. `{{ db.password }}` in the logs points at the real problem.
- **The vault is NOT the source of truth for a password.** Rotating it there alone
  changes nothing: PostgreSQL keeps the old one, the container keeps the old one in its
  environment, and everything keeps working — until the next redeploy, where the app
  fails on "incorrect password" with nobody connecting it to a rotation three weeks
  earlier. A rotation is an ORDERED PROCEDURE.
- **An app never owns its S3 bucket.** `read` + `write`, never `owner`: as owner, a
  compromised app could delete its own bucket — erasing what the backups protected.
- **Garage NEVER returns a secret key twice.** `CreateKey` gives it once; `GetKeyInfo`
  returns null afterwards. Idempotency therefore cannot rest on "does the key exist?" —
  the vault is authoritative, or a resumed run starts without a secret and the app fails
  on an "invalid signature" that points nowhere.
- **Homelabus can verify NONE of the access safeguards**, except the recovery drill: it
  does not know how many passkeys exist or whether the codes are printed. So it asks for
  a dated attestation and expires it — and the one point it *can* prove is not
  attestable by hand, or you would paint the most important safeguard green with no drill
  having happened.

### Operations and correctness

- **A periodic heartbeat proves nothing.** It attests that a thread is alive, not that
  the system works: the controller can have an unreadable database and a dead Docker and
  keep beating imperturbably. The watchdog then stays green over an unusable system —
  **worse than no deadman, since you trust it**. The beat is conditional on a successful
  check, and silence is the signal.
- **The watchdog does not run on what it watches**, and does not alert through it. A
  deadman hosted by the controller dies with it; an alert relayed by the controller does
  not leave when the controller is what died. And if `curl` fails, the failure is
  swallowed by `>/dev/null 2>&1`: hence the fallback to stderr, which cron mails out.
- **Provisioning is not connecting.** The resolver created the database, the isolated
  role and the password, then deployed the app without telling it anything: it fell back
  to its internal SQLite. Healthy service, green probe, green dashboard — and the data in
  a file nobody backed up, while an empty database was faithfully dumped every night.
  Hence `spec.env` and binding tokens.
- **A missing companion is invisible.** Immich without its machine-learning service
  imports and displays photos perfectly, and never recognises anyone. Hence deploying the
  companion BEFORE the app, waiting for it to become healthy, and a guide step that makes
  you check it really works.
- **Counting Swarm tasks**: filter on `desired-state` **and** the actual state. Swarm
  keeps the history of dead tasks, which you would otherwise count as alive.
- **A dead Swarm task is not a stopped task.** `desired_state` AND `state` decide whether
  it lives; but a deliberately stopped task (update, scale-down) is not a failure —
  counting it as one would make the dashboard blink on every normal deploy, and you would
  stop looking at it.
- **Anti-affinity is about HARDWARE, never `node.id`.** Two VMs on the same server are
  two Swarm nodes and **one** point of failure: spreading two replicas "across two nodes"
  protects nothing, and Swarm returns an illusion of redundancy. The domain is declared
  at `hlb node add` (label `hlb.failureDomain`) — neither Swarm nor the agent can guess
  it.
- **An undeclared domain is not an isolated domain.** Assuming isolation would be exactly
  the optimistic assumption that creates the illusion. Nodes without a domain form a
  "we do not know" group, displayed as such.
- **Simulate the loss of a DOMAIN, never of a machine.** On two VMs of one server,
  per-node simulation concludes "the service survives" where per-domain says "it goes
  down entirely". And quorum requires a STRICT majority of managers: out of four, two
  survivors are not enough — a naive `>=` would conclude the cluster holds.
- **Draining the last active node would empty the cluster.** Swarm accepts it without
  complaint — it is on us to refuse.
- **A causal chain you cannot follow stops.** On "unknown cause", never on a guess: a
  plausible but wrong diagnosis makes you repair the wrong thing, then doubt the screen.
  An alert is only attached if the node's own reading corroborates it.
- **Reconciliation's non-actions were invisible.** Nothing distinguished "there is
  nothing to do" from "there is something and I deliberately chose not to touch it". The
  refusal names the reason, and a test requires correctable and refused to be exactly
  complementary. A refusal is painted GREEN: it is a decision, not a failure.
- **`record_verification` inferred failure from the presence of a detail.** Describing a
  successful verification therefore recorded it as a failure, and the app stayed
  "never verified" forever. `succeeded: bool` is a first-class argument.
- **The capacity budget does not add up.** A service is not split across two machines:
  two nodes with 400 MB free do not make 800 MB usable, they make 400. And there is NO
  memory field in manifests — announce what is left on the targeted tier, never a margin
  you do not have.
- **A node of unknown tier belongs to no tier.** Assuming otherwise announces space where
  there is none; a tier with no node makes `wait_healthy` expire without ever saying why.
- **The CPU rate needs TWO readings.** `/proc/stat` is cumulative since boot: on the
  first pass the value is `None` and never `0.0` — a "0 %" reads as "idle machine", the
  exact opposite of "I do not know". Same after a reboot, where counters go backwards:
  the subtraction is checked, not wrapped.
- **Load is only comparable divided by cores.** 4 is dramatic on one core and comfortable
  on sixteen; a homelab is made of heterogeneous machines.
- **Memory is measured on AVAILABLE, not free.** Linux caches everything it can: "free"
  is almost always near zero on a healthy machine. Trusting it would cry out-of-memory
  permanently.
- **Swap starting to be used is a signal BEFORE the failure.** The machine slows without
  having fallen over yet. The threshold is low (5 %) for that reason.
- **The agent protocol goes up, compatibility stays both ways.** Every added field is
  `Option` + `serde(default)`, and nothing is `deny_unknown_fields`: you can update the
  controller before the agents or the reverse. Without that, the first update would make
  the whole fleet "unreachable" — precisely when you need to see it.
- **Prometheus values are STRINGS, not numbers.** Reading them with `as_f64()` returns
  `None` on all of them, and the curve is empty with no error at all.
- **An empty series is not a zero series.** A flat line reads as "all calm";
  `Series::Unavailable` is a distinct variant the type forces you to handle.
- **A muted alert stays DISPLAYED.** Muting silences the notification, not the screen:
  hiding it would give a green dashboard for a known, unresolved problem. It carries a
  deadline and comes back whole afterwards.
- **A non-evaluable rule is not a satisfied rule.** If collection fails, the unknown
  state surfaces at `Important` level — not at the rule's level, which would suggest the
  threshold is breached when you do not know whether it is.
- **`hlb_backup_copies` existed nowhere** while the `single-copy` rule queried it: the
  rule guarding 3-2-1 therefore never fired once.
- **A dependency cycle reveals where code should live.** `hlb-state` cannot implement a
  trait from `hlb-backup` (which depends on `hlb-updater`, which depends on `hlb-state`).
  The adapter therefore goes in the controller, which already depends on both — and the
  logic stays in `hlb-backup`, testable in memory.
- **"Nothing before" is not "nothing changed".** In manifest history, the first known
  version does not have an empty diff because nothing moved: it has nothing before it.
  And a commit not touching the app still carries its file — without deduplication,
  twenty identical versions would drown the one real change.
- **A timeline source you cannot read must APPEAR.** Hiding it would suggest "no human
  action preceded the outage" when you know nothing — and this screen is read mid-outage.
- **SQLite writes timestamps without a timezone or a "T".** Rejecting them as RFC 3339
  returns `None` on every row, and the timeline is empty on healthy data.
- **A named plan is replayed AS PREVIEWED**, never recomputed: two computations at two
  moments can diverge, and you would execute something other than what you read.
  Replaying reruns the preview, not the execution. A plan targeting an unknown route is
  refused AT SAVE TIME — accepted, it would fail weeks later on a 404 pointing nowhere.
- **A path template is compared segment by segment.** A prefix comparison would let
  `/api/apps/gitea/install/really` through, which does not exist.
- **A runbook written by hand is wrong the day you need it.** This one is generated from
  real state, carries its date, and contains NO secret — it is meant to be printed and
  stored elsewhere. When the restart order cannot be computed, the REASON is printed:
  "garage is missing" can be fixed, "the order could not be computed" cannot.
- **Comparing two computations from the SAME function can never fail.** The exposure
  screen compared manifests to `routes_from_manifest` applied to those same manifests: it
  would have shown "compliant" whatever happened. The comparison is against what was
  ACTUALLY published, versus what the manifests ask for today.
- **An orphan route appears in no walk over installed apps.** A removed app whose route
  still answers is in no manifest, therefore in no loop: look for it from the PUBLISHED
  routes, not from the apps.
- **A CSV field that is not quoted shifts every following column.** The audit log
  contains details written by humans: commas and quotes are the norm. And the line ending
  is CRLF, or Excel merges rows.
- **`*.example.org` does not cover `example.org`.** Both names must be requested.
- **Caddy's `status` matcher only exists inside a `forward_auth` block.** At site level,
  Caddy refuses to start with "module not registered".

### Interface

- **egui does not embed every glyph.** "●", the variation selector of "⚠️" and "⚑"
  render as an empty box, and a tofu looks enough like an icon to pass review. Status
  shapes are **painted**, not written, and a test scans every literal in the file
  (comments excluded).
- **A tofu can come from CONTENT, not only from literals.** The source scanner does not
  protect against an emoji in an announcement or a Sieve folder name. The sanitiser
  replaces with a visible character — removing it would make text silently disappear,
  which is worse.
- **Shared text must depend on NONE of its consumers.** Coherence messages carried a 🔴:
  fine in a terminal, replaced by "¤" in egui. Severity travels through content and
  through the caller's colour, never through a glyph.
- **Serving wasm requires `Content-Type: application/wasm`.**
  `WebAssembly.instantiateStreaming` refuses `application/octet-stream` with a message
  that does not say what it expected.
- **The `wasm-bindgen` binary must match the crate version EXACTLY.** A mismatch produces
  a bundle that loads and panics on the first function.
- **A stale response must be DISCARDED, not adopted.** A request abandoned on timeout can
  arrive afterwards: without a turn number it would be consumed as fresh and the screen
  would date minutes-old data as now.
- **A palette may not make states indistinguishable.** Traffic-light green and red
  converge under deuteranopia (distance 35, 60 needed): the two most important indicators
  were indistinguishable for 8 % of men. Green is shifted toward cyan and the accent is
  **cool** — the initial copper read as "critical". Not taste, a constraint, and the
  palette validator enforces it.
- **Each quantity has its own colour thresholds.** Seen on screen: with the CPU scale, a
  swap at 71 % showed GREEN — a machine already swapping 70 % is crawling. Sharing one
  hue function across CPU, memory and swap is an economy that lies.
- **Without `set_width`, each egui card takes the width of its CONTENT.** A list of cards
  becomes a staircase whose right edge follows text length. Invisible in the code,
  obvious on screen — hence a test scanning containers.
- **A written screen absent from navigation is wasted work.** The secrets screen existed
  and was reachable only by typing the URL. A test now crosses implemented screens with
  navigation entries.
- **Never offer a screen that does not exist.** An entry leading to "coming soon"
  promises, you click, you get nothing, and you doubt the rest.
- **A written screen deliberately out of navigation deserves its own test.** Otherwise
  the "every written screen is reachable" rule eventually adds an entry for it.
- **A screen can compile and PANIC AT RENDER.** An out-of-bounds index in a display loop
  only shows when you open the screen — and out of twenty screens, the broken one is
  rarely the one you look at. `Context::run` renders them all offscreen, empty and
  narrow. Purely VISUAL defects, on the other hand, were all found by looking at a
  screenshot, never by comparing two images.
- **A QR code is painted, not written.** No font is involved, therefore no tofu. The
  module must be a WHOLE number of pixels — fractional, egui smooths the edges, squares
  blend and the code becomes unreadable to a scanner while looking crisp to the eye. The
  4-module quiet zone is mandatory: it is the most frequent cause of a QR that "only
  works on some phones".
- **Kiosk mode is an ALLOWLIST of screens, never a denylist.** A wall is visible to
  anyone in the room; you cannot enumerate what will be sensitive tomorrow, you can
  enumerate what is harmless today. A screen added later is excluded by default.
- **🔴 The service worker NEVER caches the API.** A data cache would resurrect exactly
  the lie freshness exists to prevent: green apps served from cache while the cluster
  burns. A test scans `sw.js` and refuses `/api/`, `/auth/` and `/metrics`.
- **Confirmation comes from the PREVIEW, never fabricated by the interface.** The server
  says which target must be confirmed; the interface repeats it after the user has read
  what it destroys. Two states to keep in sync would eventually diverge.
- **Three beats, not two.** A button followed by a generic "Confirm?" says nothing about
  what is going to happen: you click by reflex and the protection stops protecting. The
  confirmation is about **the plan**.
- **Scaling to zero replicas is not a resize, it is a shutdown.** Refused from a numeric
  field, where it never happens on purpose.
- **A warning is NOT a blocker.** "This link will let five people in" filed under blockers
  made the action impossible — while it is a legitimate choice you simply want to see
  first. Two distinct fields, two shapes on screen.
- **An invitation is NOT kept in local storage**, unlike the access token: it is used once,
  and a shared browser would offer it to the next person — whose account would then carry
  the role meant for someone else.
- **An invitation for N uses that leaks lets N people in.** The default stays 1, the
  remaining count is displayed, and a widely open link stands out visually — that is the
  one you forget to close.
- **Revoking an invitation EXHAUSTS it, does not delete it.** Deleting it would lose the
  trace of who created it and who already came in, at the exact moment you need it.
- **An invitation refused for a typo must NOT be consumed.** The name is validated first,
  or a single-use link is wasted on a capital letter.
- **The role and the profile are fixed at INVITATION time**, never chosen by the invitee:
  otherwise anyone would sign up as an administrator.
- **The sign-up screen has NEITHER navigation NOR a session header.** It addresses
  someone with no account: offering "Dashboard" would send them to a refusal, and showing
  the identity of whoever opened the link would be confusing at best.
- **An incident is FOLLOWED, not rewritten.** It is the chronology you re-read
  afterwards. And it stays open until someone closes it: silence must not pass for a
  resolution.
- **An announced maintenance is not an outage.** It was planned, and showing it as an
  outage sends people looking for what is wrong.
- **An announcement that does not concern its reader is noise.** Flooding a portal user
  with operational messages makes them stop reading — exactly when one will matter. Hence
  audience by role.
- **The status page is PRIVATE by default.** Published, it reveals the list of what runs
  at your place and the calendar of your outages. Open, it shows only **exposed**
  services — never nodes, backups or accounts.
- **The status page requires ReadSelf, not Read.** It is made for the people suffering
  the outage, not those operating it: requiring a console right would remove it from the
  portal, which is where people look for it.
- **Homelabus ANNOUNCES applications, it does not grant access.** That comes from
  PocketID and forward-auth. And a link to a stopped app leads to an error page people
  read as a permissions problem.
- **A preview is logged as `preview`, not `ok`.** Knowing someone looked at what a purge
  would do is information; confusing it with an execution would make the log useless.
- **An unreachable node must show NO gauge.** It does not have bad numbers, it has none:
  bars at zero would read as "idle machine". Show the reason and stop there.
- **The theme is a NAME, not a palette.** A palette stored per person would survive the
  removal of the theme it came from, and you could no longer evolve it.
- **"The installation's own" is a distinct option**, not the absence of a choice: whoever
  picks it says "follow the brand", and their theme changes if the administrator changes
  the default.
- **An unknown theme is REFUSED, not silently accepted.** Accepted, it would be stored,
  fall back to the default on display, and you would think the choice was lost to a bug.
- **The theme list lives on the server.** With one on each side, a removed theme would
  keep being offered until the next wasm deploy. A test keeps them aligned.
- **The action panel lives in the dispatcher, not in a screen.** It used to be in the app
  detail: a preview triggered from the accounts screen fired with nothing displayed, and
  the click looked inert.
- **The request to apply is rebuilt from the PREVIEW**, never from state kept alongside:
  two sources would eventually diverge and you would apply something other than what you
  just read. An unrecognised action falls back to nothing — it returns 404, which shows.
- **A dead route is invisible.** `/api/apps/{name}` existed with no caller. A test crosses
  declared routes with what the interface actually requests; routes served to other
  clients (Bitwarden, the watchdog, the CLI) are listed explicitly — a decision, not an
  oversight.
- **A wizard not tried end to end ships something false.** The Bitwarden wizard bound the
  MAILBOX and not the ACCOUNT: its token was refused by the alias API, with six
  reassuring steps sending you to look at Bitwarden. Found by actually calling
  `/api/v1/aliases` with the token it produced.
- **A demo that invents its own names teaches a false convention.** That is what let a
  secret-naming defect go unnoticed.
- **Secret name suffixes are read from the resolver, not from memory.** Two kinds were
  inferred from guessed conventions (`-s3-key` instead of `-s3-secret`): the rule never
  fired, and the screen stayed silent about exactly the secrets that matter.
- **An age in days is not displayed in seconds.** "Verified 0 s ago" for a drill counted
  in whole days reads as "just now" when it may date from last night. The type carries
  its resolution, or the display invents a precision that does not exist.

## Repository hygiene

🔴 **`hlb-master.key` was tracked by git from 2026-08-16 to 2026-08-21**, although the
file carries "DO NOT COMMIT" in its own header. Fixed on 2026-08-21, before publication:
removed from the index and added to `.gitignore`, history purged with `git-filter-repo`
(no blob in the repository contains `AGE-SECRET-KEY-1` any more), and the key rotated.
The old key had never been pushed — the remote only ever held the shell prototype — so
it was never public.

⚠️ **There is no `hlb secrets rekey`.** The vault was empty, so rotation reduced to
generating a key. With a populated vault you would have to decrypt each entry with the
old key and rewrite it with the new one — to be written the day it comes up, and treated
as an ordered procedure, not a file write.

⚠️ **`PLAN.md` is local only and not committed.** It holds the long-form architecture
notes. Do not add cross-references to it from code or documentation: a reader of the
public repository cannot follow them.

## What is left

Verified on 2026-08-21: `cargo test --workspace` passes (**1370 unit tests, 66
integration `#[ignore]`d**) and `cargo clippy --all-targets` is at zero warnings.

### 1. Finish translating the codebase to English

Comments and displayed strings were French until 2026-08-21. Documentation and
repository files are translated; **the code is not finished**. Roughly 13 900 comment
lines and 2 500 lines carrying accented display strings across 174 files.

Two parts are not a translation but a redesign:

- **`hlb_api::plural`** encodes "0 replica" as singular, a French rule. In English zero
  takes the plural, so the function and its tests invert.
- **The tests that scan displayed strings** (the "action(s)" ban, the two-consecutive-
  spaces check, the tofu scanner) assert on French text and must follow.

Do it crate by crate, keeping the reasoning rather than the wording, and run the suite
after each one. A half-translated codebase is worse than either language.

### 2. Real executors for four action routes

Four routes build a correct preview, then return `Unimplemented` with the reason instead
of acting. Honest, but these are the four gestures you want from the interface.

| Action | What is missing | Where |
|---|---|---|
| install an app | vault + orchestrator + platform clients in shared state | `hlb-controller/src/actions.rs` |
| run a backup | the restic repository lives in the controller loop | `hlb-controller/src/actions.rs` |
| drain a node | `Orchestrator` exposes labels, not availability | `hlb-controller/src/actions.rs` |
| delete an app | orchestrator + executor | `hlb-controller/src/actions.rs` |

**Draining is the easiest** — one method on the `Orchestrator` trait, facing
`docker node update --availability`. **Installing is the most structural**: it needs the
API to share the context the CLI already assembles, and the rest follows.

⚠️ Do not "wire" it by shelling out to the CLI: the plan would be recomputed instead of
replayed, and you would execute something other than what was previewed.

### 3. Three declared, unwritten screens

`Route::implemented()` keeps them out of navigation, so nothing lies on screen. They are
still missing: **`MyMailbox`** (self-service aliases — the API, quotas and roles are in
place; this is what would make aliases usable by someone other than the administrator),
**`MyAccount`**, and **`Catalog`** (already exposed by the API).

### 4. 🔴 Nothing in the mail path is verified against a real Stalwart

`hlb-mail` was written from upstream source, never executed against an instance. To
prove when one is available: the `/jmap/upload/{accountId}/` path, the shape of
`onSuccessActivateScript`, the `/jmap/download/` format, and `x:Account/get` on
`aliases`. **MariaDB dumps** are in the same state (simulated runner). This needs an
instance, not code.

### 5. The rest, in decreasing order of interest

- **`hlb db failover`**: assisted switchover. No occurrence of "failover" in the
  workspace today. Replication works and is verified against a real pair; the command is
  missing, and a second real `heavy` node to exercise it.
- **`hlb secrets rekey`**, see above.
- **`hlb user mailbox add` does not open the Stalwart account** — it only records it. And
  IMAP ACLs (which Stalwart implements) would allow seeing several mailboxes under ONE
  connection instead of configuring three.
- **`hlb self update`** awaits a distribution URL. Ed25519 verification and the binary
  swap are done and tested.
- **The catalog**: 11 apps and 12 platform services today.
- **Garage multi-node** goes through `garage layout`, not `replicas`.
- **No TUI wizard** for `hlb cluster init`.

### Ruled out, and not coming back

- **mailcow** and the `compose` runtime. Stalwart replaces it entirely.
- **OpenAPI `utoipa` + TypeScript generation**: moot since choosing egui.
- **`docker-compose.yml` import**: ruled out from the start, greenfield context.
- **`egui_kittest`**: the image-snapshot variant needs a GPU, and the light variant
  enables egui's `accesskit` feature, which breaks `egui-winit` 0.33.3 compilation.
  `Context::run` runs windowless and catches what matters: a screen that panics at
  render.
