# Homelabus

[![CI](https://github.com/Turi-Industries/Homelabus/actions/workflows/ci.yml/badge.svg)](https://github.com/Turi-Industries/Homelabus/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Self-hosting platform for a Docker Swarm cluster: app deployment, shared databases,
SSO, reverse proxy, backups and automatic updates — with one rule running through all
of it.

> **An absence must never look like a success.**

That is the whole design. A missing backup does not report zero, it reports nothing. A
provisioning step the executor cannot perform is recorded as *unimplemented*, never as
done. A stale dashboard says so instead of showing yesterday's green. Most of this
codebase is the difference between "nothing is wrong" and "I cannot tell".

---

## The central idea: a capability resolver

A manifest never says "connect to `postgres:5432`". It declares a **need**:

```yaml
requires:
  - kind: database
    engine: postgres
  - kind: sso
    mode: native
    redirectPaths: ["/user/oauth2/PocketID/callback"]
```

The resolver turns needs into concrete actions: create the database and an isolated
role, generate the password, register an OIDC client whose redirect URIs are computed
from the domain chosen at install time. The same manifest works whatever the real
topology is.

`Capability` is an exhaustive enum. Adding a variant breaks compilation everywhere a
`match` must be updated — that is the main reason this is written in Rust.

### The flow

```
catalog/*/manifest.yaml
   ↓  hlb-catalog       load, validate, check folder name == metadata.name
Manifest (hlb-types)
   ↓  hlb-resolver      capability resolution + dependency graph
Plan { actions: Vec<Action> }
   ↓  hlb-engine        execution: preview by default, idempotent, resumable
hlb-orchestrator        trait Orchestrator → bollard → Docker Swarm
   ↕  hlb-state         frozen manifest + progress journal (SQLite)
```

Swarm has no `depends_on`: it starts everything in parallel, and an app that comes up
before PostgreSQL crash-loops. The resolver derives the dependency graph from the
declared `requires` and emits a topological order. Adding a platform service to the
catalog updates the graph automatically — there is no hand-maintained list.

---

## Status

Everything below is implemented and tested: **1370 unit tests, 66 integration tests**
(the latter `#[ignore]`d — they need Docker, a network, or a live controller), and
`cargo clippy --all-targets` stays at zero warnings.

| Crate | What it does | Tests |
|---|---|---|
| `hlb-types` | Manifests, capabilities, bindings — the single schema definition | 69 |
| `hlb-catalog` | Loading and validation | 9 |
| `hlb-resolver` | Capability resolution, dependency graph, plan | 26 |
| `hlb-engine` | Executor and reconciliation | 28 |
| `hlb-orchestrator` | `Orchestrator` trait and its Swarm implementation | 24 + 11 |
| `hlb-state` | Persistent state, resume, secrets, accounts (sqlx/SQLite) | 87 |
| `hlb-secrets` | `age` vault, password generation | 11 |
| `hlb-platform` | Isolated PostgreSQL and MariaDB provisioning | 14 + 11 |
| `hlb-ingress` | Caddyfile, CrowdSec, forward-auth, ACME wildcard | 40 + 7 |
| `hlb-registry` | Digest resolution, version policy | 28 + 6 |
| `hlb-updater` | Release watch, windows, rollback, Trivy + cosign | 30 |
| `hlb-backup` | restic, PITR, SQLite, DR drills, replication, destinations | 207 + 17 |
| `hlb-identity` | PocketID: OIDC provisioning and human sign-in (PKCE) | 17 + 4 |
| `hlb-mail` | Stalwart client (JMAP): mailboxes, aliases, Sieve | 16 |
| `hlb-users` | Accounts, mailboxes, aliases, quotas, Sieve, addy.io API | 51 |
| `hlb-guide` | Verification and automation of manual steps | 16 |
| `hlb-gitops` | Git mirror of the desired state | 10 |
| `hlb-bootstrap` | Distributions, prechecks, managed SSH access | 78 + 4 |
| `hlb-agent` | Node telemetry, disk thresholds, PKI + mTLS | 61 |
| `hlb-mesh` | WireGuard keys, addressing, configuration | 23 |
| `hlb-metrics` | Alert rules, scraping, deadman switch | 31 |
| `hlb-notify` | ntfy: levels, quiet hours | 16 |
| `hlb-objstore` | Garage client: isolated buckets and keys | 6 |
| `hlb-selfupdate` | N/N+1 compatibility, sequencing, rollback | 44 |
| `hlb-api` | API types, defined once for both server and UI | 97 |
| `hlb-controller` | Daemon: API, RBAC, chained audit log, background loops | 185 + 3 |
| `hlb-ui` | 20 egui screens: native, web, phone, PWA, kiosk | 146 + 3 |
| `hlb-cli` | 28 commands | — |

---

## Quick start

```sh
cargo build

./target/debug/hlb catalog list
./target/debug/hlb order                          # deployment order
./target/debug/hlb plan gitea --domain git.example.org

./target/debug/hlb install valkey                 # preview — changes nothing
./target/debug/hlb install valkey --apply         # actually runs
```

Most commands need state and a vault. To try things without touching a real install:

```sh
export HLB_STATE=/tmp/try.db HLB_MASTER_KEY=/tmp/try.key
```

> 🔴 **The master key is created on first use.** Losing it makes every secret and every
> backup unrecoverable — keep two offline copies. It is in `.gitignore`; it must never
> enter a repository.

> ⚠️ **On macOS (colima or Docker Desktop), `DOCKER_HOST` is mandatory.** `bollard`
> looks for `/var/run/docker.sock`, which does not exist there, and every Docker-facing
> command fails with `SocketNotFoundError`.
>
> ```sh
> export DOCKER_HOST=$(docker context inspect -f '{{.Endpoints.docker.Host}}')
> ```

---

## The web UI

20 screens in [egui](https://github.com/emilk/egui): the same code runs natively, in a
browser through WebAssembly, and on a phone as an installable PWA. `hlb-api` defines the
API types **once** for both the server and the interface — there is no OpenAPI, and
there will not be one.

The fastest way to see it, with no cluster and no Docker, is **demo mode**. It fills an
in-memory database with the cases you never have on hand: an app that was never backed
up, an off-site destination dead for three weeks, an expired alias still receiving mail,
a half-created account in both directions.

```sh
./target/debug/hlb-controller --demo --listen 127.0.0.1:8420 &
./target/debug/hlb-ui --url http://127.0.0.1:8420 --route /apps
```

For the browser build:

```sh
crates/hlb-ui/build-web.sh          # size budget enforced: 6 MB
./target/debug/hlb-controller --demo --ui-dir crates/hlb-ui/web
```

What the UI does that the CLI cannot:

- **Topology.** Nodes grouped by **failure domain**, and anti-affinity violations. Two
  VMs on one server are two Swarm nodes and a single point of failure — spreading two
  replicas "across two nodes" protects nothing, and Swarm returns an illusion of
  redundancy. The information lived in Swarm labels and was readable nowhere.
- **Correlation.** Recoverability ("if I lose everything right now, what comes back?"),
  a failure simulator, a causal chain from the failing task down to the full disk, a
  unified timeline of backups and actions, and **declared versus actually published**
  ingress routes.
- **Rare, dangerous operations.** Guided secret rotation (the vault is *not* the source
  of truth for a password), break-glass with dated attestations that expire, a printable
  runbook generated from real state and containing no secrets, and named plans prepared
  cold then replayed **exactly as previewed**.

> 🔴 **Stale data must never look fresh.** If the controller dies, the UI would happily
> keep its last known state: every app green while the cluster burns. `Resource<T>`
> carries its own freshness and the type forces you to handle it — and the PWA service
> worker never caches the API.

---

## Backups: the 3-2-1 rule, made real

Routing is by **volume class**, not by importance: everything is important, but not
everything fits through a home connection.

```sh
hlb backup dest add nas     --location /mnt/nas/restic --classes critical,bulk
hlb backup dest add garage  --location s3:http://garage:3900/hlb --classes critical
hlb backup dest add offsite --location s3:https://s3.example.com/repo \
  --classes critical,bulk --access-key <key>   # the secret is read from STDIN

hlb backup route immich  --critical nas,garage,offsite --bulk nas,offsite
hlb backup status        # per destination, never aggregated
hlb backup run --force
```

> 🔴 **Freshness is measured per destination.** Aggregating made an off-site copy dead
> for three weeks look like a two-hour-old backup, because the NAS was still running.
> You would believe 3-2-1 held while a single copy remained, on the same machines.

A failure on one destination never starves the others, each has its own deadline, and
consecutive failures are counted — a destination that fails every time would otherwise
look "fresh" for twelve hours.

---

## Accounts and aliases

```sh
hlb user add remy --email remy@example.org   # PocketID identity + mailbox, in one go

# Three independent axes: lifetime, generated or chosen name, site hint
hlb user alias add remy                            # random, permanent
hlb user alias add remy --for amazon               # random, tied to a site
hlb user alias add remy --for fnac --for-days 30   # disposable and attributable
hlb user alias add remy --alias-name contact       # chosen, permanent

hlb user alias list remy --problems   # expired but STILL ACTIVE
hlb user alias purge --apply          # what makes expiry real
hlb user alias sieve remy --apply     # install sorting rules in Stalwart
```

> 🔴 **A mail server cannot expire an alias.** A Stalwart account's alias list carries
> no dates: what is written there stays. A "temporary" alias is only temporary if a
> purge actually removes it — so there are **three** states, not two: valid,
> expired-and-removed, and expired-but-still-receiving. The controller runs the purge
> hourly, because a promise that depends on someone remembering a command is not one.

The point of a disposable alias is not disposal, it is **attribution**: one address per
recipient tells you *who* leaked it. So the readable hint is kept — fifty purely random
addresses would lose the only real benefit — and always followed by a random suffix,
because a guessable alias undoes the whole compartmentalisation.

### Generating aliases from Bitwarden

Homelabus speaks the addy.io protocol, which Bitwarden knows how to call:

```sh
hlb token create bw-personal --user remy                  # → default mailbox
hlb token create bw-photo    --user remy --mailbox photo  # → "photo" mailbox
```

The protocol has no field for choosing a mailbox, so the **token** carries it: one
token per mailbox.

> ⚠️ A token without `--user` is a **service** token: it cannot create aliases on
> anyone's behalf, even with the `admin` role. Privilege does not substitute for
> identity.

---

## The daemon

```sh
./target/debug/hlb-controller \
  --listen 127.0.0.1:8420 \
  --agent-service hlb-agent --agent-poll-secs 60 \
  --reconcile-secs 60 --reconcile-apply \
  --backup-repo hlb-repo --backup-check-secs 600 \
  --heartbeat /mnt/nas/hlb-heartbeat
```

The heartbeat goes **outside the cluster**: the controller is what sends alerts, so
nothing would warn you if it died.

> 🔴 **The heartbeat is conditional, not periodic.** It only fires if the state database
> answers and Docker answers. A plain timer would prove a thread is alive, nothing more
> — the controller could have an unreadable database and a dead orchestrator and keep
> beating, leaving the watchdog green over an unusable system. That is worse than no
> deadman at all, because you trust it.

The watchdog script is generated and installed **on the NAS**, on a ntfy topic distinct
from the cluster's — if the controller is dead, the watchdog alone must be able to
speak:

```sh
hlb metrics deadman --ntfy https://ntfy.sh/my-watchdog > watchdog.sh
#   */5 * * * * /srv/hlb/watchdog.sh
```

---

## Development

```sh
cargo test                      # unit tests, no Docker
cargo clippy --all-targets      # must stay at zero warnings
cargo fmt --all
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for the invariants and the style rules. The
integration suites are opt-in:

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
```

---

## Catalog

11 applications and 12 platform services.

**Apps** — Gitea, Vikunja, Vaultwarden, n8n, Jellyfin, LibreSpeed, Termix, Immich (with
its machine-learning companion), Seafile CE (three databases, one role), Bulwark and
Roundcube.

**Platform** — PostgreSQL, MariaDB, Valkey, PocketID, Stalwart, Caddy, CrowdSec,
oauth2-proxy, ntfy, VictoriaMetrics, Grafana, Garage.

Two webmails is deliberate: Bulwark speaks JMAP natively to Stalwart, and Roundcube is
the safety net — intentionally **without** SSO, so it stays reachable when PocketID is
down.

---

## Known limitations

These gaps are explicit in the code, never masked. An absence that would look like a
success is treated as a defect, not a shortcut.

### Not verified against a real server

- 🔴 **The entire mail path.** `hlb-mail` was written from Stalwart's source but has
  **never run against a live instance**. Still to be proven: the
  `/jmap/upload/{accountId}/` path, the shape of `onSuccessActivateScript`, the
  `/jmap/download/` format, and `x:Account/get` on `aliases`. This is weaker than
  PostgreSQL replication, which *is* verified against a real primary/standby pair.
- **MariaDB dumps** go through a simulated runner, for the same reason.

### API actions not yet wired

The UI previews these four correctly — the plan shown is the real one, produced by the
resolver — but execution returns `Unimplemented` with its reason and points at the
command to run. Never a false success.

| Action | What is missing |
|---|---|
| Install an app | Vault, orchestrator and platform clients in the API's shared state |
| Run a backup | The restic repository lives in the controller loop, not the API state |
| Drain a node | `Orchestrator` does not expose availability, only labels |
| Delete an app | Orchestrator and executor |

Everything else in that batch acts for real: attesting a guide, declaring a destination,
scaling, all settings, and account management.

### Missing features

- **No self-service aliases.** Users go through the CLI or the addy.io API; the
  `MyMailbox` screen is unwritten. Two other screens are in the same state, `MyAccount`
  and `Catalog`. They are **absent from navigation** until they exist — offering a
  screen that leads nowhere is worse than not offering it.
- **`hlb secrets rekey` does not exist.** Rotating the master key of a populated vault
  would mean decrypting every entry with the old key and rewriting it with the new one.
  Generating a fresh key, on the other hand, happens on first use.
- **`hlb user mailbox add` does not open the Stalwart account**, it only records it.
  IMAP ACLs — several mailboxes under one connection — are not wired.
- **`hlb db failover` does not exist.** Replication works and is verified; the
  switchover is still manual and needs a second real `heavy` node to be exercised.
- **Garage multi-node** goes through `garage layout`, not `replicas`: a single instance
  as long as there is one storage node.
- **No `docker-compose.yml` import** — ruled out from the start, greenfield context.
- **No TUI wizard** for `hlb cluster init`: the command exists and is idempotent,
  without the guided experience.

### Deliberate choices

- **Reconciliation does not correct by default**: `--reconcile-apply` must be asked for.
  A system that over-corrects is more dangerous than one that corrects nothing.
- **`Verify::Exec`** is reported as unverified, never as successful.
- **Without a configured repository, any update requiring a backup is refused.** Same if
  the app has no known volume: "nothing to back up" never means "backup succeeded".
- **`Unimplemented` is never `Done`.** Without a vault, without PostgreSQL, without
  Stalwart, the action is recorded as unimplemented — never simulated.
- **Bulwark is pinned** (`channel: pin`): no Git releases, no declared license, only
  images exist.
- `age` pulls in `proc-macro-error2`, flagged as incompatible with a future Rust. It is
  a transitive dependency; nothing to do on our side.

---

## The bollard spike

`bollard` was identified up front as the project's main risk — less battle-tested than
the Go SDK on the Swarm surface. Seven questions had to be settled before writing
anything else.

| # | Question | Result |
|---|---|---|
| 1 | Daemon and Swarm reachable | ✅ |
| 2 | Service creation and replica convergence | ✅ 2/2 tasks |
| 3 | Placement constraints | ✅ satisfiable **and** unsatisfiable both handled |
| 4 | Image update with concurrency control | ✅ |
| 5 | 🔴 **Automatic rollback on a failed update** | ✅ `RollbackStarted`, service never went down |
| 6 | Label filtering — never touch what we do not manage | ✅ |
| 7 | Typed errors rather than panics | ✅ `NotFound` |

**No fallback to the raw HTTP API is needed.** Point 5 is the important one: it proves
`failure_action: rollback` + `order: start-first` genuinely work, which is the only
thing that makes it acceptable to let a system update your services at 3 a.m.

---

## License

[MIT](LICENSE).
