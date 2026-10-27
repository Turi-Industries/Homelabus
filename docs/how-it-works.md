# How Homelabus works

The design, from a manifest's needs to what runs. For the commands, see
[cli-tour.md](cli-tour.md); for running an installation, [operating.md](operating.md).

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

### What an app must keep true

Configuration closes a door; nothing proves it stays closed. A variable removed by hand,
a setting brought back by a restore, an app's own settings page — the files say one
thing and the app does another. So a manifest also declares what the running app must
keep true, and the controller reads it back **by its effect**, every night:

```yaml
assertions:
  - id: signups-closed
    holds: nobody opens a vault here without PocketID or an invitation
    check:
      type: http                 # the app's own endpoint, on the overlay
      path: /api/config
      pointer: /settings/disableUserRegistration
      equals: true
  - id: no-default-admin
    holds: the image's default administrator me@example.com does not exist
    check:
      type: sql                  # one SELECT, in a read-only transaction
      database: ccnet_db
      query: SELECT count(*) FROM EmailUser WHERE email = 'me@example.com'
      equals: "0"
```

A third kind reads the environment the running task was really started with. A door
found open is a critical line in the inbox and a notification; an assertion never read,
or not for two days, is reported unknown — never fine. `hlb assert` reads them now.

And no app is left where the first visitor becomes the administrator: a first-run
wizard (n8n's owner, Jellyfin's administrator) is run by the guide's `api` step at the
install, after the app is healthy and before any route exists, with a password
generated into the vault — `hlb secret-get <app>-admin-password` prints it.

Each of those passwords is also where an owner looks for it the day PocketID signs
nobody in: in Vaultwarden. A manifest declares its recovery sign-ins (`recovery:` — the
secret, the name it goes with), and every night Homelabus writes them into the
household organisation's "Server" collection, as a member that sees that collection and
nothing else — checked before anything is written, with its own second factor. What
restores the vault itself — the master key, the backup repository's password, each
destination's credentials — goes on a printed emergency kit (`hlb emergency kit`), which
stops counting the day a rekey or a new destination makes it stale.

### Work on a schedule, and what a companion answers

Some apps need work done while they run: Seafile frees the space of deleted files only
when its garbage collection runs. A manifest declares it, and the controller runs it in
the app's own container when it is due — wherever Swarm placed the app. A failed run is
tried again the next day, notified, and stays in the inbox until one succeeds:

```yaml
jobs:
  - id: gc
    does: frees the blocks no library references, and history past its 90 days
    every: week                  # or day
    command: [/scripts/gc.sh]
```

```sh
hlb job                          # every installed app's jobs, and their last run
hlb job seafile gc --apply       # now
```

A companion starts the way its image needs, with a `command` and `files` of its own as
the app has — NATS takes JetStream from its command line only. A command takes no token:
a value Homelabus fills goes in a variable or a file, never where `ps` shows it.

A companion has no route of its own. The app may hand it one path of its host —
Seafile's notification server answers `/notification`, websockets included — and that
path keeps the route's whole chain (the bouncer, the private ranges, the portal):

```yaml
ingress:
  - host: "{{ domain }}"
    port: 80
    paths:
      - { prefix: /notification, companion: notification, port: 8083 }
```

The prefix is taken off before the companion sees the request; `keepPrefix: true` hands
it the path whole, for one that answers under its full name (`/.well-known/fluxer`).

`{{ timezone }}` gives an app the installation's time zone, set once with `hlb config
timezone Europe/Paris --apply`. An app reading it cannot be installed before it is set:
Seafile writes its zone into its own settings at its first start.

### What an app may take

Every service in the catalog says what it needs of a node's memory and where it is
stopped — its companions too, each on its own:

```yaml
swarm:
  tier: heavy
  memory: { reserve: 512M, limit: 3G }
```

Swarm places a service only on a node with its reservation still free, and says
"insufficient resources" where it used to start it and let the kernel choose what to
kill. Installing compares the reservation with the largest node of the tier — what is
left there, not the sum of the tier: one service never spans two machines. The limit is
set for the app's peak, a thumbnail run or a migration, not for its rest: too low, and
it is killed under load and looks healthy between two kills.

### Where an app checks a secret

A manifest says where its app checks a password, a second factor or a token, and what
the app answers a wrong one with — read in each app's own source, since they differ:

```yaml
ingress:
  - host: "{{ domain }}"
    port: 80
    authRoutes:
      - paths: [/identity/connect/token, /api/two-factor/send-email-login]
        failsWith: 400           # Vaultwarden's refusal; most apps say 401
```

Caddy lets an address try ten a minute there, on the path as the app routes it
(`/identity/connect/%74oken` and `//identity/connect/token` are the same route to
Vaultwarden, and to the limit), and marks each line of its access log with the app's
refusal, which CrowdSec bans on (`homelabus/auth-failures`). Every route also answers
scanners' probes (`/.env`, `/wp-login.php`…) itself, refuses a write another site's page
made the browser send, cuts a client trickling its headers after ten seconds, and logs
neither headers nor query strings.

### Who enters an app

A role is data: a name, one of four permission levels (`user`, `viewer`, `operator`,
`admin`), mail limits, a storage quota per app. Each role is a group in PocketID, and
each app lets in the roles allowed into it and nobody else — a native app through its
own client's restriction, an app behind the portal at every request. **An app no role is
allowed into lets nobody in.** The manifest says the rest:

```yaml
access:
  floor: admin                      # Termix holds every machine's SSH access
  admins: { level: admin, means: "every machine's SSH access, through Termix" }
  claims:
    hlb_termix: { byLevel: { admin: admin } }   # written on each allowed role's group
```

What the app makes of a role — Gitea's administrator, Grafana's `Editor`, Immich's
quota, a Vikunja team — it reads from claims on the role's group; a quota the app only
reads when it creates an account is kept in step after by one `UPDATE` on its database
or a command in its container. An app whose administrators no claim makes — Fluxer's
is an ACL on the account — is told by command too (`admins.apply`, `grant` and
`revoke`, in its own service or one of its companions): made one when a role reaches
the level, the right taken back when it no longer does. Giving a role says first what
it opens:

```sh
hlb role set family --name Family --level user --apply
hlb role allow family immich --apply
hlb role quota family immich --gib 200 --apply
hlb user role camille admin        # lists the apps an admin role administers, then --apply
hlb role sync                      # what PocketID and the apps would be made to hold
```

Every change syncs at once; the controller puts back, every hour, what was changed
elsewhere — a group edited in PocketID, a quota changed in the app.

### The machines, in Termix

A manifest saying `access.nodes: termix` gets every node of the cluster. On each, an
account `hlb-termix` with no right beyond a shell — no sudo, no docker group; Homelabus
never writes `sudoers` — and a key Homelabus draws in memory, accepted only from the
node Termix runs on. Never Homelabus's own key, which provisions the nodes. In Termix, a
host per node, shared with the role its sign-in gives, and removed when the node leaves
the cluster. The key is deposited in the emergency vault with the rest.

```sh
hlb termix connect --apply   # once: paste an administrator's Termix API key
hlb termix sync              # preview — reads every node, writes nothing
hlb termix rotate --apply    # a new key everywhere, Termix never shut out
```

A rotation authorizes the next key beside the current one on every node, moves Termix
to it, and only then takes the former off. The controller syncs every night.

## Catalog

11 applications and 13 platform services.

**Apps** — Gitea, Vikunja, Vaultwarden, n8n, Jellyfin, LibreSpeed, Termix, Immich (with
its machine-learning companion), Seafile CE (three databases, one role), Bulwark,
Roundcube, and Fluxer (a Discord-like chat: thirteen services, four buckets, its calls
straight to the ingress's node).

**Platform** — PostgreSQL, MariaDB, Valkey, PocketID, Stalwart, Caddy, Anubis, CrowdSec,
oauth2-proxy, ntfy, VictoriaMetrics, Grafana, Garage.

Two webmails is deliberate: Bulwark speaks JMAP natively to Stalwart, and Roundcube is
the safety net — intentionally **without** SSO, so it stays reachable when PocketID is
down.

## The crates

controller — and `cargo clippy --all-targets` stays at zero warnings.

| Crate | What it does |
|---|---|
| `hlb-types` | Manifests, capabilities, bindings — the single schema definition |
| `hlb-catalog` | Loading and validation |
| `hlb-resolver` | Capability resolution, dependency graph, plan |
| `hlb-engine` | Executor, reconciliation, volume backings |
| `hlb-orchestrator` | `Orchestrator` trait and its Swarm implementation |
| `hlb-state` | Persistent state, resume, secrets, accounts (sqlx/SQLite) |
| `hlb-secrets` | `age` vault, password generation |
| `hlb-platform` | Isolated PostgreSQL and MariaDB provisioning |
| `hlb-ingress` | Caddyfile, CrowdSec, forward-auth, ACME wildcard |
| `hlb-registry` | Digest resolution, version policy |
| `hlb-updater` | Release watch, windows, rollback, Trivy + cosign |
| `hlb-backup` | restic, PITR, SQLite, DR drills, replication, failover, what proves a destination out of reach |
| `hlb-backup-run` | The one backup pass the CLI and the controller both run, restores of what it took, destination proofs, and the emergency kit |
| `hlb-identity` | PocketID: OIDC provisioning and human sign-in (PKCE) |
| `hlb-bitwarden` | Vaultwarden: an organisation's members, the emergency vault, Bitwarden's client cryptography |
| `hlb-termix` | Termix: its API, the nodes' key, the account each node holds |
| `hlb-mail` | Stalwart client (JMAP): mailboxes, aliases, Sieve |
| `hlb-users` | Accounts, roles and who enters each app, mailboxes, aliases, Sieve, addy.io API |
| `hlb-guide` | Verification and automation of manual steps |
| `hlb-gitops` | Git mirror of the desired state |
| `hlb-bootstrap` | Distributions, prechecks, managed SSH access, ZFS pools |
| `hlb-agent` | Node telemetry, disk thresholds, PKI + mTLS |
| `hlb-mesh` | WireGuard keys, addressing, configuration |
| `hlb-metrics` | Alert rules, scraping, deadman switch |
| `hlb-notify` | ntfy: levels, quiet hours |
| `hlb-objstore` | Garage client: isolated buckets and keys; the signed S3 calls of a destination's proof |
| `hlb-selfupdate` | N/N+1 compatibility, sequencing, rollback |
| `hlb-api` | API types, defined once; the interface gets them through OpenAPI |
| `hlb-controller` | Daemon: API, RBAC, chained audit log, background loops |
| `hlb-cli` | 45 commands |

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
