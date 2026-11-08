# Operating an installation

The interface, backups, storage, accounts and the daemon: what each does, and the
commands behind it. Every verb is in [cli-tour.md](cli-tour.md) with an example.

## The web UI

A SvelteKit single-page app in `web/`, served by the controller itself. The contract
between the two is the controller's OpenAPI document, generated from the Rust types and
served at `/api/openapi.json` (a copy is committed as `web/openapi.json`) — the
TypeScript is generated from it, never written by hand, and every business rule stays
in Rust: the interface receives verdicts as values and only chooses how to say them.

It is organised by the question you come with, not by endpoint:

- **Home** — what needs you: every item any module judges not `ok`, merged when two
  report the same application, critical first. Below it, cards you pin and order; the
  arrangement follows you from one device to the next.
- **Seven modules** — Applications, Infrastructure, Data, Security, Activity, People,
  Settings — and **Me**, which is the whole interface for an account that only has a
  mailbox. `Ctrl+K` finds any page, application or machine.
- **One action panel** for everything that changes something: the controller's preview
  first, then the plan, then — for what destroys — the target's name typed back.
- Outside the console: the status page (`/uptime`), a wall display (`/kiosk`) and the
  sign-up an invitation leads to.

The fastest way to see it, with no cluster and no Docker, is **demo mode**. It fills an
in-memory database with the cases you never have on hand: an app that was never backed
up, an off-site destination dead for three weeks, an expired alias still receiving mail,
a half-created account in both directions.

```sh
./target/debug/hlb-controller --demo --listen 127.0.0.1:8420 &
curl -s http://127.0.0.1:8420/api/apps
```

The interface, built with [Bun](https://bun.sh) and served by the same controller:

```sh
(cd web && bun install && bun run build)
./target/debug/hlb-controller --demo --insecure-no-auth --ui-dir web/build \
    --listen 127.0.0.1:8420
# then http://127.0.0.1:8420/ — and /uptime, /kiosk
```

What the interface is for — what it shows that the CLI cannot:

- **Topology.** Nodes grouped by **failure domain**, and anti-affinity violations. Two
  VMs on one server are two Swarm nodes and a single point of failure — spreading two
  replicas "across two nodes" protects nothing, and Swarm returns an illusion of
  redundancy. The information lived in Swarm labels and was readable nowhere.
- **Correlation.** Recoverability ("if I lose everything right now, what comes back?"),
  a failure simulator, a causal chain from the failing task down to the full disk, a
  unified timeline of backups and actions, and **declared versus actually published**
  ingress routes.
- **Rare, dangerous operations.** Guided secret rotation (the vault is *not* the source
  of truth for a password), break-glass with dated attestations that expire — three
  of them proved by Homelabus itself: a restore drill, the emergency vault's deposit, a
  current kit —, a printable runbook generated from real state and containing no
  secrets, and named plans prepared
  cold then replayed **exactly as previewed**.

> 🔴 **Stale data must never look fresh.** If the controller dies, an interface would
> happily keep its last known state: every app green while the cluster burns. Every
> resource the interface shows carries when it was received, the outage is shown rather
> than papered over, and the service worker never caches the API.


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

### A copy an intruder cannot reach

Whoever takes the cluster holds every credential it backs up with. The copy that
survives is on a destination that credential cannot erase, and `hlb backup dest prove`
says which ones are: it writes a witness with the destination's own credential, then
tries to delete it with that same credential.

| Destination | Out of reach when | Proven by |
|---|---|---|
| a directory | never — the machine's root erases it | — |
| `rest:` | the REST server runs `--append-only` | `restic forget` of a witness snapshot, refused |
| `s3:` | the bucket is versioned, and the credential is DENIED `s3:DeleteObjectVersion` | deleting the witness's version, refused, then reading it back |

Garage keeps no versions, so the cluster's own Garage is never out of reach. On MinIO,
leaving `s3:DeleteObjectVersion` out of a policy is not enough: `s3:DeleteObject`
deletes versions too, and only an explicit `Deny` stops it — tried, and why the proof
tries rather than reads the policy. A lifecycle rule expiring old versions would still
erase them; the proof does not try that one, since trying writes a rule.

The weekly upkeep prunes a destination to the retention policy only where the proof,
taken in the same pass, says it is erasable — forgetting snapshots is what an intruder
holding the credential does. One out of reach is pruned by its owner, never on a
schedule from the cluster: `hlb backup dest prune-script <name>` prints the upkeep's
own `restic forget` passes as a script, holding no secret, to run with a credential that
may delete and the repositories' password from the emergency kit.

### What a restore brings back

`hlb backup restore` takes only a snapshot Homelabus took itself. One someone else
wrote into the repository — with its password, after an intrusion, dated in 2099 so
that it is "the latest" forever — is set aside, and the preview says so; naming it by
its full id restores it, since restic's id is the hash of the snapshot.

And what a volume holds is data, never what an app runs: Gitea rebuilds `app.ini`
from its environment at every start, removes `custom/`, and keeps each repository's
hooks and config to its own; Vaultwarden reads its `config.json` from outside its
volume. A recovery drill restores a database onto a server with no network, archiving
and replicating nothing, and starts no application on it — a restored n8n would run
its workflows against the real world.


## Storage: where an app's bytes actually land

A manifest declares a **tier**, not a path:

```yaml
- kind: storage
  name: data
  path: /data
  tier: nfs        # or: local
```

On a node carrying a ZFS pool, that declaration becomes real:

```sh
hlb node add big-01 --storage-node --apply   # + ZFS, + the NFS server
hlb storage init --apply                     # import the pool, one dataset per volume
hlb storage export --network 10.0.0.0/24     # the /etc/exports lines, printed

export HLB_STORAGE_ROOT=/tank/apps           # tier: local -> bind mounts on the pool
export HLB_NFS_SERVER=10.0.0.2               # tier: nfs
export HLB_NFS_EXPORT=/tank/apps
```

> 🔴 **A tier this installation cannot provide stops the install.** A `tier: nfs` volume
> quietly given a local Docker volume takes the uploads and loses them on the next
> redeployment — and the app is healthy the whole time. The refusal happens at preview,
> before the manifest is frozen.

`tier: local` falling back to Docker's own directory is fine, and the asymmetry is the
point: *this node owns it* is satisfied by anything local; *this does not fit here* is
satisfied by nothing local.

**A pool is never created for you.** `zpool create` writes labels to the disks with no
confirmation and no way back, so the command is printed with the disks left to you —
by `/dev/disk/by-id/`, never `/dev/sdX`, which is assigned at boot. Importing one *is*
offered, because `zpool export` undoes it.


## Accounts and aliases

```sh
hlb user add lena --email lena@example.org --role standard --apply   # PocketID identity + mailbox
hlb user quota lena immich --gib 500 --apply   # their own quota, over their role's

# Three independent axes: lifetime, generated or chosen name, site hint
hlb user alias add lena                            # random, permanent
hlb user alias add lena --for amazon               # random, tied to a site
hlb user alias add lena --for fnac --for-days 30   # disposable and attributable
hlb user alias add lena --alias-name contact       # chosen, permanent

hlb user alias list lena --problems   # expired but STILL ACTIVE
hlb user alias purge --apply          # what makes expiry real
hlb user alias sieve lena --apply     # install sorting rules in Stalwart
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
hlb token create bw-personal --user lena                  # → default mailbox
hlb token create bw-photo    --user lena --mailbox photo  # → "photo" mailbox
```

The protocol has no field for choosing a mailbox, so the **token** carries it: one
token per mailbox.

> ⚠️ A token without `--user` is a **service** token: it cannot create aliases on
> anyone's behalf, even with the `admin` role. Privilege does not substitute for
> identity.


## The daemon

```sh
./target/debug/hlb-controller \
  --listen 127.0.0.1:8420 \
  --agent-service hlb-agent --agent-poll-secs 60 \
  --reconcile-secs 60 \
  --backup-repo hlb-repo --backup-check-secs 600 \
  --heartbeat /mnt/nas/hlb-heartbeat
```

Run so, one process holds both sides. Deployed, they are apart (`hlb fleet
controller`): the same flags go to `hlb-privd --socket <dir>/privd.sock --web-uid
<uid>`, and the web side is `hlb-controller --privd-socket <dir>/privd.sock`, reading
`--state` read-only.

The heartbeat goes **outside the cluster**: the daemon is what sends alerts, so
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

The catalog's ntfy refuses anyone without an account. The controller publishes as
`homelabus` and the watchdog as `watchdog`, both generated at ntfy's install; the
script carries its account (keep it `chmod 600`) and hands it to curl on standard
input, never on the command line. A phone subscribes as `reader`:
`hlb secret-get ntfy-reader-password`.

The manifests' assertions are read once a day (`--assertions-secs`, default 86400); their
scheduled jobs are looked at every hour (`--jobs-secs`, default 3600), each run when due.
