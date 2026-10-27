# Known limitations

These gaps are explicit in the code, never masked. An absence that would look like a
success is treated as a defect, not a shortcut.

### Not verified against a real server

- 🔴 **The entire mail path.** `hlb-mail` was written from Stalwart's source but has
  **never run against a live instance**. Still to be proven: the
  `/jmap/upload/{accountId}/` path, the shape of `onSuccessActivateScript`, the
  `/jmap/download/` format, and `x:Account/get` on `aliases`. This is weaker than
  PostgreSQL replication, which *is* verified against a real primary/standby pair.
- **MariaDB dumps** go through a simulated runner, for the same reason.

### Not exercised against real hardware

Written against parsed output and unit tests, never run on a machine that has one:

- **The ZFS path.** Reading pools, importing one, creating the datasets. The decision
  logic is tested; the shelling out is not.
- **`hlb node preseed`.** The Debian preseed refuses any system disk not named by
  `/dev/disk/by-id/` — a preseed that lets the installer pick the "largest disk" wipes a
  ZFS pool — but no netinst has been run from one yet.
- **Termix's node jobs on a real Swarm.** The script ran on real `sshd`s in containers,
  and the `chroot` with its four capabilities on a Debian root; Swarm's job path and a
  real `docker_gwbridge` did not. A node whose firewall drops what comes from a Docker
  bridge — `ufw`'s default — would shut Termix out of that node.
- **`hlb replication failover`.** It decides correctly — a lagging standby says how many
  megabytes it would drop, an unreachable primary never claims nothing was lost — but a
  real switchover needs a second `heavy` node.

### Missing features

- **A Vaultwarden organisation is made by an owner, once.** Homelabus keeps its members
  — invited and removed by role — but cannot create it, nor confirm a member: both
  encrypt the organisation's key in an owner's client. Until its id and API key are in
  the vault, the sync says "not configured". The emergency vault's collection and
  account are an owner's to make too; `hlb emergency vault` lists the steps, and
  verifies them.
- **Termix's first API key is an administrator's to make, once.** Termix makes none
  without a session, and sign-up and password sign-in are closed: `hlb termix connect`
  turns the one handed over into Homelabus's own account and key, then deletes it. Each
  node's host key is accepted by a person at their first connection — no API sets it;
  `hlb termix sync` prints them to compare.
- **Gitea's team map is not written**: it maps onto organisations and teams that must
  already exist. Its administrators and who may enter do follow the roles.

- **A ZFS pool is never created automatically**, deliberately. `zpool create` writes
  labels to the disks with no way back, so the command is printed with the disks left to
  you. Importing one IS offered — `zpool export` undoes it.
- **`/etc/exports` is printed, not written.** The file may already carry lines you added.
- **IMAP ACLs** — several mailboxes under one connection — are not wired.
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
- **Every image by its digest, and none younger than a week.** The catalog pins each
  image it was tried with; `hlb catalog images` and `hlb update` propose only builds
  published `maturationDays` ago (7, never fewer), never downward, never a major — a
  major is said, and rehearsed by a person on a restored copy first.
- **`Unimplemented` is never `Done`.** Without a vault, without PostgreSQL, without
  Stalwart, the action is recorded as unimplemented — never simulated.
- **Bulwark is pinned** (`channel: pin`): no Git releases, no declared license, only
  images exist.
- `age` pulls in `proc-macro-error2`, flagged as incompatible with a future Rust. It is
  a transitive dependency; nothing to do on our side.
