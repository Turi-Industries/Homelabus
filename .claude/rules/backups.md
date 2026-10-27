---
paths:
  - "crates/hlb-backup/**/*.rs"
  - "crates/hlb-backup-run/**/*.rs"
  - "crates/hlb-agent/**/*.rs"
  - "crates/hlb-metrics/**/*.rs"
  - "crates/hlb-controller/src/{loops,metrics,recovery,health}.rs"
---

# Backups

restic, destinations, freshness and verification. Recorded so they are not rediscovered
during an outage.

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
- **Freshness is per KIND too.** Dumps and SQLite snapshots record a success on every
  pass they run: an age read across kinds made a volume backed up once never due again,
  "fresh" on every screen, and "no longer backed up" never fired. Every reader asks for
  its kinds (`seconds_since_last_success_of`), an app is as old as the OLDEST of what
  it holds (`backup_age`), and an app holding nothing is owed nothing.
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
- **Two copies of the backup pass had drifted.** The controller's loop wrote to
  `--backup-repo` only — the off-site destination was served by hand or never — skipped
  Homelabus's state and the SQLite files, and mounted volumes under `/data/` where the
  CLI uses `/donnees/`: the two produced snapshots with different paths. There is one
  pass now, `hlb-backup-run`, and both call it.
- **The pass reads a volume by its host path**, on the machine it runs on. The
  controller's container had none of them mounted (every SQLite backup: "No such
  file"), then could not cross an app's 0700 directory with every capability dropped
  ("Permission denied"): `fleet controller` mounts `/var/lib/docker/volumes` and gives
  back `DAC_READ_SEARCH` and `DAC_OVERRIDE`. A volume on another node is said to be
  there, by name, rather than missing.
- **A restore without `--delete` is a merge.** `restic restore` writes the snapshot's
  files over the volume and leaves the rest: a journal written since stays beside the
  database it no longer matches. `hlb backup restore` restores one path in place with
  `--delete`, the app stopped — and located BEFORE it stops: a stopped service on NFS
  runs nowhere, and no pin says where its volume is.
- **The copy a restore takes first is never "the latest".** It is tagged
  `kind:pre-restore`; taken as the default, a second restore would bring back the very
  data the first replaced. Only its id restores it. ⚠️ `kind:pre-update` is what every
  ordinary volume snapshot carries, the pass's included — a stored value, not a
  description.
- **restic finds Garage's region on its own** (checked against v2.3.0): no
  `AWS_DEFAULT_REGION` needed for a destination on `garage:3900`. Apps going through
  `{{ s3.region }}` still need it.
- **A destination is out of reach when the proof says so, never the policy.**
  `hlb backup dest prove` writes a witness with the destination's credential and deletes
  it with the same one. Measured 2026-10-19: Garage 2.4.1 answers every PUT with an
  `x-amz-version-id` and keeps no version — read `GetBucketVersioning` first, a version
  id proves nothing —; MinIO deletes a version with `s3:DeleteObject` alone, so a policy
  leaving `s3:DeleteObjectVersion` out protects nothing there and only a `Deny` does;
  and on a versioned bucket `restic forget` always "succeeds" (a delete marker), so
  restic cannot be the proof for S3. rest-server `--append-only` answers 403, which
  restic prints as `unexpected HTTP response (403)`.
- **A restore takes only what Homelabus took.** Every snapshot id goes into
  `snapshots_taken` — each volume's, not the last of a run, and the copies taken before
  an update or a restore. One nobody recorded is set aside and NAMED in the preview,
  never skipped silently and never restored by a prefix; its full id restores it (a
  restic id is the hash of the snapshot). ⚠️ A new place that snapshots a volume must
  record it, or the restore that needs it refuses it — `back_up_where_they_are` and
  `restore::in_place` go through `snapshot()`, which records.
- **Retention runs only where the destination can be erased anyway.** Forgetting old
  snapshots is what an intruder holding the credential does, so the weekly upkeep
  (`hlb_backup_run::upkeep`, the controller) proves the destination again first and
  prunes only on "erasable" — never on a proof remembered, never on "unproven". One out
  of reach is its owner's to prune. ⚠️ restic 0.19 keeps the OLDEST snapshot of a bucket
  that is not full ("oldest hourly snapshot"): four of one hour leave two.
- **A SQLite snapshot is archived at the database's own path in its volume**, owned and
  moded as the database is, beside an EMPTY `-wal` and `-shm` — restored over the live
  copy, a journal left from it would be replayed onto the consistent one. Restored as
  root, an app dropping its privileges opened its own database read-only. Its paths are
  the database's files, NEVER the volume's own: `pick` matches the volume's path
  exactly, and a snapshot of it restored with `--delete` would empty the volume around
  the database. A volume restore then puts each back from the one carrying the same
  `pass:` tag as the volume's (`restore::sqlite_of_pass`) — paired by time, a copy
  taken before an update got the database the next pass took after the migration —,
  restored from its own directory onto it: at `--target /`, the staging volume's
  directories came back over the app's, root's and 0755.
- **🔴 restic saves the half of a stream it got.** `restic backup --stdin` reading a
  stream that ENDS — a pipe whose writer failed and was dropped ends like one that
  finished — saves what came as a good snapshot; and killing the `docker` client of
  `docker run -i` leaves the container running, to do exactly that (measured on 0.19.1,
  `hlb-backup/tests/restic_stream.rs`). A bucket's archive goes through
  `tarball::pipe`, whose end counts only when the archive's writer closed it; a broken
  input has the container killed BY NAME before its standard input closes. And the
  archive ends with a trailer counting its objects: a restore refuses one without it,
  whatever cut it.
- **A bucket is backed up through the app's own key, as one archive** (`bucket::back_up`):
  listed in key order and streamed — no copy on a disk. An unchanged bucket adds 0 bytes
  to the repository, 25 MiB of new objects among 1 GB added 31 (measured): restic
  chunks by content. Every pass still READS every byte from Garage. All of an app's
  buckets are one outcome per destination, as its volumes: recorded one by one, the
  bucket that succeeded made the app fresh while the other went unread.
- **A database had no way back.** Dumps were taken, recorded and verified every night,
  and `hlb backup restore` put back volumes and buckets only: Fluxer whole could not be
  restored. `--database` drops the database and recreates it with provisioning's own
  statements (`hlb_platform::database_statements` — owned by the app's role, shut to
  every other), then `pg_restore --single-transaction --exit-on-error` into it. Three
  traps, each held on a real PostgreSQL 17 (`hlb-backup-run/tests/database.rs`):
  restored INTO the old database it is a merge — a table a migration added since stays
  beside a schema that no longer knows it; restored by the administrator under
  `--no-owner`, every table is the administrator's and the app can no longer read its
  own — `--role <app>`; and under that role the dump's `COMMENT ON EXTENSION` fails
  (`must be owner of extension citext`, seen): the extensions the manifest declares are
  enabled by the administrator first and left out of the dump's list. The dump is read
  back and its `PGDMP` signature checked BEFORE anything is dropped. ⚠️ A dump's path is
  `/staging/<app>-<db>-<time>.dump`, new every pass: it is found by its `db:` tag AND
  that shape — the tag alone is a SQLite snapshot's too —, and by its engine's
  extension: an app needing both engines, its databases unnamed, has two `db:<app>`.
- **A MariaDB dump restores where its own `USE` says.** Taken with `--databases`, it
  carries `CREATE DATABASE IF NOT EXISTS` and `USE`: restored "into" one database, a
  dump of another leaves it as it was and writes over the other — another app's, on the
  shared server. `mariadump::check_database` refuses a `USE` naming anything else,
  before the drop. Restored by the administrator, not the app's user: MariaDB owns no
  table to anyone, and the dump's `DEFINER`s stay the app's. And it is NOT one
  transaction — each `CREATE TABLE` commits —: stopped halfway, the database holds what
  it reached, so the app is left stopped and the copy taken first named
  (`hlb-backup-run/tests/maria_database.rs`).
