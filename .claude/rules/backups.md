---
paths:
  - "crates/hlb-backup/**/*.rs"
  - "crates/hlb-backup-run/**/*.rs"
  - "crates/hlb-agent/**/*.rs"
  - "crates/hlb-metrics/**/*.rs"
  - "crates/hlb-controller/src/{metrics,recovery,health}.rs"
  - "crates/hlb-privd/src/{backup.rs,daemon/schedule.rs}"
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
- **🔴 A destination's place and secret are root's.** The pass binds a local location
  read-write into a root container and signs an S3 one's requests with the secret it
  names: the web side may only change its classes (`SetDestinationClasses`, no path, no
  secret's name on the wire), and the daemon refuses a name it has no row for. Moving
  the off-site elsewhere would have kept it "fresh" on every screen.
- **restic reading a repository mounted read-only waits for ever.** It retries its
  lock every minute (`read-only file system`) and never fails: a drill reading a
  destination by hand passes `--no-lock`.
- **A locked repository fails a backup at once.** The daemon's loops share
  destinations: at privd's start the upkeep's prune held `nas` exclusively and a backup
  four seconds later exited 11, "already locked". Every command `Repository` runs waits
  `LOCK_WAIT` (`--retry-lock`), measured on 0.19.1 against a prune held 25 s.
- **🔴 An engine's store copied live restores nothing, and restic says nothing.**
  restic 0.19.1 reads a directory in name order, so RocksDB's `MANIFEST-*` comes after
  its `000*.sst`: a flush between the two left a copy naming an SST it never took, and
  Stalwart refused to start on it (`Corruption: … No such file`, played on deb1
  2026-10-31). A file that vanished mid-copy fails the pass (exit 3); one created after
  restic's listing is no error at all. An idle server's copy opens, so one good drill
  proves nothing. The pass copies a volume while its service runs unless it says
  `copy: stopped`: then its services are held, stopped once for every destination and
  started again — and a copy nothing can stop fails, never taken live instead.
  PostgreSQL's directory says `copy: pg-basebackup` (`engine_copy`): written into
  `hlb-copy-<volume>` beside it, by the SERVER's image, then backed up AT THE VOLUME'S
  OWN PATH, so the plain volume restore puts back a directory that starts. Without its
  administrator the copy fails. Replication needs its own `pg_hba` line: the
  catalog's `hlb_hba.conf` includes the data directory's file first. MariaDB's says
  `copy: mariadb-backup`: the tool reads the live directory (mounted READ-ONLY at its
  own path, same node) and must `--prepare` what it took, or nothing starts. ⚠️ It
  copies tables only: the image's `.my-healthcheck.cnf` is taken beside them, or the
  restored server's probe signs in as nobody until an entrypoint run with
  `MARIADB_AUTO_UPGRADE` recreates its user.
- **A restic S3 repository is not MOUNTED.** Mounting it creates an empty directory and
  restic replies "repository does not exist", naming a local path unrelated to the real
  destination. And joining an internal Garage needs a `--network`.
- **A verification nobody runs verifies nothing.** `hlb backup verify` existed and only
  ran when typed: on 2026-11-04 every app of the lab read "verified never". The daemon reads
  one app an hour, each weekly, a failure again a day later (`VerifyLoop`), through
  `hlb_backup_run::verify`, the CLI's too. Volumes are restored and counted. Each dump goes
  into a disposable server of the installed image, no network, and its tables are counted
  against what it names (`dump_reading`): `pg_restore --list`, and a MariaDB dump's lines
  starting `CREATE TABLE`, since a view's stand-in is `/*!50001 CREATE TABLE`. Ready means
  answering over TCP: both images' first start runs a temporary server on the socket.
  Unasked it refuses what would not leave a tenth of the disk free (a dump counts for four
  times its size), a dump past 1 GiB, held in the daemon's memory, and past 5 GiB from S3,
  which may bill. A SQLite snapshot goes through `PRAGMA integrity_check`, in a temporary
  directory; a bucket's archive is read to its end and written nowhere. ⚠️ A volume's store
  is counted and never started, and the servers' images pulled for it stay on that node
  until the nightly prune: deb1 lost 700 MB.
- **A reader gone at the trailer breaks the writer.** A tar ends with zero blocks after its
  last entry: stopped at `TRAILER`, the reader closed its pipe on `restic dump`, and a whole
  bucket failed with "broken pipe" (the first real reading of Fluxer's, 2026-11-04).
  `tarball::Reader::drain`. `bucket::restore` had the same race, once every object was back.
- **🔴 A daemon replaced during a copy took Termix down for good** (the lab, 2026-11-04). It
  had scaled it to 0 for `copy: stopped`; the next pass read that 0 as what to give back,
  "started" it at 0 and released the hold, so with no `--reconcile-apply` nothing ever ran it
  again, a gap in a log line. Stalwart stops the same way. A hold records the replicas, held
  again keeps the larger (`service_holds.replicas`), `restore::start` trusts it over its
  caller, and the daemon restarts an interrupted copy as it starts. A pass refuses a service
  a restore holds: it would have copied the half-written volume, then started the app on it.
  A restore refuses a service a copy holds (`restore::stop_for_restore`), since the copy's end
  would start it the same way, and moves nothing to say so: starting it to undo the refusal
  pulls it out from under the copy. A restore's own hold refuses nothing, or one that died
  would lock the next out for a day.
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
- **A service in a crash loop is placed where Swarm keeps starting it** (`placement::locate`):
  no task of it is ever `running`, so an NFS app kept down by what its volume holds could not
  be restored, the moment a restore exists for. Immich refuses an empty share once its
  database says it had files, so on a restored house it stayed down for good. A data pin still
  beats it: a start elsewhere does not move a volume.
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
- **🔴 Restored on NFS, every file failed, and the app stayed stopped.** An NFSv4 client shows
  `system.nfs4_acl` where the share's filesystem has ACLs (ext4, XFS) and refuses to remove it;
  restic 0.19.1 removes each attribute the snapshot lacks, so it exited 1 after writing every
  file. Both restores pass `--exclude-xattr` (`restic::NFS4_ACL`), found on a share of ext4:
  the lab's ZFS has none, and no drill had restored one. A restore stopped halfway leaves an
  NFS app at 0 replicas with no pin: the hold records the volume's node before anything stops
  (`service_holds.node`), and `place_of` reads it last. Never "here" without it: a node lacking
  the volume creates an empty local one, and the restore lands in that.
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
- **An update's prior copy dumps every database the app declares**
  (`PlacedProvider::copy`): it held volumes alone, so a migration gone wrong went back to
  the last pass, and an app holding only a database was refused for ever. Volumes go to the
  first bulky destination and dumps to the first critical one, as a pass routes them, and each
  refusal comes before anything stops. Tagged as a pass's dump: the newest, which a restore
  takes unasked, and retention's to forget.
- **An update's prior copy stops what writes SQLite, and reads the buckets**
  (`stopped_for_update_copy`, `PlacedProvider::copy_buckets`). Taken live, a rollback got three
  files restic read one after another: `restore::sqlite_after` puts back only a snapshot of the
  same `pass:` tag, and this copy carries none. Not `VACUUM INTO`, which reads the file from
  the machine it runs on and refuses a volume elsewhere: stopped, the database is consistent as
  it lies, on any node, and the update is about to restart the app anyway; the copy is tagged
  `copy:stopped`, so the restore does not warn of a live one. Which volumes hold
  SQLite is the state's word (`app_volumes.sqlite`), the manifest's plus what a pass found. ⚠️ A
  volume no manifest flags, updated before any pass looked in it, is still copied live. A bucket
  Garage cannot be asked for, from here, refuses the update; it holds the objects a migration
  may rewrite. Every byte is read at each update, as at each pass.
- **🔴 A pass copies the state again at its end, once it took anything.** A restore takes
  only what the state recorded (`snapshots_taken`), and the kit brings back the newest state:
  copied first and only then, it had no row for the volumes and dumps its own pass took, and
  after a disaster they were "a backup someone else wrote", the pass before chosen by default
  (12 hours on the lab, 2026-11-05, `tests/pass.rs`). The first copy stays for a pass cut
  short. ⚠️ A pass of one app (`--app`, "back up now") copies no state, and an update's copy
  neither: until the next pass that took something, each is set aside and restored by its
  full id.
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
