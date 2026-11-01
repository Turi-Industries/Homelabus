---
paths:
  - "crates/hlb-platform/**/*.rs"
  - "crates/hlb-backup/**/*.rs"
  - "crates/hlb-state/**/*.rs"
  - "crates/hlb-state/migrations/*.sql"
  - "crates/hlb-resolver/**/*.rs"
  - "crates/hlb-engine/**/*.rs"
---

# Databases

PostgreSQL, MariaDB and SQLite. Most of these produce a dump or a replica that restores
cleanly and is missing data.

- **A migration never rewrites `audit_log`.** Each entry's hash covers its actor, role,
  action, target and outcome, chained to the previous one: an `UPDATE` there — even a
  harmless rename — makes `hlb audit --verify` and the health check report tampering on
  every installation that upgrades, and rehashing the chain to hide it is exactly what
  tampering does. Found while renaming French values on 2026-10-05: migration 0026
  renames the break-glass ids and leaves the log's old words where they are.
- **🔴 An applied migration is never edited, not even a comment.** `sqlx` checksums the
  whole file: one name changed in a comment of 0035 (the history rewrite of 2026-10-27)
  made every build since refuse every state migrated before — "migration 35 was
  previously applied but has been modified", the CLI and the controller alike. The lab's
  row was set to the new checksum by hand on 2026-10-28, after checking the SQL was
  byte-identical. A change of mind goes in a NEW migration.
- **A PostgreSQL extension cannot be installed from SQL.** It must be in the server
  IMAGE, or `CREATE EXTENSION` fails with "is not available", which looks like a
  permissions problem. And it is **per-database**: installed on `postgres`, it succeeds
  and the app never sees it.
- **Changing the PostgreSQL image's libc breaks text indexes.** musl (alpine) and glibc
  (debian) do not sort alike. B-trees built under one become incoherent under the other:
  incomplete searches, unique constraints letting duplicates through. PostgreSQL only
  warns about a "collation version mismatch". Hence `REINDEX DATABASE` +
  `REFRESH COLLATION VERSION`.
- **A drill restores into the SERVER's image, never a client's.** `hlb dr exercise`
  defaulted to `postgres:17-alpine` — musl, no vectorchord — for base backups of the
  catalog's glibc server: the one tool meant to prove a restore ran it on the libc
  that breaks text indexes. It takes the installed PostgreSQL's own image now. The dump
  CLIENTS may differ (`hlb_backup::images`), held to the servers' major and image by
  `hlb-catalog/tests/clients.rs`.
- **A restored server is production's configuration.** A drill's PostgreSQL comes back
  with the real `archive_command`, subscriptions and settings: started as is, it would
  push WAL into the real archive or consume a publisher's slot. It runs with
  `--network none` and `-c archive_mode=off -c max_logical_replication_workers=0
  -c listen_addresses=''` (`drill::ISOLATION`) — given on the command line, they beat
  the restored `postgresql.auto.conf` (tried on the catalog's image). And no drill starts
  an application: a restored n8n runs its workflows.
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
- **A standby's `primary_conninfo` needs the password.** The line written after
  `pg_basebackup -R` REPLACES the one it wrote, which held it: without it the standby is
  refused ("no password supplied"), stays in recovery, answers reads — and replicates
  nothing. Check `pg_stat_wal_receiver` on it, never only `pg_is_in_recovery()`.
- **Fencing a primary means removing its service.** Scaled to zero, it came back with
  the next `hlb reconcile` and took writes the new primary never saw (run on a real
  pair). And the apps find a primary by the name `postgres`: the promoted standby takes
  it as a network alias, published only once its probe passes.
- **An app creating its own extensions at start dies on it.** Its isolated role may
  not: Immich stopped on "permission denied to create extension earthdistance". Every
  extension an app uses is declared in its manifest, in dependency order (`cube` before
  `earthdistance`), and created by the admin in the app's database.
- **A brand-new replication slot retains nothing** until a standby connects (absent
  `immediately_reserve`). The dangerous case is not the never-used slot, it is the one
  *that has been used* and whose consumer disappeared: only that one grows `pg_wal`.
- **A failing WAL `archive_command` does not lose journals, it keeps them.** `pg_wal`
  grows until the disk is full. Archiving to a broken destination is more dangerous than
  not archiving.
- **A pooled connection dies at a quarter of an hour of silence** — Swarm's VIP, not
  the server (`operations-swarm.md`); MariaDB's too ("Lost connection to server during
  query" after 17 minutes, measured). Both servers send keepalives from their
  manifest's `args`, after the image's own `Cmd` — `args` replace `Cmd` whole, and
  without its configuration file PostgreSQL would lose the vector extensions'
  `shared_preload_libraries`: PostgreSQL `tcp_keepalives_idle=300`, MariaDB
  `--tcp-keepalive-time=300` (0, the image's default, is the system's 7200). ⚠️ PostgreSQL's `SHOW` over the local socket says 0
  — keepalives apply to TCP only; `pg_settings.source` says `command line`.
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
- **MariaDB's clients ignore `MYSQL_HOST`.** They try the local socket and fail "Can't
  connect to local server": every dump failed against a real server, and a simulated
  runner had answered whatever it was given. Host, port and user go as arguments; only
  the password stays in `MYSQL_PWD`, out of `ps`. `tests/maria_roundtrip.rs` holds it.
- **A MariaDB user is `'name'@'host'`.** Without an explicit host part the app is
  refused from another container, with a message about an incorrect password. And
  `_`/`%` are WILDCARDS in a `GRANT`: `%` is refused, `_` is escaped (`ccnet\_db`) —
  refusing it made Seafile, whose databases carry it, impossible to install.
- **An app's connection pools are counted against the shared server's limit.**
  Seafile's seaf-server opens TWO pools of `[database] max_connections` (100 by default)
  and its file server 16 more: past MariaDB's 151 on its own. Left to their defaults,
  Gitea's pool is unlimited, Vikunja's 100, Roundcube one per Apache worker (150) —
  each could take PostgreSQL's 97 alone. Every database requirement says
  `connections` (required by the catalog, optional when read); `catalog validate` sums
  them per server, the largest twice (an update's new task opens its pool before the
  old one closes), against the limit the server's `args` set — 200 and 250. The
  executor sets the role's `CONNECTION LIMIT` / `MAX_USER_CONNECTIONS` to twice the
  app's sum: past it the APP is refused, never its neighbours. The manifest caps the
  pools in its own variables where the app has one; Immich and Mealie have none, their
  figure read from the source.
- **An app that creates its own databases asks for root.** Seafile's first start did,
  and Homelabus never hands out MariaDB's root: `USE_EXISTING_DB=1` makes it use the
  databases and the account already provisioned.
- **A SQLite file cannot be copied hot.** In WAL mode restic copies three files one
  after another while the app writes. `VACUUM INTO` produces a consistent snapshot, and
  the failure only shows at restore time. 🔴 `sqlite: true` is a list kept by hand:
  three of six SQLite volumes lacked it (CrowdSec, ntfy, Grafana) and were copied
  live. The pass looks in every backed-up volume by header now — one on another node
  only when flagged.
