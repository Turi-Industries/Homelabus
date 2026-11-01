//! Putting a volume back as one of its snapshots holds it.
//!
//! 🔴 The snapshots existed and nothing restored them: when PocketID 1.16 could not
//! start on the schema 2.18 had migrated, getting its volume back was restic by hand —
//! on the node holding it, under the path the pass had used, with the app stopped —
//! in the middle of the outage.

use std::collections::{BTreeMap, HashSet};
use std::time::Duration;

use hlb_backup::restic::Snapshot;
use hlb_backup::{Class, Destination};
use hlb_orchestrator::Orchestrator;
use hlb_secrets::Vault;
use hlb_state::State;
use hlb_types::DbEngine;

use crate::placement::Place;
use crate::{credentials, effective_destinations, restic_password, runner_at, volume_path};

/// The tag of the copy a restore takes first of what it overwrites.
pub const BEFORE_RESTORE: &str = "kind:pre-restore";

/// How long a stopped service may take to let go of its volume.
const STOP_TIMEOUT: Duration = Duration::from_secs(120);

/// Why a snapshot a restore could have taken was passed over.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SetAside {
    /// Homelabus never took it: something else wrote it into the repository.
    NotTaken,
    /// Never taken here, and dated after now: what a forged "latest" looks like — one
    /// dated 2099 would be the latest forever.
    Future,
}

impl SetAside {
    pub fn describe(self) -> &'static str {
        match self {
            Self::NotTaken => "not taken by this installation",
            Self::Future => "not taken by this installation, and dated in the future",
        }
    }
}

/// How far ahead of this machine's clock a snapshot may be dated before it is said to
/// be from the future: two clocks are never exactly together.
const CLOCK_SKEW: i64 = 3600;

/// What [`pick`] chose, and what it passed over.
#[derive(Debug)]
pub struct Picked<'a> {
    pub snapshot: Option<&'a Snapshot>,
    /// Newer than the one taken — or the one named —, each with why it was not.
    pub set_aside: Vec<(&'a Snapshot, SetAside)>,
}

/// The snapshot of `volume` a restore takes: `wanted`, by its id or the first
/// characters of it, or else the latest — among those Homelabus took (`taken`).
///
/// 🔴 A repository holds whatever was written into it, and after an intrusion the
/// intruder held the repository's password: a snapshot of theirs, dated in 2099, would
/// be "the latest" for every restore that follows. One Homelabus never took is set
/// aside, and said. A person who knows it is good names it by its FULL id — restic's
/// id is the hash of the snapshot, so naming it pins its content.
///
/// The latest is never a copy a restore took of what it overwrote: run twice, the
/// second restore would bring back the data the first one replaced.
pub fn pick<'a>(
    snapshots: &'a [Snapshot],
    volume: &str,
    wanted: Option<&str>,
    taken: &HashSet<String>,
    now: i64,
) -> Picked<'a> {
    pick_at(snapshots, &volume_path(volume), wanted, taken, now)
}

/// [`pick`], for the snapshots holding `path` — a volume's, or a bucket's archive.
pub fn pick_at<'a>(
    snapshots: &'a [Snapshot],
    path: &str,
    wanted: Option<&str>,
    taken: &HashSet<String>,
    now: i64,
) -> Picked<'a> {
    let path = path.to_string();
    pick_where(snapshots, |s| s.paths.contains(&path), wanted, taken, now)
}

/// [`pick`], for the dumps of `database`. Each dump is archived under its own dated
/// name, so they are found by their `db:` tag and the shape of their path — the tag
/// alone is a SQLite snapshot's too.
pub fn pick_dump<'a>(
    snapshots: &'a [Snapshot],
    engine: DbEngine,
    database: &str,
    wanted: Option<&str>,
    taken: &HashSet<String>,
    now: i64,
) -> Picked<'a> {
    pick_where(
        snapshots,
        |s| is_dump_of(s, engine, database),
        wanted,
        taken,
        now,
    )
}

/// Whether `s` is a dump of `database`: its tag, and its one file the staging's dump of
/// `engine`. ⚠️ The tag alone is not the engine's: an app needing both, its databases
/// unnamed, has two called after it.
fn is_dump_of(s: &Snapshot, engine: DbEngine, database: &str) -> bool {
    let tag = format!("db:{database}");
    let extension = match engine {
        DbEngine::Postgres => ".dump",
        DbEngine::Mariadb => ".sql",
    };
    s.tags.contains(&tag)
        && matches!(s.paths.as_slice(), [p] if p.starts_with("/staging/") && p.ends_with(extension))
}

fn pick_where<'a>(
    snapshots: &'a [Snapshot],
    holds: impl Fn(&Snapshot) -> bool,
    wanted: Option<&str>,
    taken: &HashSet<String>,
    now: i64,
) -> Picked<'a> {
    let why = |s: &Snapshot| match s.epoch() {
        Some(t) if t > now + CLOCK_SKEW => SetAside::Future,
        _ => SetAside::NotTaken,
    };
    let mut picked = Picked {
        snapshot: None,
        set_aside: Vec::new(),
    };
    // restic lists them oldest first.
    let candidates = snapshots.iter().rev().filter(|s| holds(s));
    for s in candidates {
        match wanted {
            Some(w) if !s.id.starts_with(w) => continue,
            Some(w) => {
                if taken.contains(&s.id) || s.id == w {
                    picked.snapshot = Some(s);
                } else {
                    picked.set_aside.push((s, why(s)));
                }
                break;
            }
            None if s.tags.iter().any(|t| t == BEFORE_RESTORE) => continue,
            None if taken.contains(&s.id) => {
                picked.snapshot = Some(s);
                break;
            }
            None => picked.set_aside.push((s, why(s))),
        }
    }
    picked
}

/// The pass that took `s`: its [`crate::PASS_TAG`] tag, whole.
fn pass_of(s: &Snapshot) -> Option<&str> {
    s.tags
        .iter()
        .map(String::as_str)
        .find(|t| t.starts_with(crate::PASS_TAG))
}

/// The consistent snapshot of each SQLite database of `volume` taken by the pass that
/// took `of`: by database (`db:` tag), the first Homelabus took with the same pass tag.
/// Only snapshots whose every path lies inside the volume.
///
/// 🔴 The SAME pass, by its tag — never "the first within hours after". A copy taken
/// before an update carries no pass: paired by time, it got the database the next pass
/// took AFTER the update had migrated it, restored over the files of before — a newer
/// database over an older volume. A volume snapshot of no pass gets no database back,
/// and stays as restic copied it.
pub fn sqlite_of_pass<'a>(
    snapshots: &'a [Snapshot],
    volume: &str,
    of: &Snapshot,
    taken: &HashSet<String>,
) -> Vec<(String, &'a Snapshot)> {
    let inside = format!("{}/", volume_path(volume));
    let Some(pass) = pass_of(of) else {
        return Vec::new();
    };
    let mut first: std::collections::BTreeMap<String, &Snapshot> = Default::default();
    for s in snapshots {
        if !s
            .tags
            .iter()
            .any(|t| t == hlb_backup::sqlite::SNAPSHOT_KIND)
            || pass_of(s) != Some(pass)
            || !taken.contains(&s.id)
            || s.paths.is_empty()
            || !s.paths.iter().all(|p| p.starts_with(&inside))
        {
            continue;
        }
        let Some(at) = s.epoch() else {
            continue;
        };
        let Some(db) = s.tags.iter().find_map(|t| t.strip_prefix("db:")) else {
            continue;
        };
        let earlier = first
            .get(db)
            .is_some_and(|f| f.epoch().is_some_and(|e| e <= at));
        if !earlier {
            first.insert(db.to_string(), s);
        }
    }
    first.into_iter().collect()
}

/// Where a restore reads from.
#[derive(Debug, Clone)]
pub struct Source {
    pub destination: Destination,
    pub snapshot: Snapshot,
    /// Newer snapshots passed over, and why: said before anything is restored.
    pub set_aside: Vec<(Snapshot, SetAside)>,
}

/// An app's database, as its manifest and the resolver name it.
pub struct Database<'a> {
    pub engine: DbEngine,
    pub name: &'a str,
    /// The app's role, which owns it.
    pub role: &'a str,
    /// Enabled by the administrator before the dump is restored, as at installation:
    /// the app's role may not create them.
    pub extensions: &'a [String],
}

/// What a restore is told about the installation.
pub struct Restore<'a> {
    pub state: &'a State,
    pub vault: &'a Vault,
    /// `--backup-repo`, used when no destination is declared.
    pub fallback_repo: Option<&'a str>,
    /// The overlay where the S3 endpoint resolves.
    pub network: &'a str,
    /// Where the volume lives, and how to run restic there. `None`: on this machine.
    pub orchestrator: Option<&'a dyn Orchestrator>,
}

/// Why a restore did not end.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Failure {
    /// Nothing was touched.
    Refused(String),
    /// The volume was being overwritten: what it held before is the snapshot `before`.
    Interrupted { before: String, error: String },
}

impl Restore<'_> {
    /// The snapshot to restore, looked for in the destinations that receive the app's
    /// volumes — or in `from` alone — in their order. Why none was found, otherwise.
    pub async fn find(
        &self,
        app: &str,
        volume: &str,
        from: Option<&str>,
        wanted: Option<&str>,
    ) -> Result<Source, String> {
        self.find_at(app, &volume_path(volume), volume, from, wanted)
            .await
    }

    /// The snapshot of `bucket`'s archive to restore, as [`Restore::find`] does.
    pub async fn find_bucket(
        &self,
        app: &str,
        bucket: &str,
        from: Option<&str>,
        wanted: Option<&str>,
    ) -> Result<Source, String> {
        self.find_at(
            app,
            &crate::bucket::archive_path(bucket),
            bucket,
            from,
            wanted,
        )
        .await
    }

    /// The dump of `database` to restore, looked for in the destinations that receive
    /// the app's critical data — where dumps go —, as [`Restore::find`] does.
    pub async fn find_dump(
        &self,
        app: &str,
        engine: DbEngine,
        database: &str,
        from: Option<&str>,
        wanted: Option<&str>,
    ) -> Result<Source, String> {
        self.find_where(
            app,
            Class::Critical,
            |all, taken, now| pick_dump(all, engine, database, wanted, taken, now),
            &format!("the database {database}"),
            from,
            wanted,
        )
        .await
    }

    /// The snapshot holding `path` — `what` is how it is said.
    async fn find_at(
        &self,
        app: &str,
        path: &str,
        volume: &str,
        from: Option<&str>,
        wanted: Option<&str>,
    ) -> Result<Source, String> {
        self.find_where(
            app,
            Class::Bulky,
            |all, taken, now| pick_at(all, path, wanted, taken, now),
            volume,
            from,
            wanted,
        )
        .await
    }

    /// The snapshot `pick` chooses, in the destinations receiving the app's `class`.
    async fn find_where(
        &self,
        app: &str,
        class: Class,
        pick: impl for<'s> Fn(&'s [Snapshot], &HashSet<String>, i64) -> Picked<'s>,
        volume: &str,
        from: Option<&str>,
        wanted: Option<&str>,
    ) -> Result<Source, String> {
        let dests: Vec<Destination> =
            effective_destinations(self.state, app, class, self.fallback_repo)
                .await
                .map_err(|e| e.to_string())?
                .into_iter()
                .filter(|d| from.is_none_or(|f| d.name == f))
                .collect();
        let held = match class {
            Class::Critical => "dumps",
            Class::Bulky => "volumes",
        };
        if dests.is_empty() {
            return Err(match from {
                Some(f) => format!("\"{f}\" does not receive {app}'s {held}"),
                None => format!("no destination receives {app}'s {held}: nothing to restore"),
            });
        }
        let password = restic_password(self.state, self.vault)
            .await
            .map_err(|e| e.to_string())?;
        let taken = self
            .state
            .snapshots_taken(app)
            .await
            .map_err(|e| e.to_string())?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or_default();
        let mut tried = Vec::new();
        for d in dests {
            let env = self.env(&d).await?;
            let (runner, location) = d.runner(Some(self.network));
            let repo = hlb_backup::Repository::new(runner, location, &password).extra_env(env);
            match repo.snapshots(Some(&format!("app:{app}"))).await {
                Ok(all) => {
                    let picked = pick(&all, &taken, now);
                    let set_aside: Vec<(Snapshot, SetAside)> = picked
                        .set_aside
                        .iter()
                        .map(|(s, why)| ((*s).clone(), *why))
                        .collect();
                    match picked.snapshot {
                        Some(s) => {
                            return Ok(Source {
                                snapshot: s.clone(),
                                destination: d,
                                set_aside,
                            })
                        }
                        None if set_aside.is_empty() => tried.push(format!("{}: none", d.name)),
                        None => tried.push(format!(
                            "{}: {} set aside — {} (name one by its full id to restore it)",
                            d.name,
                            set_aside.len(),
                            set_aside
                                .iter()
                                .map(|(s, why)| format!("{} {}", s.id, why.describe()))
                                .collect::<Vec<_>>()
                                .join("; ")
                        )),
                    }
                }
                // One unreachable destination must not hide a copy on the next.
                Err(e) => tried.push(format!("{}: {e}", d.name)),
            }
        }
        Err(match wanted {
            Some(w) => format!("no snapshot {w} of {volume} — {}", tried.join("; ")),
            None => format!("no snapshot of {volume} — {}", tried.join("; ")),
        })
    }

    /// The machine holding `volume`. Asked while its app still runs: a stopped
    /// service whose data no node pins — on the pool, over NFS — runs nowhere to be
    /// found.
    pub async fn place_of(&self, app: &str, volume: &str) -> Result<Place, String> {
        let services = crate::services_of(self.state, app)
            .await
            .map_err(|e| e.to_string())?;
        let volumes = [volume.to_string()];
        crate::locate_volumes(self.orchestrator, &volumes, &services)
            .await
            .into_keys()
            .next()
            .ok_or_else(|| format!("{volume} could not be placed"))
    }

    /// Restores `volume` in place, on the machine holding it, from `source`. What it
    /// holds now is backed up first, to the same destination: restoring the wrong day
    /// is undone by restoring that copy. The copy's id.
    ///
    /// ⚠️ The app must be stopped: restic writing under a running app races its writes.
    pub async fn in_place(
        &self,
        app: &str,
        volume: &str,
        place: &Place,
        source: &Source,
    ) -> Result<String, Failure> {
        let d = &source.destination;
        let password = restic_password(self.state, self.vault)
            .await
            .map_err(|e| Failure::Refused(e.to_string()))?;
        let env = self.env(d).await.map_err(Failure::Refused)?;
        let volumes = [volume.to_string()];
        let (runner, location) = runner_at(
            self.orchestrator,
            self.network,
            d,
            app,
            place,
            &volumes,
            &BTreeMap::new(),
            true,
        )
        .map_err(Failure::Refused)?;
        let repo = hlb_backup::Repository::new(runner, location, password).extra_env(env);

        let path = volume_path(volume);
        let before = crate::snapshot(
            &repo,
            (self.state, &d.name),
            app,
            std::slice::from_ref(&path),
            &[BEFORE_RESTORE],
        )
        .await
        .map_err(|e| {
            Failure::Refused(format!(
                "{volume} as it is could not be backed up first: {e}"
            ))
        })?;
        repo.restore_path(&source.snapshot.id, &path)
            .await
            .map_err(|e| Failure::Interrupted {
                before: before.clone(),
                error: e.to_string(),
            })?;
        Ok(before)
    }

    /// Restores `bucket` from `source`, through the app's own key at `endpoint`. What it
    /// holds now is backed up first, to the same destination, as a volume's is. The
    /// copy's id, and what was put back.
    ///
    /// ⚠️ The app must be stopped: it would write beside the restore, and the objects it
    /// wrote would be deleted as written since.
    pub async fn bucket_in_place(
        &self,
        app: &str,
        bucket: &str,
        endpoint: &str,
        source: &Source,
    ) -> Result<(String, crate::bucket::Restored), Failure> {
        let d = &source.destination;
        let password = restic_password(self.state, self.vault)
            .await
            .map_err(|e| Failure::Refused(e.to_string()))?;
        let env = self.env(d).await.map_err(Failure::Refused)?;
        let (runner, location) = d.runner(Some(self.network));
        let repo = hlb_backup::Repository::new(runner, location, password).extra_env(env);
        let b = crate::bucket::open(self.state, self.vault, endpoint, app, bucket)
            .await
            .map_err(Failure::Refused)?;

        let tag = format!("app:{app}");
        let before = crate::bucket::back_up(&repo, &b, bucket, &[&tag, BEFORE_RESTORE])
            .await
            .map_err(|e| {
                Failure::Refused(format!(
                    "{bucket} as it is could not be backed up first: {e}"
                ))
            })?;
        self.state
            .record_snapshot(app, &d.name, &before)
            .await
            .map_err(|e| {
                Failure::Refused(format!("snapshot {before} taken, but not recorded: {e}"))
            })?;
        let restored = crate::bucket::restore(&repo, &source.snapshot.id, &b, bucket)
            .await
            .map_err(|error| Failure::Interrupted {
                before: before.clone(),
                error,
            })?;
        Ok((before, restored))
    }

    /// Restores `db` from the dump `source`, through the server's administrator at
    /// `admin_url`. The dump is read back first — nothing is touched when it cannot
    /// be —, what the database holds now is dumped to the same destination, then the
    /// database is recreated as provisioning makes it and the dump restored into it,
    /// the app's. The copy's id.
    ///
    /// ⚠️ The app must be stopped: its connections are closed by the drop, and it would
    /// reconnect to a database half restored.
    pub async fn database_in_place(
        &self,
        app: &str,
        db: &Database<'_>,
        admin_url: &str,
        source: &Source,
    ) -> Result<String, Failure> {
        use hlb_backup::pgdump::scheduled;
        let refused = |e: String| Failure::Refused(e);
        let d = &source.destination;
        let password = restic_password(self.state, self.vault)
            .await
            .map_err(|e| refused(e.to_string()))?;
        let creds = credentials(self.state, self.vault, d)
            .await
            .map_err(|e| refused(e.to_string()))?;
        let env = d
            .env(creds.as_deref())
            .map_err(|e| refused(e.to_string()))?;
        let (runner, location) = d.runner(Some(self.network));
        let repo = hlb_backup::Repository::new(runner, location, &password).extra_env(env);

        let id = source.snapshot.short_id();
        let [path] = source.snapshot.paths.as_slice() else {
            return Err(refused(format!("snapshot {id} holds more than one dump")));
        };
        let mut dump = Vec::new();
        repo.dump(&source.snapshot.id, path, &mut dump)
            .await
            .map_err(|e| refused(format!("the dump could not be read back: {e}")))?;
        // Everything a dump is checked for is checked here, before the drop: found by
        // the restore, it is found with the database gone.
        let put_back = match db.engine {
            DbEngine::Postgres => {
                // The custom format's signature.
                if !dump.starts_with(b"PGDMP") {
                    return Err(refused(format!("snapshot {id} is not a PostgreSQL dump")));
                }
                PutBack::postgres(db, admin_url, self.network)
            }
            DbEngine::Mariadb => {
                use hlb_backup::mariadump;
                mariadump::check_full(db.name, &dump)
                    .and_then(|()| mariadump::check_database(db.name, &dump))
                    .map_err(|e| refused(format!("snapshot {id}: {e}")))?;
                PutBack::mariadb(db, admin_url, self.network)
            }
        }
        .map_err(refused)?;

        let current = match db.engine {
            DbEngine::Postgres => crate::pg_dump(self.network, app, db.name, admin_url).await,
            DbEngine::Mariadb => crate::maria_dump(self.network, app, db.name, admin_url).await,
        }
        .map_err(|e| {
            refused(format!(
                "{} as it is could not be dumped first: {e}",
                db.name
            ))
        })?;
        let before = scheduled::archive_as(
            d,
            creds.as_deref(),
            Some(self.network),
            &password,
            &current,
            BEFORE_RESTORE,
        )
        .await
        .map_err(|e| {
            refused(format!(
                "{} as it is could not be backed up first: {e}",
                db.name
            ))
        })?;
        self.state
            .record_snapshot(app, &d.name, &before)
            .await
            .map_err(|e| refused(format!("snapshot {before} taken, but not recorded: {e}")))?;

        put_back
            .run(db, &dump)
            .await
            .map_err(|error| Failure::Interrupted {
                before: before.clone(),
                error,
            })?;
        Ok(before)
    }

    /// After `volume` was restored from `source`: each of its SQLite databases put back
    /// from the consistent snapshot the same pass took of it ([`sqlite_of_pass`]). What
    /// restic copied of a live database may not open; this one does. `(database,
    /// snapshot)` for each put back.
    ///
    /// ⚠️ The app must still be stopped. A database with no consistent snapshot of that
    /// pass — a copy taken before an update or a restore, a pass before 2026-10-21 that
    /// tagged none — stays as restic copied it.
    pub async fn sqlite_after(
        &self,
        app: &str,
        volume: &str,
        place: &Place,
        source: &Source,
    ) -> Result<Vec<(String, String)>, String> {
        let d = &source.destination;
        let password = restic_password(self.state, self.vault)
            .await
            .map_err(|e| e.to_string())?;
        let env = self.env(d).await?;
        let volumes = [volume.to_string()];
        let (runner, location) = runner_at(
            self.orchestrator,
            self.network,
            d,
            app,
            place,
            &volumes,
            &BTreeMap::new(),
            true,
        )?;
        let repo = hlb_backup::Repository::new(runner, location, password).extra_env(env);
        let taken = self
            .state
            .snapshots_taken(app)
            .await
            .map_err(|e| e.to_string())?;
        let all = repo
            .snapshots(Some(&format!("app:{app}")))
            .await
            .map_err(|e| e.to_string())?;
        let mut back = Vec::new();
        for (db, s) in sqlite_of_pass(&all, volume, &source.snapshot, &taken) {
            let dir = files_dir(s, volume).ok_or_else(|| {
                format!(
                    "{db}: snapshot {} holds files of more than one directory",
                    s.short_id()
                )
            })?;
            repo.restore_files_in(&s.id, &dir)
                .await
                .map_err(|e| format!("{db}: {e}"))?;
            back.push((db, s.id.clone()));
        }
        Ok(back)
    }

    /// A destination's variables, its credentials out of the vault.
    async fn env(&self, d: &Destination) -> Result<Vec<(String, String)>, String> {
        let creds = credentials(self.state, self.vault, d)
            .await
            .map_err(|e| e.to_string())?;
        d.env(creds.as_deref()).map_err(|e| e.to_string())
    }
}

/// A database dropped, recreated and its dump restored, each engine its own way — its
/// statements built before anything is dropped, so a name refused stops it first.
enum PutBack {
    Postgres {
        dumper: hlb_backup::PgDumper<hlb_backup::PgContainerRunner>,
        admin: hlb_backup::pitr::Credentials,
        /// The drop and provisioning's statements, run from `postgres`.
        recreate: Vec<String>,
        /// Enabled by the administrator in the new database.
        extensions: Vec<String>,
    },
    Mariadb {
        dumper: hlb_backup::mariadump::MariaDumper<hlb_backup::MariaContainerRunner>,
        target: hlb_backup::mariadump::MariaTarget,
        recreate: Vec<String>,
    },
}

impl PutBack {
    fn postgres(db: &Database<'_>, admin_url: &str, network: &str) -> Result<Self, String> {
        let e = |e: hlb_platform::Error| e.to_string();
        let mut recreate = vec![hlb_platform::drop_database_statement(db.name).map_err(e)?];
        recreate.extend(hlb_platform::database_statements(db.name, db.role).map_err(e)?);
        let extensions = db
            .extensions
            .iter()
            .map(|x| hlb_platform::extension_statement(x))
            .collect::<Result<Vec<_>, _>>()
            .map_err(e)?;
        let admin = hlb_backup::parse_pg_url(admin_url)
            .ok_or_else(|| "unreadable PostgreSQL admin URL".to_string())?;
        Ok(Self::Postgres {
            dumper: hlb_backup::PgDumper::new(
                hlb_backup::PgContainerRunner::default().network(network),
            ),
            admin,
            recreate,
            extensions,
        })
    }

    /// 🔴 Restored by the administrator, not the app's user: MariaDB owns no table to
    /// anyone, and the dump's `DEFINER`s — the app's user on its triggers, routines and
    /// events — are kept as they were. The dump was checked to be this database's: it
    /// restores where its `USE` says, at server level.
    fn mariadb(db: &Database<'_>, admin_url: &str, network: &str) -> Result<Self, String> {
        use hlb_platform::mariadb;
        let e = |e: hlb_platform::Error| e.to_string();
        let mut recreate = vec![mariadb::drop_database_statement(db.name).map_err(e)?];
        recreate.extend(mariadb::database_statements(db.name, db.role).map_err(e)?);
        let admin = hlb_backup::parse_maria_url(admin_url)
            .ok_or_else(|| "unreadable MariaDB admin URL".to_string())?;
        Ok(Self::Mariadb {
            dumper: hlb_backup::mariadump::MariaDumper::new(
                hlb_backup::MariaContainerRunner::default().network(network),
            ),
            target: hlb_backup::mariadump::MariaTarget {
                host: admin.host,
                port: admin.port,
                database: db.name.to_string(),
                user: admin.user,
                password: admin.password,
            },
            recreate,
        })
    }

    async fn run(&self, db: &Database<'_>, dump: &[u8]) -> Result<(), String> {
        let e = |e: hlb_backup::Error| e.to_string();
        match self {
            Self::Postgres {
                dumper,
                admin,
                recreate,
                extensions,
            } => {
                let at = |database: &str| hlb_backup::PgTarget {
                    host: admin.host.clone(),
                    port: admin.port,
                    database: database.to_string(),
                    user: admin.user.clone(),
                    password: admin.password.clone(),
                };
                dumper.psql(&at("postgres"), recreate).await.map_err(e)?;
                if !extensions.is_empty() {
                    dumper.psql(&at(db.name), extensions).await.map_err(e)?;
                }
                dumper
                    .restore_as(&at(db.name), dump, db.role, db.extensions)
                    .await
                    .map_err(e)
            }
            // Not one transaction, unlike PostgreSQL's: MariaDB commits each `CREATE
            // TABLE` on its own. Stopped halfway, the database holds what it reached —
            // the app is left stopped on it, and the copy taken first named.
            Self::Mariadb {
                dumper,
                target,
                recreate,
            } => {
                dumper.sql(target, recreate).await.map_err(e)?;
                dumper.restore(target, dump).await.map_err(e)
            }
        }
    }
}

/// The one directory of the volume holding every file of `s` — a database and its
/// `-wal` and `-shm` —, where it is restored from and onto. `None` when they are not
/// all in one directory inside the volume.
fn files_dir(s: &Snapshot, volume: &str) -> Option<String> {
    let root = volume_path(volume);
    let mut dirs = s.paths.iter().map(|p| {
        std::path::Path::new(p)
            .parent()
            .map(|d| d.to_string_lossy().into_owned())
    });
    let first = dirs.next()??;
    let inside = first == root || first.starts_with(&format!("{root}/"));
    (inside && dirs.all(|d| d.as_deref() == Some(first.as_str()))).then_some(first)
}

/// The replicas each of `services` that is deployed runs: what to give back.
pub async fn replicas(o: &dyn Orchestrator, services: &[String]) -> Vec<(String, u64)> {
    let mut out = Vec::new();
    for s in services {
        if let Ok(st) = o.status(s).await {
            out.push((s.clone(), st.desired_replicas));
        }
    }
    out
}

/// How long a hold keeps reconciliation away: past it, a process that died holding
/// services stopped gets them started again — longer than any copy or restore.
const HOLD_SECS: i64 = 24 * 3600;

/// Stops each service and waits until none of its tasks runs, held for `why`.
///
/// 🔴 Held before it is scaled: with `--reconcile-apply`, the next minute started a
/// service scaled to zero again — onto a volume half restored, or being copied.
pub async fn stop(
    o: &dyn Orchestrator,
    state: &State,
    services: &[(String, u64)],
    why: &str,
) -> Result<(), String> {
    let names: Vec<String> = services.iter().map(|(s, _)| s.clone()).collect();
    state
        .hold_services(&names, why, HOLD_SECS)
        .await
        .map_err(|e| format!("holding {} stopped: {e}", names.join(", ")))?;
    for (s, replicas) in services {
        if *replicas > 0 {
            o.scale(s, 0)
                .await
                .map_err(|e| format!("stopping {s}: {e}"))?;
        }
    }
    let deadline = tokio::time::Instant::now() + STOP_TIMEOUT;
    for (s, _) in services {
        // Scaled to zero is asked, not done: the task still writes until it exits.
        while o
            .status(s)
            .await
            .map_err(|e| e.to_string())?
            .running_replicas
            > 0
        {
            if tokio::time::Instant::now() > deadline {
                return Err(format!("{s} still runs after {} s", STOP_TIMEOUT.as_secs()));
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    }
    Ok(())
}

/// Gives each service back its replicas, its companions before the app — the order
/// they were deployed in.
///
/// The hold is released whatever happened: a service that did not start is then
/// reconciliation's to start again, where one still held would stay down.
pub async fn start(
    o: &dyn Orchestrator,
    state: &State,
    stopped: &[(String, u64)],
) -> Result<(), String> {
    let mut failed = None;
    for (s, replicas) in stopped.iter().rev() {
        if *replicas > 0 {
            if let Err(e) = o.scale(s, *replicas).await {
                failed.get_or_insert(format!("starting {s} again: {e}"));
            }
        }
    }
    let names: Vec<String> = stopped.iter().map(|(s, _)| s.clone()).collect();
    if let Err(e) = state.release_services(&names).await {
        failed.get_or_insert(format!("releasing {}: {e}", names.join(", ")));
    }
    failed.map_or(Ok(()), Err)
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_792_400_000; // 2026-10-18

    fn snap(id: &str, time: &str, path: &str, tags: &[&str]) -> Snapshot {
        Snapshot {
            id: id.into(),
            time: time.into(),
            paths: vec![path.into()],
            tags: tags.iter().map(|t| t.to_string()).collect(),
            hostname: "homelabus".into(),
        }
    }

    fn taken(ids: &[&str]) -> HashSet<String> {
        ids.iter().map(|i| i.to_string()).collect()
    }

    #[test]
    fn a_dump_is_its_engine_s() {
        // An app needing both engines, its databases unnamed: both are `db:<app>`.
        let all = vec![
            snap(
                "pg1",
                "2026-10-17T10:00:00Z",
                "/staging/chat-chat-20261017T100000Z.dump",
                &["app:chat", "db:chat"],
            ),
            snap(
                "ma1",
                "2026-10-17T09:00:00Z",
                "/staging/chat-chat-20261017T090000Z.sql",
                &["app:chat", "db:chat"],
            ),
            // A SQLite database's consistent copy carries the tag too.
            snap(
                "sq1",
                "2026-10-17T11:00:00Z",
                "/donnees/chat-data/chat",
                &["app:chat", "db:chat"],
            ),
        ];
        let t = taken(&["pg1", "ma1", "sq1"]);
        let pg = pick_dump(&all, DbEngine::Postgres, "chat", None, &t, NOW);
        assert_eq!(pg.snapshot.map(|s| s.id.as_str()), Some("pg1"));
        let ma = pick_dump(&all, DbEngine::Mariadb, "chat", None, &t, NOW);
        assert_eq!(ma.snapshot.map(|s| s.id.as_str()), Some("ma1"));
    }

    #[test]
    fn each_database_comes_back_from_the_pass_that_took_the_volume() {
        let sq = |id: &str, time: &str, path: &str, db: &str, pass: &str| {
            snap(
                id,
                time,
                path,
                &["app:pocket-id", hlb_backup::sqlite::SNAPSHOT_KIND, db, pass],
            )
        };
        let volume = snap(
            "vol1",
            "2026-10-19T10:00:00Z",
            "/donnees/pocket-id-data",
            &["pass:a"],
        );
        let all = vec![
            // Before the volume's: another pass.
            sq(
                "old1",
                "2026-10-19T09:00:00Z",
                "/donnees/pocket-id-data/pocket-id.db",
                "db:pocket-id.db",
                "pass:z",
            ),
            sq(
                "pass1",
                "2026-10-19T10:00:30Z",
                "/donnees/pocket-id-data/pocket-id.db",
                "db:pocket-id.db",
                "pass:a",
            ),
            sq(
                "pass2",
                "2026-10-19T10:00:40Z",
                "/donnees/pocket-id-data/pocket-id.db",
                "db:pocket-id.db",
                "pass:a",
            ),
            // The next day's pass.
            sq(
                "late1",
                "2026-10-20T10:00:30Z",
                "/donnees/pocket-id-data/x/other.db",
                "db:x/other.db",
                "pass:b",
            ),
            // Never taken here.
            sq(
                "forged",
                "2026-10-19T10:00:31Z",
                "/donnees/pocket-id-data/x/y.db",
                "db:x/y.db",
                "pass:a",
            ),
            // Another volume.
            sq(
                "else1",
                "2026-10-19T10:00:30Z",
                "/donnees/gitea-data/g.db",
                "db:g.db",
                "pass:a",
            ),
        ];
        let ours = taken(&["vol1", "old1", "pass1", "pass2", "late1", "else1"]);
        let got: Vec<(String, String)> = sqlite_of_pass(&all, "pocket-id-data", &volume, &ours)
            .into_iter()
            .map(|(db, s)| (db, s.id.clone()))
            .collect();
        assert_eq!(got, vec![("pocket-id.db".to_string(), "pass1".to_string())]);
    }

    #[test]
    fn a_copy_taken_before_an_update_gets_no_database_of_a_later_pass() {
        // 🔴 Found by review: a copy taken before an update carries no pass, and was
        // paired with the first database snapshot within six hours after it — the one
        // the next pass took of the database the update had just migrated.
        let before_update = snap(
            "pre1",
            "2026-10-19T10:00:00Z",
            "/donnees/pocket-id-data",
            &["app:pocket-id", "kind:pre-update"],
        );
        let migrated = snap(
            "next1",
            "2026-10-19T10:05:00Z",
            "/donnees/pocket-id-data/pocket-id.db",
            &[
                "app:pocket-id",
                hlb_backup::sqlite::SNAPSHOT_KIND,
                "db:pocket-id.db",
                "pass:later",
            ],
        );
        let all = vec![migrated];
        let ours = taken(&["pre1", "next1"]);
        assert!(sqlite_of_pass(&all, "pocket-id-data", &before_update, &ours).is_empty());
    }

    #[test]
    fn a_database_is_put_back_into_its_own_directory_only() {
        // 🔴 Restored at `/`, the directories above it came back root's from the
        // staging volume. From its directory onto its directory, nothing above moves.
        let mut s = snap(
            "q1",
            "2026-10-19T10:00:30Z",
            "/donnees/app-data/data/app.db",
            &[],
        );
        s.paths.push("/donnees/app-data/data/app.db-wal".into());
        s.paths.push("/donnees/app-data/data/app.db-shm".into());
        assert_eq!(
            files_dir(&s, "app-data").as_deref(),
            Some("/donnees/app-data/data")
        );
        let at_root = snap("q2", "x", "/donnees/app-data/app.db", &[]);
        assert_eq!(
            files_dir(&at_root, "app-data").as_deref(),
            Some("/donnees/app-data")
        );
        s.paths.push("/donnees/app-data/other/x".into());
        assert_eq!(files_dir(&s, "app-data"), None, "two directories");
        let outside = snap("q3", "x", "/donnees/app-database/app.db", &[]);
        assert_eq!(files_dir(&outside, "app-data"), None, "another volume");
    }

    fn id(p: &Picked<'_>) -> Option<String> {
        p.snapshot.map(|s| s.id.clone())
    }

    #[test]
    fn the_latest_snapshot_of_the_volume_is_taken_never_a_copy_a_restore_made() {
        let at = "2026-10-17T10:00:00Z";
        let all = [
            snap(
                "aaa1",
                at,
                "/donnees/pocket-id-data",
                &["app:pocket-id", "kind:pre-update"],
            ),
            snap(
                "bbb2",
                at,
                "/donnees/pocket-id-data",
                &["app:pocket-id", "kind:pre-update"],
            ),
            // Another volume of the app, more recent.
            snap("ccc3", at, "/donnees/pocket-id-other", &["app:pocket-id"]),
            // What a first restore overwrote: the broken data.
            snap(
                "ddd4",
                at,
                "/donnees/pocket-id-data",
                &["app:pocket-id", BEFORE_RESTORE],
            ),
        ];
        let ours = taken(&["aaa1", "bbb2", "ccc3", "ddd4"]);
        let pick = |w| pick(&all, "pocket-id-data", w, &ours, NOW);
        assert_eq!(id(&pick(None)).as_deref(), Some("bbb2"));
        // Named, any of them — the copy a restore made included, to undo it.
        assert_eq!(id(&pick(Some("aa"))).as_deref(), Some("aaa1"));
        assert_eq!(id(&pick(Some("ddd"))).as_deref(), Some("ddd4"));
        assert!(id(&pick(Some("ccc"))).is_none());
        assert!(id(&super::pick(&all, "gitea-data", None, &ours, NOW)).is_none());
    }

    #[test]
    fn a_snapshot_this_installation_never_took_is_set_aside_and_said() {
        let path = "/donnees/gitea-data";
        let full = "f".repeat(64);
        let all = [
            snap("aaa1", "2026-10-16T03:00:00+02:00", path, &["app:gitea"]),
            // Written by whoever held the repository's password.
            snap("bbb2", "2026-10-17T03:00:00+02:00", path, &["app:gitea"]),
            snap(&full, "2099-01-01T00:00:00Z", path, &["app:gitea"]),
        ];
        let ours = taken(&["aaa1"]);

        let latest = pick(&all, "gitea-data", None, &ours, NOW);
        assert_eq!(id(&latest).as_deref(), Some("aaa1"));
        let aside: Vec<(&str, SetAside)> = latest
            .set_aside
            .iter()
            .map(|(s, why)| (s.id.as_str(), *why))
            .collect();
        assert_eq!(
            aside,
            [
                (full.as_str(), SetAside::Future),
                ("bbb2", SetAside::NotTaken)
            ]
        );

        // Named by a prefix, it stays aside: a prefix pins nothing.
        let named = pick(&all, "gitea-data", Some("bbb"), &ours, NOW);
        assert!(named.snapshot.is_none());
        assert_eq!(named.set_aside.len(), 1);
        // By its full id — the hash of its content — a person vouches for it.
        let pinned = pick(&all, "gitea-data", Some(&full), &ours, NOW);
        assert_eq!(id(&pinned).as_deref(), Some(full.as_str()));

        // Nothing of ours at all: nothing is restored, and why is kept.
        let none = pick(&all, "gitea-data", None, &taken(&[]), NOW);
        assert!(none.snapshot.is_none());
        assert_eq!(none.set_aside.len(), 3);
    }
}
