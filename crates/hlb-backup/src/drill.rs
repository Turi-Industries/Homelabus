//! Disaster recovery drills.
//!
//! > **A recovery procedure never rehearsed does not work the day you need it.**
//!
//! That is not a slogan: the restore is the least-travelled code path in the system.
//! Everything else runs constantly — backups, reconciliation, updates — and so breaks
//! loudly. The restore only runs one day, and that is the worst possible day to
//! discover a password changed, a path moved, or a `down` was wrong.
//!
//! ## 🔴 What separates a drill from a disaster
//!
//! A recovery drill that touches production is **worse than no drill at all**: you turn
//! a rehearsal into a real incident, and you do it deliberately, on a day when
//! everything was fine.
//!
//! Three safeguards, each checked by a test:
//!
//! 1. **A disposable target is mandatory.** The drill refuses to start if the target is
//!    not explicitly marked as such. No default, no inference.
//! 2. **No write outside the target.** We read the backups, we write into a container
//!    and a volume created for the occasion, destroyed at the end.
//! 3. **The result has no side effect.** A failed drill stops nothing, fails nothing
//!    over, deletes nothing. It *reports*.
//! 4. **What is restored reaches nothing.** The restored server is the production one's
//!    configuration and catalog: its `archive_command` would push WAL into the real
//!    archive, a subscription would consume the publisher's slot, a scheduled job would
//!    run. It starts with no network and with archiving and replication workers off
//!    ([`ISOLATION`]). And no application is ever started on it: a restored n8n would
//!    run its workflows — send the mail, call the webhooks — against the real world.
//!
//! ## What a drill proves, and what it does not
//!
//! | | Proved | Not proved |
//! |---|---|---|
//! | `backup verify` | the bytes come back | that they form a usable database |
//! | **drill** | the database opens and holds the data | that the application service restarts |
//!
//! The right-hand column stays: a restored PostgreSQL can be perfect and the application
//! still refuse to start for a reason of its own. The drill does not claim otherwise.

use crate::{Error, Result};

/// How the restored server is started: reachable through its socket only, archiving
/// nothing, replicating nothing. Given on the command line, they beat the restored
/// `postgresql.conf` and `postgresql.auto.conf`.
pub const ISOLATION: &str =
    "-c listen_addresses='' -c archive_mode=off -c max_logical_replication_workers=0";

/// The `docker run` of a drill's container: no network at all, the backup read-only.
fn startup_args<'a>(target: &'a Target, mount: &'a str, image: &'a str) -> Vec<&'a str> {
    vec![
        "run",
        "-d",
        "--name",
        &target.container,
        // The socket inside the container is all `psql` needs.
        "--network",
        "none",
        "--entrypoint",
        "sleep",
        "-v",
        mount,
        image,
        "600",
    ]
}

/// What is being drilled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    /// Restore a base backup and check PostgreSQL opens it.
    Postgres,
    /// Restore a logical dump and count the rows.
    SqlDump,
}

impl Scope {
    pub fn describe(&self) -> &'static str {
        match self {
            Self::Postgres => "PostgreSQL base backup",
            Self::SqlDump => "logical dump",
        }
    }
}

/// A drill's target.
///
/// 🔴 `disposable` has **no** default of `true`, and is not inferred. A drill that
/// guessed its target would one day guess wrong — and on that day it would overwrite
/// production with a four-hour-old backup.
#[derive(Debug, Clone)]
pub struct Target {
    /// Name of the disposable container created for the drill.
    pub container: String,
    /// The caller asserts this target is disposable.
    pub disposable: bool,
}

/// Why a drill cannot take place.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refused {
    /// 🔴 The target is not declared disposable.
    NotDisposable { container: String },
    /// 🔴 The target's name looks like production.
    LooksLikeProduction { container: String, pattern: String },
    /// Nothing to restore.
    NothingToRestore,
}

impl Refused {
    pub fn describe(&self) -> String {
        match self {
            Self::NotDisposable { container } => format!(
                "🔴 \"{container}\" is not declared disposable. A drill that touches \
                 production turns a rehearsal into a real incident — on a day when \
                 everything was fine. Pass --disposable if the target really is a \
                 container created for the occasion."
            ),
            Self::LooksLikeProduction { container, pattern } => format!(
                "🔴 \"{container}\" contains \"{pattern}\": that name looks like \
                 production. Even with --disposable we refuse — a typo in a container \
                 name must not cost a database."
            ),
            Self::NothingToRestore => "no backup to restore: the drill would have \
                 nothing to prove. Run `hlb backup pitr base --apply` first."
                .to_string(),
        }
    }
}

/// The name fragments that give away a production target.
///
/// ⚠️ Deliberately broad. A false positive costs renaming a test container; a false
/// negative costs a production database.
const FORBIDDEN_NAMES: &[&str] = &["prod", "production", "live", "main", "primary", "primaire"];

/// Checks a drill can take place without risk.
pub fn authorize(target: &Target, has_backup: bool) -> std::result::Result<(), Refused> {
    // 🔴 The name first: even declared disposable, a target called "postgres-prod" is
    // very probably a typo, and the order of the checks means `--disposable` cannot get
    // around it.
    let low = target.container.to_lowercase();
    if let Some(m) = FORBIDDEN_NAMES.iter().find(|m| low.contains(**m)) {
        return Err(Refused::LooksLikeProduction {
            container: target.container.clone(),
            pattern: (*m).to_string(),
        });
    }

    if !target.disposable {
        return Err(Refused::NotDisposable {
            container: target.container.clone(),
        });
    }

    if !has_backup {
        return Err(Refused::NothingToRestore);
    }
    Ok(())
}

/// A drill's result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    pub scope: Scope,
    /// Did the restored database open?
    pub opened: bool,
    /// Number of tables found. `None` = not queried.
    pub tables: Option<i64>,
    /// Duration, in seconds.
    pub seconds: u64,
    pub detail: String,
}

impl Outcome {
    /// Did the drill prove anything?
    ///
    /// 🔴 Opening is not enough: a PostgreSQL restored from an empty backup opens
    /// perfectly and holds nothing. That is exactly the case a drill must catch, and the
    /// one a size-based verification lets through.
    pub fn succeeded(&self) -> bool {
        self.opened && self.tables.is_some_and(|n| n > 0)
    }

    pub fn describe(&self) -> String {
        if self.succeeded() {
            format!(
                "{} restored in {} s — {} readable",
                self.scope.describe(),
                self.seconds,
                crate::plural_tables(self.tables.unwrap_or(0))
            )
        } else if self.opened {
            format!(
                "{} opens but holds NOTHING ({}). An empty database restores \
                 perfectly — the worst possible result, because it looks like a \
                 success.",
                self.scope.describe(),
                crate::plural_tables(self.tables.unwrap_or(0))
            )
        } else {
            format!("{} does not open: {}", self.scope.describe(), self.detail)
        }
    }
}

/// How long since the drill was last run?
///
/// The target is once a month. Past two, the procedure has had time to diverge: a path
/// that moves, a password that rotates, a version that changes.
pub const INTERVAL_DAYS: i64 = 30;
pub const LATE_DAYS: i64 = 60;

/// The state of the preparation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Readiness {
    /// Drilled recently.
    Ready { days: i64 },
    /// It is about time.
    Due { days: i64 },
    /// 🔴 Too old to be relied on any more.
    Overdue { days: i64 },
    /// 🔴 Never drilled.
    Never,
}

impl Readiness {
    pub fn from_days(days: Option<i64>) -> Self {
        match days {
            None => Self::Never,
            Some(d) if d > LATE_DAYS => Self::Overdue { days: d },
            Some(d) if d > INTERVAL_DAYS => Self::Due { days: d },
            Some(d) => Self::Ready { days: d },
        }
    }

    /// Should this raise an alert?
    pub fn needs_attention(&self) -> bool {
        !matches!(self, Self::Ready { .. })
    }

    pub fn describe(&self) -> String {
        match self {
            Self::Ready { days } => format!("drilled {days} d ago"),
            Self::Due { days } => {
                format!("drilled {days} d ago — the target is every 30 d")
            }
            Self::Overdue { days } => format!(
                "drilled {days} d ago. Past {LATE_DAYS} d the procedure has had time \
                 to diverge: a path that moves, a password that rotates, a version that \
                 changes."
            ),
            Self::Never => "NEVER drilled. The restore is the least-travelled code path \
                 in the system, and the only one you discover on the worst day."
                .to_string(),
        }
    }
}

/// Runs a drill on a PostgreSQL base backup.
///
/// ⚠️ Restores into a **brand-new** container, never into an existing server. A
/// `pg_basebackup` restored over a populated data directory would destroy its
/// contents.
pub async fn run_postgres(
    target: &Target,
    base_dir: &str,
    base_id: &str,
    image: &str,
) -> Result<Outcome> {
    let start = std::time::SystemTime::now();

    // The container is destroyed first: a leftover from a previous drill would carry
    // data that would skew the result.
    let _ = docker(&["rm", "-f", &target.container]).await;

    let source = format!("{}/{base_id}", base_dir.trim_end_matches('/'));

    // 🔴 `:ro` on the backup mount: whatever happens inside the container, the archive
    // cannot be modified. That is the protection that matters most — an archive
    // corrupted BY a drill would be the last straw.
    //
    // ⚠️ And above all: we replace the command with a `sleep`, so the image's entrypoint
    // does NOT start PostgreSQL. Letting it would create a fresh database that then has
    // to be stopped — and `pg_ctl` fails on "another server might be running" because
    // the server runs under a different user from the one stopping it.
    let mount = format!("{source}:/backup:ro");
    let startup = docker(&startup_args(target, &mount, image)).await;

    if let Err(e) = startup {
        return Ok(Outcome {
            scope: Scope::Postgres,
            opened: false,
            tables: None,
            seconds: 0,
            detail: format!("container not started: {e}"),
        });
    }

    // The data directory is CREATED by us, empty, then filled from the archive.
    //
    // ⚠️ `chmod 700` is not cosmetic: PostgreSQL refuses to start on a data directory
    // others can reach, with a message that talks about permissions without saying
    // which.
    let script = restore_script();
    let restore = docker(&["exec", &target.container, "sh", "-c", &script]).await;

    let open = restore.is_ok();
    let detail = restore.err().unwrap_or_default();

    // 🔴 Count across EVERY database in the cluster, not just `postgres`.
    //
    // The first version only queried the `postgres` database, which is empty on a real
    // installation: the data lives in one database per app. The drill therefore
    // announced "empty database" on a perfectly healthy backup — a false negative that,
    // repeated, teaches you to ignore the alert.
    let tables = if open {
        docker(&[
            "exec", &target.container, "sh", "-c",
            "total=0; \
             for d in $(psql -U postgres -tAc \
                 \"SELECT datname FROM pg_database WHERE datallowconn AND NOT datistemplate\"); do \
               n=$(psql -U postgres -d \"$d\" -tAc \
                 \"SELECT count(*) FROM information_schema.tables \
                   WHERE table_schema NOT IN ('pg_catalog','information_schema')\" 2>/dev/null || echo 0); \
               total=$((total + n)); \
             done; \
             echo $total",
        ])
        .await
        .ok()
        .and_then(|s| s.trim().parse::<i64>().ok())
    } else {
        None
    };

    // Unconditional cleanup: a drill leaves nothing behind.
    let _ = docker(&["rm", "-f", &target.container]).await;

    Ok(Outcome {
        scope: Scope::Postgres,
        opened: open,
        tables,
        seconds: start.elapsed().map(|d| d.as_secs()).unwrap_or(0),
        detail,
    })
}

/// Fills a new data directory from the archive and starts the server on it, isolated.
fn restore_script() -> String {
    format!(
        "set -e; \
         mkdir -p /var/lib/postgresql/data; \
         rm -rf /var/lib/postgresql/data/*; \
         tar xzf /backup/base.tar.gz -C /var/lib/postgresql/data; \
         mkdir -p /var/lib/postgresql/data/pg_wal; \
         tar xzf /backup/pg_wal.tar.gz -C /var/lib/postgresql/data/pg_wal 2>/dev/null || true; \
         chown -R postgres:postgres /var/lib/postgresql/data; \
         chmod 700 /var/lib/postgresql/data; \
         su postgres -c \"pg_ctl -D /var/lib/postgresql/data -w -t 60 -l /tmp/pg.log -o \\\"{ISOLATION}\\\" start\" \
           || (cat /tmp/pg.log; exit 1)"
    )
}

async fn docker(args: &[&str]) -> std::result::Result<String, String> {
    let out = tokio::process::Command::new("docker")
        .args(args)
        .output()
        .await
        .map_err(|e| format!("docker not found: {e}"))?;

    if !out.status.success() {
        return Err(String::from_utf8_lossy(&out.stderr).trim().to_string());
    }
    Ok(String::from_utf8_lossy(&out.stdout).to_string())
}

/// The name of a drill container.
///
/// Prefixed and timestamped: recognisable at a glance in a `docker ps`, and impossible
/// to confuse with a real service.
pub fn container_name(at: i64) -> Result<String> {
    let (y, m, d, hh, mm, ss) = crate::pitr::civil_public(at);
    Ok(format!(
        "hlb-exercice-{y:04}{m:02}{d:02}T{hh:02}{mm:02}{ss:02}Z"
    ))
}

#[allow(dead_code)]
fn _assert_error_used(_: Error) {}

#[cfg(test)]
mod tests {
    use super::*;

    const J0: i64 = 1_786_881_600;

    fn disposable() -> Target {
        Target {
            container: container_name(J0).expect("name"),
            disposable: true,
        }
    }

    #[test]
    fn an_undeclared_target_is_refused() {
        // 🔴 No default, no inference: a drill that guessed its target would one day
        // guess wrong.
        let t = Target {
            disposable: false,
            ..disposable()
        };
        let e = authorize(&t, true).unwrap_err();
        assert!(matches!(e, Refused::NotDisposable { .. }));
        assert!(e.describe().contains("real incident"), "{}", e.describe());
    }

    #[test]
    fn a_production_looking_name_is_refused_even_when_declared_disposable() {
        // 🔴 The order of the checks means --disposable can NOT get around this: a typo
        // in a container name must not cost a database.
        for name in [
            "postgres-prod",
            "db-production",
            "pg-main",
            "PRIMARY-db",
            "live-pg",
        ] {
            let t = Target {
                container: name.into(),
                disposable: true,
            };
            let e = authorize(&t, true).unwrap_err();
            assert!(
                matches!(e, Refused::LooksLikeProduction { .. }),
                "\"{name}\" should have been refused"
            );
        }
    }

    #[test]
    fn a_disposable_target_passes() {
        assert!(authorize(&disposable(), true).is_ok());
    }

    #[test]
    fn without_a_backup_there_is_nothing_to_prove() {
        assert_eq!(
            authorize(&disposable(), false).unwrap_err(),
            Refused::NothingToRestore
        );
    }

    #[test]
    fn the_container_name_is_unmistakable() {
        let n = container_name(J0).expect("name");
        assert!(n.starts_with("hlb-exercice-"), "{n}");
        // And it trips none of the name safeguards.
        assert!(authorize(
            &Target {
                container: n,
                disposable: true
            },
            true
        )
        .is_ok());
    }

    #[test]
    fn the_restored_server_reaches_nothing() {
        let target = disposable();
        let args = startup_args(&target, "/b:/backup:ro", "postgres:17");
        assert!(
            args.windows(2).any(|w| w == ["--network", "none"]),
            "{args:?}"
        );
        assert!(args.contains(&"/b:/backup:ro"));
        let script = restore_script();
        assert!(script.contains(ISOLATION), "{script}");
        for setting in [
            "listen_addresses=''",
            "archive_mode=off",
            "max_logical_replication_workers=0",
        ] {
            assert!(ISOLATION.contains(setting), "{setting}");
        }
    }

    #[test]
    fn an_empty_database_that_opens_is_the_worst_result() {
        // 🔴 An empty database restores PERFECTLY: it opens, no error. That is the case
        // a size-based verification lets through, and the one that looks most like a
        // success.
        let o = Outcome {
            scope: Scope::Postgres,
            opened: true,
            tables: Some(0),
            seconds: 12,
            detail: String::new(),
        };
        assert!(!o.succeeded());
        assert!(o.describe().contains("holds NOTHING"), "{}", o.describe());
        assert!(
            o.describe().contains("looks like a success"),
            "{}",
            o.describe()
        );
    }

    #[test]
    fn a_populated_database_succeeds() {
        let o = Outcome {
            scope: Scope::Postgres,
            opened: true,
            tables: Some(14),
            seconds: 30,
            detail: String::new(),
        };
        assert!(o.succeeded());
        assert!(o.describe().contains("14 table"));
    }

    #[test]
    fn a_database_that_does_not_open_fails_loudly() {
        let o = Outcome {
            scope: Scope::Postgres,
            opened: false,
            tables: None,
            seconds: 5,
            detail: "could not read file pg_control".into(),
        };
        assert!(!o.succeeded());
        assert!(
            o.describe().contains("pg_control"),
            "the cause must be visible"
        );
    }

    #[test]
    fn never_drilled_is_the_loudest_state() {
        let r = Readiness::from_days(None);
        assert_eq!(r, Readiness::Never);
        assert!(r.needs_attention());
        assert!(r.describe().contains("NEVER"));
        assert!(r.describe().contains("worst day"), "{}", r.describe());
    }

    #[test]
    fn the_drill_ages_through_three_states() {
        // The target is every 30 days; past 60 the procedure has had time to
        // diverge.
        assert_eq!(Readiness::from_days(Some(5)), Readiness::Ready { days: 5 });
        assert_eq!(Readiness::from_days(Some(45)), Readiness::Due { days: 45 });
        assert_eq!(
            Readiness::from_days(Some(120)),
            Readiness::Overdue { days: 120 }
        );

        assert!(!Readiness::from_days(Some(5)).needs_attention());
        assert!(Readiness::from_days(Some(45)).needs_attention());
    }

    #[test]
    fn the_thresholds_leave_room_to_react() {
        // Alerting at exactly 30 d leaves no margin: we want to know it is due BEFORE
        // it is too old.
        // `const`: checked at compile time, so changing a threshold without thinking
        // does not even compile.
        const _: () = assert!(INTERVAL_DAYS < LATE_DAYS);
        const _: () = assert!(LATE_DAYS - INTERVAL_DAYS >= 30);
    }
}
