//! Backups.
//!
//! Three principles this crate encodes:
//!
//! 1. **Retention is mandatory.** A repository with no policy fills the disk and brings
//!    down the machine it was protecting.
//! 2. **The password never touches the command line.**
//! 3. **An untested backup is not a backup**: restore verification is part of
//!    this module, not a later refinement.

pub mod destination;
pub mod docker_env;
pub mod dr;
pub mod drill;
pub mod erasure;
pub mod images;
pub mod mariadump;
pub mod pgdump;
pub mod pgrunner;
pub mod pitr;
pub mod provider;
pub mod replay;
pub mod replication;
pub mod restic;
pub mod restorability;
pub mod retention;
pub mod runner;
pub mod schedule;
pub mod snapshot;
pub mod sqlite;
pub mod tarball;
pub mod verify;
pub mod wal_ship;

pub use destination::{
    coverage_of, destinations_for, Class, Coverage, CoverageSource, Destination,
    State as DestinationState,
};
pub use dr::{plan_promotion, Profile as DrProfile};
pub use drill::{Readiness, Scope as DrillScope, Target as DrillTarget};
pub use mariadump::{Consistency, MariaDumper, MariaTarget};
pub use pgdump::{PgDumper, PgTarget};
pub use pgrunner::{MariaContainerRunner, PgContainerRunner};
pub use pitr::{parse_maria_url, parse_pg_url, scan_archive, wal_coverage, Segment};
pub use provider::ResticBackupProvider;
pub use replication::{Health as StandbyHealth, StandbyStatus};
pub use restic::{Repository, Runner, Snapshot};
pub use restorability::{Confidence, Restorability};
pub use retention::RetentionPolicy;
pub use schedule::Schedule;
pub use verify::{verify_by_restore, verify_snapshot, verify_snapshot_on, Verification};
// ⚠️ `Snapshot` already exists for restic: renamed here, or the two notions — "restic
// snapshot" and "filesystem snapshot" — would blur together in use, while they do NOT
// protect against the same failures.
pub use runner::{ContainerRunner, HostRunner};
pub use snapshot::{detect as detect_filesystem, Filesystem, Snapshot as FsSnapshot};
pub use sqlite::{snapshot as sqlite_snapshot, snapshot_all as sqlite_snapshot_all};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("restore to {target} impossible: {reason}")]
    Pitr { target: String, reason: String },

    #[error("restic unavailable: {0}")]
    ResticMissing(String),

    #[error("restic {command} failed: {stderr}")]
    Restic { command: String, stderr: String },

    #[error("empty retention policy: `forget` would delete every snapshot")]
    EmptyRetention,

    #[error("dump of \"{database}\": {stderr}")]
    Dump { database: String, stderr: String },

    #[error("{0}")]
    Unexpected(String),

    #[error(transparent)]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, Error>;

/// "1 table" / "4 tables" — English plural, where zero takes the plural.
///
/// ⚠️ `hlb-backup` does not depend on `hlb-api` (it is the other way round), so
/// `hlb_api::plural` is not reachable here. Duplicating the RULE would risk divergence;
/// duplicating this single case, with the test that goes with it, does not.
pub(crate) fn plural_tables(n: i64) -> String {
    if n == 1 {
        format!("{n} table")
    } else {
        format!("{n} tables")
    }
}

#[cfg(test)]
mod display_tests {
    use crate::destination::{Coverage, State};
    use crate::drill::{Outcome, Readiness, Scope};

    /// A glyph that carries meaning on its own: emoji, dingbats, warning signs.
    ///
    /// Same predicate as `hlb-api`'s, duplicated because this crate does not depend on
    /// it and must not start to for a test.
    fn is_pictograph(c: char) -> bool {
        matches!(c as u32, 0x2600..=0x27BF | 0x2B00..=0x2BFF | 0xFE0F | 0x1F000..=0x1FAFF)
    }

    #[test]
    fn shared_messages_carry_no_pictograph() {
        // 🔴 The trap already seen twice (`Coherence::describe`, then the topology
        // verdict): shared text must depend on NONE of its consumers. Severity travels
        // through the words and the caller's colour; a "✓" or "🔴" inside the sentence is
        // a second channel no caller can restyle, and a screen reader says it aloud.
        //
        // ⚠️ This test covers ONLY the displayed messages. The generators of
        // configuration files and shell scripts (`pitr`, `replication`, `deadman`,
        // `sqlite`) keep their emoji: they are read in a terminal only, and removing them
        // would impoverish comments you re-read in a terminal, at the worst moment.
        let mut messages: Vec<String> = Vec::new();

        for r in [
            Readiness::Ready { days: 3 },
            Readiness::Due { days: 40 },
            Readiness::Overdue { days: 120 },
            Readiness::Never,
        ] {
            messages.push(r.describe());
        }

        messages.push(
            Outcome {
                scope: Scope::Postgres,
                opened: true,
                tables: Some(42),
                seconds: 12,
                detail: String::new(),
            }
            .describe(),
        );
        messages.push(
            Outcome {
                scope: Scope::Postgres,
                opened: true,
                tables: Some(0),
                seconds: 3,
                detail: String::new(),
            }
            .describe(),
        );

        let c = Coverage {
            app: "gitea".into(),
            per_destination: vec![
                ("nas".into(), State::Fresh { age_s: 600 }),
                ("offsite".into(), State::Stale { age_s: 900_000 }),
            ],
            classes: vec![crate::Class::Critical, crate::Class::Bulky],
        };
        let r = crate::Restorability::compute(&c, None, None, Readiness::Never);
        messages.push(r.verdict());
        messages.push(r.confidence().describe().to_string());
        messages.extend(r.remedies());

        for m in &messages {
            for ch in m.chars() {
                assert!(!is_pictograph(ch), "\"{m}\" contains U+{:04X}", ch as u32);
            }
            // And the parenthesised-plural tic, banned everywhere else.
            let tic = format!("({})", "s");
            assert!(!m.contains(&tic), "{m}");
        }
    }
}
