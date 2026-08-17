//! Sauvegardes (§8 du plan).
//!
//! Trois principes que ce crate encode :
//!
//! 1. **La rétention est obligatoire.** Un dépôt sans politique remplit le disque et
//!    fait tomber la machine qu'il protégeait (§9bis).
//! 2. **Le mot de passe ne touche jamais la ligne de commande.**
//! 3. **Un backup non testé n'est pas un backup** (§8.3) : la vérification de
//!    restauration fait partie du module, pas d'un raffinement ultérieur.

pub mod mariadump;
pub mod pgdump;
pub mod dr;
pub mod drill;
pub mod pitr;
pub mod snapshot;
pub mod sqlite;
pub mod pgrunner;
pub mod provider;
pub mod replication;
pub mod restic;
pub mod retention;
pub mod schedule;
pub mod verify;
pub mod runner;

pub use pgdump::{PgDumper, PgTarget};
pub use pgrunner::{MariaContainerRunner, PgContainerRunner};
pub use provider::{provider_for_state, ResticBackupProvider};
pub use restic::{Repository, Runner, Snapshot};
pub use retention::RetentionPolicy;
pub use schedule::Schedule;
pub use verify::{verify_by_restore, verify_snapshot, Verification};
pub use pitr::{parse_maria_url, parse_pg_url, scan_archive, wal_coverage, Segment};
pub use dr::{plan_promotion, Profile as DrProfile};
pub use drill::{Readiness, Scope as DrillScope, Target as DrillTarget};
pub use replication::{Health as StandbyHealth, StandbyStatus};
pub use mariadump::{Coherence, MariaDumper, MariaTarget};
// ⚠️ `Snapshot` existe déjà pour restic : renommé ici, sinon les deux notions —
// « instantané restic » et « instantané de système de fichiers » — se confondraient
// à l'usage alors qu'elles ne protègent PAS des mêmes pannes.
pub use snapshot::{detect as detect_filesystem, Filesystem, Snapshot as FsSnapshot};
pub use sqlite::{snapshot as sqlite_snapshot, snapshot_all as sqlite_snapshot_all};
pub use runner::{ContainerRunner, HostRunner};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("restauration à {target} impossible : {reason}")]
    Pitr { target: String, reason: String },

    #[error("restic indisponible : {0}")]
    ResticMissing(String),

    #[error("restic {command} a échoué : {stderr}")]
    Restic { command: String, stderr: String },

    #[error("politique de rétention vide : `forget` supprimerait tous les instantanés")]
    EmptyRetention,

    #[error("dump de « {database} » : {stderr}")]
    Dump { database: String, stderr: String },

    #[error("{0}")]
    Unexpected(String),
}

pub type Result<T> = std::result::Result<T, Error>;
