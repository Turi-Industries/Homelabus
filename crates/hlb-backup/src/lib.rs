//! Sauvegardes (§8 du plan).
//!
//! Trois principes que ce crate encode :
//!
//! 1. **La rétention est obligatoire.** Un dépôt sans politique remplit le disque et
//!    fait tomber la machine qu'il protégeait (§9bis).
//! 2. **Le mot de passe ne touche jamais la ligne de commande.**
//! 3. **Un backup non testé n'est pas un backup** (§8.3) : la vérification de
//!    restauration fait partie du module, pas d'un raffinement ultérieur.

pub mod destination;
pub mod dr;
pub mod drill;
pub mod mariadump;
pub mod pgdump;
pub mod pgrunner;
pub mod pitr;
pub mod provider;
pub mod replication;
pub mod restaurabilite;
pub mod restic;
pub mod retention;
pub mod runner;
pub mod schedule;
pub mod snapshot;
pub mod sqlite;
pub mod verify;

pub use destination::{
    couverture_de, destinations_pour, Classe, Couverture, Destination, Etat as EtatDestination,
    SourceCouverture,
};
pub use dr::{plan_promotion, Profile as DrProfile};
pub use drill::{Readiness, Scope as DrillScope, Target as DrillTarget};
pub use mariadump::{Coherence, MariaDumper, MariaTarget};
pub use pgdump::{PgDumper, PgTarget};
pub use pgrunner::{MariaContainerRunner, PgContainerRunner};
pub use pitr::{parse_maria_url, parse_pg_url, scan_archive, wal_coverage, Segment};
pub use provider::{provider_for_state, ResticBackupProvider};
pub use replication::{Health as StandbyHealth, StandbyStatus};
pub use restaurabilite::{Confiance, Restaurabilite};
pub use restic::{Repository, Runner, Snapshot};
pub use retention::RetentionPolicy;
pub use schedule::Schedule;
pub use verify::{verify_by_restore, verify_snapshot, Verification};
// ⚠️ `Snapshot` existe déjà pour restic : renommé ici, sinon les deux notions —
// « instantané restic » et « instantané de système de fichiers » — se confondraient
// à l'usage alors qu'elles ne protègent PAS des mêmes pannes.
pub use runner::{ContainerRunner, HostRunner};
pub use snapshot::{detect as detect_filesystem, Filesystem, Snapshot as FsSnapshot};
pub use sqlite::{snapshot as sqlite_snapshot, snapshot_all as sqlite_snapshot_all};

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

/// « 1 table » / « 4 tables » — le pluriel français, où zéro prend le singulier.
///
/// ⚠️ `hlb-backup` ne dépend pas de `hlb-api` (c'est l'inverse), donc `hlb_api::pluriel`
/// n'est pas atteignable ici. Dupliquer la RÈGLE serait un risque de divergence ;
/// dupliquer ce seul cas, avec le test qui va avec, ne l'est pas.
pub(crate) fn pluriel_tables(n: i64) -> String {
    if n <= 1 {
        format!("{n} table")
    } else {
        format!("{n} tables")
    }
}

#[cfg(test)]
mod tests_affichage {
    use crate::destination::{Couverture, Etat};
    use crate::drill::{Outcome, Readiness, Scope};

    /// Ce caractère s'affiche-t-il dans l'interface egui ?
    ///
    /// Même règle que `hlb_ui::design::glyphes::sur` — dupliquée ici parce que
    /// `hlb-backup` ne dépend pas de l'interface, et ne doit pas commencer.
    fn sur(c: char) -> bool {
        let n = c as u32;
        n < 0x2C0 || (0x2000..=0x206F).contains(&n)
    }

    #[test]
    fn messages_shown_by_the_interface_carry_no_glyph_it_cannot_display() {
        // 🔴 Le piège déjà constaté deux fois (`Coherence::describe`, puis le verdict de
        // topologie) : un texte partagé ne doit dépendre d'AUCUN de ses consommateurs.
        // Le terminal rend « ✓ » et « 🔴 », egui les remplace par un carré vide.
        //
        // ⚠️ Ce test ne couvre QUE les messages affichés. Les générateurs de fichiers de
        // configuration et de scripts shell (`pitr`, `replication`, `deadman`, `sqlite`)
        // gardent leurs emoji : ils ne traversent jamais l'interface, et les retirer
        // appauvrirait des commentaires que l'on relit dans un terminal, au pire moment.
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

        let c = Couverture {
            app: "gitea".into(),
            par_destination: vec![
                ("nas".into(), Etat::Frais { age_s: 600 }),
                ("offsite".into(), Etat::Perime { age_s: 900_000 }),
            ],
        };
        let r = crate::Restaurabilite::calculer(&c, None, None, Readiness::Never);
        messages.push(r.verdict());
        messages.push(r.confiance().describe().to_string());
        messages.extend(r.remedes());

        for m in &messages {
            for ch in m.chars() {
                assert!(sur(ch), "« {m} » contient U+{:04X}", ch as u32);
            }
            // Et le tic du pluriel entre parenthèses, interdit partout ailleurs.
            let tic = format!("({})", "s");
            assert!(!m.contains(&tic), "{m}");
        }
    }
}
