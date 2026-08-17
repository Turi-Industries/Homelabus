//! L'agent de nœud (§2).
//!
//! Déployé comme service Swarm **`global`** : automatiquement présent sur chaque
//! nœud, y compris ceux ajoutés plus tard. C'est ce qui le distingue d'un démon
//! qu'il faudrait installer à la main partout.
//!
//! Il fait ce que le controller ne peut pas faire à distance :
//!
//! | Besoin | Pourquoi ça doit être local |
//! |---|---|
//! | Espace disque par nœud | `df` d'un nœud ne dit rien des autres (§9bis) |
//! | Sauvegarde des volumes | restic doit tourner **où sont les données** (§8) |
//! | Purge d'images | le stockage d'images est local à chaque nœud |
//!
//! ## Ce que l'agent ne fait pas
//!
//! Il ne décide rien. Il **observe et exécute**, le controller décide. Un agent qui
//! prendrait des décisions locales produirait un cluster incohérent, où chaque nœud
//! agirait selon sa vue partielle.

pub mod disk;
pub mod pki;
pub mod tls;
pub mod report;

pub use disk::{DiskPressure, DiskUsage, Projection, Thresholds};
pub use pki::{CertPair, Purpose};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("PKI : {0}")]
    Pki(String),
}
pub use report::NodeReport;

/// Version du dialogue agent ↔ controller (§7bis).
///
/// 🔴 À incrémenter **uniquement** quand le format des échanges change de façon
/// incompatible — pas à chaque version du binaire. Les confondre ferait refuser des
/// agents parfaitement fonctionnels à chaque correctif.
pub const PROTOCOL: u32 = 1;
