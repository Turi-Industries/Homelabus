//! Sauvegardes (§8 du plan).
//!
//! Trois principes que ce crate encode :
//!
//! 1. **La rétention est obligatoire.** Un dépôt sans politique remplit le disque et
//!    fait tomber la machine qu'il protégeait (§9bis).
//! 2. **Le mot de passe ne touche jamais la ligne de commande.**
//! 3. **Un backup non testé n'est pas un backup** (§8.3) : la vérification de
//!    restauration fait partie du module, pas d'un raffinement ultérieur.

pub mod provider;
pub mod restic;
pub mod retention;
pub mod runner;

pub use provider::ResticBackupProvider;
pub use restic::{Repository, Runner, Snapshot};
pub use retention::RetentionPolicy;
pub use runner::{ContainerRunner, HostRunner};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("restic indisponible : {0}")]
    ResticMissing(String),

    #[error("restic {command} a échoué : {stderr}")]
    Restic { command: String, stderr: String },

    #[error("politique de rétention vide : `forget` supprimerait tous les instantanés")]
    EmptyRetention,

    #[error("{0}")]
    Unexpected(String),
}

pub type Result<T> = std::result::Result<T, Error>;
