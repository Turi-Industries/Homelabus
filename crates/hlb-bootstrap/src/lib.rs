//! Bootstrap d'un nœud (§2ter).
//!
//! Ce crate répond à une promesse du plan : **« n'importe quelle distribution
//! serveur »**. Tenir ça demande une abstraction, pas une pile de `if`.
//!
//! Trois étages, du plus pur au plus concret :
//!
//! | Module | Rôle | Testable sans machine ? |
//! |---|---|---|
//! | [`distro`] | identifier la distribution et son gestionnaire | ✅ entièrement |
//! | [`deps`] | décider quoi installer, et quoi laisser tranquille | ✅ entièrement |
//! | [`preflight`] | juger si le bootstrap peut démarrer | ✅ entièrement |
//! | [`observe`] | constater l'état d'une machine, sans rien modifier | partiellement |
//! | [`runner`] | exécuter, en local ou par SSH | partiellement |
//!
//! Cette séparation est délibérée : la logique qui décide est indépendante de celle
//! qui exécute. On peut donc tester le raisonnement complet — « Debian ancienne avec
//! un Docker trop vieux et une horloge désynchronisée » — sans provisionner de VM.

pub mod deps;
pub mod observe;
pub mod distro;
pub mod preflight;
pub mod runner;

pub use deps::{plan as plan_dependencies, DependencyPlan, Presence};
pub use observe::observe;
pub use distro::{Distro, Family, PackageManager};
pub use preflight::{Level, Observation, Report};
pub use runner::{LocalRunner, Runner, SshRunner, WriteFile};
