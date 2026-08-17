//! Mise à jour de HomelabUS lui-même (§7bis).
//!
//! C'est l'opération la plus délicate du système : on remplace l'outil qui pilote
//! tout, **pendant qu'il pilote tout**.
//!
//! Une propriété rend la chose supportable : le controller n'est **pas dans le chemin
//! critique** du trafic (§7bis). Swarm continue de faire tourner les services déployés
//! sans lui. L'arrêter fait perdre le pilotage, pas le service — ce qui transforme une
//! opération terrifiante en opération simplement délicate.
//!
//! 🔴 **Jamais automatique.** Le controller est le seul composant dont la panne
//! t'empêche de réparer les autres. Notification, puis validation manuelle.

pub mod plan;
pub mod version;

pub use plan::{plan, AgentNode, Blocker, Migration, Preflight, Rollback, UpdatePlan};
pub use version::{compatible, Compatibility, Jump, Version, PROTOCOL};
