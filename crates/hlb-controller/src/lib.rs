//! Le controller HomelabUS.
//!
//! Exposé en bibliothèque autant qu'en binaire : les tests d'intégration doivent
//! pouvoir exercer l'interrogation des agents et l'API sans passer par un
//! sous-processus.

pub mod agents;
pub mod api;
pub mod loops;

pub use agents::{AgentPoller, AgentStatus, ClusterHealth};
