//! Le controller HomelabUS.
//!
//! Exposé en bibliothèque autant qu'en binaire : les tests d'intégration doivent
//! pouvoir exercer l'interrogation des agents et l'API sans passer par un
//! sous-processus.

pub mod agents;
pub mod actions;
pub mod api;
pub mod auth;
pub mod bitwarden;
pub mod capacite;
pub mod comptes;
pub mod connexion;
pub mod couverture;
pub mod debit;
pub mod demo;
pub mod diff;
pub mod export;
pub mod exposition;
pub mod frise;
pub mod loops;
pub mod metrics;
pub mod portail;
pub mod promql;
pub mod runbook;
pub mod sante;
pub mod secours;

pub use agents::{AgentPoller, AgentStatus, ClusterHealth};
