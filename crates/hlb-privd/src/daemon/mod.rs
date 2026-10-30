//! What the daemon runs by itself, on a timer, with the capabilities only this side
//! holds: reconciliation with Docker, the alias purge and the readings of Stalwart,
//! the assertions with the vault's passwords.
//!
//! The web side reads what these record, never the clients they read with.

pub mod aliases;
pub mod assertions;
pub mod mail_dns;
pub mod mail_queue;
pub mod reconcile;

pub use aliases::{AliasPurgeLoop, PurgeReport};
pub use reconcile::{DriftState, LastReconciled, ReconcileLoop, TickReport};
