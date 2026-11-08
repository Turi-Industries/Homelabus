//! What the daemon runs by itself, on a timer, with the capabilities only this side
//! holds: reconciliation with Docker, the alias purge and the readings of Stalwart,
//! the assertions with the vault's passwords, the alerts and the notifications that
//! carry ntfy's credentials.
//!
//! The web side reads what these record, never the clients they read with.

pub mod alerts;
pub mod aliases;
pub mod assertions;
pub mod domain;
pub mod flaws;
pub mod mail_dns;
pub mod mail_queue;
pub mod notify;
pub mod reconcile;
pub mod schedule;
pub mod start;
pub mod updates;

pub use alerts::{AlertLoop, AlertReport, AlertsState, Measure, Query};
pub use aliases::{AliasPurgeLoop, PurgeReport};
pub use notify::Notifier;
pub use reconcile::{DriftState, LastReconciled, ReconcileLoop, TickReport};
pub use schedule::every;
pub use start::{start, Config, StartError, Started};
