//! The node agent.
//!
//! Deployed as a **`global`** Swarm service: automatically present on every node,
//! including those added later. That is what separates it from a daemon you would have
//! to install by hand everywhere.
//!
//! It does what the controller cannot do remotely:
//!
//! | Need | Why it must be local |
//! |---|---|
//! | Per-node disk space | one node's `df` says nothing about the others |
//! | Volume backups | restic must run **where the data is** |
//! | Image pruning | image storage is local to each node |
//!
//! ## What the agent does not do
//!
//! It decides nothing. It **observes and executes**; the controller decides. An agent
//! making local decisions would produce an incoherent cluster, where each node acted on
//! its own partial view.

pub mod disk;
pub mod pki;
pub mod report;
pub mod systeme;
pub mod tls;

pub use disk::{DiskPressure, DiskUsage, Projection, Thresholds};
pub use pki::{CertPair, Purpose};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("PKI : {0}")]
    Pki(String),
}
pub use report::NodeReport;

/// The agent ↔ controller dialogue version.
///
/// 🔴 To be incremented **only** when the exchange format changes incompatibly - not on
/// every binary version. Confusing them would refuse perfectly working agents on every
/// patch release.
///
/// | Version | What it adds |
/// |---|---|
/// | 1 | disks, memory |
/// | 2 | load, CPU usage, swap, network interfaces, kernel/distro, uptime |
///
/// ⚠️ Moving from 1 to 2 is **compatible in both directions**: every added field is
/// `Option` + `serde(default)`. An up-to-date controller reads an old agent (the new
/// measurements are `None`), and an old controller reads an up-to-date agent (it
/// ignores what it does not know).
///
/// That is what allows updating the fleet in any order. Without it, the first update
/// would make every agent "unreachable" - precisely when you need to see them.
pub const PROTOCOL: u32 = 2;
