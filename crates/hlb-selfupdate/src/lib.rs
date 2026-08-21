//! Updating Homelabus itself.
//!
//! This is the most delicate operation in the system: replacing the tool that drives
//! everything, **while it drives everything**.
//!
//! One property makes it bearable: the controller is **not in the critical path** of
//! traffic. Swarm keeps the deployed services running without it. Stopping it loses
//! control, not service - which turns a terrifying operation into a merely delicate
//! one.
//!
//! 🔴 **Never automatic.** The controller is the one component whose failure stops you
//! repairing the others. Notify, then wait for manual approval.

pub mod plan;
pub mod signature;
pub mod swap;
pub mod version;

pub use plan::{plan, AgentNode, Blocker, Migration, Preflight, Rollback, UpdatePlan};
pub use signature::{verify as verify_release, Manifest as ReleaseManifest, Rejected};
pub use swap::{swap, Paths as SwapPaths, SwapError};
pub use version::{compatible, Compatibility, Jump, Version, PROTOCOL};
