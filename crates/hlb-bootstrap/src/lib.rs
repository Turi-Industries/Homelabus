//! Bootstrapping a node.
//!
//! This crate answers one promise: **"any server distribution"**. Keeping it needs an
//! abstraction, not a pile of `if`s.
//!
//! Several layers, from the purest to the most concrete:
//!
//! | Module | Role | Testable without a machine? |
//! |---|---|---|
//! | [`distro`] | identify the distribution and its package manager | ✅ entirely |
//! | [`deps`] | decide what to install, and what to leave alone | ✅ entirely |
//! | [`docker`] | where Docker comes from, and its daemon configuration | ✅ entirely |
//! | [`updates`] | unattended security updates, full upgrades, reboots | ✅ entirely |
//! | [`host`] | the journal capped, the kernel hardened | ✅ entirely |
//! | [`mesh`] | applying the WireGuard mesh, and keeping it in sync | ✅ entirely |
//! | [`provision`] | the ordered steps that turn a machine into a node | plan ✅, run partly |
//! | [`preflight`] | judge whether the bootstrap can start | ✅ entirely |
//! | [`observe`] | observe a machine's state, without modifying anything | partly |
//! | [`runner`] | execute, locally or over SSH | partly |
//! | [`zfs`] | read the pools, decide what to do about them | ✅ entirely |
//! | [`preseed`] | render a Debian preseed for an automated netinst | ✅ entirely |
//! | [`protection`] | a machine's protection level, from its firmware, TPM and systemd | ✅ entirely |
//! | [`seal`] | the vault's key sealed to the machine, unsealed into memory | ✅ entirely |
//! | [`unlock`] | Swarm's unlock key sealed to a manager, handed to Docker | ✅ entirely |
//!
//! The separation is deliberate: the logic that decides is independent of the one that
//! executes. So the whole line of reasoning - "an old Debian with a Docker that is too
//! old and a clock out of sync" - is testable without provisioning a VM.

pub mod access;
pub mod deps;
pub mod distro;
pub mod docker;
pub mod host;
pub mod mesh;
pub mod observe;
pub mod preflight;
pub mod preseed;
pub mod protection;
pub mod provision;
pub mod runner;
pub mod seal;
pub mod unlock;
pub mod updates;
pub mod zfs;

pub use access::{grant, revoke, ManagedKey};
pub use deps::{plan as plan_dependencies, DependencyPlan, Presence};
pub use distro::{Distro, Family, PackageManager};
pub use observe::observe;
pub use preflight::{Level, Observation, Report};
pub use runner::{LocalRunner, Runner, SshRunner};
