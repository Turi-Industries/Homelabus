//! The Homelabus controller.
//!
//! Exposed as a library as much as a binary: the integration tests must be able to
//! exercise agent polling and the API without going through a subprocess.

pub mod accounts;
pub mod actions;
pub mod agents;
pub mod api;
pub mod assertions;
pub mod auth;
pub mod bitwarden;
pub mod capacity;
pub mod coverage;
pub mod demo;
pub mod diff;
pub mod disks;
pub mod domain;
pub mod error;
pub mod export;
pub mod exposure;
pub mod extract;
pub mod flaws;
// Empty outside tests: its one module is gated where the source scans can see it.
mod fake_mail;
pub mod health;
pub mod history;
pub mod issues;
pub mod limits;
pub mod mail_dns;
pub mod mail_queue;
pub mod me;
pub mod metrics;
pub mod mutes;
pub mod openapi;
pub mod passkey;
pub mod portal;
pub mod power;
pub mod promql;
pub mod recovery;
pub mod roles;
pub mod runbook;
pub mod signin;
pub mod throughput;
pub mod timeline;
pub mod updates;

pub use agents::{AgentStatus, ClusterHealth};
