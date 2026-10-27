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
pub mod backup;
pub mod bitwarden;
pub mod capacity;
pub mod coverage;
pub mod demo;
pub mod diff;
pub mod error;
pub mod export;
pub mod exposure;
pub mod extract;
// Empty outside tests: its one module is gated where the source scans can see it.
mod fake_mail;
pub mod health;
pub mod history;
pub mod issues;
pub mod limits;
pub mod loops;
pub mod mail_dns;
pub mod mail_queue;
pub mod me;
pub mod metrics;
pub mod mutes;
pub mod notify;
pub mod openapi;
pub mod portal;
pub mod promql;
pub mod recovery;
pub mod roles;
pub mod runbook;
pub mod signin;
pub mod throughput;
pub mod timeline;

pub use agents::{AgentPoller, AgentStatus, ClusterHealth};
