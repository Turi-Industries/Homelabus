//! WireGuard mesh between nodes.
//!
//! 🔴 **Swarm's ports must NEVER be exposed publicly.**
//!
//! Swarm needs 2377 (cluster API), 7946 (discovery) and 4789 (VXLAN overlay). Opening
//! them to the internet exposes the cluster's control API; port 4789 in particular has
//! **no authentication at all** - anyone who can send it packets can inject traffic
//! into the overlay networks.
//!
//! The mesh solves that: Swarm listens only on the WireGuard interface, and node to
//! node traffic is encrypted independently of the overlay.
//!
//! ## What this crate does, and does not
//!
//! It **generates** keys and configurations. It does not **apply** them: bringing up a
//! network interface needs root on each machine, which is bootstrap's job. That split
//! is what makes the whole address-allocation and config-generation logic testable
//! without touching the network.

pub mod config;
pub mod keys;

pub use config::{provision_node, MeshConfig, Peer};
pub use keys::KeyPair;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("mesh addresses exhausted: at most {0} nodes in {1}")]
    AddressPoolExhausted(usize, String),

    #[error("node \"{0}\" is already in the mesh")]
    DuplicateNode(String),

    #[error("invalid key: {0}")]
    InvalidKey(String),
}

pub type Result<T> = std::result::Result<T, Error>;
