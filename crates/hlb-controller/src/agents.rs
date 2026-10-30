//! The node agents as the web side sees them: what the daemon's poller found, asked for
//! by `Intent::Fleet` (`crate::api::fleet_now`).

pub use hlb_privd::fleet::{AgentStatus, ClusterHealth};
