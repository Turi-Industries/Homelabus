//! The house's router, OPNsense — on a machine of its own, never a service of the
//! cluster, which needs the network to start. Homelabus drives it through its API.
//!
//! What it holds: the API client ([`client`]), the pinned certificate it is reached
//! through ([`tls`]), the names it answers inside the house ([`names`]) and the ports it
//! forwards from the internet ([`forwards`]). Putting
//! it together — the vault, the state, the routes — is `hlb_engine::router`.
//!
//! ## The API, as it is
//!
//! Established against OPNsense 26.7's image, its controllers read on the machine
//! (`/usr/local/opnsense/mvc/app/controllers/OPNsense/*/Api`):
//!
//! | Operation | Call |
//! |---|---|
//! | What it is | `GET diagnostics/system/system_information` |
//! | Accounts / make one | `auth/user/search`, `auth/user/add` |
//! | The administrators' group | `auth/group/search` (`page-all`) |
//! | API keys | `auth/user/search_api_key`, `add_api_key/{user}`, `del_api_key/{base64 key}` |
//! | Networks | `interfaces/overview/interfaces_info` |
//! | Unbound's overrides | `unbound/settings/{search,add,set,del}_host_override`, then `unbound/service/reconfigure` |
//! | Port forwards | `firewall/d_nat/{search,add,set,del}_rule`, then `firewall/d_nat/apply` |
//! | Outbound NAT | `firewall/source_nat/{search,add,set,del}_rule`, its mode `firewall/source_nat/{get,set}`, then `firewall/source_nat/apply` |
//!
//! Authentication by HTTP Basic, an API key and its secret, which act as the account
//! they belong to. A key is made by an administrator (System → Access → Users → the
//! account → API keys); `hlb router connect` takes one once and turns it into an
//! account of Homelabus's own, then deletes it.
//!
//! 🔴 **A refused write is a 200.** OPNsense answers a write it did not make with
//! `{"result": "failed", "validations": {…}}` and HTTP 200: [`client`] turns it into
//! [`Error::Refused`], never a success.

pub mod client;
pub mod forwards;
pub mod names;
pub mod tls;

pub use client::{Credentials, Opnsense};
pub use tls::Fingerprint;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("the router is unreachable ({context}): {source}")]
    Http {
        #[source]
        source: reqwest::Error,
        context: String,
    },

    #[error("the router refused the API key: deleted, or never one")]
    Unauthorized,

    #[error("the router's account may not {0}: it must be in the group \"admins\"")]
    Forbidden(String),

    #[error("the router answered {status} to {call}{}", if .detail.is_empty() { String::new() } else { format!(" — {}", .detail) })]
    Api {
        status: u16,
        call: String,
        detail: String,
    },

    #[error("the router refused {call}{}", if .why.is_empty() { String::new() } else { format!(": {}", .why) })]
    Refused { call: String, why: String },

    #[error("unexpected answer from the router: {0}")]
    Unexpected(String),

    #[error("TLS to the router: {0}")]
    Tls(String),
}

pub type Result<T> = std::result::Result<T, Error>;
