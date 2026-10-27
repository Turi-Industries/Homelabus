//! Termix, given the cluster's nodes. Termix-specific by nature — no other app reaches
//! the machines — and kept in one crate like `hlb-identity` for that reason: an app
//! named in production code anywhere else would be a manifest's job done in Rust.
//!
//! What it holds: the API client ([`client`]), the nodes' key generated in memory
//! ([`key`]), the account and lines each node holds ([`node`]), and the hosts Termix
//! should list ([`hosts`]). Putting it together — the vault, Swarm's nodes, the jobs —
//! is `hlb_engine::termix`.
//!
//! ## The API, as it is
//!
//! Established against Termix 2.9.2's image, its routes read from its own sources:
//!
//! | Operation | Call |
//! |---|---|
//! | Who am I | `GET /users/me` |
//! | Accounts / make one / make it admin | `GET /users/list`, `POST /users/admin-create`, `POST /users/make-admin` |
//! | API keys | `GET`, `POST /users/api-keys`, `DELETE /users/api-keys/{id}` |
//! | Credentials | `GET`, `POST /credentials`, `PUT /credentials/{id}` |
//! | Roles | `GET`, `POST /rbac/roles` |
//! | Hosts | `GET`, `POST /host/db/host`, `PUT`, `DELETE /host/db/host/{id}` |
//! | Sharing | `POST /rbac/host/{id}/share`, `GET /rbac/host/{id}/access` |
//!
//! Authentication by a bearer API key (`tmx_…`), which signs in as the account it was
//! made for. ⚠️ Making one takes an administrator's session: with sign-up and password
//! sign-in closed, Homelabus cannot make its first, and a person hands it one key once
//! — `hlb termix connect` turns it into an account of Homelabus's own, then deletes it.
//!
//! 🔴 **A role a host is shared with reads its key.** `connect` with the owner's
//! sign-in shared (`shareSshAuth`) is what lets a member open the host at all — and it
//! answers the private key to every member who asks
//! (`/host/db/host/{id}/local-connection-auth`, for the desktop app's own
//! connections). The key's `from=` on each node is what keeps it useless anywhere but
//! Termix's node.

pub mod client;
pub mod hosts;
pub mod key;
pub mod node;

pub use client::Termix;
pub use key::NodeKey;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Termix unreachable ({context}): {source}")]
    Http {
        #[source]
        source: reqwest::Error,
        context: String,
    },

    #[error("Termix refused the API key: deleted, expired, or never one")]
    Unauthorized,

    #[error("Termix answered {status} to {call}{}", if .detail.is_empty() { String::new() } else { format!(" — {}", .detail) })]
    Api {
        status: u16,
        call: String,
        detail: String,
    },

    #[error("unexpected answer from Termix: {0}")]
    Unexpected(String),

    #[error("the nodes' key: {0}")]
    Key(String),
}

pub type Result<T> = std::result::Result<T, Error>;
