//! Vaultwarden, from Homelabus's side: an organisation's members ([`directory`]), and the
//! emergency vault — the organisation's "Server" collection, where every recovery
//! sign-in Homelabus generated is deposited ([`emergency`]).
//!
//! ## 🔴 The server decrypts nothing
//!
//! Everything in a Bitwarden vault is encrypted by the client before it is sent, under
//! keys the server never holds. Writing an item into an organisation therefore means
//! being a CLIENT: signing in as a member, unwrapping that member's keys with its master
//! password, opening the organisation's key — sealed for the member when an owner
//! confirmed it — and encrypting each field under it. [`crypto`] is that, written from
//! Bitwarden's own derivation rather than delegated to the official CLI: a CLI version
//! that stops unlocking a given server (the sibling installation's 2026.9.x against
//! Vaultwarden 1.37.3) is a nightly deposit that silently stops.
//!
//! ## What the account can read is what a compromise reads
//!
//! Homelabus signs in as a member with access to ONE collection, as a `User`: a
//! compromised controller could read what Homelabus deposited — which it already holds
//! — and nothing else. An owner's or an admin's account would open every collection;
//! [`emergency::check`] refuses them.

pub mod client;
pub mod crypto;
pub mod directory;
pub mod emergency;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Vaultwarden unreachable ({context}): {source}")]
    Http {
        #[source]
        source: reqwest::Error,
        context: String,
    },

    #[error("Vaultwarden answered {status} — {detail}")]
    Api { status: u16, detail: String },

    /// The credentials were refused — said without echoing them.
    #[error("{0}")]
    Refused(String),

    #[error("Bitwarden cryptography: {0}")]
    Crypto(String),

    #[error("unexpected answer from Vaultwarden: {0}")]
    Unexpected(String),
}

pub type Result<T> = std::result::Result<T, Error>;
