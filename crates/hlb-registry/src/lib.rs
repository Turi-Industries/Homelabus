//! Veille sur les registres OCI (§7 du plan).
//!
//! Deux responsabilités :
//!   1. résoudre un tag en digest, **sans télécharger l'image** ;
//!   2. décider quelle mise à jour le canal du manifest autorise.
//!
//! Un tag est mutable, un digest ne l'est pas. C'est pour ça que le catalogue déclare
//! une intention (`tag` + `channel`) et que le déploiement, lui, est toujours épinglé.

pub mod client;
pub mod reference;
pub mod version;

pub use client::RegistryClient;
pub use reference::ImageRef;
pub use version::{best_upgrade, Version};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("registre injoignable ({context}) : {source}")]
    Http {
        #[source]
        source: reqwest::Error,
        context: String,
    },

    #[error("le registre a répondu {status} — {detail}")]
    Registry { status: u16, detail: String },

    #[error("tag introuvable : {image}")]
    TagNotFound { image: String },

    #[error("le registre n'a pas renvoyé de digest pour {image}")]
    NoDigest { image: String },

    #[error("authentification au registre : {detail}")]
    Auth { detail: String },
}

pub type Result<T> = std::result::Result<T, Error>;
