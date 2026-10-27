//! Watching OCI registries.
//!
//! Two responsibilities:
//!   1. resolve a tag to a digest, **without downloading the image**;
//!   2. decide which update the manifest's channel allows.
//!
//! A tag is mutable, a digest is not. That is why the catalog declares an intent
//! (`tag` + `channel`) while a deployment is always pinned.

pub mod client;
pub mod reference;
pub mod version;

pub use client::RegistryClient;
pub use reference::ImageRef;
pub use version::{best_upgrade, Version};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("registry unreachable ({context}): {source}")]
    Http {
        #[source]
        source: reqwest::Error,
        context: String,
    },

    #[error("the registry answered {status} - {detail}")]
    Registry { status: u16, detail: String },

    #[error("tag not found: {image}")]
    TagNotFound { image: String },

    #[error("the registry returned no digest for {image}")]
    NoDigest { image: String },

    #[error("registry authentication: {detail}")]
    Auth { detail: String },

    #[error(
        "the registry's rate limit is reached ({detail}) — Docker Hub allows an anonymous \
         address 100 manifest reads an hour; try again later"
    )]
    RateLimited { detail: String },

    #[error("{image} has more than {pages} pages of tags: not read to the end")]
    TooManyTags { image: String, pages: usize },
}

pub type Result<T> = std::result::Result<T, Error>;
