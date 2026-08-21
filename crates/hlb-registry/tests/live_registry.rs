//! Checks digest resolution against real registries.
//!
//! The OCI auth dance (401 → `WWW-Authenticate` → token → retry) cannot be tested
//! against a stub: every registry has its quirks. Docker Hub and
//! ghcr.io sont les deux qu'utilise le catalogue.
//!
//! ```sh
//! cargo test -p hlb-registry -- --ignored --nocapture
//! ```
//!
//! ⚠️ Needs network access. Docker Hub applies per-IP rate limits.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use hlb_registry::{best_upgrade, ImageRef, RegistryClient};
use hlb_types::UpdateChannel;

#[tokio::test]
#[ignore = "needs network access"]
async fn resolves_a_digest_on_docker_hub_without_pulling() {
    let c = RegistryClient::new();
    let image = ImageRef::parse("postgres:17-alpine");

    let digest = c.resolve_digest(&image).await.expect("resolution");

    assert!(digest.starts_with("sha256:"), "digest inattendu : {digest}");
    assert_eq!(digest.len(), 71, "sha256: plus 64 characters");
    println!("✓ postgres:17-alpine → {digest}");
}

#[tokio::test]
#[ignore = "needs network access"]
async fn resolves_a_digest_on_ghcr() {
    // ghcr.io negotiates tokens slightly differently from Docker Hub.
    let c = RegistryClient::new();
    let image = ImageRef::parse("ghcr.io/pocket-id/pocket-id:v1");

    let digest = c.resolve_digest(&image).await.expect("resolution");
    assert!(digest.starts_with("sha256:"));
    println!("✓ pocket-id:v1 → {digest}");
}

#[tokio::test]
#[ignore = "needs network access"]
async fn the_digest_is_stable_across_calls() {
    // Without this we would redeploy on every reconciliation cycle.
    let c = RegistryClient::new();
    let image = ImageRef::parse("alpine:3");

    let a = c.resolve_digest(&image).await.expect("premier appel");
    let b = c.resolve_digest(&image).await.expect("second appel");

    assert_eq!(a, b, "the same tag must give a stable digest");
    println!("✓ digest stable : {a}");
}

#[tokio::test]
#[ignore = "needs network access"]
async fn a_missing_tag_gives_a_clear_error() {
    let c = RegistryClient::new();
    let image = ImageRef::parse("alpine:cette-version-nexiste-pas");

    let err = c.resolve_digest(&image).await.unwrap_err();
    assert!(
        matches!(err, hlb_registry::Error::TagNotFound { .. }),
        "erreur inattendue : {err}"
    );
    println!("✓ typed error: {err}");
}

#[tokio::test]
#[ignore = "needs network access"]
async fn listing_tags_feeds_the_update_policy() {
    let c = RegistryClient::new();
    let image = ImageRef::parse("postgres:17-alpine");

    let tags = c.list_tags(&image).await.expect("liste des tags");
    assert!(tags.len() > 50, "{} tags seulement ?", tags.len());
    assert!(tags.iter().any(|t| t == "17-alpine"));

    // The policy applies to real tags, not made-up ones.
    // `15-alpine` is a rolling tag: it must never be pinned.
    assert_eq!(
        best_upgrade("15-alpine", &tags, UpdateChannel::Minor),
        None,
        "a rolling tag updates through its digest, not its name"
    );

    // A precise tag, on the other hand, moves up within its major.
    let within = best_upgrade("17.0-alpine", &tags, UpdateChannel::Minor);
    println!("✓ {} tags ; 17.0-alpine → {within:?}", tags.len());
    assert!(within.is_some(), "17.x devrait exister");

    // But never beyond.
    assert_eq!(
        best_upgrade("17.0-alpine", &tags, UpdateChannel::Patch)
            .and_then(|t| hlb_registry::Version::parse(&t))
            .map(|v| v.major),
        None,
        "on the patch channel, 17.0 → 17.x changes the minor: refused"
    );
}

#[tokio::test]
#[ignore = "needs network access"]
async fn every_catalog_image_resolves() {
    // A catalog manifest pointing at a non-existent image must be caught here, not at
    // deploy time.
    let c = RegistryClient::new();

    for name in [
        "postgres:17-alpine",
        "valkey/valkey:8-alpine",
        "gitea/gitea:1.24",
        "vikunja/vikunja:0.24",
        "vaultwarden/server:1.37.1",
        "ghcr.io/pocket-id/pocket-id:v1",
    ] {
        let image = ImageRef::parse(name);
        match c.resolve_digest(&image).await {
            Ok(d) => println!("✓ {name:<34} {}", &d[..19]),
            Err(e) => panic!("{name} : {e}"),
        }
    }
}
