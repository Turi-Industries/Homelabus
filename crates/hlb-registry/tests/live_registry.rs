//! Vérifie la résolution de digest contre de vrais registres.
//!
//! La danse d'authentification OCI (401 → `WWW-Authenticate` → jeton → réessai) ne se
//! teste pas contre un bouchon : chaque registre a ses particularités. Docker Hub et
//! ghcr.io sont les deux qu'utilise le catalogue.
//!
//! ```sh
//! cargo test -p hlb-registry -- --ignored --nocapture
//! ```
//!
//! ⚠️ Nécessite un accès réseau. Docker Hub applique des quotas par IP.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use hlb_registry::{best_upgrade, ImageRef, RegistryClient};
use hlb_types::UpdateChannel;

#[tokio::test]
#[ignore = "nécessite un accès réseau"]
async fn resolves_a_digest_on_docker_hub_without_pulling() {
    let c = RegistryClient::new();
    let image = ImageRef::parse("postgres:17-alpine");

    let digest = c.resolve_digest(&image).await.expect("résolution");

    assert!(digest.starts_with("sha256:"), "digest inattendu : {digest}");
    assert_eq!(digest.len(), 71, "sha256: + 64 caractères");
    println!("✓ postgres:17-alpine → {digest}");
}

#[tokio::test]
#[ignore = "nécessite un accès réseau"]
async fn resolves_a_digest_on_ghcr() {
    // ghcr.io a une négociation de jeton légèrement différente de Docker Hub.
    let c = RegistryClient::new();
    let image = ImageRef::parse("ghcr.io/pocket-id/pocket-id:v1");

    let digest = c.resolve_digest(&image).await.expect("résolution");
    assert!(digest.starts_with("sha256:"));
    println!("✓ pocket-id:v1 → {digest}");
}

#[tokio::test]
#[ignore = "nécessite un accès réseau"]
async fn the_digest_is_stable_across_calls() {
    // Sans ça, on redéploierait à chaque cycle de réconciliation.
    let c = RegistryClient::new();
    let image = ImageRef::parse("alpine:3");

    let a = c.resolve_digest(&image).await.expect("premier appel");
    let b = c.resolve_digest(&image).await.expect("second appel");

    assert_eq!(a, b, "un même tag doit donner un digest stable");
    println!("✓ digest stable : {a}");
}

#[tokio::test]
#[ignore = "nécessite un accès réseau"]
async fn a_missing_tag_gives_a_clear_error() {
    let c = RegistryClient::new();
    let image = ImageRef::parse("alpine:cette-version-nexiste-pas");

    let err = c.resolve_digest(&image).await.unwrap_err();
    assert!(
        matches!(err, hlb_registry::Error::TagNotFound { .. }),
        "erreur inattendue : {err}"
    );
    println!("✓ erreur typée : {err}");
}

#[tokio::test]
#[ignore = "nécessite un accès réseau"]
async fn listing_tags_feeds_the_update_policy() {
    let c = RegistryClient::new();
    let image = ImageRef::parse("postgres:17-alpine");

    let tags = c.list_tags(&image).await.expect("liste des tags");
    assert!(tags.len() > 50, "{} tags seulement ?", tags.len());
    assert!(tags.iter().any(|t| t == "17-alpine"));

    // La politique s'applique sur des tags réels, pas fabriqués.
    // `15-alpine` est un tag roulant : il ne doit jamais être épinglé (§7).
    assert_eq!(
        best_upgrade("15-alpine", &tags, UpdateChannel::Minor),
        None,
        "un tag roulant se met à jour par son digest, pas par son nom"
    );

    // Un tag précis, en revanche, monte dans sa majeure.
    let within = best_upgrade("17.0-alpine", &tags, UpdateChannel::Minor);
    println!("✓ {} tags ; 17.0-alpine → {within:?}", tags.len());
    assert!(within.is_some(), "17.x devrait exister");

    // Mais jamais au-delà.
    assert_eq!(
        best_upgrade("17.0-alpine", &tags, UpdateChannel::Patch)
            .and_then(|t| hlb_registry::Version::parse(&t))
            .map(|v| v.major),
        None,
        "en canal patch, 17.0 → 17.x change la mineure : refusé"
    );
}

#[tokio::test]
#[ignore = "nécessite un accès réseau"]
async fn every_catalog_image_resolves() {
    // Un manifest du catalogue qui pointe vers une image inexistante doit être
    // détecté ici, pas au moment du déploiement.
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
