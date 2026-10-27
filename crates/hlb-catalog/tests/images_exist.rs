//! Every image the catalog names exists, at its digest, in its registry.
//!
//! 🔴 `catalog validate` checks shapes, not registries: `crowdsecurity/crowdsec:v1.7`
//! passed it for months, and no such tag was ever published. The failure would have
//! surfaced at install time, as a registry error naming nothing in the catalog.
//!
//! ```sh
//! cargo test -p hlb-catalog --test images_exist -- --ignored --nocapture
//! ```

#![allow(clippy::expect_used, clippy::unwrap_used)]

#[tokio::test]
#[ignore = "needs network access to the registries"]
async fn every_catalog_image_resolves_at_its_tag() {
    let root = concat!(env!("CARGO_MANIFEST_DIR"), "/../../catalog");
    let catalog = hlb_catalog::Catalog::load(root).expect("catalog");
    let client = hlb_registry::RegistryClient::new();

    let mut refs = Vec::new();
    for m in catalog.manifests() {
        let images = std::iter::once((m.metadata.name.clone(), &m.spec.image)).chain(
            m.spec
                .companions
                .iter()
                .map(|c| (format!("{}/{}", m.metadata.name, c.name), &c.image)),
        );
        // Built here: published by a release, under the project's own credentials.
        refs.extend(
            images
                .filter(|(_, i)| !i.built_here)
                .map(|(who, i)| (who, i.reference())),
        );
    }
    assert!(
        refs.len() >= 20,
        "only {} images found in the catalog",
        refs.len()
    );

    let mut missing = Vec::new();
    for (who, reference) in &refs {
        let image = hlb_registry::ImageRef::parse(reference);
        if let Err(e) = client.resolve_digest(&image).await {
            missing.push(format!("{who}: {reference} — {e}"));
            continue;
        }
        // Said, not failed: a moving tag names a newer build by design, and the catalog
        // keeps the one it was tried with until `hlb catalog images` moves it.
        let named = hlb_registry::ImageRef {
            digest: None,
            ..image.clone()
        };
        if let (Some(pinned), Ok(now)) = (&image.digest, client.resolve_digest(&named).await) {
            if *pinned != now {
                println!("  {who}: {} names another build now ({now})", image.tag);
            }
        }
        // Bulwark's image resolved for months and was built for FreeBSD only.
        match client.platforms(&image).await {
            Ok(p) if p.iter().any(|p| p.starts_with("linux/")) => {
                println!("✓ {who:<26} {reference}  [{}]", p.join(", "))
            }
            Ok(p) => missing.push(format!("{who}: {reference} — no Linux build: {p:?}")),
            Err(e) => missing.push(format!("{who}: {reference} — platforms: {e}")),
        }
    }
    assert!(
        missing.is_empty(),
        "images that do not resolve, or not for Linux:\n  {}",
        missing.join("\n  ")
    );
}
