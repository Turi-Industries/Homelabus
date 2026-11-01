//! Every image the catalog declares a signer for is signed by it, at its digest.
//!
//! 🔴 A signer that names the wrong workflow refuses every update of its image as
//! "INVALID signature", and nothing says so until the first one. Checked with the
//! `cosign` an update runs, through the same call.
//!
//! ```sh
//! cargo test -p hlb-catalog --test signatures -- --ignored --nocapture
//! ```

#![allow(clippy::expect_used, clippy::unwrap_used)]

#[tokio::test]
#[ignore = "needs cosign and network access to the registries and Sigstore"]
async fn every_declared_signer_signed_its_pinned_image() {
    let root = concat!(env!("CARGO_MANIFEST_DIR"), "/../../catalog");
    let catalog = hlb_catalog::Catalog::load(root).expect("catalog");

    let mut signed = Vec::new();
    for m in catalog.manifests() {
        let images =
            std::iter::once(&m.spec.image).chain(m.spec.companions.iter().map(|c| &c.image));
        signed.extend(
            images
                .filter(|i| i.signed_by.is_some())
                .map(|i| (i.reference(), i.signed_by.clone())),
        );
    }
    // Measured 2026-10-30: Vikunja, Stalwart and Fluxer's Meilisearch; 2026-11-01:
    // Vaultwarden, Bulwark and Anubis, by their SLSA provenance alone. Fewer means the
    // walk lost some, not that publishers stopped signing.
    assert!(
        signed.len() >= 6,
        "only {} signed images found",
        signed.len()
    );

    let mut failed = Vec::new();
    for (reference, signer) in &signed {
        let v = hlb_updater::scan::verify_signed_by(reference, signer.as_ref()).await;
        println!("  {reference}: {v:?}");
        if v != hlb_updater::Verdict::Clean {
            failed.push(format!("{reference}: {}", v.describe()));
        }
    }
    assert!(failed.is_empty(), "{failed:#?}");
}
