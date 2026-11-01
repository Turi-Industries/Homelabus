//! Every file the catalog downloads is still served at its URL, with its hash.
//!
//! 🔴 A release asset replaced under the same URL is refused by the job, at install
//! time, on the owner's machine: this finds it first. Fetched as the job fetches it,
//! following redirects (GitHub's assets are served from another host).
//!
//! ```sh
//! cargo test -p hlb-catalog --test downloads -- --ignored --nocapture
//! ```

#![allow(clippy::expect_used, clippy::unwrap_used)]

#[tokio::test]
#[ignore = "needs network access to every download's publisher"]
async fn every_download_is_served_with_its_declared_hash() {
    let root = concat!(env!("CARGO_MANIFEST_DIR"), "/../../catalog");
    let catalog = hlb_catalog::Catalog::load(root).expect("catalog");
    let downloads: Vec<_> = catalog
        .manifests()
        .into_iter()
        .flat_map(|m| {
            let app = m.metadata.name.clone();
            m.spec.downloads.into_iter().map(move |d| (app.clone(), d))
        })
        .collect();
    // Jellyfin's SSO plugin, 2026-11-01. Fewer means the walk lost some.
    assert!(!downloads.is_empty(), "no download found");

    let http = reqwest::Client::new();
    let mut failed = Vec::new();
    for (app, d) in downloads {
        let body = match http
            .get(&d.url)
            .send()
            .await
            .and_then(|r| r.error_for_status())
        {
            Ok(r) => r.bytes().await.expect("body"),
            Err(e) => {
                failed.push(format!("{app}: {}: {e}", d.url));
                continue;
            }
        };
        let got = hlb_types::token::sha256_hex(&body);
        println!("  {app}: {} → {got}", d.url);
        if got != d.sha256 {
            failed.push(format!("{app}: {} is {got}, not {}", d.url, d.sha256));
        }
        // What the job extracts must be a zip, or `unzip` fails on the owner's node.
        if d.unzip && !body.starts_with(b"PK\x03\x04") {
            failed.push(format!("{app}: {} is not a zip", d.url));
        }
    }
    assert!(failed.is_empty(), "{failed:#?}");
}
