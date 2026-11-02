//! A release commits the schema it reads; a build between releases commits none.
//!
//! `catalog validate` holds each manifest to the schema of the oldest `hlb` its range
//! accepts: a release without its file leaves every range naming it uncheckable, and a
//! file edited after the release would check against what that release never read.
//!
//! ```sh
//! HLB_UPDATE_SCHEMA=1 cargo test -p hlb-types --test release_schema   # at a release
//! ```

#![allow(clippy::expect_used)]

use std::path::Path;

#[test]
fn a_release_commits_its_schema_and_a_build_between_releases_none() {
    let version = semver::Version::parse(env!("CARGO_PKG_VERSION")).expect("version");
    let file = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("schemas")
        .join(format!(
            "{}.{}.{}.json",
            version.major, version.minor, version.patch
        ));
    let live = hlb_types::release::schema();

    if !version.pre.is_empty() {
        // Committed now, it would hold whatever the next release ends up reading.
        assert!(
            !file.exists(),
            "{} is {version}'s, a release not made yet: it is written at the release",
            file.display()
        );
        return;
    }
    if std::env::var_os("HLB_UPDATE_SCHEMA").is_some() {
        let text = serde_json::to_string_pretty(&live).expect("json") + "\n";
        std::fs::write(&file, text).expect("schema written");
    }
    let committed: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&file).unwrap_or_else(|_| {
            panic!(
                "{} is missing: a release commits the schema it reads \
                 (HLB_UPDATE_SCHEMA=1 cargo test -p hlb-types --test release_schema)",
                file.display()
            )
        }))
        .expect("json");
    assert_eq!(
        committed,
        live,
        "{} is not what {version} reads",
        file.display()
    );
}
