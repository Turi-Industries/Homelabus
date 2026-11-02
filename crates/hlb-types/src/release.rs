//! Which `hlb` an app runs on: its manifest's `metadata.hlb` range, and each release's
//! schema, so that a range is checked against what that release could read.
//!
//! 🔴 `deny_unknown_fields` makes an older `hlb` refuse a manifest using one field it
//! does not know — and `Catalog::load` failed on it, so the whole catalog went with
//! it. Fields reach the schema between releases (thirteen in the two days after 0.3.0),
//! so a catalog published apart from `hlb` would do that to every installation one
//! release behind.

use semver::{Op, VersionReq};

pub use semver::Version;

include!(concat!(env!("OUT_DIR"), "/schemas.rs"));

/// This build's release: its version without a pre-release. Between releases the
/// workspace carries the NEXT one (`0.4.0-dev`), which runs what that release will: a
/// manifest using a field added since 0.3.0 says `>=0.4.0`, and must run on the
/// repository's own `hlb`.
pub fn running() -> Version {
    let mut v = Version::parse(env!("CARGO_PKG_VERSION")).unwrap_or(Version::new(0, 0, 0));
    v.pre = semver::Prerelease::EMPTY;
    v.build = semver::BuildMetadata::EMPTY;
    v
}

fn parse(range: &str) -> Result<VersionReq, String> {
    VersionReq::parse(range)
        .map_err(|e| format!("hlb \"{range}\" is not a version range ({e}) — \">=0.4.0\""))
}

/// Is `release` inside `range`? `Err`: the range is not one.
pub fn accepts(range: &str, release: &Version) -> Result<bool, String> {
    Ok(parse(range)?.matches(release))
}

/// The oldest release `range` accepts: the schema a manifest is held to.
///
/// A range with no lower bound would claim every release ever made, the ones that
/// cannot read it included: refused.
pub fn floor(range: &str) -> Result<Version, String> {
    parse(range)?
        .comparators
        .iter()
        .filter_map(|c| {
            let (minor, patch) = (c.minor.unwrap_or(0), c.patch.unwrap_or(0));
            match c.op {
                Op::Exact | Op::GreaterEq | Op::Tilde | Op::Caret | Op::Wildcard => {
                    Some(Version::new(c.major, minor, patch))
                }
                // `>0.4` is the first release after every 0.4.
                Op::Greater => Some(match (c.minor, c.patch) {
                    (Some(_), Some(_)) => Version::new(c.major, minor, patch + 1),
                    (Some(_), None) => Version::new(c.major, minor + 1, 0),
                    _ => Version::new(c.major + 1, 0, 0),
                }),
                Op::Less | Op::LessEq => None,
                // `Op` is non-exhaustive: an operator a newer `semver` adds bounds nothing
                // here until it is read, and a range left with no bound is refused.
                _ => None,
            }
        })
        .max()
        .ok_or_else(|| {
            format!(
                "hlb \"{range}\" has no lower bound — name the oldest hlb it runs on, \
                 \">=0.4.0\""
            )
        })
}

/// What this build reads, as a release commits it: the manifest's schema and the
/// guide's — a guide using a step an older `hlb` does not know breaks it the same way.
pub fn schema() -> serde_json::Value {
    serde_json::json!({
        "manifest": schemars::schema_for!(crate::Manifest),
        "guide": schemars::schema_for!(crate::Guide),
    })
}

/// The schema `release` read, as committed when it was made.
pub fn release_schema(release: &Version) -> Option<serde_json::Value> {
    RELEASE_SCHEMAS
        .iter()
        .find(|(v, _)| Version::parse(v).ok().as_ref() == Some(release))
        .and_then(|(_, s)| serde_json::from_str(s).ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(s: &str) -> Version {
        Version::parse(s).expect("version")
    }

    #[test]
    fn a_floor_is_the_oldest_release_a_range_accepts() {
        assert_eq!(floor(">=0.4.0").expect("floor"), v("0.4.0"));
        assert_eq!(floor(">=0.4").expect("floor"), v("0.4.0"));
        assert_eq!(floor("^0.4.2").expect("floor"), v("0.4.2"));
        assert_eq!(floor(">=0.4.0, <0.6").expect("floor"), v("0.4.0"));
        assert_eq!(floor(">0.4").expect("floor"), v("0.5.0"));
        assert_eq!(floor(">0.4.1").expect("floor"), v("0.4.2"));
        assert!(floor("<0.6").is_err(), "no lower bound");
        assert!(floor("*").is_err(), "no lower bound");
        assert!(floor("0.4 or newer").is_err());
    }

    #[test]
    fn a_dev_build_runs_what_its_release_will() {
        // `running()` drops the pre-release: 0.4.0-dev is 0.4.0 here.
        assert!(running().pre.is_empty());
        assert!(accepts(">=0.4.0", &v("0.4.0")).expect("range"));
        assert!(!accepts(">=0.5.0", &v("0.4.0")).expect("range"));
        assert!(accepts(">=0.4.0, <0.6", &v("0.5.3")).expect("range"));
        assert!(!accepts(">=0.4.0, <0.6", &v("0.6.0")).expect("range"));
    }

    #[test]
    fn every_committed_schema_is_a_release_this_build_follows() {
        let running = running();
        assert!(!RELEASE_SCHEMAS.is_empty(), "the walk found no schema");
        for (version, schema) in RELEASE_SCHEMAS {
            let release = Version::parse(version).expect("schemas/<version>.json");
            assert!(
                release.pre.is_empty(),
                "{version}: a release, not a pre-release"
            );
            assert!(release <= running, "{version} is newer than this build");
            let read: serde_json::Value = serde_json::from_str(schema).expect("json");
            assert!(
                read.get("manifest").is_some() && read.get("guide").is_some(),
                "{version}: the manifest's and the guide's"
            );
        }
    }
}
