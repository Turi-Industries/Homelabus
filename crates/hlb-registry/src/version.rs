//! Version comparison and channel policy.
//!
//! Real-world tags are irregular: `1.24`, `1.24.3`, `v1.24.3`, `17-alpine`,
//! `8-alpine`, `0.24`. So the parser is tolerant, but **strict about what matters**:
//!
//! 🔴 **The suffix must match.** `17-alpine` may move up to `18-alpine`, but never to
//! `18` or `18-bookworm`: that would swap the base distribution out from under the
//! service, with different paths and different libraries.

use hlb_types::UpdateChannel;

/// A version extracted from a tag.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Version {
    pub major: u64,
    pub minor: Option<u64>,
    pub patch: Option<u64>,
    /// What follows the version: `alpine`, `bookworm`, `rootless`...
    pub suffix: Option<String>,
    /// The original tag, kept as-is for deployment.
    pub raw: String,
}

impl Version {
    /// Parses a tag. Returns `None` when it is not a usable version (`latest`,
    /// `stable`, `main`, a sha...).
    pub fn parse(tag: &str) -> Option<Self> {
        let body = tag.strip_prefix('v').unwrap_or(tag);

        // The suffix starts at the first "-".
        let (numbers, suffix) = match body.split_once('-') {
            Some((n, s)) => (n, Some(s.to_string())),
            None => (body, None),
        };

        let mut parts = numbers.split('.');
        let major: u64 = parts.next()?.parse().ok()?;
        let minor = parts.next().and_then(|p| p.parse().ok());
        let patch = parts.next().and_then(|p| p.parse().ok());

        // A fourth segment signals a scheme we do not know how to compare.
        if parts.next().is_some() {
            return None;
        }

        Some(Self {
            major,
            minor,
            patch,
            suffix,
            raw: tag.to_string(),
        })
    }

    /// Ordering within one family. Missing fields count as 0.
    fn cmp_numeric(&self, other: &Self) -> std::cmp::Ordering {
        (self.major, self.minor.unwrap_or(0), self.patch.unwrap_or(0)).cmp(&(
            other.major,
            other.minor.unwrap_or(0),
            other.patch.unwrap_or(0),
        ))
    }

    /// Same image variant (same base, same flavour)?
    ///
    /// 🔴 This is a guard rail: without it, `17-alpine` could "move up" to
    /// `18-bookworm`, changing the entire runtime environment.
    pub fn same_flavor(&self, other: &Self) -> bool {
        self.suffix == other.suffix
    }

    /// How many numeric components the tag has: `15` → 1, `15.18` → 2, `1.37.1` → 3.
    pub fn precision(&self) -> u8 {
        1 + u8::from(self.minor.is_some()) + u8::from(self.patch.is_some())
    }

    /// Does `channel` allow moving from `self` up to `candidate`?
    pub fn allows(&self, candidate: &Self, channel: UpdateChannel) -> bool {
        if !self.same_flavor(candidate) {
            return false;
        }

        // 🔴 A tag's precision must never change.
        //
        // `postgres:15-alpine` is a *rolling* tag: it always follows the latest 15.x.
        // "Moving it up" to `15.18-alpine` would pin it, and it would stop following -
        // the deployment's semantics would have changed while we believed we were
        // applying an update.
        //
        // For a rolling tag it is not the tag that changes but the **digest**: the
        // digest watcher is what spots the new build, not this selector.
        if self.precision() != candidate.precision() {
            return false;
        }
        if candidate.cmp_numeric(self) != std::cmp::Ordering::Greater {
            return false;
        }

        match channel {
            // Never updated automatically.
            UpdateChannel::Pin => false,
            // Forbidden by manifest validation; refused here as a second line.
            UpdateChannel::Latest => false,
            UpdateChannel::Patch => candidate.major == self.major && candidate.minor == self.minor,
            UpdateChannel::Minor => candidate.major == self.major,
        }
    }
}

/// Picks the best available update, or `None` when there is nothing to do.
pub fn best_upgrade(current_tag: &str, tags: &[String], channel: UpdateChannel) -> Option<String> {
    let current = Version::parse(current_tag)?;

    let mut best: Option<Version> = None;
    for t in tags {
        let Some(v) = Version::parse(t) else { continue };
        if !current.allows(&v, channel) {
            continue;
        }
        let better = match &best {
            None => true,
            Some(b) => v.cmp_numeric(b) == std::cmp::Ordering::Greater,
        };
        if better {
            best = Some(v);
        }
    }

    best.map(|v| v.raw)
}

#[cfg(test)]
mod tests {
    use super::*;
    use UpdateChannel::{Minor, Patch, Pin};

    fn v(s: &str) -> Version {
        Version::parse(s).unwrap_or_else(|| panic!("\"{s}\" should be parsable"))
    }

    #[test]
    fn parses_common_shapes() {
        assert_eq!(v("1.24.3").major, 1);
        assert_eq!(v("1.24.3").minor, Some(24));
        assert_eq!(v("1.24.3").patch, Some(3));
        assert_eq!(v("v1.24.3").major, 1);
        assert_eq!(v("17").minor, None);
        assert_eq!(v("17-alpine").suffix.as_deref(), Some("alpine"));
        assert_eq!(v("0.24").major, 0);
    }

    #[test]
    fn rejects_non_versions() {
        for t in ["latest", "stable", "main", "sha-abc123", "edge"] {
            assert!(Version::parse(t).is_none(), "« {t} » ne devrait pas passer");
        }
    }

    #[test]
    fn patch_stays_within_the_minor() {
        assert!(v("1.24.3").allows(&v("1.24.4"), Patch));
        assert!(!v("1.24.3").allows(&v("1.25.0"), Patch));
        assert!(!v("1.24.3").allows(&v("2.0.0"), Patch));
    }

    #[test]
    fn minor_stays_within_the_major() {
        assert!(v("1.24.3").allows(&v("1.25.0"), Minor));
        assert!(v("1.24.3").allows(&v("1.24.4"), Minor));
        assert!(
            !v("1.24.3").allows(&v("2.0.0"), Minor),
            "a major bump must NEVER be automatic"
        );
    }

    #[test]
    fn pin_never_allows_anything() {
        assert!(!v("1.24.3").allows(&v("1.24.4"), Pin));
        assert!(!v("1.24.3").allows(&v("1.25.0"), Pin));
    }

    #[test]
    fn downgrades_and_identity_are_refused() {
        assert!(!v("1.24.3").allows(&v("1.24.2"), Minor));
        assert!(!v("1.24.3").allows(&v("1.24.3"), Minor));
    }

    #[test]
    fn the_flavor_must_match() {
        // 🔴 The guard rail: swapping the base out from under the service.
        assert!(!v("17-alpine").allows(&v("18"), Minor));
        assert!(!v("17-alpine").allows(&v("18-bookworm"), Minor));
        assert!(!v("17").allows(&v("18-alpine"), Minor));
        assert!(
            !v("17-alpine").allows(&v("18-alpine"), Minor),
            "une majeure reste interdite"
        );
    }

    #[test]
    fn a_rolling_tag_never_becomes_pinned() {
        // `15-alpine` follows the latest 15.x. Pinning it would be a change of
        // semantics disguised as an update.
        assert!(!v("15-alpine").allows(&v("15.18-alpine"), Minor));
        assert!(!v("17").allows(&v("17.4"), Minor));

        // And the reverse is just as wrong.
        assert!(!v("17.2").allows(&v("18"), Minor));
    }

    #[test]
    fn a_rolling_tag_updates_through_its_digest_not_its_name() {
        // Consequence: nothing for the tag selector to do. That is intended.
        let tags: Vec<String> = ["15-alpine", "15.18-alpine", "16-alpine"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert_eq!(
            best_upgrade("15-alpine", &tags, Minor),
            None,
            "a rolling tag updates through its digest"
        );
    }

    #[test]
    fn alpine_minors_upgrade_within_the_major() {
        assert!(v("17.2-alpine").allows(&v("17.4-alpine"), Minor));
        assert!(!v("17.2-alpine").allows(&v("18.0-alpine"), Minor));
    }

    #[test]
    fn best_upgrade_picks_the_highest_allowed() {
        let tags: Vec<String> = ["1.24.1", "1.24.5", "1.24.3", "1.25.0", "2.0.0", "latest"]
            .iter()
            .map(|s| s.to_string())
            .collect();

        assert_eq!(
            best_upgrade("1.24.2", &tags, Patch).as_deref(),
            Some("1.24.5")
        );
        assert_eq!(
            best_upgrade("1.24.2", &tags, Minor).as_deref(),
            Some("1.25.0")
        );
        assert_eq!(best_upgrade("1.24.2", &tags, Pin), None);
    }

    #[test]
    fn best_upgrade_ignores_other_flavors() {
        let tags: Vec<String> = ["17.4", "17.4-alpine", "17.9-bookworm"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert_eq!(
            best_upgrade("17.2-alpine", &tags, Minor).as_deref(),
            Some("17.4-alpine"),
            "only the alpine flavour is eligible"
        );
    }

    #[test]
    fn nothing_to_do_returns_none() {
        let tags = vec!["1.24.0".to_string()];
        assert_eq!(best_upgrade("1.24.0", &tags, Minor), None);
    }

    #[test]
    fn an_unparseable_current_tag_blocks_updates() {
        // Better to do nothing than to guess.
        assert_eq!(best_upgrade("latest", &["1.0.0".into()], Minor), None);
    }
}
