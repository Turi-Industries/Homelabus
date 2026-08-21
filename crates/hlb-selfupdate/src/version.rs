//! Versions and agent ↔ controller compatibility.
//!
//! ## 🔴 Why compatibility is the heart of the problem
//!
//! Updating Homelabus means replacing the tool that drives everything **while it drives
//! everything**. The replacement cannot be atomic across several machines: there is
//! necessarily a window where agents on version N talk to a controller on N+1, or the
//! other way round.
//!
//! Without an explicit rule that window breaks the cluster - and it breaks it at the
//! **worst moment**, while the administrator is in the middle of a delicate operation.
//!
//! The rule chosen: **within one major version, both directions work**. A different
//! major refuses, and says so before touching anything.
//!
//! ## The protocol number, distinct from the version number
//!
//! ⚠️ The binary's version (`0.1.0`) and the **protocol** version between agent and
//! controller are two different things. A patch that changes nothing in the dialogue
//! must not make agents incompatible; conversely, a report-format change inside a patch
//! release must be signalled.
//!
//! Hence [`PROTOCOL`], incremented only when the dialogue changes.

use serde::{Deserialize, Serialize};

/// The agent ↔ controller dialogue version.
///
/// 🔴 To be incremented **only** when the exchange format changes incompatibly.
/// Confusing it with the binary version would refuse perfectly working agents on every
/// patch release.
pub const PROTOCOL: u32 = 1;

/// A semantic version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Version {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
}

impl Version {
    pub const fn new(major: u32, minor: u32, patch: u32) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }

    /// La version de ce binaire, lue au moment de la compilation.
    pub fn current() -> Self {
        Self::parse(env!("CARGO_PKG_VERSION")).unwrap_or(Self::new(0, 0, 0))
    }

    pub fn parse(s: &str) -> Option<Self> {
        // A leading "v" is tolerated: Git tags often carry one, and refusing "v0.2.0"
        // would fail the update over a cosmetic detail.
        let s = s.trim().trim_start_matches('v');
        // And a pre-release suffix: `0.2.0-rc1` is still 0.2.0 for compatibility
        // comparison.
        let s = s.split(['-', '+']).next()?;

        let mut it = s.split('.');
        let major = it.next()?.parse().ok()?;
        let minor = it.next()?.parse().ok()?;
        let patch = it.next().unwrap_or("0").parse().ok()?;
        if it.next().is_some() {
            return None;
        }
        Some(Self {
            major,
            minor,
            patch,
        })
    }
}

impl std::fmt::Display for Version {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

/// The compatibility verdict between two components.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Compatibility {
    /// Les deux se comprennent.
    Ok,
    /// 🔴 Incompatible: the update must stop before it starts.
    Incompatible { reason: String },
}

impl Compatibility {
    pub fn is_ok(&self) -> bool {
        matches!(self, Self::Ok)
    }

    pub fn describe(&self) -> String {
        match self {
            Self::Ok => "compatibles".to_string(),
            Self::Incompatible { reason } => reason.clone(),
        }
    }
}

/// Can an agent on version `agent` talk to a controller on `controller`?
///
/// 🔴 The question arises **in both directions**, because the update is not atomic:
/// agents go first, so for a while there are N+1 agents facing an N controller. Then,
/// if a node was powered off, an N agent will face an N+1 controller.
///
/// A rule covering only one direction would let the other break silently.
pub fn compatible(agent: Version, controller: Version) -> Compatibility {
    if agent.major != controller.major {
        return Compatibility::Incompatible {
            reason: format!(
                "agent {agent} and controller {controller}: different MAJOR \
                 versions. A major changes the dialogue incompatibly; updating one \
                 without the other would cut control of the cluster."
            ),
        };
    }
    Compatibility::Ok
}

/// Do two protocols understand each other?
pub fn protocol_compatible(agent: u32, controller: u32) -> Compatibility {
    if agent == controller {
        return Compatibility::Ok;
    }
    Compatibility::Incompatible {
        reason: format!(
            "protocol {agent} on the agent side, {controller} on the controller \
             side - the exchange format changed. Update the agent before the \
             controller."
        ),
    }
}

/// Le type de saut entre deux versions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Jump {
    /// Nothing to do.
    None,
    /// Correctif : sans risque connu.
    Patch,
    /// Minor: features added, schema possibly migrated.
    Minor,
    /// 🔴 Major: a deliberate break, manual approval required.
    Major,
    /// 🔴 A downgrade. Never done by `update` - that is `rollback`.
    Downgrade,
}

impl Jump {
    pub fn between(from: Version, to: Version) -> Self {
        use std::cmp::Ordering::*;
        match to.cmp(&from) {
            Equal => Self::None,
            Less => Self::Downgrade,
            Greater if to.major > from.major => Self::Major,
            Greater if to.minor > from.minor => Self::Minor,
            Greater => Self::Patch,
        }
    }

    /// Is explicit approval needed beyond `--apply`?
    pub fn needs_confirmation(&self) -> bool {
        matches!(self, Self::Major | Self::Downgrade)
    }

    pub fn describe(&self) -> &'static str {
        match self {
            Self::None => "no change",
            Self::Patch => "patch",
            Self::Minor => "minor version",
            Self::Major => "🔴 MAJOR version - a deliberate break",
            Self::Downgrade => "🔴 DOWNGRADE",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions_parse_in_the_forms_that_exist_in_the_wild() {
        assert_eq!(Version::parse("1.2.3"), Some(Version::new(1, 2, 3)));
        // Git tags often carry a "v": refusing it would fail the update over a
        // cosmetic detail.
        assert_eq!(Version::parse("v1.2.3"), Some(Version::new(1, 2, 3)));
        // A pre-release is still the same version for compatibility.
        assert_eq!(Version::parse("1.2.3-rc1"), Some(Version::new(1, 2, 3)));
        assert_eq!(Version::parse("1.2"), Some(Version::new(1, 2, 0)));
    }

    #[test]
    fn nonsense_is_refused() {
        assert_eq!(Version::parse("abc"), None);
        assert_eq!(Version::parse("1.2.3.4"), None);
        assert_eq!(Version::parse(""), None);
    }

    #[test]
    fn versions_order_as_expected() {
        assert!(Version::new(1, 0, 0) > Version::new(0, 9, 9));
        assert!(Version::new(0, 2, 0) > Version::new(0, 1, 99));
        assert!(Version::new(0, 1, 2) > Version::new(0, 1, 1));
    }

    #[test]
    fn compatibility_is_checked_in_both_directions() {
        // 🔴 The update is not atomic: agents go first, so there are N+1 agents facing
        // an N controller, then the reverse if a node was powered off. A one-way rule
        // would let the other direction break silently.
        let n = Version::new(0, 1, 0);
        let n_plus = Version::new(0, 2, 0);

        assert!(compatible(n_plus, n).is_ok(), "agent en avance");
        assert!(compatible(n, n_plus).is_ok(), "agent en retard");
    }

    #[test]
    fn a_major_difference_is_refused_before_anything_is_touched() {
        let c = compatible(Version::new(1, 0, 0), Version::new(0, 9, 0));
        assert!(!c.is_ok());
        assert!(c.describe().contains("MAJOR"), "{}", c.describe());
        // The message must state the CONSEQUENCE, not merely the observation.
        assert!(c.describe().contains("cut control"), "{}", c.describe());
    }

    #[test]
    fn the_protocol_number_is_not_the_binary_version() {
        // ⚠️ Confusing them would refuse perfectly working agents on every patch.
        assert!(protocol_compatible(1, 1).is_ok());
        assert!(!protocol_compatible(1, 2).is_ok());

        // Two binaries of different versions but the same protocol get along.
        assert!(compatible(Version::new(0, 1, 0), Version::new(0, 3, 5)).is_ok());
    }

    #[test]
    fn a_protocol_mismatch_says_what_to_do() {
        let c = protocol_compatible(1, 2);
        assert!(
            c.describe().contains("agent before the"),
            "{}",
            c.describe()
        );
    }

    #[test]
    fn jumps_are_classified() {
        let v = Version::new(0, 2, 3);
        assert_eq!(Jump::between(v, v), Jump::None);
        assert_eq!(Jump::between(v, Version::new(0, 2, 4)), Jump::Patch);
        assert_eq!(Jump::between(v, Version::new(0, 3, 0)), Jump::Minor);
        assert_eq!(Jump::between(v, Version::new(1, 0, 0)), Jump::Major);
        assert_eq!(Jump::between(v, Version::new(0, 2, 2)), Jump::Downgrade);
    }

    #[test]
    fn only_risky_jumps_demand_extra_confirmation() {
        // A patch must not ask for three approvals: eventually you click through them
        // without reading, and the one that mattered goes through too.
        assert!(!Jump::Patch.needs_confirmation());
        assert!(!Jump::Minor.needs_confirmation());
        assert!(Jump::Major.needs_confirmation());
        assert!(Jump::Downgrade.needs_confirmation());
    }

    #[test]
    fn a_downgrade_is_never_an_update() {
        // 🔴 Going back goes through `rollback`, which ALSO restores the schema.
        // Passing it off as an update would leave the database on schema N+1 under an
        // N binary - the state there is no way out of.
        assert_eq!(
            Jump::between(Version::new(0, 3, 0), Version::new(0, 2, 0)),
            Jump::Downgrade
        );
        assert!(Jump::Downgrade.describe().contains("DOWNGRADE"));
    }

    #[test]
    fn the_current_version_is_readable() {
        // If this failed, `Version::current()` would return 0.0.0 and every comparison
        // would conclude an update is permanently available.
        let v = Version::current();
        assert_ne!(v, Version::new(0, 0, 0), "version du paquet illisible");
    }
}
