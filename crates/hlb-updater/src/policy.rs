//! Who applies an update: nobody, a click, or a person following the migration guide.
//!
//! The jump decides, against how far the manifest — or the house, over it — lets an update
//! go alone. A patch applies itself in its window, a minor waits for a click, a major for
//! a person. The guards that stop the automatic path come on top, never under.

use hlb_registry::Version;
use hlb_types::{Automatic, Image, Manifest};

use crate::{Candidate, UpdateKind};

/// How far a candidate moves what runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Jump {
    Patch,
    Minor,
    /// A new major, another image, or a move no version says the size of.
    Major,
}

impl Jump {
    /// The jump between two tags of one image.
    ///
    /// A rebuild of the same tag moves whatever the tag follows: `1.24.3` rebuilt for its
    /// base is a patch, `1.24` a patch, `v2` a minor. 🔴 A tag that is no version
    /// (`latest`, `stable`) can carry anything, so it is a major: a person looks.
    pub fn between(from: &str, to: &str) -> Self {
        let (Some(f), Some(t)) = (Version::parse(from), Version::parse(to)) else {
            return Self::Major;
        };
        if !f.same_flavor(&t) {
            return Self::Major;
        }
        if f.raw == t.raw {
            return if f.precision() == 1 {
                Self::Minor
            } else {
                Self::Patch
            };
        }
        if t.major != f.major {
            Self::Major
        } else if t.minor != f.minor {
            Self::Minor
        } else {
            Self::Patch
        }
    }

    /// The candidate's largest jump, its companions' included.
    pub fn of(c: &Candidate, installed: &Manifest) -> Self {
        let own = match &c.kind {
            // The app's own image stays: the companions alone say how far it moves.
            UpdateKind::Companions => Self::Patch,
            UpdateKind::DigestOnly => Self::between(&c.from_tag, &c.from_tag),
            UpdateKind::NewVersion { to_tag } => Self::between(&c.from_tag, to_tag),
            UpdateKind::Catalog { repo, tag } if *repo == installed.spec.image.repo => {
                Self::between(&c.from_tag, tag)
            }
            UpdateKind::Catalog { .. } => Self::Major,
        };
        let companions = c.companions.iter().map(|m| {
            match installed.spec.companions.iter().find(|i| i.name == m.name) {
                Some(i) => companion_jump(&i.image, &m.to),
                None => Self::Major,
            }
        });
        companions.fold(own, Self::max)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Patch => "patch",
            Self::Minor => "minor",
            Self::Major => "major",
        }
    }
}

fn companion_jump(from: &Image, to: &Image) -> Jump {
    if from.repo != to.repo {
        return Jump::Major;
    }
    Jump::between(&from.tag, &to.tag)
}

/// Who applies a candidate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// In its window, with nobody there.
    Automatic,
    /// A person's click, from the inbox or `hlb update apply`.
    OneClick { why: String },
    /// A person, with the migration guide: never from a click.
    Manual { why: String },
}

impl Decision {
    pub fn is_automatic(&self) -> bool {
        matches!(self, Self::Automatic)
    }
}

/// Decides who applies `c`. `house` is the owner's setting for this app, or for the whole
/// house, and wins over the manifest's either way: the house is theirs.
pub fn decide(c: &Candidate, installed: &Manifest, house: Option<Automatic>) -> Decision {
    let jump = Jump::of(c, installed);
    if jump == Jump::Major {
        return Decision::Manual {
            why: "a major move: its migration guide first".into(),
        };
    }
    let (reach, whose) = match house {
        Some(a) => (a, "the house"),
        None => (installed.spec.update.automatic(), "the manifest"),
    };
    let reached = match reach {
        Automatic::None => false,
        Automatic::Patch => jump == Jump::Patch,
        Automatic::Minor => true,
    };
    if reached {
        Decision::Automatic
    } else {
        Decision::OneClick {
            why: format!(
                "a {} move, and {whose} applies {} alone",
                jump.as_str(),
                match reach {
                    Automatic::None => "nothing".to_string(),
                    a => format!("up to a {}", a.as_str()),
                }
            ),
        }
    }
}

/// Why the catalog holds the candidate back, if it does: its target tag, or a companion's,
/// is in the catalog manifest's `update.hold`.
pub fn held_by_catalog(c: &Candidate, installed: &Manifest, catalog: &Manifest) -> Option<String> {
    let hold = &catalog.spec.update.hold;
    if hold.is_empty() {
        return None;
    }
    let own = match &c.kind {
        UpdateKind::NewVersion { to_tag } => Some(to_tag.as_str()),
        UpdateKind::Catalog { tag, .. } => Some(tag.as_str()),
        UpdateKind::DigestOnly => Some(installed.spec.image.tag.as_str()),
        UpdateKind::Companions => None,
    };
    let tags = own
        .into_iter()
        .chain(c.companions.iter().map(|m| m.to.tag.as_str()));
    for tag in tags {
        if hold.iter().any(|h| h == tag) {
            return Some(format!(
                "the catalog holds {tag} back: a release found broken — the update waits \
                 for the next one"
            ));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Maturity;

    #[test]
    fn a_jump_is_measured_by_what_moves() {
        assert_eq!(Jump::between("1.24.3", "1.24.4"), Jump::Patch);
        assert_eq!(Jump::between("1.24.3", "1.25.0"), Jump::Minor);
        assert_eq!(Jump::between("1.24.3", "2.0.0"), Jump::Major);
        assert_eq!(
            Jump::between("v1.15.0", "1.15.1"),
            Jump::Major,
            "another flavour"
        );
        assert_eq!(Jump::between("17-alpine", "17-bookworm"), Jump::Major);
    }

    #[test]
    fn a_rebuild_moves_whatever_its_tag_follows() {
        assert_eq!(Jump::between("1.24.3", "1.24.3"), Jump::Patch);
        assert_eq!(Jump::between("1.24", "1.24"), Jump::Patch);
        assert_eq!(Jump::between("v2", "v2"), Jump::Minor);
        assert_eq!(Jump::between("17-alpine", "17-alpine"), Jump::Minor);
        // 🔴 Anything can be behind it.
        assert_eq!(Jump::between("latest", "latest"), Jump::Major);
        assert_eq!(Jump::between("stable", "stable"), Jump::Major);
    }

    fn manifest(update: &str) -> Manifest {
        serde_yaml_ng::from_str(&format!(
            r#"
apiVersion: hlb/v1
kind: App
metadata: {{ name: gitea }}
spec:
  image: {{ repo: gitea/gitea, tag: "1.24.3", digest: "sha256:old" }}
  update: {update}
"#
        ))
        .expect("manifest")
    }

    fn moving_to(tag: &str) -> Candidate {
        Candidate {
            app: "gitea".into(),
            kind: UpdateKind::NewVersion { to_tag: tag.into() },
            from_tag: "1.24.3".into(),
            from_digest: Some("sha256:old".into()),
            to_digest: "sha256:new".into(),
            in_window: true,
            needs_backup: false,
            maturity: Maturity::Mature,
            companions: Vec::new(),
        }
    }

    #[test]
    fn a_patch_applies_itself_a_minor_waits_for_a_click_a_major_for_a_person() {
        let m = manifest("{ channel: minor }");
        assert_eq!(decide(&moving_to("1.24.4"), &m, None), Decision::Automatic);
        assert!(matches!(
            decide(&moving_to("1.25.0"), &m, None),
            Decision::OneClick { .. }
        ));
        let catalog_major = Candidate {
            kind: UpdateKind::Catalog {
                repo: "gitea/gitea".into(),
                tag: "2.0.0".into(),
            },
            ..moving_to("")
        };
        assert!(matches!(
            decide(&catalog_major, &m, None),
            Decision::Manual { .. }
        ));
    }

    #[test]
    fn pin_applies_nothing_alone_unless_the_manifest_says_otherwise() {
        let pinned = manifest("{ channel: pin }");
        assert!(matches!(
            decide(&moving_to("1.24.4"), &pinned, None),
            Decision::OneClick { .. }
        ));
        let minor_alone = manifest("{ channel: minor, automatic: minor }");
        assert_eq!(
            decide(&moving_to("1.25.0"), &minor_alone, None),
            Decision::Automatic
        );
    }

    #[test]
    fn the_house_wins_over_the_manifest_both_ways() {
        let m = manifest("{ channel: minor }");
        let p = moving_to("1.24.4");
        let Decision::OneClick { why } = decide(&p, &m, Some(Automatic::None)) else {
            panic!("the house stopped it");
        };
        assert!(why.contains("the house"), "{why}");
        assert_eq!(
            decide(&moving_to("1.25.0"), &m, Some(Automatic::Minor)),
            Decision::Automatic
        );
        // Never a major, whatever the house says.
        let other = Candidate {
            kind: UpdateKind::Catalog {
                repo: "forgejo/forgejo".into(),
                tag: "1.24.4".into(),
            },
            ..moving_to("")
        };
        assert!(matches!(
            decide(&other, &m, Some(Automatic::Minor)),
            Decision::Manual { .. }
        ));
    }

    #[test]
    fn the_catalog_holds_a_broken_release_back_from_every_house() {
        let installed = manifest("{ channel: minor }");
        let catalog = manifest(r#"{ channel: minor, hold: ["1.24.4"] }"#);
        assert!(held_by_catalog(&moving_to("1.24.4"), &installed, &catalog).is_some());
        assert!(held_by_catalog(&moving_to("1.24.5"), &installed, &catalog).is_none());
        // The frozen manifest's hold is not what counts.
        assert!(held_by_catalog(&moving_to("1.24.4"), &catalog, &installed).is_none());
    }
}
