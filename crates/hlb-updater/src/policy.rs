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
        // 🔴 Below 1.0 the second number is the one that breaks (SemVer §4, Cargo's
        // rule), and below 0.1 every release may: `hlb-caddy` 0.2.1 → 0.4.8 went alone on
        // the lab (2026-11-08), read as a minor an exploited flaw may take.
        if t.major != f.major || (f.major == 0 && (t.minor != f.minor || f.minor == Some(0))) {
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
    OneClick { why: Why },
    /// A person, with the migration guide: never from a click.
    Manual { why: Why },
}

impl Decision {
    pub fn is_automatic(&self) -> bool {
        matches!(self, Self::Automatic)
    }
}

/// Why a candidate waits for a person. A value, not a sentence: the interface words it
/// in the person's language, the command line through [`std::fmt::Display`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Why {
    /// A new major, another image, or a tag no version reads: its migration guide first.
    Major,
    /// Further than the house — or the manifest, when the house says nothing — lets an
    /// update go alone.
    BeyondReach {
        jump: Jump,
        reach: Automatic,
        by_house: bool,
    },
    /// A release on the way says it breaks something, or migrates data.
    NotesSay { tag: String, word: String },
    /// The target's notes are not among the releases: nobody read what it changes.
    NotesMissing { tag: String },
    /// The notes could not be read.
    NotesUnreadable { error: String },
}

impl std::fmt::Display for Why {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Major => write!(f, "a major move: its migration guide first"),
            Self::BeyondReach {
                jump,
                reach,
                by_house,
            } => write!(
                f,
                "a {} move, and {} applies {} alone",
                jump.as_str(),
                if *by_house {
                    "the house"
                } else {
                    "the manifest"
                },
                match reach {
                    Automatic::None => "nothing".to_string(),
                    a => format!("up to a {}", a.as_str()),
                }
            ),
            Self::NotesSay { tag, word } => {
                write!(f, "the notes of {tag} say \"{word}\": read them first")
            }
            Self::NotesMissing { tag } => {
                write!(
                    f,
                    "no release notes found for {tag}: nobody read what it changes"
                )
            }
            Self::NotesUnreadable { error } => {
                write!(f, "its release notes could not be read ({error})")
            }
        }
    }
}

/// Decides who applies `c`. `house` is the owner's setting for this app, or for the whole
/// house, and wins over the manifest's either way: the house is theirs.
///
/// `exploited`: what runs carries a flaw exploited in the wild. The manifest's reach is
/// then raised to a minor — a fix waiting a week for a click is a week of the flaw —,
/// never the house's, nor past a major.
pub fn decide(
    c: &Candidate,
    installed: &Manifest,
    house: Option<Automatic>,
    exploited: bool,
) -> Decision {
    let jump = Jump::of(c, installed);
    if jump == Jump::Major {
        return Decision::Manual { why: Why::Major };
    }
    let (reach, by_house) = match house {
        Some(a) => (a, true),
        None if exploited => (Automatic::Minor, false),
        None => (installed.spec.update.automatic(), false),
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
            why: Why::BeyondReach {
                jump,
                reach,
                by_house,
            },
        }
    }
}

/// The repository whose releases say what `c` changes — the catalog's manifest first,
/// which may name it since the app was installed.
pub fn notes_source<'a>(installed: &'a Manifest, catalog: Option<&'a Manifest>) -> Option<&'a str> {
    catalog
        .and_then(|m| m.spec.update.notes.as_ref())
        .or(installed.spec.update.notes.as_ref())
        .map(|n| n.github.as_str())
}

/// The tag whose notes are read up to. `None` for the same tag rebuilt, or companions
/// alone: no release of their own.
pub fn notes_target(c: &Candidate) -> Option<&str> {
    match &c.kind {
        UpdateKind::NewVersion { to_tag } => Some(to_tag),
        UpdateKind::Catalog { tag, .. } => Some(tag),
        UpdateKind::DigestOnly | UpdateKind::Companions => None,
    }
}

/// [`decide`], then the release notes between what runs and the target, when the manifest
/// says where they are. They only ever take the automatic path away: a warning, or notes
/// that could not be read, leave the update to a person.
pub async fn judge(
    registry: &hlb_registry::RegistryClient,
    c: &Candidate,
    installed: &Manifest,
    catalog: Option<&Manifest>,
    house: Option<Automatic>,
    exploited: bool,
) -> Decision {
    let decision = decide(c, installed, house, exploited);
    if !decision.is_automatic() {
        return decision;
    }
    let (Some(github), Some(to)) = (notes_source(installed, catalog), notes_target(c)) else {
        return decision;
    };
    guarded(
        decision,
        registry
            .release_notes(github, &c.from_tag, to)
            .await
            .map(|read| hlb_registry::notes::warning(&read, to))
            .map_err(|e| e.to_string()),
    )
}

/// The automatic path, kept only when the notes were read and warn of nothing.
pub fn guarded(
    decision: Decision,
    notes: Result<Option<hlb_registry::notes::Warning>, String>,
) -> Decision {
    use hlb_registry::notes::Warning;
    if !decision.is_automatic() {
        return decision;
    }
    let why = match notes {
        Ok(None) => return decision,
        Ok(Some(Warning::Says { tag, word })) => Why::NotesSay {
            tag,
            word: word.to_string(),
        },
        Ok(Some(Warning::TargetMissing { tag })) => Why::NotesMissing { tag },
        Err(error) => Why::NotesUnreadable { error },
    };
    Decision::OneClick { why }
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
    fn below_one_the_second_number_is_the_major() {
        assert_eq!(Jump::between("0.2.1", "0.4.8"), Jump::Major);
        assert_eq!(Jump::between("0.2.1", "0.2.5"), Jump::Patch);
        assert_eq!(Jump::between("0.0.1", "0.0.2"), Jump::Major);
        assert_eq!(Jump::between("0.9.3", "1.0.0"), Jump::Major);
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
        assert_eq!(
            decide(&moving_to("1.24.4"), &m, None, false),
            Decision::Automatic
        );
        assert!(matches!(
            decide(&moving_to("1.25.0"), &m, None, false),
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
            decide(&catalog_major, &m, None, false),
            Decision::Manual { .. }
        ));
    }

    #[test]
    fn pin_applies_nothing_alone_unless_the_manifest_says_otherwise() {
        let pinned = manifest("{ channel: pin }");
        assert!(matches!(
            decide(&moving_to("1.24.4"), &pinned, None, false),
            Decision::OneClick { .. }
        ));
        let minor_alone = manifest("{ channel: minor, automatic: minor }");
        assert_eq!(
            decide(&moving_to("1.25.0"), &minor_alone, None, false),
            Decision::Automatic
        );
    }

    #[test]
    fn the_house_wins_over_the_manifest_both_ways() {
        let m = manifest("{ channel: minor }");
        let p = moving_to("1.24.4");
        let Decision::OneClick { why } = decide(&p, &m, Some(Automatic::None), false) else {
            panic!("the house stopped it");
        };
        assert!(
            matches!(why, Why::BeyondReach { by_house: true, .. }),
            "{why}"
        );
        assert!(why.to_string().contains("the house"), "{why}");
        assert_eq!(
            decide(&moving_to("1.25.0"), &m, Some(Automatic::Minor), false),
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
            decide(&other, &m, Some(Automatic::Minor), false),
            Decision::Manual { .. }
        ));
    }

    #[test]
    fn an_exploited_flaw_raises_the_manifests_reach_and_never_the_houses() {
        let pinned = manifest("{ channel: pin }");
        assert_eq!(
            decide(&moving_to("1.25.0"), &pinned, None, true),
            Decision::Automatic
        );
        // The owner said no: theirs, exploited or not.
        assert!(matches!(
            decide(&moving_to("1.24.4"), &pinned, Some(Automatic::None), true),
            Decision::OneClick { .. }
        ));
        let major = Candidate {
            kind: UpdateKind::NewVersion {
                to_tag: "2.0.0".into(),
            },
            ..moving_to("")
        };
        assert!(matches!(
            decide(&major, &pinned, None, true),
            Decision::Manual { .. }
        ));
    }

    /// 🔴 Notes nobody could read are not notes that say nothing.
    #[test]
    fn notes_only_ever_take_the_automatic_path_away() {
        use hlb_registry::notes::Warning;
        assert_eq!(guarded(Decision::Automatic, Ok(None)), Decision::Automatic);
        let says = Warning::Says {
            tag: "v1.24.5".into(),
            word: "breaking",
        };
        assert!(matches!(
            guarded(Decision::Automatic, Ok(Some(says))),
            Decision::OneClick { .. }
        ));
        let missing = Warning::TargetMissing {
            tag: "1.24.5".into(),
        };
        assert!(matches!(
            guarded(Decision::Automatic, Ok(Some(missing))),
            Decision::OneClick { .. }
        ));
        assert!(matches!(
            guarded(Decision::Automatic, Err("rate limit".into())),
            Decision::OneClick {
                why: Why::NotesUnreadable { .. }
            }
        ));
        // What already waits for a person is left as it is.
        let manual = Decision::Manual { why: Why::Major };
        assert_eq!(guarded(manual.clone(), Err("x".into())), manual);
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
