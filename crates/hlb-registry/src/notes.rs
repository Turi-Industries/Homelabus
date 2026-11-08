//! What releases say about themselves, read before an update applies with nobody there.
//!
//! A registry carries no notes: they live with the source, on GitHub for most of the
//! catalog. Every release between what runs and the target is read — a jump from 1.24.3
//! to 1.24.6 skips the notes of 1.24.4 and 1.24.5 otherwise, and the warning is often
//! in the one in between.

use serde::Deserialize;

use crate::{Error, Result, Version};

/// One release's notes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Notes {
    pub tag: String,
    pub body: String,
    pub url: String,
}

/// What the notes between two versions say, for a path with nobody there.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Warning {
    /// A release says it breaks something, or migrates data.
    Says { tag: String, word: &'static str },
    /// 🔴 The target's notes were not found among the releases: not read is not quiet.
    TargetMissing { tag: String },
}

/// Words that stop the automatic path. A false alarm costs a click; a missed one an
/// app that starts on a schema it cannot read.
const WARNINGS: &[&str] = &["breaking", "migration", "manual action", "action required"];

/// Reads the notes of each release after `from` up to `to` (tags of the image; GitHub's
/// may carry a `v` the image's do not, or none where they do).
pub async fn between(
    http: &reqwest::Client,
    github: &str,
    from: &str,
    to: &str,
) -> Result<Vec<Notes>> {
    let (Some(f), Some(t)) = (Version::parse(from), Version::parse(to)) else {
        return Ok(Vec::new());
    };
    if !t.is_newer_than(&f) {
        // A rebuild of the same tag has no release of its own.
        return Ok(Vec::new());
    }
    let url = format!("https://api.github.com/repos/{github}/releases?per_page=100");
    let r = http
        .get(&url)
        .header("Accept", "application/vnd.github+json")
        .send()
        .await
        .map_err(|source| Error::Http {
            source,
            context: url.clone(),
        })?;
    let status = r.status();
    if !status.is_success() {
        return Err(Error::Registry {
            status: status.as_u16(),
            detail: format!("{github}'s releases"),
        });
    }
    let releases: Vec<Release> = r.json().await.map_err(|source| Error::Http {
        source,
        context: url,
    })?;
    Ok(in_range(releases, &f, &t))
}

#[derive(Deserialize)]
struct Release {
    tag_name: String,
    #[serde(default)]
    body: Option<String>,
    #[serde(default)]
    html_url: String,
    #[serde(default)]
    draft: bool,
    #[serde(default)]
    prerelease: bool,
}

fn in_range(releases: Vec<Release>, from: &Version, to: &Version) -> Vec<Notes> {
    let mut notes: Vec<(Version, Notes)> = releases
        .into_iter()
        .filter(|r| !r.draft && !r.prerelease)
        .filter_map(|r| {
            let v = Version::parse(&r.tag_name)?;
            // On GitHub a suffix marks a release candidate (`1.24.5-rc1`), not a flavour:
            // its notes are not the release's.
            (v.suffix.is_none() && v.is_newer_than(from) && !v.is_newer_than(to)).then(|| {
                (
                    v,
                    Notes {
                        tag: r.tag_name,
                        body: r.body.unwrap_or_default(),
                        url: r.html_url,
                    },
                )
            })
        })
        .collect();
    notes.sort_by(|a, b| {
        if a.0.is_newer_than(&b.0) {
            std::cmp::Ordering::Greater
        } else if b.0.is_newer_than(&a.0) {
            std::cmp::Ordering::Less
        } else {
            std::cmp::Ordering::Equal
        }
    });
    notes.into_iter().map(|(_, n)| n).collect()
}

/// The first warning the notes carry, or the target's notes missing.
pub fn warning(notes: &[Notes], to: &str) -> Option<Warning> {
    for n in notes {
        let body = n.body.to_lowercase();
        if let Some(word) = WARNINGS.iter().find(|w| body.contains(*w)) {
            return Some(Warning::Says {
                tag: n.tag.clone(),
                word,
            });
        }
    }
    let target = Version::parse(to)?;
    let found = notes.iter().any(|n| {
        Version::parse(&n.tag)
            .is_some_and(|v| !v.is_newer_than(&target) && !target.is_newer_than(&v))
    });
    (!found).then(|| Warning::TargetMissing {
        tag: to.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn release(tag: &str, body: &str) -> Release {
        Release {
            tag_name: tag.into(),
            body: Some(body.into()),
            html_url: format!("https://github.com/acme/app/releases/tag/{tag}"),
            draft: false,
            prerelease: false,
        }
    }

    fn v(tag: &str) -> Version {
        Version::parse(tag).expect("version")
    }

    #[test]
    fn every_release_between_is_read_not_only_the_target() {
        let notes = in_range(
            vec![
                release("v1.24.6", "fixes"),
                release("v1.24.5", "BREAKING: the config key moved"),
                release("v1.24.4", "fixes"),
                release("v1.24.3", "what runs"),
                release("v1.25.0", "later"),
            ],
            &v("1.24.3"),
            &v("1.24.6"),
        );
        let tags: Vec<&str> = notes.iter().map(|n| n.tag.as_str()).collect();
        assert_eq!(tags, ["v1.24.4", "v1.24.5", "v1.24.6"]);
        assert_eq!(
            warning(&notes, "1.24.6"),
            Some(Warning::Says {
                tag: "v1.24.5".into(),
                word: "breaking"
            })
        );
    }

    #[test]
    fn quiet_notes_reaching_the_target_warn_of_nothing() {
        let notes = in_range(
            vec![release("1.24.4", "Fixes a crash.")],
            &v("1.24.3"),
            &v("1.24.4"),
        );
        assert_eq!(warning(&notes, "1.24.4"), None);
    }

    /// 🔴 Notes not found are not notes that say nothing.
    #[test]
    fn a_target_with_no_notes_is_not_a_quiet_one() {
        let notes = in_range(
            vec![
                release("1.24.4", "Fixes a crash."),
                release("1.24.5-rc1", ""),
            ],
            &v("1.24.3"),
            &v("1.24.5"),
        );
        assert_eq!(
            warning(&notes, "1.24.5"),
            Some(Warning::TargetMissing {
                tag: "1.24.5".into()
            })
        );
    }

    #[test]
    fn drafts_and_prereleases_are_no_one_s_notes() {
        let mut pre = release("1.24.4", "breaking");
        pre.prerelease = true;
        let notes = in_range(vec![pre], &v("1.24.3"), &v("1.24.4"));
        assert!(notes.is_empty());
    }
}
