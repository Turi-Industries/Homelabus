//! Moving the catalog's own images: the maintainers' side of an update.
//!
//! An installation follows the catalog (`catalog_move`); this decides what the catalog
//! names. The rules a sibling installation learned from its update bot, in code rather
//! than in a configuration the bot could edit:
//!
//! - **never a major**, which is a person's, rehearsed on a restored copy first — it is
//!   only ever SAID here;
//! - **the same tag shape**: `8.1.9-alpine` moves to `8.1.10-alpine`, never to `8.1.10`
//!   nor to `8.1-alpine` (`Version::allows`);
//! - **mature**: published at least the manifest's `maturationDays` ago, dated by the
//!   build itself;
//! - **never downward**, and the digest written is the one the tag names at the
//!   registry when it is written.

use hlb_registry::{ImageRef, RegistryClient, Version};
use hlb_types::{Image, UpdateChannel};

use crate::{Maturity, Result};

/// How many candidate builds are dated before giving up on finding a mature one: every
/// date costs requests, and Docker Hub allows an anonymous address 100 an hour.
const DATED_AT_MOST: usize = 4;

/// What the catalog could move one image to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proposal {
    /// The app, or `app/companion`.
    pub owner: String,
    pub current: Image,
    /// The image to write, when it differs from `current`.
    pub to: Option<Image>,
    /// When `to` was built, Unix seconds.
    pub published: Option<i64>,
    /// Why nothing newer is proposed, when something newer exists.
    pub held: Vec<String>,
    /// The newest later major of the same shape: a person's to rehearse, never written.
    pub major: Option<String>,
}

/// The later tags of `current`'s shape: those of its major, newest first, and the
/// newest of a later major.
pub fn later_tags(current: &str, tags: &[String]) -> (Vec<String>, Option<String>) {
    let Some(now) = Version::parse(current) else {
        return (Vec::new(), None);
    };
    let mut same_major: Vec<Version> = Vec::new();
    let mut major: Option<Version> = None;
    for t in tags {
        let Some(v) = Version::parse(t) else { continue };
        if now.allows(&v, UpdateChannel::Minor) {
            same_major.push(v);
        } else if v.same_flavor(&now)
            && v.precision() == now.precision()
            && v.major > now.major
            && major.as_ref().is_none_or(|m| v.is_newer_than(m))
        {
            major = Some(v);
        }
    }
    same_major.sort_by(|a, b| {
        if a.is_newer_than(b) {
            std::cmp::Ordering::Less
        } else if b.is_newer_than(a) {
            std::cmp::Ordering::Greater
        } else {
            a.raw.cmp(&b.raw)
        }
    });
    (
        same_major.into_iter().map(|v| v.raw).collect(),
        major.map(|v| v.raw),
    )
}

/// Reads the registry for what `current` could move to.
///
/// A tag of its own shape within the major, the newest mature one; for a tag that
/// names a moving build (`v2`, `11.8`), the build it names today when that one is
/// mature. The digest is resolved here, at writing time: what the tag names now.
pub async fn propose(
    registry: &RegistryClient,
    owner: &str,
    current: &Image,
    maturation_days: u32,
    now: i64,
) -> Result<Proposal> {
    let mut p = Proposal {
        owner: owner.to_string(),
        current: current.clone(),
        to: None,
        published: None,
        held: Vec::new(),
        major: None,
    };
    if current.built_here {
        p.held
            .push("built here: its release builds it, from the Dockerfile's pinned bases".into());
        return Ok(p);
    }
    let at = |tag: &str| ImageRef::parse(&format!("{}:{tag}", current.repo));

    let tags = registry.list_tags(&at(&current.tag)).await?;
    let (later, major) = later_tags(&current.tag, &tags);
    p.major = major;

    // The current tag itself is the last candidate: a moving tag's newer build, or the
    // first digest of an image the catalog never pinned.
    for tag in later
        .iter()
        .map(String::as_str)
        .chain(std::iter::once(current.tag.as_str()))
        .take(DATED_AT_MOST)
    {
        let digest = registry.resolve_digest(&at(tag)).await?;
        if tag == current.tag && current.digest.as_deref() == Some(digest.as_str()) {
            break;
        }
        let dated = ImageRef {
            digest: Some(digest.clone()),
            ..at(tag)
        };
        let published = registry.created(&dated).await?;
        match Maturity::of(published, maturation_days, now).refusal(now) {
            Some(why) => p.held.push(format!("{tag}: {why}")),
            None => {
                p.to = Some(Image {
                    repo: current.repo.clone(),
                    tag: tag.to_string(),
                    digest: Some(digest),
                    built_here: false,
                });
                p.published = published;
                break;
            }
        }
    }
    Ok(p)
}

/// `manifest` with `from`'s image line naming `to` instead — the text edited in place,
/// comments and layout kept. `None` when the line is not found exactly once.
///
/// Images are written `image: { repo: …, tag: "…" }` across the catalog, with an
/// optional `digest: "…"`; anything else is left for a person to edit.
pub fn rewrite(manifest: &str, from: &Image, to: &Image) -> Option<String> {
    let old = match &from.digest {
        Some(d) => format!(
            "{{ repo: {}, tag: \"{}\", digest: \"{d}\" }}",
            from.repo, from.tag
        ),
        None => format!("{{ repo: {}, tag: \"{}\" }}", from.repo, from.tag),
    };
    let new = format!(
        "{{ repo: {}, tag: \"{}\", digest: \"{}\" }}",
        to.repo,
        to.tag,
        to.digest.as_deref()?
    );
    (manifest.matches(&old).count() == 1).then(|| manifest.replacen(&old, &new, 1))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tags(t: &[&str]) -> Vec<String> {
        t.iter().map(|s| s.to_string()).collect()
    }

    fn image(tag: &str, digest: Option<&str>) -> Image {
        Image {
            repo: "valkey/valkey".into(),
            tag: tag.into(),
            digest: digest.map(Into::into),
            built_here: false,
        }
    }

    #[test]
    fn a_major_is_said_never_proposed() {
        let (later, major) = later_tags(
            "1.24.3",
            &tags(&[
                "1.24.2", "1.24.7", "1.27.3", "28.2.0", "28.1.0", "1.25", "latest",
            ]),
        );
        assert_eq!(
            later,
            ["1.27.3", "1.24.7"],
            "newest first, the major left out"
        );
        assert_eq!(major.as_deref(), Some("28.2.0"));
    }

    #[test]
    fn the_shape_is_kept() {
        let (later, major) = later_tags(
            "8.1.9-alpine",
            &tags(&[
                "8.1.10-alpine",
                "8.1.10",
                "8.2-alpine",
                "9.0.1-alpine",
                "8.1.8-alpine",
            ]),
        );
        assert_eq!(later, ["8.1.10-alpine"]);
        assert_eq!(major.as_deref(), Some("9.0.1-alpine"));
        // A moving tag has no later tag of its shape within its major: its builds move.
        let (later, major) = later_tags("8-alpine", &tags(&["8.1.10-alpine", "9-alpine"]));
        assert!(later.is_empty());
        assert_eq!(major.as_deref(), Some("9-alpine"));
    }

    #[test]
    fn a_tag_that_is_not_a_version_proposes_nothing() {
        assert_eq!(later_tags("latest", &tags(&["1.0.0"])), (Vec::new(), None));
    }

    #[test]
    fn the_image_line_is_rewritten_in_place() {
        let yaml =
            "spec:\n  # Kept.\n  image: { repo: valkey/valkey, tag: \"8-alpine\" }\n  x: 1\n";
        let to = image("8.1.10-alpine", Some("sha256:new"));
        assert_eq!(
            rewrite(yaml, &image("8-alpine", None), &to).as_deref(),
            Some(
                "spec:\n  # Kept.\n  image: { repo: valkey/valkey, tag: \"8.1.10-alpine\", \
                 digest: \"sha256:new\" }\n  x: 1\n"
            )
        );
        // A pinned one is matched with its digest.
        let pinned = rewrite(yaml, &image("8-alpine", None), &to).expect("rewritten");
        let again = rewrite(&pinned, &to, &image("8.1.11-alpine", Some("sha256:newer")));
        assert!(again.is_some_and(|y| y.contains("8.1.11-alpine")));
        // Not found, or found twice: a person edits it.
        assert_eq!(rewrite(yaml, &image("9-alpine", None), &to), None);
        let twice = format!("{yaml}{yaml}");
        assert_eq!(rewrite(&twice, &image("8-alpine", None), &to), None);
    }
}
