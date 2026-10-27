//! The manifest diff between installations (batch 9.11).
//!
//! ## 🔴 What it answers
//!
//! "The app worked last week. What changed?" — a question nothing answered:
//! `apps.manifest` is overwritten on every update.
//!
//! ## The diff is line by line, and that is enough
//!
//! A manifest YAML is a few dozen lines and changes little. A longest-common-subsequence
//! algorithm would give a prettier diff on a reordered file; here the serialisation
//! always comes from the same `serde`, so the order is stable. A set comparison is enough
//! and cannot lie about what it shows.

/// Why the Git mirror was not written.
#[derive(Debug, thiserror::Error)]
pub enum MirrorError {
    #[error(transparent)]
    State(#[from] hlb_state::Error),
    #[error(transparent)]
    Git(#[from] hlb_gitops::Error),
}

/// Writes the desired state — every installed app's manifest — into the Git mirror.
/// A commit only when it moved.
pub async fn export(
    path: &std::path::Path,
    state: &hlb_state::State,
    message: &str,
) -> Result<(), MirrorError> {
    let mut apps = Vec::new();
    for (name, status) in state.installed_apps().await? {
        let manifest = state.app_manifest(&name).await?;
        apps.push((name, status, manifest));
    }
    hlb_gitops::GitMirror::open_or_init(path)?.export(&apps, message)?;
    Ok(())
}

/// A manifest's successive versions, each with its diff.
pub fn versions(
    mirror: &hlb_gitops::GitMirror,
    app: &str,
    limit: usize,
) -> Vec<hlb_api::VersionManifest> {
    let raw = mirror.versions(app, limit).unwrap_or_default();
    let mut out = Vec::new();

    for (i, (reference, subject, content)) in raw.iter().enumerate() {
        // The next version in the list is the PREVIOUS one in time: the list runs from
        // most recent to oldest.
        let previous = raw.get(i + 1).map(|(_, _, c)| c.as_str());
        out.push(hlb_api::VersionManifest {
            reference: reference.clone(),
            subject: subject.clone(),
            diff: previous.map(|p| diff(p, content)).unwrap_or_default(),
            // 🔴 The oldest known version does not have an empty diff "because nothing
            // changed": it has nothing before it. Confusing the two would read as "no
            // change" on the initial install.
            origin: previous.is_none(),
        });
    }
    out
}

/// The lines removed then added, in the file's order.
pub fn diff(before: &str, after: &str) -> Vec<String> {
    let a: Vec<&str> = before.lines().collect();
    let b: Vec<&str> = after.lines().collect();

    let mut out = Vec::new();
    for l in &a {
        if !b.contains(l) {
            out.push(format!("- {l}"));
        }
    }
    for l in &b {
        if !a.contains(l) {
            out.push(format!("+ {l}"));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_changed_tag_shows_both_sides() {
        // The common case: an image update. Showing only the "+" would leave you
        // guessing where you came from, and that is precisely what we are after.
        let d = diff("image:\n  tag: 1.23\n", "image:\n  tag: 1.24\n");
        assert_eq!(d, vec!["-   tag: 1.23", "+   tag: 1.24"], "{d:?}");
    }

    #[test]
    fn an_identical_manifest_produces_nothing() {
        // 🔴 An empty diff shown as a change would send you looking for what moved when
        // nothing moved.
        assert!(diff("a\nb\n", "a\nb\n").is_empty());
    }

    #[test]
    fn the_first_known_version_is_not_reported_as_unchanged() {
        // ⚠️ "No change" and "nothing before" are two opposite answers. It is the
        // `origin` field that distinguishes them, not the size of the diff.
        let tmp = tempfile::tempdir().expect("temp directory");
        let m = hlb_gitops::GitMirror::open_or_init(tmp.path()).expect("mirror");
        let manifest = |tag: &str| -> hlb_types::Manifest {
            serde_yaml_ng::from_str(&format!(
                "apiVersion: hlb/v1\nkind: App\nmetadata: {{ name: gitea }}\n\
                 spec:\n  image: {{ repo: a/b, tag: \"{tag}\" }}\n"
            ))
            .expect("manifest")
        };

        m.export(
            &[("gitea".into(), "running".into(), manifest("1.23"))],
            "installation",
        )
        .expect("export");
        m.export(
            &[("gitea".into(), "running".into(), manifest("1.24"))],
            "update",
        )
        .expect("export");

        let v = versions(&m, "gitea", 10);
        assert_eq!(v.len(), 2);
        assert!(!v[0].origin, "the most recent one has a predecessor");
        assert!(!v[0].diff.is_empty(), "and a diff");
        assert!(v[1].origin, "the oldest one has nothing before it");
        assert!(v[1].diff.is_empty());
    }
}
