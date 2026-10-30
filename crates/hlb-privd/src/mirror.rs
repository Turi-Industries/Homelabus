//! The Git mirror of the desired state: every installed app's manifest, committed when
//! it moves. Written here, beside the state it copies; the web side reads its history.

use hlb_api::intent::Acted;

use crate::Privd;

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

impl Privd {
    /// Commits the desired state after an action that may have moved it.
    ///
    /// 🔴 At once, not at the next reconciliation: an install from the interface reached
    /// the mirror at the next restart — and the history screen, which reads the mirror,
    /// never showed it. A run that stopped halfway still froze its manifest, so an
    /// unplannable APPLY is mirrored too; a preview moved nothing.
    pub(crate) async fn mirror(&self, moved: bool, action: &str, target: &str) {
        let (true, Some(path)) = (moved, &self.mirror) else {
            return;
        };
        if let Err(e) = export(path, &self.state, &format!("{action} {target}")).await {
            tracing::warn!("Git mirror not updated after {action} {target}: {e}");
        }
    }
}

/// Whether an answer may have moved the desired state.
pub(crate) fn moved(acted: &Acted, apply: bool) -> bool {
    match acted {
        Acted::Planned(r) => r.applied,
        Acted::Unplannable(_) => apply,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn applied(applied: bool) -> Acted {
        Acted::Planned(hlb_api::ActionResult {
            applied,
            summary: "install gitea".into(),
            steps: Vec::new(),
            cli_command: String::new(),
            blockers: Vec::new(),
            warnings: Vec::new(),
            confirmation_required: None,
        })
    }

    #[tokio::test]
    async fn an_applied_install_reaches_the_git_mirror_at_once() {
        let st = std::sync::Arc::new(hlb_state::State::in_memory().await.expect("state"));
        let m: hlb_types::Manifest = serde_yaml_ng::from_str(
            "apiVersion: hlb/v1\nkind: App\nmetadata: { name: gitea }\n\
             spec:\n  image: { repo: a/b, tag: \"1\" }\n",
        )
        .expect("manifest");
        st.upsert_app("gitea", &m, None).await.expect("app");
        let dir = tempfile::tempdir().expect("dir");
        let p = Privd::new(st).with_mirror(Some(dir.path().to_path_buf()));
        let versions = || {
            hlb_gitops::GitMirror::open_or_init(dir.path())
                .expect("mirror")
                .versions("gitea", 10)
                .expect("versions")
                .len()
        };

        p.mirror(moved(&applied(false), false), "app-install", "gitea")
            .await;
        assert_eq!(versions(), 0, "a preview moved nothing");
        p.mirror(moved(&applied(true), true), "app-install", "gitea")
            .await;
        assert_eq!(
            versions(),
            1,
            "the install waited for a restart to be mirrored"
        );
    }

    #[test]
    fn only_an_apply_that_stopped_halfway_is_mirrored() {
        let stopped = Acted::Unplannable("the run stopped".into());
        assert!(moved(&stopped, true));
        assert!(!moved(&stopped, false));
    }
}
